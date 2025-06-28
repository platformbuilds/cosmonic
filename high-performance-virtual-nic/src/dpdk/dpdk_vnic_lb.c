/*
 * DPDK Virtual NIC with Advanced Session Load Balancing
 * Provides line-rate performance with intelligent traffic distribution
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_ring.h>

#include "../common/vnic_common.h"

#define RTE_LOGTYPE_VNIC RTE_LOGTYPE_USER1
#define MEMPOOL_CACHE_SIZE 256
#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16

static volatile bool force_quit;

struct vnic_port_config {
    uint32_t rx_ring_size;
    uint32_t tx_ring_size;
    uint16_t nb_rxd;
    uint16_t nb_txd;
};

struct session_load_balancer {
    struct rte_hash *session_table;
    struct session_stats *sessions;
    struct interface_stats interfaces[MAX_PHYSICAL_PORTS];
    enum lb_algorithm algorithm;
    uint32_t rr_counter;
    uint64_t total_sessions;
    struct rte_ring *rebalance_queue;
};

struct vnic_context {
    struct rte_mempool *mbuf_pool;
    struct session_load_balancer *lb;
    uint16_t port_ids[MAX_PHYSICAL_PORTS];
    uint16_t nb_ports;
    char name[32];
};

static struct vnic_context g_vnic_ctx;

// Hash-based load balancing with perfect session affinity
static uint16_t hash_based_lb(struct session_load_balancer *lb, struct session_key *key) {
    uint32_t hash = rte_jhash(key, sizeof(*key), 0);
    
    // Count healthy interfaces
    uint8_t healthy_count = 0;
    for (int i = 0; i < MAX_PHYSICAL_PORTS; i++) {
        if (lb->interfaces[i].enabled && lb->interfaces[i].health_status) {
            healthy_count++;
        }
    }
    
    if (healthy_count == 0) return 0;
    
    // Map hash to healthy interface
    uint16_t target = hash % healthy_count;
    uint8_t current = 0;
    
    for (int i = 0; i < MAX_PHYSICAL_PORTS; i++) {
        if (lb->interfaces[i].enabled && lb->interfaces[i].health_status) {
            if (current == target) return i;
            current++;
        }
    }
    return 0;
}

// Least connections load balancing
static uint16_t least_connections_lb(struct session_load_balancer *lb) {
    uint16_t best_interface = 0;
    uint32_t min_sessions = UINT32_MAX;
    
    for (int i = 0; i < MAX_PHYSICAL_PORTS; i++) {
        if (lb->interfaces[i].enabled && lb->interfaces[i].health_status) {
            if (lb->interfaces[i].active_sessions < min_sessions) {
                min_sessions = lb->interfaces[i].active_sessions;
                best_interface = i;
            }
        }
    }
    return best_interface;
}

// Weighted load balancing
static uint16_t weighted_lb(struct session_load_balancer *lb) {
    uint16_t best_interface = 0;
    uint64_t min_weighted_load = UINT64_MAX;
    
    for (int i = 0; i < MAX_PHYSICAL_PORTS; i++) {
        if (lb->interfaces[i].enabled && lb->interfaces[i].health_status) {
            uint64_t weighted_load = (lb->interfaces[i].active_sessions * 100) / 
                                   (lb->interfaces[i].weight > 0 ? lb->interfaces[i].weight : 1);
            if (weighted_load < min_weighted_load) {
                min_weighted_load = weighted_load;
                best_interface = i;
            }
        }
    }
    return best_interface;
}

// Extract session key from packet
static int extract_session_key(struct rte_mbuf *pkt, struct session_key *key) {
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ipv4_hdr;
    struct rte_tcp_hdr *tcp_hdr;
    struct rte_udp_hdr *udp_hdr;
    
    eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    if (eth_hdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
        return -1;
    }
    
    ipv4_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    
    key->src_ip = ipv4_hdr->src_addr;
    key->dst_ip = ipv4_hdr->dst_addr;
    key->protocol = ipv4_hdr->next_proto_id;
    
    if (key->protocol == IPPROTO_TCP) {
        tcp_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_tcp_hdr *, 
                                         sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
        key->src_port = tcp_hdr->src_port;
        key->dst_port = tcp_hdr->dst_port;
    } else if (key->protocol == IPPROTO_UDP) {
        udp_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_udp_hdr *,
                                         sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
        key->src_port = udp_hdr->src_port;
        key->dst_port = udp_hdr->dst_port;
    } else {
        key->src_port = 0;
        key->dst_port = 0;
    }
    
    return 0;
}

// Main load balancing function
static uint16_t select_interface_lb(struct session_load_balancer *lb, struct rte_mbuf *pkt) {
    struct session_key key;
    
    if (extract_session_key(pkt, &key) < 0) {
        return 0; // Non-IP traffic to first interface
    }
    
    // Look up existing session
    int32_t session_idx = rte_hash_lookup(lb->session_table, &key);
    
    if (session_idx >= 0) {
        // Existing session - use assigned interface
        struct session_stats *session = &lb->sessions[session_idx];
        session->packets++;
        session->bytes += rte_pktmbuf_pkt_len(pkt);
        session->last_seen = rte_rdtsc();
        return session->assigned_interface;
    }
    
    // New session - apply load balancing
    uint16_t selected_interface;
    switch (lb->algorithm) {
        case LB_HASH:
            selected_interface = hash_based_lb(lb, &key);
            break;
        case LB_LEAST_CONN:
            selected_interface = least_connections_lb(lb);
            break;
        case LB_WEIGHTED:
            selected_interface = weighted_lb(lb);
            break;
        case LB_ROUND_ROBIN:
        default:
            selected_interface = (lb->rr_counter++) % MAX_PHYSICAL_PORTS;
            while (!lb->interfaces[selected_interface].enabled || 
                   !lb->interfaces[selected_interface].health_status) {
                selected_interface = (lb->rr_counter++) % MAX_PHYSICAL_PORTS;
            }
            break;
    }
    
    // Add new session
    session_idx = rte_hash_add_key(lb->session_table, &key);
    if (session_idx >= 0) {
        struct session_stats *new_session = &lb->sessions[session_idx];
        new_session->packets = 1;
        new_session->bytes = rte_pktmbuf_pkt_len(pkt);
        new_session->last_seen = rte_rdtsc();
        new_session->assigned_interface = selected_interface;
        new_session->connection_state = 1;
        
        lb->interfaces[selected_interface].active_sessions++;
        lb->total_sessions++;
    }
    
    return selected_interface;
}

// Process packets with load balancing
static int process_packets_lb(struct vnic_context *ctx, struct rte_mbuf **pkts, uint16_t nb_pkts) {
    struct session_load_balancer *lb = ctx->lb;
    
    for (uint16_t i = 0; i < nb_pkts; i++) {
        uint16_t target_port = select_interface_lb(lb, pkts[i]);
        
        // Update statistics
        lb->interfaces[target_port].tx_packets++;
        lb->interfaces[target_port].tx_bytes += rte_pktmbuf_pkt_len(pkts[i]);
        
        // Transmit packet
        uint16_t sent = rte_eth_tx_burst(ctx->port_ids[target_port], 0, &pkts[i], 1);
        if (sent != 1) {
            rte_pktmbuf_free(pkts[i]);
            lb->interfaces[target_port].tx_dropped++;
        }
    }
    
    return nb_pkts;
}

// Main processing loop
static int vnic_main_loop(__rte_unused void *dummy) {
    struct rte_mbuf *pkts_burst[BURST_SIZE];
    uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc;
    unsigned lcore_id;
    
    lcore_id = rte_lcore_id();
    RTE_LOG(INFO, VNIC, "Starting main loop on lcore %u\n", lcore_id);
    
    timer_tsc = 0;
    prev_tsc = 0;
    
    while (!force_quit) {
        cur_tsc = rte_rdtsc();
        diff_tsc = cur_tsc - prev_tsc;
        
        // Process packets from all ports
        for (uint16_t port = 0; port < g_vnic_ctx.nb_ports; port++) {
            uint16_t nb_rx = rte_eth_rx_burst(g_vnic_ctx.port_ids[port], 0,
                                            pkts_burst, BURST_SIZE);
            
            if (unlikely(nb_rx == 0))
                continue;
            
            // Update RX statistics
            g_vnic_ctx.lb->interfaces[port].rx_packets += nb_rx;
            for (int i = 0; i < nb_rx; i++) {
                g_vnic_ctx.lb->interfaces[port].rx_bytes += rte_pktmbuf_pkt_len(pkts_burst[i]);
            }
            
            // Process with load balancing
            process_packets_lb(&g_vnic_ctx, pkts_burst, nb_rx);
        }
        
        // Periodic maintenance
        if (unlikely(diff_tsc > timer_tsc)) {
            // Session cleanup and health monitoring
            timer_tsc = cur_tsc + rte_get_tsc_hz(); // 1 second
            prev_tsc = cur_tsc;
        }
    }
    
    return 0;
}

// Initialize session load balancer
static struct session_load_balancer* init_session_lb(enum lb_algorithm alg) {
    struct session_load_balancer *lb = rte_zmalloc("session_lb", 
                                                   sizeof(*lb), RTE_CACHE_LINE_SIZE);
    if (!lb) return NULL;
    
    // Create session hash table
    struct rte_hash_parameters hash_params = {
        .name = "session_table",
        .entries = MAX_SESSIONS,
        .key_len = sizeof(struct session_key),
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id()
    };
    
    lb->session_table = rte_hash_create(&hash_params);
    if (!lb->session_table) {
        rte_free(lb);
        return NULL;
    }
    
    lb->sessions = rte_zmalloc("sessions", 
                               sizeof(struct session_stats) * MAX_SESSIONS,
                               RTE_CACHE_LINE_SIZE);
    if (!lb->sessions) {
        rte_hash_free(lb->session_table);
        rte_free(lb);
        return NULL;
    }
    
    lb->algorithm = alg;
    lb->rr_counter = 0;
    lb->total_sessions = 0;
    
    // Initialize interface stats
    for (int i = 0; i < MAX_PHYSICAL_PORTS; i++) {
        lb->interfaces[i].weight = 100;
        lb->interfaces[i].enabled = 1;
        lb->interfaces[i].health_status = 1;
    }
    
    return lb;
}

// Signal handler
static void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\nSignal %d received, preparing to exit...\n", signum);
        force_quit = true;
    }
}

// Print statistics
static void print_stats(void) {
    struct session_load_balancer *lb = g_vnic_ctx.lb;
    
    printf("\n=== DPDK Virtual NIC Statistics ===\n");
    printf("Load Balancing Algorithm: %s\n",
           lb->algorithm == LB_HASH ? "Hash-based" :
           lb->algorithm == LB_ROUND_ROBIN ? "Round Robin" :
           lb->algorithm == LB_LEAST_CONN ? "Least Connections" :
           lb->algorithm == LB_WEIGHTED ? "Weighted" : "Adaptive");
    
    printf("Total Active Sessions: %lu\n", lb->total_sessions);
    
    for (int i = 0; i < g_vnic_ctx.nb_ports; i++) {
        printf("\nPort %d Statistics:\n", i);
        printf("  RX: %lu packets, %lu bytes\n", 
               lb->interfaces[i].rx_packets, lb->interfaces[i].rx_bytes);
        printf("  TX: %lu packets, %lu bytes\n",
               lb->interfaces[i].tx_packets, lb->interfaces[i].tx_bytes);
        printf("  Active Sessions: %u\n", lb->interfaces[i].active_sessions);
        printf("  Health: %s\n", lb->interfaces[i].health_status ? "OK" : "FAIL");
    }
}

// Main function
int main(int argc, char **argv) {
    int ret;
    uint16_t nb_ports;
    uint16_t portid;
    
    // Initialize DPDK EAL
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_panic("Cannot init EAL\n");
    
    argc -= ret;
    argv += ret;
    
    force_quit = false;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Check number of ports
    nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0)
        rte_panic("No Ethernet ports - bye\n");
    
    // Initialize VNIC context
    memset(&g_vnic_ctx, 0, sizeof(g_vnic_ctx));
    strcpy(g_vnic_ctx.name, "dpdk-vnic-lb");
    g_vnic_ctx.nb_ports = nb_ports;
    
    // Create mbuf pool
    g_vnic_ctx.mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", 8192 * nb_ports,
                                                   MEMPOOL_CACHE_SIZE, 0,
                                                   RTE_MBUF_DEFAULT_BUF_SIZE,
                                                   rte_socket_id());
    if (g_vnic_ctx.mbuf_pool == NULL)
        rte_panic("Cannot create mbuf pool\n");
    
    // Initialize session load balancer
    g_vnic_ctx.lb = init_session_lb(LB_HASH);
    if (!g_vnic_ctx.lb)
        rte_panic("Cannot initialize session load balancer\n");
    
    // Initialize ports
    RTE_ETH_FOREACH_DEV(portid) {
        if (portid >= MAX_PHYSICAL_PORTS)
            break;
            
        g_vnic_ctx.port_ids[portid] = portid;
        
        // Configure port (simplified)
        ret = rte_eth_dev_configure(portid, 1, 1, NULL);
        if (ret < 0)
            rte_panic("Cannot configure device: err=%d, port=%u\n", ret, portid);
        
        // Setup RX/TX queues (simplified)
        ret = rte_eth_rx_queue_setup(portid, 0, 1024, rte_eth_dev_socket_id(portid),
                                     NULL, g_vnic_ctx.mbuf_pool);
        if (ret < 0)
            rte_panic("rte_eth_rx_queue_setup:err=%d, port=%u\n", ret, portid);
        
        ret = rte_eth_tx_queue_setup(portid, 0, 1024, rte_eth_dev_socket_id(portid), NULL);
        if (ret < 0)
            rte_panic("rte_eth_tx_queue_setup:err=%d, port=%u\n", ret, portid);
        
        // Start device
        ret = rte_eth_dev_start(portid);
        if (ret < 0)
            rte_panic("rte_eth_dev_start:err=%d, port=%u\n", ret, portid);
        
        printf("Port %u initialized\n", portid);
    }
    
    printf("DPDK Virtual NIC with Session Load Balancing initialized\n");
    printf("Using %u ports with %s algorithm\n", nb_ports, "Hash-based");
    
    // Launch main loop
    rte_eal_mp_remote_launch(vnic_main_loop, NULL, CALL_MAIN);
    
    // Wait for lcores to finish
    RTE_LCORE_FOREACH_WORKER(portid) {
        if (rte_eal_wait_lcore(portid) < 0) {
            ret = -1;
            break;
        }
    }
    
    // Print final statistics
    print_stats();
    
    // Cleanup
    force_quit = true;
    
    RTE_ETH_FOREACH_DEV(portid) {
        printf("Closing port %d...", portid);
        ret = rte_eth_dev_stop(portid);
        if (ret != 0)
            printf("rte_eth_dev_stop: err=%d, port=%d\n", ret, portid);
        rte_eth_dev_close(portid);
        printf(" Done\n");
    }
    
    rte_eal_cleanup();
    printf("Bye...\n");
    
    return ret;
}
