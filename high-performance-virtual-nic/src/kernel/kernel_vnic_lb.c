/*
 * Linux Kernel Virtual NIC with eBPF Session Load Balancing
 * Provides high performance with standard Linux networking
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <pthread.h>
#include <poll.h>
#include <sys/mman.h>
#include <time.h>

// Optional eBPF support
#ifdef HAVE_LIBBPF
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#endif

#include "../common/vnic_common.h"

#define RING_SIZE 2048
#define FRAME_SIZE 2048
#define JUMBO_FRAME_SIZE 9018

struct kernel_vnic_context {
    char name[32];
    int session_map_fd;
    int stats_map_fd;
    enum lb_algorithm algorithm;
    struct interface_stats interfaces[MAX_PHYSICAL_PORTS];
    uint8_t nb_interfaces;
    pthread_mutex_t session_mutex;
    volatile int running;
};

static struct kernel_vnic_context g_ctx;

// Hash-based session load balancing (userspace fallback)
static uint16_t hash_session_lb(struct session_key *key) {
    uint32_t hash = 0;
    uint32_t *data = (uint32_t*)key;
    
    // Simple hash function
    for (int i = 0; i < sizeof(*key) / sizeof(uint32_t); i++) {
        hash ^= data[i];
        hash = (hash << 13) | (hash >> 19);
    }
    
    // Find healthy interface
    uint8_t healthy_count = 0;
    for (int i = 0; i < g_ctx.nb_interfaces; i++) {
        if (g_ctx.interfaces[i].enabled && g_ctx.interfaces[i].health_status) {
            healthy_count++;
        }
    }
    
    if (healthy_count == 0) return 0;
    
    return hash % healthy_count;
}

// Extract session from packet
static int extract_session_from_packet(const void *packet, size_t len, struct session_key *key) {
    const struct ethhdr *eth;
    const struct iphdr *ip;
    const struct tcphdr *tcp;
    
    if (len < sizeof(struct ethhdr)) return -1;
    
    eth = (const struct ethhdr *)packet;
    if (ntohs(eth->h_proto) != ETH_P_IP) return -1;
    
    if (len < sizeof(struct ethhdr) + sizeof(struct iphdr)) return -1;
    
    ip = (const struct iphdr *)((const char *)packet + sizeof(struct ethhdr));
    
    key->src_ip = ip->saddr;
    key->dst_ip = ip->daddr;
    key->protocol = ip->protocol;
    
    if (ip->protocol == IPPROTO_TCP) {
        if (len < sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr))
            return -1;
        tcp = (const struct tcphdr *)((const char *)ip + (ip->ihl * 4));
        key->src_port = tcp->source;
        key->dst_port = tcp->dest;
    } else {
        key->src_port = 0;
        key->dst_port = 0;
    }
    
    return 0;
}

// Process packet with session load balancing
static uint16_t process_packet_lb(const void *packet, size_t len) {
    struct session_key key;
    
    if (extract_session_from_packet(packet, len, &key) < 0) {
        return 0; // Default to first interface
    }
    
    uint16_t target_interface;
    
#ifdef HAVE_LIBBPF
    // Try eBPF map lookup first
    if (g_ctx.session_map_fd >= 0) {
        struct session_stats stats;
        if (bpf_map_lookup_elem(g_ctx.session_map_fd, &key, &stats) == 0) {
            // Existing session
            stats.packets++;
            stats.bytes += len;
            stats.last_seen = time(NULL);
            bpf_map_update_elem(g_ctx.session_map_fd, &key, &stats, BPF_EXIST);
            return stats.assigned_interface;
        } else {
            // New session
            target_interface = hash_session_lb(&key);
            struct session_stats new_stats = {
                .packets = 1,
                .bytes = len,
                .last_seen = time(NULL),
                .assigned_interface = target_interface,
                .connection_state = 1
            };
            bpf_map_update_elem(g_ctx.session_map_fd, &key, &new_stats, BPF_NOEXIST);
            g_ctx.interfaces[target_interface].active_sessions++;
        }
    } else
#endif
    {
        // Fallback to userspace load balancing
        target_interface = hash_session_lb(&key);
    }
    
    // Update statistics
    g_ctx.interfaces[target_interface].tx_packets++;
    g_ctx.interfaces[target_interface].tx_bytes += len;
    
    return target_interface;
}

// Main packet processing loop
static void* packet_processing_thread(void *arg) {
    printf("Kernel VNIC packet processing thread started\n");
    
    while (g_ctx.running) {
        // Simplified packet processing
        // In real implementation, would use AF_PACKET sockets
        usleep(1000); // 1ms
    }
    
    return NULL;
}

// Initialize eBPF session tracking
static int init_ebpf_session_tracking(void) {
#ifdef HAVE_LIBBPF
    // Load eBPF program for session tracking
    struct bpf_object *obj;
    struct bpf_program *prog;
    
    obj = bpf_object__open_file("session_tracker.o", NULL);
    if (libbpf_get_error(obj)) {
        printf("Failed to open eBPF object file\n");
        return -1;
    }
    
    if (bpf_object__load(obj)) {
        printf("Failed to load eBPF object\n");
        return -1;
    }
    
    // Get session map
    struct bpf_map *session_map = bpf_object__find_map_by_name(obj, "session_map");
    if (!session_map) {
        printf("Failed to find session map\n");
        return -1;
    }
    
    g_ctx.session_map_fd = bpf_map__fd(session_map);
    
    printf("eBPF session tracking initialized\n");
    return 0;
#else
    printf("eBPF support not available, using userspace fallback\n");
    g_ctx.session_map_fd = -1;
    return 0;
#endif
}

// Print statistics
static void print_kernel_vnic_stats(void) {
    printf("\n=== Kernel Virtual NIC Statistics ===\n");
    printf("Algorithm: %s\n",
           g_ctx.algorithm == LB_HASH ? "Hash-based" :
           g_ctx.algorithm == LB_ROUND_ROBIN ? "Round Robin" :
           g_ctx.algorithm == LB_LEAST_CONN ? "Least Connections" : "Weighted");
    
    uint64_t total_tx_packets = 0, total_tx_bytes = 0;
    uint32_t total_sessions = 0;
    
    for (int i = 0; i < g_ctx.nb_interfaces; i++) {
        printf("Interface %d:\n", i);
        printf("  TX: %lu packets, %lu bytes\n",
               g_ctx.interfaces[i].tx_packets, g_ctx.interfaces[i].tx_bytes);
        printf("  Sessions: %u\n", g_ctx.interfaces[i].active_sessions);
        printf("  Health: %s\n", g_ctx.interfaces[i].health_status ? "OK" : "FAIL");
        
        total_tx_packets += g_ctx.interfaces[i].tx_packets;
        total_tx_bytes += g_ctx.interfaces[i].tx_bytes;
        total_sessions += g_ctx.interfaces[i].active_sessions;
    }
    
    printf("\nTotals:\n");
    printf("  TX Packets: %lu\n", total_tx_packets);
    printf("  TX Bytes: %lu\n", total_tx_bytes);
    printf("  Active Sessions: %u\n", total_sessions);
}

// Signal handler
static void signal_handler(int sig) {
    printf("\nReceived signal %d, shutting down...\n", sig);
    g_ctx.running = 0;
}

// Main function
int main(int argc, char **argv) {
    pthread_t processing_thread;
    
    printf("Kernel Virtual NIC with Session Load Balancing\n");
    
    // Initialize context
    memset(&g_ctx, 0, sizeof(g_ctx));
    strcpy(g_ctx.name, "kernel-vnic-lb");
    g_ctx.algorithm = LB_HASH;
    g_ctx.nb_interfaces = 4; // Example with 4 interfaces
    g_ctx.running = 1;
    g_ctx.session_map_fd = -1;
    
    // Initialize interfaces
    for (int i = 0; i < g_ctx.nb_interfaces; i++) {
        g_ctx.interfaces[i].enabled = 1;
        g_ctx.interfaces[i].health_status = 1;
        g_ctx.interfaces[i].weight = 100;
    }
    
    pthread_mutex_init(&g_ctx.session_mutex, NULL);
    
    // Setup signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Initialize eBPF session tracking
    if (init_ebpf_session_tracking() < 0) {
        printf("Warning: eBPF initialization failed, using userspace fallback\n");
    }
    
    // Start packet processing thread
    if (pthread_create(&processing_thread, NULL, packet_processing_thread, NULL) != 0) {
        printf("Failed to create processing thread\n");
        return 1;
    }
    
    printf("Kernel VNIC started with %d interfaces\n", g_ctx.nb_interfaces);
    printf("Press Ctrl+C to stop...\n");
    
    // Main loop - print stats every 5 seconds
    while (g_ctx.running) {
        sleep(5);
        print_kernel_vnic_stats();
    }
    
    // Cleanup
    printf("\nShutting down...\n");
    pthread_join(processing_thread, NULL);
    pthread_mutex_destroy(&g_ctx.session_mutex);
    
    printf("Kernel VNIC shutdown complete\n");
    return 0;
}
