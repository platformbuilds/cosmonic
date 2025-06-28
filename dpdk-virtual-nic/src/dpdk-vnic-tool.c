#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <getopt.h>
#include <inttypes.h>

#include <rte_common.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ring.h>
#include <rte_lcore.h>
#include <rte_launch.h>
#include <rte_cycles.h>
#include <rte_timer.h>
#include <rte_debug.h>
#include <rte_flow.h>

#define MAX_VNICS 16
#define MAX_PHYSICAL_PORTS 8
#define MAX_QUEUES 8
#define MBUF_CACHE_SIZE 512
#define BURST_SIZE 32
#define MAX_PKT_BURST 32
#define JUMBO_FRAME_MAX_SIZE 9018
#define STANDARD_FRAME_MAX_SIZE 1518
#define MBUF_SIZE (JUMBO_FRAME_MAX_SIZE + RTE_PKTMBUF_HEADROOM)

struct physical_port {
    uint16_t port_id;
    char name[RTE_ETH_NAME_MAX_LEN];
    struct rte_ether_addr mac_addr;
    uint16_t mtu;
    uint8_t enabled;
    uint8_t link_status;
    struct rte_eth_dev_info dev_info;
};

struct vnic_port_mapping {
    uint16_t physical_ports[MAX_PHYSICAL_PORTS];
    uint8_t num_ports;
    uint8_t active_port_idx;
    uint8_t failover_enabled;
};

struct vnic_config {
    char name[32];
    uint8_t vnic_id;
    struct vnic_port_mapping port_mapping;
    struct rte_ether_addr mac_addr;
    uint32_t ip_addr;
    uint32_t netmask;
    uint16_t mtu;
    uint8_t jumbo_frames;
    uint8_t enabled;
    uint8_t created;
    
    // DPDK resources
    struct rte_mempool *mbuf_pool;
    struct rte_ring *rx_ring;
    struct rte_ring *tx_ring;
    uint16_t nb_rx_queues;
    uint16_t nb_tx_queues;
};

struct dpdk_vnic_manager {
    struct physical_port physical_ports[MAX_PHYSICAL_PORTS];
    struct vnic_config vnics[MAX_VNICS];
    uint8_t num_physical_ports;
    uint8_t num_vnics;
    uint8_t initialized;
    struct rte_mempool *global_mbuf_pool;
};

// Global manager instance
static struct dpdk_vnic_manager g_manager = {0};
static volatile bool force_quit = false;

// Function prototypes
int init_dpdk_environment(int argc, char **argv);
int discover_physical_ports(void);
int create_vnic(const char *name, const char *port_list, int jumbo_frames);
int configure_vnic_ip(const char *name, const char *ip_cidr);
int enable_vnic(const char *name);
int disable_vnic(const char *name);
int delete_vnic(const char *name);
int show_vnic_info(const char *name);
int list_physical_ports(void);
int list_vnics(void);
int configure_physical_port(uint16_t port_id, int jumbo_frames);
int setup_vnic_datapath(struct vnic_config *vnic);
static int vnic_worker_thread(void *arg);
void cleanup_dpdk_resources(void);
void signal_handler(int signum);
void print_usage(const char *prog_name);

/**
 * Initialize DPDK environment
 */
int init_dpdk_environment(int argc, char **argv) {
    int ret;
    
    // Initialize DPDK EAL
    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_panic("Cannot init EAL\n");
        return -1;
    }
    
    // Check if we have enough ports
    g_manager.num_physical_ports = rte_eth_dev_count_avail();
    if (g_manager.num_physical_ports == 0) {
        printf("No Ethernet ports available\n");
        return -1;
    }
    
    printf("Detected %d physical Ethernet ports\n", g_manager.num_physical_ports);
    
    // Create global memory pool for mbufs
    g_manager.global_mbuf_pool = rte_pktmbuf_pool_create("GLOBAL_MBUF_POOL",
        8192 * g_manager.num_physical_ports, MBUF_CACHE_SIZE, 0,
        MBUF_SIZE, rte_socket_id());
    
    if (g_manager.global_mbuf_pool == NULL) {
        rte_panic("Cannot create global mbuf pool\n");
        return -1;
    }
    
    g_manager.initialized = 1;
    return 0;
}

/**
 * Discover and initialize physical ports
 */
int discover_physical_ports(void) {
    uint16_t port_id;
    int ret;
    
    if (!g_manager.initialized) {
        printf("DPDK not initialized\n");
        return -1;
    }
    
    RTE_ETH_FOREACH_DEV(port_id) {
        if (port_id >= MAX_PHYSICAL_PORTS) {
            printf("Too many ports, maximum supported: %d\n", MAX_PHYSICAL_PORTS);
            break;
        }
        
        struct physical_port *port = &g_manager.physical_ports[port_id];
        port->port_id = port_id;
        
        // Get device info
        ret = rte_eth_dev_info_get(port_id, &port->dev_info);
        if (ret != 0) {
            printf("Error getting device info for port %d: %s\n", 
                   port_id, strerror(-ret));
            continue;
        }
        
        // Get device name
        rte_eth_dev_get_name_by_port(port_id, port->name);
        
        // Get MAC address
        ret = rte_eth_macaddr_get(port_id, &port->mac_addr);
        if (ret != 0) {
            printf("Error getting MAC address for port %d\n", port_id);
            continue;
        }
        
        // Initialize with jumbo frame support
        port->mtu = JUMBO_FRAME_MAX_SIZE - RTE_ETHER_HDR_LEN - RTE_ETHER_CRC_LEN;
        port->enabled = 1;
        
        printf("Port %d: %s MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               port_id, port->name,
               port->mac_addr.addr_bytes[0], port->mac_addr.addr_bytes[1],
               port->mac_addr.addr_bytes[2], port->mac_addr.addr_bytes[3],
               port->mac_addr.addr_bytes[4], port->mac_addr.addr_bytes[5]);
    }
    
    return 0;
}

/**
 * Configure a physical port for DPDK
 */
int configure_physical_port(uint16_t port_id, int jumbo_frames) {
    struct rte_eth_conf port_conf = {0};
    struct rte_eth_rxconf rxq_conf;
    struct rte_eth_txconf txq_conf;
    int ret;
    uint16_t nb_rxd = 1024;
    uint16_t nb_txd = 1024;
    
    if (port_id >= g_manager.num_physical_ports) {
        printf("Invalid port ID: %d\n", port_id);
        return -1;
    }
    
    struct physical_port *port = &g_manager.physical_ports[port_id];
    
    // Configure port for jumbo frames if requested
    if (jumbo_frames) {
        port_conf.rxmode.mtu = JUMBO_FRAME_MAX_SIZE - RTE_ETHER_HDR_LEN - RTE_ETHER_CRC_LEN;
        port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MULTI_SEGS;
        port->mtu = port_conf.rxmode.mtu;
    } else {
        port_conf.rxmode.mtu = STANDARD_FRAME_MAX_SIZE - RTE_ETHER_HDR_LEN - RTE_ETHER_CRC_LEN;
        port->mtu = port_conf.rxmode.mtu;
    }
    
    // Enable checksums and other offloads
    port_conf.rxmode.offloads = RTE_ETH_RX_OFFLOAD_CHECKSUM;
    port_conf.txmode.offloads = RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | 
                                RTE_ETH_TX_OFFLOAD_TCP_CKSUM | 
                                RTE_ETH_TX_OFFLOAD_UDP_CKSUM;
    
    // Configure the Ethernet device
    ret = rte_eth_dev_configure(port_id, 1, 1, &port_conf);
    if (ret != 0) {
        printf("Cannot configure device: err=%d, port=%d\n", ret, port_id);
        return ret;
    }
    
    // Adjust descriptor numbers
    ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd);
    if (ret != 0) {
        printf("Cannot adjust number of descriptors: err=%d, port=%d\n", ret, port_id);
        return ret;
    }
    
    // Setup RX queue
    rxq_conf = port->dev_info.default_rxconf;
    rxq_conf.offloads = port_conf.rxmode.offloads;
    ret = rte_eth_rx_queue_setup(port_id, 0, nb_rxd, rte_eth_dev_socket_id(port_id),
                                 &rxq_conf, g_manager.global_mbuf_pool);
    if (ret < 0) {
        printf("Cannot setup RX queue: err=%d, port=%d\n", ret, port_id);
        return ret;
    }
    
    // Setup TX queue
    txq_conf = port->dev_info.default_txconf;
    txq_conf.offloads = port_conf.txmode.offloads;
    ret = rte_eth_tx_queue_setup(port_id, 0, nb_txd, rte_eth_dev_socket_id(port_id), &txq_conf);
    if (ret < 0) {
        printf("Cannot setup TX queue: err=%d, port=%d\n", ret, port_id);
        return ret;
    }
    
    // Start the Ethernet port
    ret = rte_eth_dev_start(port_id);
    if (ret < 0) {
        printf("Cannot start device: err=%d, port=%d\n", ret, port_id);
        return ret;
    }
    
    // Enable promiscuous mode
    ret = rte_eth_promiscuous_enable(port_id);
    if (ret != 0) {
        printf("Cannot enable promiscuous mode: err=%s, port=%d\n",
               rte_strerror(-ret), port_id);
        return ret;
    }
    
    printf("Port %d configured successfully with %s frames (MTU: %d)\n",
           port_id, jumbo_frames ? "jumbo" : "standard", port->mtu);
    
    return 0;
}

/**
 * Create a virtual NIC
 */
int create_vnic(const char *name, const char *port_list, int jumbo_frames) {
    struct vnic_config *vnic = NULL;
    char *port_str, *token, *saveptr;
    int port_num;
    int i;
    
    // Find available VNIC slot
    for (i = 0; i < MAX_VNICS; i++) {
        if (!g_manager.vnics[i].created) {
            vnic = &g_manager.vnics[i];
            break;
        }
    }
    
    if (!vnic) {
        printf("Maximum number of VNICs (%d) reached\n", MAX_VNICS);
        return -1;
    }
    
    // Initialize VNIC configuration
    memset(vnic, 0, sizeof(*vnic));
    strncpy(vnic->name, name, sizeof(vnic->name) - 1);
    vnic->vnic_id = i;
    vnic->jumbo_frames = jumbo_frames;
    vnic->mtu = jumbo_frames ? (JUMBO_FRAME_MAX_SIZE - RTE_ETHER_HDR_LEN - RTE_ETHER_CRC_LEN) :
                               (STANDARD_FRAME_MAX_SIZE - RTE_ETHER_HDR_LEN - RTE_ETHER_CRC_LEN);
    
    // Parse port list
    port_str = strdup(port_list);
    if (!port_str) {
        printf("Memory allocation failed\n");
        return -1;
    }
    
    token = strtok_r(port_str, ",", &saveptr);
    while (token && vnic->port_mapping.num_ports < MAX_PHYSICAL_PORTS) {
        port_num = atoi(token);
        if (port_num >= 0 && port_num < g_manager.num_physical_ports) {
            vnic->port_mapping.physical_ports[vnic->port_mapping.num_ports] = port_num;
            vnic->port_mapping.num_ports++;
            
            // Configure the physical port
            configure_physical_port(port_num, jumbo_frames);
        } else {
            printf("Invalid port number: %d\n", port_num);
        }
        token = strtok_r(NULL, ",", &saveptr);
    }
    
    free(port_str);
    
    if (vnic->port_mapping.num_ports == 0) {
        printf("No valid ports specified\n");
        return -1;
    }
    
    // Set active port to first in list
    vnic->port_mapping.active_port_idx = 0;
    vnic->port_mapping.failover_enabled = (vnic->port_mapping.num_ports > 1);
    
    // Create memory pool for this VNIC
    char pool_name[32];
    snprintf(pool_name, sizeof(pool_name), "MBUF_POOL_%s", name);
    vnic->mbuf_pool = rte_pktmbuf_pool_create(pool_name, 4096, MBUF_CACHE_SIZE, 0,
                                              MBUF_SIZE, rte_socket_id());
    if (!vnic->mbuf_pool) {
        printf("Cannot create mbuf pool for VNIC %s\n", name);
        return -1;
    }
    
    // Create rings for packet processing
    char ring_name[32];
    snprintf(ring_name, sizeof(ring_name), "RX_RING_%s", name);
    vnic->rx_ring = rte_ring_create(ring_name, 1024, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    
    snprintf(ring_name, sizeof(ring_name), "TX_RING_%s", name);
    vnic->tx_ring = rte_ring_create(ring_name, 1024, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    
    if (!vnic->rx_ring || !vnic->tx_ring) {
        printf("Cannot create rings for VNIC %s\n", name);
        return -1;
    }
    
    // Generate MAC address for VNIC
    vnic->mac_addr.addr_bytes[0] = 0x02; // Locally administered
    vnic->mac_addr.addr_bytes[1] = 0x00;
    vnic->mac_addr.addr_bytes[2] = 0x00;
    vnic->mac_addr.addr_bytes[3] = 0x00;
    vnic->mac_addr.addr_bytes[4] = 0x00;
    vnic->mac_addr.addr_bytes[5] = vnic->vnic_id;
    
    vnic->created = 1;
    g_manager.num_vnics++;
    
    printf("Created VNIC '%s' with %d physical ports (%s frames)\n",
           name, vnic->port_mapping.num_ports, jumbo_frames ? "jumbo" : "standard");
    printf("Assigned ports: ");
    for (i = 0; i < vnic->port_mapping.num_ports; i++) {
        printf("%d%s", vnic->port_mapping.physical_ports[i],
               (i < vnic->port_mapping.num_ports - 1) ? "," : "");
    }
    printf("\n");
    
    return 0;
}

/**
 * Configure IP address for VNIC
 */
int configure_vnic_ip(const char *name, const char *ip_cidr) {
    struct vnic_config *vnic = NULL;
    char ip_str[16];
    int prefix_len;
    int i;
    
    // Parse IP/CIDR
    char *slash = strchr(ip_cidr, '/');
    if (!slash) {
        printf("IP address must be in CIDR format (e.g., 192.168.1.10/24)\n");
        return -1;
    }
    
    strncpy(ip_str, ip_cidr, slash - ip_cidr);
    ip_str[slash - ip_cidr] = '\0';
    prefix_len = atoi(slash + 1);
    
    // Find VNIC
    for (i = 0; i < MAX_VNICS; i++) {
        if (g_manager.vnics[i].created && strcmp(g_manager.vnics[i].name, name) == 0) {
            vnic = &g_manager.vnics[i];
            break;
        }
    }
    
    if (!vnic) {
        printf("VNIC '%s' not found\n", name);
        return -1;
    }
    
    // Convert IP address
    struct in_addr addr;
    if (inet_aton(ip_str, &addr) == 0) {
        printf("Invalid IP address: %s\n", ip_str);
        return -1;
    }
    
    vnic->ip_addr = addr.s_addr;
    
    // Calculate netmask
    vnic->netmask = htonl(~((1 << (32 - prefix_len)) - 1));
    
    printf("Configured VNIC '%s' with IP %s/%d\n", name, ip_str, prefix_len);
    
    return 0;
}

/**
 * Setup VNIC datapath
 */
int setup_vnic_datapath(struct vnic_config *vnic) {
    // This would setup the actual packet processing pipeline
    // For now, we'll just print the configuration
    printf("Setting up datapath for VNIC '%s'\n", vnic->name);
    printf("  Active port: %d\n", vnic->port_mapping.physical_ports[vnic->port_mapping.active_port_idx]);
    printf("  Failover enabled: %s\n", vnic->port_mapping.failover_enabled ? "Yes" : "No");
    printf("  MTU: %d\n", vnic->mtu);
    
    return 0;
}

/**
 * Enable VNIC
 */
int enable_vnic(const char *name) {
    struct vnic_config *vnic = NULL;
    int i;
    
    for (i = 0; i < MAX_VNICS; i++) {
        if (g_manager.vnics[i].created && strcmp(g_manager.vnics[i].name, name) == 0) {
            vnic = &g_manager.vnics[i];
            break;
        }
    }
    
    if (!vnic) {
        printf("VNIC '%s' not found\n", name);
        return -1;
    }
    
    if (!vnic->ip_addr) {
        printf("VNIC '%s' has no IP address configured\n", name);
        return -1;
    }
    
    vnic->enabled = 1;
    setup_vnic_datapath(vnic);
    
    printf("VNIC '%s' enabled\n", name);
    return 0;
}

/**
 * Disable VNIC
 */
int disable_vnic(const char *name) {
    struct vnic_config *vnic = NULL;
    int i;
    
    for (i = 0; i < MAX_VNICS; i++) {
        if (g_manager.vnics[i].created && strcmp(g_manager.vnics[i].name, name) == 0) {
            vnic = &g_manager.vnics[i];
            break;
        }
    }
    
    if (!vnic) {
        printf("VNIC '%s' not found\n", name);
        return -1;
    }
    
    vnic->enabled = 0;
    printf("VNIC '%s' disabled\n", name);
    return 0;
}

/**
 * Show VNIC information
 */
int show_vnic_info(const char *name) {
    struct vnic_config *vnic = NULL;
    int i;
    
    for (i = 0; i < MAX_VNICS; i++) {
        if (g_manager.vnics[i].created && strcmp(g_manager.vnics[i].name, name) == 0) {
            vnic = &g_manager.vnics[i];
            break;
        }
    }
    
    if (!vnic) {
        printf("VNIC '%s' not found\n", name);
        return -1;
    }
    
    printf("\nVNIC Information: %s\n", vnic->name);
    printf("----------------------------------------\n");
    printf("ID: %d\n", vnic->vnic_id);
    printf("Status: %s\n", vnic->enabled ? "ENABLED" : "DISABLED");
    printf("MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
           vnic->mac_addr.addr_bytes[0], vnic->mac_addr.addr_bytes[1],
           vnic->mac_addr.addr_bytes[2], vnic->mac_addr.addr_bytes[3],
           vnic->mac_addr.addr_bytes[4], vnic->mac_addr.addr_bytes[5]);
    
    if (vnic->ip_addr) {
        struct in_addr addr;
        addr.s_addr = vnic->ip_addr;
        printf("IP Address: %s\n", inet_ntoa(addr));
        
        addr.s_addr = vnic->netmask;
        printf("Netmask: %s\n", inet_ntoa(addr));
    } else {
        printf("IP Address: Not configured\n");
    }
    
    printf("MTU: %d\n", vnic->mtu);
    printf("Jumbo Frames: %s\n", vnic->jumbo_frames ? "Enabled" : "Disabled");
    printf("Failover: %s\n", vnic->port_mapping.failover_enabled ? "Enabled" : "Disabled");
    
    printf("Physical Ports (%d): ", vnic->port_mapping.num_ports);
    for (i = 0; i < vnic->port_mapping.num_ports; i++) {
        uint16_t port_id = vnic->port_mapping.physical_ports[i];
        printf("%d%s%s", port_id,
               (i == vnic->port_mapping.active_port_idx) ? "*" : "",
               (i < vnic->port_mapping.num_ports - 1) ? "," : "");
    }
    printf(" (* = active)\n");
    
    return 0;
}

/**
 * List physical ports
 */
int list_physical_ports(void) {
    printf("\nPhysical Ports:\n");
    printf("----------------------------------------\n");
    
    for (int i = 0; i < g_manager.num_physical_ports; i++) {
        struct physical_port *port = &g_manager.physical_ports[i];
        printf("Port %d: %s\n", port->port_id, port->name);
        printf("  MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               port->mac_addr.addr_bytes[0], port->mac_addr.addr_bytes[1],
               port->mac_addr.addr_bytes[2], port->mac_addr.addr_bytes[3],
               port->mac_addr.addr_bytes[4], port->mac_addr.addr_bytes[5]);
        printf("  MTU: %d\n", port->mtu);
        printf("  Status: %s\n", port->enabled ? "UP" : "DOWN");
        printf("  Driver: %s\n", port->dev_info.driver_name);
        printf("\n");
    }
    
    return 0;
}

/**
 * List all VNICs
 */
int list_vnics(void) {
    printf("\nVirtual NICs:\n");
    printf("----------------------------------------\n");
    
    int found = 0;
    for (int i = 0; i < MAX_VNICS; i++) {
        if (g_manager.vnics[i].created) {
            struct vnic_config *vnic = &g_manager.vnics[i];
            printf("VNIC: %s (ID: %d)\n", vnic->name, vnic->vnic_id);
            printf("  Status: %s\n", vnic->enabled ? "ENABLED" : "DISABLED");
            printf("  Ports: ");
            for (int j = 0; j < vnic->port_mapping.num_ports; j++) {
                printf("%d%s", vnic->port_mapping.physical_ports[j],
                       (j < vnic->port_mapping.num_ports - 1) ? "," : "");
            }
            printf("\n  Jumbo Frames: %s\n", vnic->jumbo_frames ? "Yes" : "No");
            printf("\n");
            found = 1;
        }
    }
    
    if (!found) {
        printf("No VNICs created\n");
    }
    
    return 0;
}

/**
 * Delete VNIC
 */
int delete_vnic(const char *name) {
    struct vnic_config *vnic = NULL;
    int i;
    
    for (i = 0; i < MAX_VNICS; i++) {
        if (g_manager.vnics[i].created && strcmp(g_manager.vnics[i].name, name) == 0) {
            vnic = &g_manager.vnics[i];
            break;
        }
    }
    
    if (!vnic) {
        printf("VNIC '%s' not found\n", name);
        return -1;
    }
    
    // Cleanup resources
    if (vnic->mbuf_pool) {
        rte_mempool_free(vnic->mbuf_pool);
    }
    if (vnic->rx_ring) {
        rte_ring_free(vnic->rx_ring);
    }
    if (vnic->tx_ring) {
        rte_ring_free(vnic->tx_ring);
    }
    
    memset(vnic, 0, sizeof(*vnic));
    g_manager.num_vnics--;
    
    printf("Deleted VNIC '%s'\n", name);
    return 0;
}

/**
 * Signal handler for cleanup
 */
void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\nSignal %d received, preparing to exit...\n", signum);
        force_quit = true;
    }
}

/**
 * Cleanup DPDK resources
 */
void cleanup_dpdk_resources(void) {
    uint16_t port_id;
    
    printf("Cleaning up DPDK resources...\n");
    
    // Stop all ports
    RTE_ETH_FOREACH_DEV(port_id) {
        printf("Stopping port %d...\n", port_id);
        rte_eth_dev_stop(port_id);
        rte_eth_dev_close(port_id);
    }
    
    // Cleanup VNICs
    for (int i = 0; i < MAX_VNICS; i++) {
        if (g_manager.vnics[i].created) {
            delete_vnic(g_manager.vnics[i].name);
        }
    }
    
    rte_eal_cleanup();
}

/**
 * Print usage
 */
void print_usage(const char *prog_name) {
    printf("DPDK Virtual NIC Management Tool\n");
    printf("Usage: %s [EAL options] -- <command> [options]\n\n", prog_name);
    printf("Commands:\n");
    printf("  list-ports                         List physical ports\n");
    printf("  list-vnics                         List virtual NICs\n");
    printf("  create <n> <ports> [--jumbo]    Create VNIC (ports: comma-separated)\n");
    printf("  delete <n>                      Delete VNIC\n");
    printf("  config <n> <ip>/<prefix>        Configure IP address\n");
    printf("  enable <n>                      Enable VNIC\n");
    printf("  disable <n>                     Disable VNIC\n");
    printf("  show <n>                        Show VNIC information\n");
    printf("\nEAL Options (examples):\n");
    printf("  -l 0-3                             Use cores 0-3\n");
    printf("  --socket-mem 1024                  Allocate memory per socket\n");
    printf("  -w 0000:01:00.0                    Whitelist specific PCI device\n");
    printf("\nExamples:\n");
    printf("  %s -l 0-1 --socket-mem 1024 -- list-ports\n", prog_name);
    printf("  %s -l 0-1 --socket-mem 1024 -- create vnic0 0,1 --jumbo\n", prog_name);
    printf("  %s -l 0-1 --socket-mem 1024 -- config vnic0 192.168.1.10/24\n", prog_name);
    printf("  %s -l 0-1 --socket-mem 1024 -- enable vnic0\n", prog_name);
}

/**
 * Main function
 */
int main(int argc, char **argv) {
    int ret;
    int dpdk_argc = 0;
    char **dpdk_argv = NULL;
    int cmd_start = 0;
    
    // Setup signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Find the separator "--" in arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            dpdk_argc = i;
            dpdk_argv = argv;
            cmd_start = i + 1;
            break;
        }
    }
    
    if (cmd_start == 0) {
        // No DPDK arguments provided, use minimal defaults
        dpdk_argc = 1;
        dpdk_argv = argv;
        cmd_start = 1;
    }
    
    // Initialize DPDK
    ret = init_dpdk_environment(dpdk_argc, dpdk_argv);
    if (ret < 0) {
        printf("Failed to initialize DPDK environment\n");
        return -1;
    }
    
    // Discover physical ports
    ret = discover_physical_ports();
    if (ret < 0) {
        printf("Failed to discover physical ports\n");
        cleanup_dpdk_resources();
        return -1;
    }
    
    // Process commands
    if (cmd_start >= argc) {
        print_usage(argv[0]);
        cleanup_dpdk_resources();
        return 1;
    }
    
    const char *command = argv[cmd_start];
    
    if (strcmp(command, "list-ports") == 0) {
        ret = list_physical_ports();
        
    } else if (strcmp(command, "list-vnics") == 0) {
        ret = list_vnics();
        
    } else if (strcmp(command, "create") == 0) {
        if (cmd_start + 2 >= argc) {
            printf("Usage: create <n> <ports> [--jumbo]\n");
            ret = -1;
        } else {
            int jumbo = (cmd_start + 3 < argc && strcmp(argv[cmd_start + 3], "--jumbo") == 0);
            ret = create_vnic(argv[cmd_start + 1], argv[cmd_start + 2], jumbo);
        }
        
    } else if (strcmp(command, "delete") == 0) {
        if (cmd_start + 1 >= argc) {
            printf("Usage: delete <n>\n");
            ret = -1;
        } else {
            ret = delete_vnic(argv[cmd_start + 1]);
        }
        
    } else if (strcmp(command, "config") == 0) {
        if (cmd_start + 2 >= argc) {
            printf("Usage: config <n> <ip>/<prefix>\n");
            ret = -1;
        } else {
            ret = configure_vnic_ip(argv[cmd_start + 1], argv[cmd_start + 2]);
        }
        
    } else if (strcmp(command, "enable") == 0) {
        if (cmd_start + 1 >= argc) {
            printf("Usage: enable <n>\n");
            ret = -1;
        } else {
            ret = enable_vnic(argv[cmd_start + 1]);
        }
        
    } else if (strcmp(command, "disable") == 0) {
        if (cmd_start + 1 >= argc) {
            printf("Usage: disable <n>\n");
            ret = -1;
        } else {
            ret = disable_vnic(argv[cmd_start + 1]);
        }
        
    } else if (strcmp(command, "show") == 0) {
        if (cmd_start + 1 >= argc) {
            printf("Usage: show <n>\n");
            ret = -1;
        } else {
            ret = show_vnic_info(argv[cmd_start + 1]);
        }
        
    } else {
        printf("Unknown command: %s\n", command);
        print_usage(argv[0]);
        ret = -1;
    }
    
    cleanup_dpdk_resources();
    return (ret == 0) ? 0 : 1;
}
