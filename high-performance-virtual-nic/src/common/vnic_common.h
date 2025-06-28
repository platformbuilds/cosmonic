#ifndef VNIC_COMMON_H
#define VNIC_COMMON_H

#include <stdint.h>

#define MAX_VNICS 16
#define MAX_PHYSICAL_PORTS 8
#define MAX_SESSIONS 1000000
#define BURST_SIZE 32

enum lb_algorithm {
    LB_HASH,           // Hash-based (session affinity)
    LB_ROUND_ROBIN,    // Round-robin distribution
    LB_LEAST_CONN,     // Least connections
    LB_WEIGHTED,       // Weighted distribution
    LB_ADAPTIVE        // Adaptive based on latency/throughput
};

struct session_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
} __attribute__((packed));

struct session_stats {
    uint64_t packets;
    uint64_t bytes;
    uint64_t last_seen;
    uint16_t assigned_interface;
    uint8_t connection_state;
} __attribute__((packed));

struct interface_stats {
    uint64_t rx_packets;
    uint64_t tx_packets;
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint64_t rx_dropped;
    uint64_t tx_dropped;
    uint32_t active_sessions;
    uint32_t weight;
    uint8_t health_status;
    uint8_t enabled;
} __attribute__((packed));

#endif // VNIC_COMMON_H
