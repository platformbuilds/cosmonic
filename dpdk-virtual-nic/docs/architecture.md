# Architecture Overview

This document describes the internal architecture of the DPDK Virtual NIC system.

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Application Layer                       │
├─────────────────────────────────────────────────────────────┤
│                Virtual NIC Interface                        │
├─────────────────────────────────────────────────────────────┤
│     VNIC Manager     │    Connection State    │  Failover   │
│                      │       Manager          │ Controller  │
├─────────────────────────────────────────────────────────────┤
│              DPDK Packet Processing Layer                   │
├─────────────────────────────────────────────────────────────┤
│  Port 0  │  Port 1  │  Port 2  │  Port 3  │ ... │  Port N  │
└─────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. VNIC Manager

The VNIC Manager is the central orchestrator that:

- **Resource Management**: Allocates memory pools, rings, and queues
- **Configuration Management**: Stores and validates VNIC configurations
- **Lifecycle Management**: Handles creation, modification, and deletion of VNICs

**Key Data Structures:**
```c
struct dpdk_vnic_manager {
    struct physical_port physical_ports[MAX_PHYSICAL_PORTS];
    struct vnic_config vnics[MAX_VNICS];
    uint8_t num_physical_ports;
    uint8_t num_vnics;
    uint8_t initialized;
    struct rte_mempool *global_mbuf_pool;
};
```

### 2. Physical Port Management

Each physical port is represented by:

```c
struct physical_port {
    uint16_t port_id;
    char name[RTE_ETH_NAME_MAX_LEN];
    struct rte_ether_addr mac_addr;
    uint16_t mtu;
    uint8_t enabled;
    uint8_t link_status;
    struct rte_eth_dev_info dev_info;
};
```

**Responsibilities:**
- Port discovery and initialization
- Driver configuration (jumbo frames, offloads)
- Link state monitoring
- Statistics collection

### 3. Virtual NIC Configuration

Each VNIC maintains:

```c
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
```

### 4. Port Mapping and Failover

```c
struct vnic_port_mapping {
    uint16_t physical_ports[MAX_PHYSICAL_PORTS];
    uint8_t num_ports;
    uint8_t active_port_idx;
    uint8_t failover_enabled;
};
```

**Features:**
- Multi-port aggregation
- Automatic failover detection
- Load balancing across ports
- Health monitoring

## Packet Processing Pipeline

### 1. Receive Path

```
Physical NIC → DPDK Poll Mode Driver → RX Queue → 
Memory Pool → Packet Classification → VNIC RX Ring → 
Application
```

**Processing Steps:**
1. **Hardware Reception**: Packets received by physical NIC
2. **DMA Transfer**: Packets transferred to memory via DMA
3. **Poll Mode Driver**: DPDK PMD retrieves packets from hardware queues
4. **Memory Pool**: Packet buffers allocated from pre-allocated pools
5. **Classification**: Packets classified to appropriate VNIC
6. **Ring Enqueue**: Packets placed in VNIC-specific rings
7. **Application Delivery**: Application retrieves packets from VNIC

### 2. Transmit Path

```
Application → VNIC TX Ring → Load Balancer → 
Active Physical Port → DPDK Poll Mode Driver → Physical NIC
```

**Processing Steps:**
1. **Application Submission**: Application submits packets to VNIC
2. **Ring Dequeue**: Packets retrieved from VNIC TX ring
3. **Port Selection**: Active port selected based on failover state
4. **Load Balancing**: Traffic distributed across available ports
5. **Hardware Submission**: Packets submitted to physical NIC queues
6. **DMA Transfer**: Hardware transfers packets to network

## Memory Management

### 1. Hugepage Configuration

- **2MB Pages**: Default configuration for general use
- **1GB Pages**: Optional for reduced TLB pressure
- **NUMA Awareness**: Memory allocated on appropriate NUMA nodes

### 2. Memory Pools

```c
// Global pool for all VNICs
struct rte_mempool *global_mbuf_pool;

// Per-VNIC pools for isolation
struct rte_mempool *vnic_mbuf_pool;
```

**Pool Characteristics:**
- **Size**: Sized based on expected packet rates
- **Cache**: Per-core caches for lockless access
- **Buffer Size**: Optimized for jumbo frames (9018 bytes)

### 3. Ring Buffers

- **Lockless Design**: Single producer/single consumer rings
- **Power-of-2 Sizing**: Optimized for modulo operations
- **Batch Operations**: Support for bulk enqueue/dequeue

## Threading Model

### 1. Main Thread
- **Initialization**: DPDK EAL setup, device discovery
- **Management**: Command processing, configuration changes
- **Control Plane**: Statistics, monitoring, health checks

### 2. Worker Threads (Future Implementation)
- **Data Plane**: Packet processing, forwarding
- **Per-VNIC Threads**: Dedicated threads for high-performance VNICs
- **Shared Threads**: Multiple VNICs per thread for efficiency

### 3. Control Thread
- **Health Monitoring**: Link state detection, failover triggering
- **Statistics Collection**: Performance counters, error rates
- **Resource Management**: Memory pool maintenance

## Hardware Offloading

### 1. Checksum Offloading

```c
// TX offloads
port_conf.txmode.offloads = RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | 
                            RTE_ETH_TX_OFFLOAD_TCP_CKSUM | 
                            RTE_ETH_TX_OFFLOAD_UDP_CKSUM;

// RX offloads
port_conf.rxmode.offloads = RTE_ETH_RX_OFFLOAD_CHECKSUM;
```

### 2. Segmentation Offloading

- **TSO (TCP Segmentation Offload)**: Hardware segments large TCP packets
- **Multi-segment Support**: Handles packets larger than single buffers
- **Jumbo Frame Processing**: Optimized for 9000+ byte frames

### 3. Flow Control

- **RSS (Receive Side Scaling)**: Distributes packets across queues
- **Flow Director**: Hardware-based packet classification
- **Rate Limiting**: Hardware-enforced bandwidth limits

## Scalability Considerations

### 1. Multi-Queue Support

- **Per-CPU Queues**: Separate queues per CPU core
- **Queue Balancing**: Even distribution of work
- **Lock-Free Processing**: Avoid contention between cores

### 2. NUMA Optimization

- **Local Memory Access**: Allocate memory on same NUMA node as NIC
- **CPU Affinity**: Bind processing to optimal cores
- **Memory Pools**: Per-NUMA node memory allocation

### 3. Resource Limits

```c
#define MAX_VNICS 16
#define MAX_PHYSICAL_PORTS 8
#define MAX_QUEUES 8
```

**Configurable Limits:**
- Maximum number of VNICs per system
- Maximum physical ports per VNIC
- Maximum queues per port

## Security Considerations

### 1. Memory Protection

- **IOMMU**: Hardware memory protection and translation
- **VFIO**: Secure device access from userspace
- **Hugepage Isolation**: Dedicated memory regions

### 2. Network Isolation

- **VNIC Separation**: Each VNIC operates independently
- **MAC Address Management**: Unique addresses per VNIC
- **VLAN Support**: Layer 2 network segmentation

### 3. Resource Limits

- **Memory Quotas**: Per-VNIC memory limits
- **CPU Limits**: Core assignment and limits
- **Rate Limiting**: Bandwidth enforcement

## Extension Points

### 1. Packet Processing Hooks

- **RX Preprocessing**: Packet inspection, filtering
- **TX Postprocessing**: Packet modification, encapsulation
- **Custom Protocols**: Protocol-specific handling

### 2. Failover Algorithms

- **Custom Detection**: Pluggable failure detection
- **Load Balancing**: Various distribution algorithms
- **State Synchronization**: Custom state management

### 3. Performance Monitoring

- **Custom Metrics**: Application-specific counters
- **Event Notifications**: Real-time alerts
- **Performance Analysis**: Detailed profiling support

This architecture provides a solid foundation for high-performance virtual networking with failover capabilities while maintaining flexibility for future enhancements.
