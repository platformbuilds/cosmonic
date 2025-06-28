# Performance Tuning Guide

Complete guide to optimizing DPDK Virtual NIC performance.

## System-Level Optimizations

### 1. CPU Configuration

#### CPU Governor
```bash
# Set all CPUs to performance mode
for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    echo performance | sudo tee $cpu
done

# Verify setting
cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

#### CPU Isolation
Add to `/etc/default/grub`:
```
GRUB_CMDLINE_LINUX="isolcpus=2-7 nohz_full=2-7 rcu_nocbs=2-7"
```

#### Disable CPU Idle States
```bash
# Disable C-states for low latency
for state in /sys/devices/system/cpu/cpu*/cpuidle/state*/disable; do
    echo 1 | sudo tee $state
done
```

### 2. Memory Configuration

#### Hugepage Optimization
```bash
# Configure 1GB hugepages for better performance
echo 8 | sudo tee /sys/devices/system/node/node*/hugepages/hugepages-1048576kB/nr_hugepages

# Or use 2MB hugepages for flexibility
echo 4096 | sudo tee /sys/devices/system/node/node*/hugepages/hugepages-2048kB/nr_hugepages
```

#### NUMA Optimization
```bash
# Check NUMA topology
numactl --hardware

# Run with NUMA awareness
numactl --cpunodebind=0 --membind=0 dpdk-vnic-tool -l 0-7 --socket-mem 4096,0 -- create vnic0 0,1
```

#### Memory Bandwidth
```bash
# Monitor memory bandwidth
sudo dmidecode --type 17 | grep -E "(Speed|Type:|Size)"

# Optimize memory channels
sudo dpdk-vnic-tool -l 0-7 --socket-mem 4096 -n 4 -- create vnic0 0,1
```

### 3. Network Interface Optimization

#### NIC Configuration
```bash
# Set ring buffer sizes
sudo ethtool -G eth0 rx 4096 tx 4096

# Enable hardware offloads
sudo ethtool -K eth0 rx-checksum on tx-checksum-ip-generic on
sudo ethtool -K eth0 tso on gso on

# Set interrupt coalescing
sudo ethtool -C eth0 rx-usecs 50 tx-usecs 50
```

#### IRQ Affinity
```bash
# Distribute IRQs across cores
echo 2 | sudo tee /proc/irq/24/smp_affinity  # Core 1
echo 4 | sudo tee /proc/irq/25/smp_affinity  # Core 2
echo 8 | sudo tee /proc/irq/26/smp_affinity  # Core 3
```

## DPDK-Specific Optimizations

### 1. Memory Pool Configuration

#### Optimal Pool Sizes
```bash
# Large pools for high throughput
sudo dpdk-vnic-tool -l 0-7 --socket-mem 8192 -- create high-perf 0,1,2,3 --jumbo

# Smaller pools for low latency
sudo dpdk-vnic-tool -l 0-3 --socket-mem 2048 -- create low-latency 0,1
```

#### Cache Optimization
- **Cache Size**: Use power-of-2 sizes (256, 512)
- **Per-Core Caches**: Reduce contention
- **Pool Alignment**: Align to cache line boundaries

### 2. Core Assignment

#### Dedicated Cores
```bash
# Isolate cores for DPDK
sudo dpdk-vnic-tool -l 2-5 --socket-mem 4096 -- create dedicated-vnic 0,1

# Avoid hyperthreading siblings
sudo dpdk-vnic-tool -l 0,2,4,6 --socket-mem 4096 -- create vnic0 0,1
```

#### Core Mapping Strategy
- **Control Plane**: Core 0-1
- **Data Plane**: Core 2-7
- **OS Tasks**: Remaining cores

### 3. Queue Configuration

#### Multi-Queue Setup
```bash
# Enable multiple queues per port
# This requires application-level support
sudo dpdk-vnic-tool -l 0-7 --socket-mem 4096 -- create multi-queue 0,1 --jumbo
```

## Application-Level Optimizations

### 1. Packet Processing

#### Batch Processing
- Process packets in batches of 32-64
- Minimize per-packet overhead
- Use burst operations

#### Zero-Copy Operations
- Avoid unnecessary packet copies
- Use direct buffer manipulation
- Leverage hardware DMA

### 2. Memory Access Patterns

#### Cache Optimization
- Prefetch packet data
- Minimize cache misses
- Use cache-aligned structures

#### Lock-Free Algorithms
- Use atomic operations
- Avoid mutex/semaphore overhead
- Implement ring buffers

## Performance Monitoring

### 1. System Metrics

#### CPU Usage
```bash
# Monitor DPDK process
top -p $(pgrep dpdk-vnic-tool)

# Check core utilization
mpstat -P ALL 1

# Monitor cache misses
perf stat -e cache-misses,cache-references dpdk-vnic-tool
```

#### Memory Usage
```bash
# Monitor hugepage usage
cat /proc/meminfo | grep -i huge

# Check NUMA memory usage
numastat

# Monitor memory bandwidth
sudo intel-pcm-memory.x 1
```

#### Network Performance
```bash
# Monitor interface statistics
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- show vnic0

# Check hardware counters
sudo ethtool -S eth0

# Monitor packet rates
sudo iftop -i vnic0
```

### 2. DPDK Metrics

#### Built-in Statistics
```bash
# DPDK port statistics
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- list-ports

# Memory pool statistics
# (requires custom implementation)
```

#### Custom Metrics
- Packet processing rate
- Latency measurements
- Queue depth monitoring
- Error counters

## Benchmarking

### 1. Throughput Testing

#### Packet Generator
```bash
# Use DPDK pktgen for testing
git clone http://dpdk.org/git/apps/pktgen-dpdk
# Build and run pktgen against VNIC

# Or use iperf3 for TCP testing
iperf3 -s &  # Server
iperf3 -c <vnic_ip> -t 60 -P 4  # Client with 4 parallel streams
```

#### Jumbo Frame Testing
```bash
# Test jumbo frame performance
ping -M do -s 8972 <target_ip>
iperf3 -c <target_ip> -M 9000 -t 60
```

### 2. Latency Testing

#### Round-Trip Time
```bash
# Measure RTT with different packet sizes
ping -s 64 <target_ip>
ping -s 1472 <target_ip>
ping -s 8972 <target_ip>
```

#### Application Latency
- Use timestamping in application
- Measure processing delays
- Monitor queue depths

## Performance Tuning Checklist

### Hardware Level
- [ ] IOMMU enabled and configured
- [ ] CPU frequency scaling disabled
- [ ] CPU idle states disabled
- [ ] NUMA topology optimized
- [ ] Memory channels maximized
- [ ] NIC firmware updated

### Operating System
- [ ] Hugepages configured (1GB preferred)
- [ ] Core isolation enabled
- [ ] IRQ affinity set
- [ ] Power management disabled
- [ ] Unnecessary services disabled

### DPDK Configuration
- [ ] Optimal core assignment
- [ ] Memory pools sized correctly
- [ ] Multi-queue enabled where possible
- [ ] Hardware offloads enabled
- [ ] Jumbo frames configured

### Application
- [ ] Batch processing implemented
- [ ] Zero-copy operations used
- [ ] Lock-free algorithms employed
- [ ] Cache-friendly data structures
- [ ] Minimal system calls

## Troubleshooting Performance Issues

### 1. CPU Bottlenecks

#### Symptoms
- High CPU utilization on DPDK cores
- Packet drops in hardware
- Increased latency

#### Solutions
```bash
# Add more cores
sudo dpdk-vnic-tool -l 0-15 --socket-mem 8192 -- create vnic0 0,1

# Optimize core assignment
sudo dpdk-vnic-tool -l 2,4,6,8 --socket-mem 4096 -- create vnic0 0,1

# Check for hyperthreading conflicts
cat /proc/cpuinfo | grep -E "(processor|physical id|core id)"
```

### 2. Memory Bottlenecks

#### Symptoms
- High memory allocation failures
- NUMA misses
- Pool exhaustion

#### Solutions
```bash
# Increase memory allocation
sudo dpdk-vnic-tool -l 0-7 --socket-mem 8192,8192 -- create vnic0 0,1

# Optimize NUMA placement
numactl --cpunodebind=0 --membind=0 dpdk-vnic-tool ...

# Monitor pool usage
# (implement custom pool monitoring)
```

### 3. Network Bottlenecks

#### Symptoms
- Link utilization < 100%
- Hardware drops
- Flow control events

#### Solutions
```bash
# Check link autonegotiation
sudo ethtool eth0

# Verify flow control settings
sudo ethtool -A eth0 rx off tx off

# Monitor hardware errors
sudo ethtool -S eth0 | grep -i error
```

## Expected Performance

### Throughput
- **1GbE**: Line rate with standard frames
- **10GbE**: 14.88 Mpps with 64-byte packets
- **25GbE**: 37.2 Mpps with 64-byte packets
- **100GbE**: 148.8 Mpps with 64-byte packets

### Latency
- **Minimum**: 1-5 microseconds
- **Typical**: 5-10 microseconds
- **With Jumbo**: 10-20 microseconds

### CPU Efficiency
- **Polling Mode**: 100% CPU but lowest latency
- **Interrupt Mode**: Lower CPU but higher latency
- **Hybrid Mode**: Balanced approach

Following these guidelines should achieve optimal performance for your DPDK Virtual NIC implementation.
