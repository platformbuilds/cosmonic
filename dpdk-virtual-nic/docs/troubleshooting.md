# Troubleshooting Guide

Common issues and solutions for DPDK Virtual NIC Tool.

## Installation Issues

### DPDK Not Found

**Symptoms:**
```
ERROR: DPDK not found. Please install DPDK first.
```

**Solutions:**
```bash
# Check if DPDK is installed
pkg-config --exists libdpdk && echo "Found" || echo "Not found"

# Check environment variables
echo $PKG_CONFIG_PATH

# Reinstall DPDK
sudo ./scripts/setup-environment.sh

# Manual setup
export PKG_CONFIG_PATH=/usr/local/lib/x86_64-linux-gnu/pkgconfig/
```

### Hugepage Issues

**Symptoms:**
```
Cannot init EAL
EAL: No available hugepages reported
```

**Solutions:**
```bash
# Check hugepage status
cat /proc/meminfo | grep -i huge

# Configure hugepages
echo 1024 | sudo tee /sys/devices/system/node/node*/hugepages/hugepages-2048kB/nr_hugepages

# Mount hugepage filesystem
sudo mkdir -p /mnt/huge
sudo mount -t hugetlbfs nodev /mnt/huge

# Make persistent
echo "nodev /mnt/huge hugetlbfs defaults 0 0" | sudo tee -a /etc/fstab
```

### IOMMU Issues

**Symptoms:**
```
vfio-pci: probe of 0000:01:00.0 failed with error -22
VFIO: No IOMMU support
```

**Solutions:**
```bash
# Check IOMMU in kernel
dmesg | grep -i iommu

# Enable in GRUB
sudo nano /etc/default/grub
# Add: GRUB_CMDLINE_LINUX="iommu=pt intel_iommu=on"
sudo update-grub
sudo reboot

# Load VFIO modules
sudo modprobe vfio-pci
sudo modprobe vfio_iommu_type1
```

## Runtime Issues

### No Physical Ports Detected

**Symptoms:**
```
No Ethernet ports available
Detected 0 physical Ethernet ports
```

**Solutions:**
```bash
# Check bound devices
sudo dpdk-devbind.py --status

# Bind NICs to DPDK
sudo dpdk-devbind.py --bind=vfio-pci 0000:01:00.0

# Check if interfaces are down
sudo ip link set eth0 down
sudo dpdk-devbind.py --bind=vfio-pci 0000:01:00.0

# Verify PCI devices
lspci | grep -i ethernet
```

### VNIC Creation Fails

**Symptoms:**
```
Cannot create mbuf pool for VNIC
Maximum number of VNICs (16) reached
```

**Solutions:**
```bash
# Check available memory
free -h
cat /proc/meminfo | grep -i huge

# Increase socket memory
sudo dpdk-vnic-tool -l 0-1 --socket-mem 2048 -- create vnic0 0,1

# Delete unused VNICs
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- delete old-vnic

# Check for existing VNICs
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- list-vnics
```

### Memory Allocation Errors

**Symptoms:**
```
Cannot create global mbuf pool
rte_panic("Cannot init EAL")
```

**Solutions:**
```bash
# Check memory limits
ulimit -l
ulimit -l unlimited

# Increase hugepage allocation
echo 2048 | sudo tee /sys/devices/system/node/node*/hugepages/hugepages-2048kB/nr_hugepages

# Check NUMA memory
numastat
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024,1024 -- create vnic0 0,1
```

## Configuration Issues

### IP Configuration Fails

**Symptoms:**
```
VNIC 'vnic0' not found
Invalid IP address: 192.168.1.10
IP address must be in CIDR format
```

**Solutions:**
```bash
# Verify VNIC exists
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- list-vnics

# Use correct CIDR format
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- config vnic0 192.168.1.10/24

# Check for typos in VNIC name
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- show vnic0
```

### Jumbo Frame Issues

**Symptoms:**
```
Cannot configure device: err=-22
Jumbo frames not working
```

**Solutions:**
```bash
# Check switch support
ping -M do -s 8972 <target_ip>

# Verify NIC capability
sudo ethtool eth0 | grep -i jumbo

# Check MTU settings
ip link show
sudo ip link set dev eth0 mtu 9000

# Test without jumbo frames first
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- create vnic0 0,1
```

## Performance Issues

### Low Throughput

**Symptoms:**
- Network performance below expectations
- High CPU usage with low throughput
- Packet drops

**Diagnosis:**
```bash
# Check interface statistics
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- show vnic0
sudo ethtool -S eth0

# Monitor CPU usage
top -p $(pgrep dpdk-vnic-tool)

# Check memory usage
cat /proc/meminfo | grep -i huge
```

**Solutions:**
```bash
# Optimize CPU assignment
sudo dpdk-vnic-tool -l 2-5 --socket-mem 4096 -- create vnic0 0,1

# Increase memory allocation
sudo dpdk-vnic-tool -l 0-3 --socket-mem 2048,2048 -- create vnic0 0,1

# Enable performance optimizations
sudo ./scripts/optimize-performance.sh

# Use multiple ports
sudo dpdk-vnic-tool -l 0-3 --socket-mem 2048 -- create vnic0 0,1,2,3
```

### High Latency

**Symptoms:**
- Ping times > 100µs
- Variable response times
- Jitter in measurements

**Solutions:**
```bash
# Disable CPU idle states
sudo ./scripts/optimize-performance.sh

# Use dedicated cores
sudo dpdk-vnic-tool -l 4-7 --socket-mem 4096 -- create low-latency 0,1

# Check IRQ affinity
cat /proc/interrupts | grep eth

# Disable power management
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

### Memory Leaks

**Symptoms:**
- Increasing memory usage over time
- Hugepage exhaustion
- Performance degradation

**Diagnosis:**
```bash
# Monitor hugepage usage
watch -n 1 'cat /proc/meminfo | grep -i huge'

# Check for process memory leaks
ps aux | grep dpdk-vnic-tool
cat /proc/$(pgrep dpdk-vnic-tool)/status | grep -i vmsize
```

**Solutions:**
```bash
# Restart VNIC periodically
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- disable vnic0
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- enable vnic0

# Check for proper cleanup
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- delete vnic0
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- create vnic0 0,1
```

## Hardware-Specific Issues

### Intel NIC Problems

**Common Issues:**
- Driver compatibility
- Firmware versions
- Flow control

**Solutions:**
```bash
# Check driver version
modinfo ixgbe | grep version

# Update firmware
# (Refer to Intel documentation)

# Disable flow control
sudo ethtool -A eth0 rx off tx off autoneg off
```

### Mellanox NIC Problems

**Common Issues:**
- OFED driver requirements
- SR-IOV configuration
- ConnectX compatibility

**Solutions:**
```bash
# Install Mellanox OFED
wget http://www.mellanox.com/downloads/ofed/MLNX_OFED-5.4-3.5.8.0/MLNX_OFED_LINUX-5.4-3.5.8.0-ubuntu20.04-x86_64.tgz
# Follow Mellanox installation guide

# Check device capabilities
sudo lshw -class network
```

### Network Switch Issues

**Symptoms:**
- Intermittent connectivity
- Frame size limitations
- VLAN problems

**Solutions:**
```bash
# Test basic connectivity
ping -c 4 <target_ip>

# Test jumbo frames
ping -M do -s 8972 <target_ip>

# Check switch configuration
# (Consult switch documentation)

# Test different frame sizes
for size in 64 1500 9000; do
    ping -M do -s $((size-28)) <target_ip>
done
```

## Debugging Commands

### System Information
```bash
# Hardware information
sudo lshw -class network
lscpu
cat /proc/meminfo | grep -i huge
numactl --hardware

# Kernel information
uname -a
dmesg | grep -i iommu
lsmod | grep vfio

# Network information
ip link show
sudo ethtool eth0
sudo dpdk-devbind.py --status
```

### DPDK Information
```bash
# DPDK version
pkg-config --modversion libdpdk

# EAL information
sudo dpdk-vnic-tool -l 0 --socket-mem 512 -- list-ports

# Memory information
cat /proc/meminfo | grep -i huge
ls -la /mnt/huge/
```

### Process Information
```bash
# Process status
ps aux | grep dpdk-vnic-tool
cat /proc/$(pgrep dpdk-vnic-tool)/status

# File descriptors
lsof -p $(pgrep dpdk-vnic-tool)

# Memory maps
cat /proc/$(pgrep dpdk-vnic-tool)/maps | grep huge
```

## Getting Help

### Log Files
```bash
# System logs
sudo journalctl -u dpdk-vnic@vnic0.service
sudo dmesg | tail -50
sudo tail -f /var/log/syslog

# Application logs
# (Configure application logging)
```

### Debug Scripts
```bash
# Run debug script
sudo ./scripts/debug-vnic.sh vnic0

# Performance analysis
sudo ./tests/performance-test.sh

# System validation
sudo ./tests/unit-tests.sh
```

### Support Resources
1. Check this troubleshooting guide
2. Review DPDK documentation
3. Consult hardware vendor documentation
4. Search DPDK mailing list archives
5. Create GitHub issue with debug information

### Reporting Issues

When reporting issues, include:
1. System information (`uname -a`, `lscpu`)
2. DPDK version (`pkg-config --modversion libdpdk`)
3. Hardware details (`lshw -class network`)
4. Error messages and logs
5. Steps to reproduce
6. Output of debug script
