# User Manual

Complete guide to using the DPDK Virtual NIC Tool.

## Command Overview

The tool uses the following syntax:
```bash
dpdk-vnic-tool [EAL options] -- <command> [options]
```

### EAL Options
- `-l <cores>`: CPU cores to use (e.g., `0-3`, `0,2,4`)
- `--socket-mem <mb>`: Memory per NUMA socket in MB
- `-w <pci>`: Whitelist specific PCI devices
- `--file-prefix <prefix>`: Unique prefix for shared memory files

### Commands

#### `list-ports`
List all available physical network ports.

```bash
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- list-ports
```

#### `create <name> <ports> [--jumbo]`
Create a new virtual NIC.

Parameters:
- `name`: VNIC name (alphanumeric, max 31 chars)
- `ports`: Comma-separated list of physical port IDs
- `--jumbo`: Enable jumbo frame support (optional)

```bash
# Create VNIC using ports 0 and 1
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- create vnic0 0,1

# Create VNIC with jumbo frame support
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- create vnic0 0,1 --jumbo

# Create VNIC using multiple ports for higher bandwidth
sudo dpdk-vnic-tool -l 0-3 --socket-mem 2048 -- create data-vnic 0,1,2,3 --jumbo
```

#### `config <name> <ip>/<prefix>`
Configure IP address for a VNIC.

```bash
# Configure IP address
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- config vnic0 192.168.1.100/24

# Configure with different subnet
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- config vnic0 10.0.1.50/16
```

#### `enable <name>`
Enable a VNIC for operation.

```bash
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- enable vnic0
```

#### `disable <name>`
Disable a VNIC.

```bash
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- disable vnic0
```

#### `show <name>`
Display detailed information about a VNIC.

```bash
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- show vnic0
```

#### `list-vnics`
List all created VNICs.

```bash
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- list-vnics
```

#### `delete <name>`
Delete a VNIC and free its resources.

```bash
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- delete vnic0
```

## Usage Patterns

### Single NIC for Basic Connectivity

```bash
# Simple setup for management interface
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- create mgmt 0
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- config mgmt 192.168.1.10/24
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- enable mgmt
```

### Multiple NICs for High Bandwidth

```bash
# Aggregate multiple ports for high throughput
sudo dpdk-vnic-tool -l 0-3 --socket-mem 2048 -- create cluster-net 0,1,2,3 --jumbo
sudo dpdk-vnic-tool -l 0-3 --socket-mem 2048 -- config cluster-net 10.10.1.100/24
sudo dpdk-vnic-tool -l 0-3 --socket-mem 2048 -- enable cluster-net
```

### Redundant Setup for Failover

```bash
# Primary VNIC
sudo dpdk-vnic-tool -l 0-3 --socket-mem 2048 -- create primary-net 0,1 --jumbo
sudo dpdk-vnic-tool -l 0-3 --socket-mem 2048 -- config primary-net 172.16.1.100/24
sudo dpdk-vnic-tool -l 0-3 --socket-mem 2048 -- enable primary-net

# Backup VNIC (same IP, different ports)
sudo dpdk-vnic-tool -l 0-3 --socket-mem 2048 -- create backup-net 2,3 --jumbo
sudo dpdk-vnic-tool -l 0-3 --socket-mem 2048 -- config backup-net 172.16.1.100/24
# Note: backup enabled when primary fails
```

### Multi-Segment Network

```bash
# Management network
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- create mgmt 0
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- config mgmt 192.168.1.10/24
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- enable mgmt

# Storage network with jumbo frames
sudo dpdk-vnic-tool -l 2-3 --socket-mem 1024 -- create storage 1,2 --jumbo
sudo dpdk-vnic-tool -l 2-3 --socket-mem 1024 -- config storage 10.1.1.10/24
sudo dpdk-vnic-tool -l 2-3 --socket-mem 1024 -- enable storage

# Cluster communication
sudo dpdk-vnic-tool -l 4-5 --socket-mem 1024 -- create cluster 3,4,5,6 --jumbo
sudo dpdk-vnic-tool -l 4-5 --socket-mem 1024 -- config cluster 172.16.1.10/16
sudo dpdk-vnic-tool -l 4-5 --socket-mem 1024 -- enable cluster
```

## Advanced Configuration

### Memory Configuration

```bash
# Specify memory per NUMA node
sudo dpdk-vnic-tool -l 0-7 --socket-mem 2048,2048 -- create vnic0 0,1

# Use specific memory channels
sudo dpdk-vnic-tool -l 0-7 --socket-mem 4096 -n 4 -- create vnic0 0,1
```

### CPU Core Assignment

```bash
# Use specific cores for control vs. data plane
sudo dpdk-vnic-tool -l 0,2,4,6 --socket-mem 2048 -- create vnic0 0,1

# Isolate on specific NUMA node
sudo dpdk-vnic-tool -l 0-3 --socket-mem 2048,0 -- create vnic0 0,1
```

### Device-Specific Configuration

```bash
# Bind specific devices and create VNIC
sudo dpdk-devbind.py --bind=vfio-pci 0000:01:00.0 0000:01:00.1
sudo dpdk-vnic-tool -l 0-1 -w 0000:01:00.0 -w 0000:01:00.1 --socket-mem 1024 -- create vnic0 0,1
```

## Best Practices

### Resource Planning
1. **CPU Cores**: Reserve 1-2 cores per VNIC for optimal performance
2. **Memory**: Allocate at least 1GB per socket, more for high packet rates
3. **NIC Selection**: Use NICs on the same NUMA node for best performance

### Network Configuration
1. **Switch Configuration**: Ensure switch supports your frame sizes
2. **VLAN Setup**: Configure VLANs on physical switches if needed
3. **MTU Matching**: Ensure end-to-end MTU consistency

### Performance Optimization
1. **Core Isolation**: Use `isolcpus` kernel parameter for dedicated cores
2. **IRQ Affinity**: Disable IRQs on DPDK cores
3. **Power Management**: Set CPU governor to performance mode

### Monitoring
1. **Check Interface Status**: Regular `show` command usage
2. **Monitor Resources**: Watch hugepage and memory usage
3. **Log Analysis**: Check system logs for errors

## Troubleshooting

### Common Issues

#### VNIC Creation Fails
```bash
# Check available ports
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- list-ports

# Verify hugepages
cat /proc/meminfo | grep -i huge

# Check DPDK binding
sudo dpdk-devbind.py --status
```

#### IP Configuration Fails
```bash
# Verify VNIC exists
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- list-vnics

# Check IP format (must be CIDR notation)
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- config vnic0 192.168.1.10/24
```

#### Performance Issues
```bash
# Check CPU usage
top -p $(pgrep dpdk-vnic-tool)

# Verify core assignment
cat /proc/$(pgrep dpdk-vnic-tool)/stat

# Monitor packet statistics
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- show vnic0
```

### Getting Help

1. Use `--help` for command syntax
2. Check the [troubleshooting guide](troubleshooting.md)
3. Review log files in `/var/log/`
4. Run diagnostics: `sudo ./scripts/debug-vnic.sh <vnic_name>`
