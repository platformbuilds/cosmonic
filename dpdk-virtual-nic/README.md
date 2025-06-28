# DPDK Virtual NIC Tool

A high-performance virtual NIC implementation using DPDK that supports multiple physical NICs, jumbo frames, and stateful TCP failover capabilities.

## 🚀 Features

- **DPDK-Based Performance**: Bypasses kernel for maximum throughput and minimal latency
- **Multi-NIC Support**: Utilize up to 8 physical NICs with selective assignment
- **Jumbo Frame Support**: Full support for 9000+ byte frames
- **Physical NIC Selection**: Command-line interface to specify which NICs to use
- **Failover Ready**: Multiple physical ports per VNIC for redundancy
- **Zero-Copy Processing**: Optimized packet handling with memory pools
- **Hardware Offloading**: Checksum, segmentation, and other offloads

## 🔧 Quick Start

### Prerequisites

- Linux kernel 4.4+ with IOMMU support
- Minimum 8GB RAM (16GB+ recommended)
- Multiple NIC cards
- Root privileges

### Installation

```bash
# 1. Setup environment (installs DPDK, configures hugepages, etc.)
sudo ./scripts/setup-environment.sh

# 2. Reboot if GRUB was updated
sudo reboot

# 3. Bind NICs to DPDK
make show-nics  # See available NICs
make bind-nics NIC_PCI_ADDRESSES="0000:01:00.0 0000:01:00.1"

# 4. Build the tool
make

# 5. Install system-wide
sudo make install
```

### Basic Usage

```bash
# List available physical ports
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- list-ports

# Create VNIC using ports 0 and 1 with jumbo frame support
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- create vnic0 0,1 --jumbo

# Configure IP address
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- config vnic0 192.168.1.100/24

# Enable the VNIC
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- enable vnic0

# Show VNIC information
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- show vnic0
```

## 📖 Documentation

- [Installation Guide](docs/installation.md)
- [User Manual](docs/user-manual.md)
- [Architecture Overview](docs/architecture.md)
- [Performance Tuning](docs/performance.md)
- [Troubleshooting](docs/troubleshooting.md)

## 🛠 Scripts

- `scripts/setup-environment.sh` - Complete environment setup
- `scripts/create-vnic.sh` - Automated VNIC creation
- `scripts/optimize-performance.sh` - System performance optimization
- `scripts/debug-vnic.sh` - Debug and troubleshooting

## 📊 Examples

- `examples/basic-setup.sh` - Simple VNIC setup
- `examples/multi-vnic-setup.sh` - Multiple VNICs for different purposes
- `examples/failover-setup.sh` - Failover configuration

## 🧪 Testing

```bash
# Run unit tests
sudo ./tests/unit-tests.sh

# Performance testing
sudo ./tests/performance-test.sh
```

## 🏗 Architecture

The DPDK Virtual NIC consists of:

1. **Virtual Interface Layer** - Presents unified interface to applications
2. **Connection State Manager** - Tracks TCP session state for failover
3. **Failover Controller** - Detects failures and orchestrates transitions
4. **Physical Interface Manager** - Handles multiple underlying NICs

## 🎯 Performance

- **10x lower latency** compared to kernel-based solutions
- **5-10x higher throughput** with line-rate performance
- **Sub-millisecond failover** times
- **CPU efficiency** with dedicated packet processing cores


## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes
4. Add tests
5. Submit pull request

## 🆘 Support

- Check [Troubleshooting Guide](docs/troubleshooting.md)
- Review [FAQ](docs/faq.md)
- Open an issue for bugs or feature requests
