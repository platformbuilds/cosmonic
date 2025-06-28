# Installation Guide

This guide covers the complete installation process for the DPDK Virtual NIC Tool.

## System Requirements

### Hardware Requirements
- **CPU**: Multi-core processor with IOMMU support (Intel VT-d or AMD-Vi)
- **Memory**: Minimum 8GB RAM (16GB+ recommended for production)
- **Network**: Multiple NIC cards (tested with up to 8 NICs)
- **Storage**: At least 2GB free space for DPDK and tools

### Software Requirements
- **OS**: Linux kernel 4.4+ (Ubuntu 18.04+, CentOS 7+, RHEL 7+)
- **Compiler**: GCC 7+ or Clang 6+
- **Python**: Python 3.6+ for DPDK utilities
- **Root Access**: Required for hardware configuration

## Step-by-Step Installation

### 1. Automated Setup (Recommended)

```bash
# Clone the repository
git clone <repository-url>
cd dpdk-virtual-nic

# Run the automated setup script
sudo ./scripts/setup-environment.sh

# Reboot to apply GRUB changes
sudo reboot
```

### 2. Manual Installation

#### Install Dependencies
```bash
sudo apt-get update
sudo apt-get install -y build-essential libnuma-dev python3-pyelftools \
                         pkg-config meson ninja-build wget curl git
```

#### Download and Install DPDK
```bash
# Download DPDK LTS version
DPDK_VERSION="21.11.5"
wget https://fast.dpdk.org/rel/dpdk-${DPDK_VERSION}.tar.xz
tar -xf dpdk-${DPDK_VERSION}.tar.xz
cd dpdk-${DPDK_VERSION}

# Configure and build
meson build
cd build
ninja
sudo ninja install
sudo ldconfig

# Set environment variables
export PKG_CONFIG_PATH=/usr/local/lib/x86_64-linux-gnu/pkgconfig/
echo "export PKG_CONFIG_PATH=/usr/local/lib/x86_64-linux-gnu/pkgconfig/" | sudo tee -a /etc/environment
```

#### Configure Hugepages
```bash
# Configure hugepages at runtime
echo 1024 | sudo tee /sys/devices/system/node/node*/hugepages/hugepages-2048kB/nr_hugepages
sudo mkdir -p /mnt/huge
sudo mount -t hugetlbfs nodev /mnt/huge

# Make persistent
echo "nodev /mnt/huge hugetlbfs defaults 0 0" | sudo tee -a /etc/fstab
```

#### Configure GRUB for IOMMU
```bash
# Edit GRUB configuration
sudo nano /etc/default/grub

# Add IOMMU parameters to GRUB_CMDLINE_LINUX:
# GRUB_CMDLINE_LINUX="default_hugepagesz=1G hugepagesz=1G hugepages=8 iommu=pt intel_iommu=on"

# Update GRUB and reboot
sudo update-grub
sudo reboot
```

#### Load VFIO Modules
```bash
# Load modules
sudo modprobe vfio-pci
sudo modprobe vfio_iommu_type1

# Make persistent
echo "vfio-pci" | sudo tee -a /etc/modules
echo "vfio_iommu_type1" | sudo tee -a /etc/modules
```

### 3. Build the Tool

```bash
# Check DPDK installation
make check-dpdk

# Build
make

# Install system-wide (optional)
sudo make install
```

### 4. Configure Network Interfaces

```bash
# Show available network devices
sudo dpdk-devbind.py --status-dev net

# Bind NICs to DPDK (replace with your PCI addresses)
sudo dpdk-devbind.py --bind=vfio-pci 0000:01:00.0 0000:01:00.1

# Or use the Makefile target
make bind-nics NIC_PCI_ADDRESSES="0000:01:00.0 0000:01:00.1"
```

## Verification

### Test DPDK Installation
```bash
# Test basic functionality
sudo ./build/dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- list-ports

# Should show your bound network interfaces
```

### Run Unit Tests
```bash
sudo ./tests/unit-tests.sh
```

## Troubleshooting Installation

### Common Issues

#### DPDK not found
```bash
# Check if pkg-config can find DPDK
pkg-config --exists libdpdk && echo "Found" || echo "Not found"

# If not found, check environment
echo $PKG_CONFIG_PATH
```

#### No hugepages available
```bash
# Check hugepage configuration
cat /proc/meminfo | grep -i huge

# Reconfigure if needed
echo 1024 | sudo tee /sys/devices/system/node/node*/hugepages/hugepages-2048kB/nr_hugepages
```

#### IOMMU not enabled
```bash
# Check IOMMU status
dmesg | grep -i iommu

# Should show IOMMU initialization messages
# If not, check GRUB configuration and reboot
```

#### Cannot bind NICs
```bash
# Check if interfaces are down
sudo ip link set <interface> down

# Check for conflicting drivers
sudo dpdk-devbind.py --status

# Force binding
sudo dpdk-devbind.py --force --bind=vfio-pci <pci_address>
```

### Hardware-Specific Notes

#### Intel NICs
- Best performance with ixgbe, i40e, ice drivers
- Full hardware offload support
- Excellent DPDK compatibility

#### Mellanox NICs
- Requires Mellanox OFED drivers
- Install OFED before DPDK binding
- Check Mellanox documentation for specific versions

#### Broadcom NICs
- Use bnxt driver
- May require firmware updates
- Check vendor documentation

## Next Steps

After successful installation:

1. [Read the User Manual](user-manual.md)
2. [Try the examples](../examples/)
3. [Configure performance optimization](performance.md)
4. [Set up monitoring](monitoring.md)
