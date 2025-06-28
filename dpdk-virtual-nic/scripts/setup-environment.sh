#!/bin/bash

# DPDK Virtual NIC Environment Setup Script

set -e

echo "🚀 Setting up DPDK Virtual NIC Environment..."

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root (use sudo)"
    exit 1
fi

# Install dependencies
echo "📦 Installing dependencies..."
apt-get update
apt-get install -y build-essential libnuma-dev python3-pyelftools \
                   pkg-config meson ninja-build wget curl git

# Download and install DPDK
DPDK_VERSION="21.11.5"
DPDK_DIR="dpdk-${DPDK_VERSION}"

if [ ! -d "/usr/local/include/rte_config.h" ]; then
    echo "📥 Downloading DPDK ${DPDK_VERSION}..."
    wget -q https://fast.dpdk.org/rel/dpdk-${DPDK_VERSION}.tar.xz
    tar -xf dpdk-${DPDK_VERSION}.tar.xz
    cd ${DPDK_DIR}
    
    echo "🔨 Building DPDK..."
    meson build
    cd build
    ninja
    ninja install
    ldconfig
    
    cd ../../
    rm -rf ${DPDK_DIR} dpdk-${DPDK_VERSION}.tar.xz
    echo "✅ DPDK installed successfully"
else
    echo "✅ DPDK already installed"
fi

# Set environment variables
echo "🔧 Setting environment variables..."
export PKG_CONFIG_PATH=/usr/local/lib/x86_64-linux-gnu/pkgconfig/
echo "export PKG_CONFIG_PATH=/usr/local/lib/x86_64-linux-gnu/pkgconfig/" >> /etc/environment

# Configure hugepages
echo "💾 Configuring hugepages..."
echo 1024 > /sys/devices/system/node/node*/hugepages/hugepages-2048kB/nr_hugepages
mkdir -p /mnt/huge
mount -t hugetlbfs nodev /mnt/huge

# Make hugepage configuration persistent
if ! grep -q "hugetlbfs" /etc/fstab; then
    echo "nodev /mnt/huge hugetlbfs defaults 0 0" >> /etc/fstab
fi

# Load VFIO modules
echo "🔌 Loading VFIO modules..."
modprobe vfio-pci
modprobe vfio_iommu_type1

# Make VFIO modules persistent
echo "vfio-pci" >> /etc/modules
echo "vfio_iommu_type1" >> /etc/modules

# Configure GRUB for IOMMU (requires reboot)
echo "⚙️  Configuring GRUB for IOMMU..."
if ! grep -q "iommu=pt intel_iommu=on" /etc/default/grub; then
    sed -i 's/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="default_hugepagesz=1G hugepagesz=1G hugepages=8 iommu=pt intel_iommu=on"/' /etc/default/grub
    update-grub
    echo "⚠️  GRUB updated. Reboot required for IOMMU changes to take effect."
fi

echo "✅ Environment setup completed!"
echo ""
echo "Next steps:"
echo "1. Reboot the system if GRUB was updated"
echo "2. Run 'make bind-nics NIC_PCI_ADDRESSES=\"<your_nic_addresses>\"'"
echo "3. Build the project with 'make'"
echo "4. Test with 'sudo ./build/dpdk-vnic-tool -- list-ports'"
