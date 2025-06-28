#!/bin/bash

echo "🚀 Setting up High-Performance Virtual NIC Environment..."

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root (use sudo)"
    exit 1
fi

# Detect distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO=$ID
else
    echo "Cannot detect Linux distribution"
    exit 1
fi

echo "📦 Installing dependencies for $DISTRO..."

install_ubuntu_deps() {
    apt-get update
    apt-get install -y \
        build-essential clang llvm \
        linux-headers-$(uname -r) \
        libbpf-dev pkg-config \
        iproute2 ethtool net-tools \
        libnuma-dev python3-pyelftools \
        git wget curl
    
    # Optional DPDK installation
    read -p "Install DPDK for maximum performance? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Installing DPDK..."
        apt-get install -y dpdk dpdk-dev
    fi
}

install_centos_deps() {
    dnf update -y 2>/dev/null || yum update -y
    dnf install -y gcc clang llvm \
                   kernel-headers kernel-devel \
                   libbpf-devel pkgconfig \
                   iproute2 ethtool net-tools \
                   numactl-devel python3 \
                   git wget curl 2>/dev/null || \
    yum install -y gcc clang llvm \
                   kernel-headers kernel-devel \
                   libbpf-devel pkgconfig \
                   iproute2 ethtool net-tools \
                   numactl-devel python3 \
                   git wget curl
}

case $DISTRO in
    ubuntu|debian)
        install_ubuntu_deps
        ;;
    centos|rhel|fedora)
        install_centos_deps
        ;;
    *)
        echo "Unsupported distribution: $DISTRO"
        echo "Please install manually: gcc, clang, kernel headers, libbpf-dev"
        ;;
esac

echo "⚙️ Configuring system for high performance..."

# Network optimizations
sysctl -w net.core.rmem_max=268435456 >/dev/null 2>&1 || true
sysctl -w net.core.wmem_max=268435456 >/dev/null 2>&1 || true
sysctl -w net.core.netdev_max_backlog=5000 >/dev/null 2>&1 || true

# Load required modules
modprobe af_packet >/dev/null 2>&1 || true

echo "✅ Environment setup completed!"
echo ""
echo "📋 Next steps:"
echo "1. make              # Build the tools"
echo "2. sudo make install # Install system-wide"
echo "3. sudo make test    # Run tests"
echo "4. sudo make benchmark # Run performance tests"
