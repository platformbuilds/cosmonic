#!/bin/bash

echo "🚀 Setting up Linux Virtual NIC Environment..."

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

case $DISTRO in
    ubuntu|debian)
        apt-get update
        apt-get install -y build-essential clang llvm \
                           linux-headers-$(uname -r) \
                           libbpf-dev pkg-config \
                           iproute2 ethtool net-tools
        ;;
    centos|rhel|fedora)
        if command -v dnf >/dev/null; then
            PKG_MGR=dnf
        else
            PKG_MGR=yum
        fi
        
        $PKG_MGR update -y
        $PKG_MGR install -y gcc clang llvm \
                           kernel-headers kernel-devel \
                           libbpf-devel pkgconfig \
                           iproute2 ethtool net-tools
        ;;
    *)
        echo "Unsupported distribution: $DISTRO"
        echo "Please install manually: gcc, clang, kernel headers, libbpf-dev"
        ;;
esac

echo "⚙️ Configuring kernel parameters..."
sysctl -w net.core.rmem_max=268435456 >/dev/null 2>&1 || true
sysctl -w net.core.wmem_max=268435456 >/dev/null 2>&1 || true

echo "🔧 Loading kernel modules..."
modprobe af_packet >/dev/null 2>&1 || true

echo "✅ Environment setup completed!"
echo "Next steps: make && sudo make install"
