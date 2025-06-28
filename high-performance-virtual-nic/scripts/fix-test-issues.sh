#!/bin/bash

echo "🔧 Fixing common test issues..."

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root (use sudo)"
    exit 1
fi

# Fix 1: Load AF_PACKET module if not built-in
echo "📡 Checking AF_PACKET support..."
if ! grep -q "packet" /proc/net/protocols 2>/dev/null; then
    echo "Loading AF_PACKET module..."
    modprobe af_packet 2>/dev/null || echo "AF_PACKET module load failed (may be built-in)"
fi

# Verify AF_PACKET is available
if grep -q "packet" /proc/net/protocols 2>/dev/null; then
    echo "✅ AF_PACKET support confirmed"
elif python3 -c "import socket; socket.socket(socket.AF_PACKET, socket.SOCK_RAW)" 2>/dev/null; then
    echo "✅ AF_PACKET support confirmed (socket test)"
else
    echo "❌ AF_PACKET support not available"
    echo "💡 Your kernel may not have AF_PACKET support compiled in"
fi

# Fix 2: Set proper network permissions
echo "🔐 Checking network permissions..."
if ! python3 -c "import socket; socket.socket(socket.AF_PACKET, socket.SOCK_RAW)" 2>/dev/null; then
    echo "⚠️  Raw socket creation failed - ensure running as root"
fi

# Fix 3: Load other useful network modules
echo "🌐 Loading additional network modules..."
for module in ip_tables iptable_filter; do
    modprobe $module 2>/dev/null || true
done

# Fix 4: Check and fix network buffer limits
echo "📊 Checking network buffer configuration..."
current_rmem=$(sysctl -n net.core.rmem_max 2>/dev/null || echo "0")
if [ "$current_rmem" -lt 16777216 ]; then
    echo "Increasing network buffer limits..."
    sysctl -w net.core.rmem_max=268435456 >/dev/null 2>&1 || true
    sysctl -w net.core.wmem_max=268435456 >/dev/null 2>&1 || true
fi

# Fix 5: Ensure required directories exist
echo "📁 Checking required directories..."
mkdir -p /var/log /tmp

# Fix 6: Test basic network functionality
echo "🧪 Testing basic network functionality..."
if ip link show lo >/dev/null 2>&1; then
    echo "✅ Basic network interface control works"
else
    echo "❌ Network interface control failed"
fi

# Fix 7: Create test environment
echo "🔧 Setting up test environment..."
# Ensure test binaries are executable
if [ -f build/kernel-vnic-lb ]; then
    chmod +x build/kernel-vnic-lb
    echo "✅ Kernel VNIC binary is executable"
fi

if [ -f build/dpdk-vnic-lb ]; then
    chmod +x build/dpdk-vnic-lb
    echo "✅ DPDK VNIC binary is executable"
fi

echo ""
echo "✅ Test environment fixes completed!"
echo ""
echo "🧪 Run tests again with:"
echo "make test"
