#!/bin/bash

# Performance optimization for DPDK VNICs

echo "🚀 Optimizing system for DPDK performance..."

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root (use sudo)"
    exit 1
fi

# CPU isolation and frequency scaling
echo "⚡ Setting CPU governor to performance..."
for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    echo performance > $cpu 2>/dev/null || true
done

# Disable CPU idle states for low latency
echo "🔄 Disabling CPU idle states..."
for state in /sys/devices/system/cpu/cpu*/cpuidle/state*/disable; do
    echo 1 > $state 2>/dev/null || true
done

# Network interface optimizations
echo "🌐 Optimizing network interfaces..."
for iface in /sys/class/net/*/; do
    ifname=$(basename $iface)
    if [[ $ifname != "lo" ]]; then
        # Disable power management
        ethtool -s $ifname speed 10000 duplex full autoneg off 2>/dev/null || true
        # Set larger ring buffers
        ethtool -G $ifname rx 4096 tx 4096 2>/dev/null || true
        # Enable hardware checksumming
        ethtool -K $ifname rx-checksum on tx-checksum-ip-generic on 2>/dev/null || true
    fi
done

# IRQ affinity (spread interrupts across cores)
echo "⚙️  Setting IRQ affinity..."
irq_count=0
for irq in $(grep -E "(eth|ens|enp)" /proc/interrupts | cut -d: -f1 | tr -d ' '); do
    cpu=$((irq_count % $(nproc)))
    echo $((1 << cpu)) > /proc/irq/$irq/smp_affinity 2>/dev/null || true
    ((irq_count++))
done

echo "✅ Performance optimization completed!"
