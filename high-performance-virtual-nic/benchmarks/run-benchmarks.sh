#!/bin/bash

echo "⚡ Running High-Performance Virtual NIC Benchmarks"

if [[ $EUID -ne 0 ]]; then
    echo "Benchmarks must be run as root"
    exit 1
fi

RESULTS_FILE="benchmark_results_$(date +%Y%m%d_%H%M%S).txt"

echo "📊 Benchmark Results - $(date)" > $RESULTS_FILE
echo "=================================" >> $RESULTS_FILE

# System information
echo "" >> $RESULTS_FILE
echo "System Information:" >> $RESULTS_FILE
echo "CPU: $(lscpu | grep 'Model name' | cut -d: -f2 | xargs)" >> $RESULTS_FILE
echo "Memory: $(free -h | grep Mem | awk '{print $2}')" >> $RESULTS_FILE
echo "Kernel: $(uname -r)" >> $RESULTS_FILE
echo "NICs: $(lspci | grep -i ethernet | wc -l)" >> $RESULTS_FILE

# Network performance baseline
echo "" >> $RESULTS_FILE
echo "Network Baseline:" >> $RESULTS_FILE

# Test available interfaces
for iface in $(ip link show | grep -E '^[0-9]+: (eth|ens|enp)' | cut -d: -f2 | tr -d ' '); do
    if ip link show $iface | grep -q UP; then
        echo "Interface $iface:" >> $RESULTS_FILE
        ethtool $iface 2>/dev/null | grep Speed >> $RESULTS_FILE || echo "  Speed: Unknown" >> $RESULTS_FILE
        echo "  MTU: $(ip link show $iface | grep -o 'mtu [0-9]*' | cut -d' ' -f2)" >> $RESULTS_FILE
    fi
done

# Memory performance
echo "" >> $RESULTS_FILE
echo "Memory Performance:" >> $RESULTS_FILE
echo "Available hugepages: $(cat /proc/meminfo | grep HugePages_Free)" >> $RESULTS_FILE
echo "Memory bandwidth: $(dd if=/dev/zero of=/dev/null bs=1M count=1000 2>&1 | grep copied)" >> $RESULTS_FILE

# CPU performance
echo "" >> $RESULTS_FILE
echo "CPU Performance:" >> $RESULTS_FILE
echo "CPU cores: $(nproc)" >> $RESULTS_FILE
echo "CPU governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo 'N/A')" >> $RESULTS_FILE

# Test implementations if available
if [ -f build/kernel-vnic-lb ]; then
    echo "" >> $RESULTS_FILE
    echo "Kernel VNIC Performance:" >> $RESULTS_FILE
    echo "Binary size: $(ls -lh build/kernel-vnic-lb | awk '{print $5}')" >> $RESULTS_FILE
    echo "Startup time: $(time -p build/kernel-vnic-lb --help 2>&1 | grep real || echo 'N/A')" >> $RESULTS_FILE
fi

if [ -f build/dpdk-vnic-lb ]; then
    echo "" >> $RESULTS_FILE
    echo "DPDK VNIC Performance:" >> $RESULTS_FILE
    echo "Binary size: $(ls -lh build/dpdk-vnic-lb | awk '{print $5}')" >> $RESULTS_FILE
fi

echo "" >> $RESULTS_FILE
echo "Benchmark completed at $(date)" >> $RESULTS_FILE

echo "✅ Benchmarks completed!"
echo "📄 Results saved to: $RESULTS_FILE"
cat $RESULTS_FILE
