#!/bin/bash

echo "🚀 High-Performance Virtual NIC Basic Usage Examples"

echo ""
echo "=== Kernel Implementation ==="
echo "# Start kernel-based VNIC with session load balancing"
echo "sudo ./build/kernel-vnic-lb"
echo ""

echo "=== DPDK Implementation ==="
echo "# Start DPDK VNIC with maximum performance"
echo "sudo ./build/dpdk-vnic-lb -l 0-3 --socket-mem 1024"
echo ""

echo "=== eBPF Session Tracking ==="
echo "# Load eBPF program for hardware-accelerated session tracking"
echo "sudo ip link set dev eth0 xdp obj build/session_tracker.o sec xdp_session_lb"
echo ""

echo "=== Performance Monitoring ==="
echo "# Monitor session distribution"
echo "bpftool map show"
echo "bpftool map dump name session_map"
echo ""

echo "=== Advanced Configuration ==="
echo "# Configure for different workloads:"
echo ""
echo "# Web server (many short connections)"
echo "# Use hash-based load balancing"
echo ""
echo "# Database (few long connections)"  
echo "# Use least connections algorithm"
echo ""
echo "# Streaming (high bandwidth)"
echo "# Use weighted distribution"
