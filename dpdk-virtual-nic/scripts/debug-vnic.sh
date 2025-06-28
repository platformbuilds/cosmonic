#!/bin/bash

# VNIC debugging script

VNIC_NAME=${1:-"vnic0"}
CORES="0-1"
MEMORY="1024"

echo "🔍 Debugging VNIC: $VNIC_NAME"
echo "=========================="

# Show physical ports
echo "📋 Physical Ports:"
dpdk-vnic-tool -l $CORES --socket-mem $MEMORY -- list-ports

echo ""
echo "🔧 VNIC Information:"
dpdk-vnic-tool -l $CORES --socket-mem $MEMORY -- show $VNIC_NAME

echo ""
echo "💾 System Resources:"
echo "Hugepages: $(cat /proc/meminfo | grep -i huge)"
echo "IOMMU Groups: $(find /sys/kernel/iommu_groups/ -type l 2>/dev/null | wc -l)"
echo "VFIO Devices: $(lsmod | grep vfio)"

echo ""
echo "🌐 Network Interfaces:"
ip link show | grep -E "(vnic|eth|ens|enp)"

echo ""
echo "🔌 DPDK Device Status:"
dpdk-devbind.py --status 2>/dev/null || echo "dpdk-devbind.py not found"
