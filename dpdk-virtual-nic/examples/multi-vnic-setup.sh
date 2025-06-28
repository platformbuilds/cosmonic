#!/bin/bash

# Multi-VNIC setup for different network segments

echo "🚀 Multi-VNIC Setup Example"

CORES="0-3"
MEMORY="2048"

# VNIC for management traffic (ports 0,1)
echo "📡 Creating Management VNIC..."
sudo dpdk-vnic-tool -l $CORES --socket-mem $MEMORY -- create mgmt-vnic 0,1
sudo dpdk-vnic-tool -l $CORES --socket-mem $MEMORY -- config mgmt-vnic 192.168.1.10/24
sudo dpdk-vnic-tool -l $CORES --socket-mem $MEMORY -- enable mgmt-vnic

# VNIC for data traffic with jumbo frames (ports 2,3,4,5)
echo "💾 Creating Data VNIC with Jumbo Frames..."
sudo dpdk-vnic-tool -l $CORES --socket-mem $MEMORY -- create data-vnic 2,3,4,5 --jumbo
sudo dpdk-vnic-tool -l $CORES --socket-mem $MEMORY -- config data-vnic 10.0.1.10/24
sudo dpdk-vnic-tool -l $CORES --socket-mem $MEMORY -- enable data-vnic

# VNIC for backup/replication (ports 6,7)
echo "🔄 Creating Backup VNIC..."
sudo dpdk-vnic-tool -l $CORES --socket-mem $MEMORY -- create backup-vnic 6,7
sudo dpdk-vnic-tool -l $CORES --socket-mem $MEMORY -- config backup-vnic 172.16.1.10/24
sudo dpdk-vnic-tool -l $CORES --socket-mem $MEMORY -- enable backup-vnic

# List all VNICs
echo "📋 All VNICs:"
sudo dpdk-vnic-tool -l $CORES --socket-mem $MEMORY -- list-vnics

echo "✅ Multi-VNIC setup completed!"
