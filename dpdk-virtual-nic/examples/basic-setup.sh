#!/bin/bash

# Basic VNIC setup example

echo "🚀 Basic VNIC Setup Example"

# Create management VNIC (ports 0,1)
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- create mgmt-vnic 0,1
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- config mgmt-vnic 192.168.1.10/24
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- enable mgmt-vnic

echo "✅ Management VNIC created on ports 0,1"
echo "🔍 VNIC Status:"
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- show mgmt-vnic
