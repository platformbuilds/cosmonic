#!/bin/bash

# Failover VNIC configuration example

VNIC_NAME="failover-vnic"
PRIMARY_PORTS="0,1"      # Primary port group
BACKUP_PORTS="2,3"       # Backup port group
IP_ADDRESS="10.0.1.100/24"
CORES="0-7"
MEMORY="4096"

echo "🔄 Creating Failover VNIC Configuration"

# Create primary VNIC
echo "🟢 Creating primary VNIC..."
sudo dpdk-vnic-tool -l $CORES --socket-mem $MEMORY -- \
    create ${VNIC_NAME}_primary $PRIMARY_PORTS --jumbo

sudo dpdk-vnic-tool -l $CORES --socket-mem $MEMORY -- \
    config ${VNIC_NAME}_primary $IP_ADDRESS

sudo dpdk-vnic-tool -l $CORES --socket-mem $MEMORY -- \
    enable ${VNIC_NAME}_primary

# Create backup VNIC  
echo "🟡 Creating backup VNIC..."
sudo dpdk-vnic-tool -l $CORES --socket-mem $MEMORY -- \
    create ${VNIC_NAME}_backup $BACKUP_PORTS --jumbo

sudo dpdk-vnic-tool -l $CORES --socket-mem $MEMORY -- \
    config ${VNIC_NAME}_backup $IP_ADDRESS

echo "✅ Failover VNIC setup complete!"
echo "🟢 Primary VNIC uses ports: $PRIMARY_PORTS"
echo "🟡 Backup VNIC uses ports: $BACKUP_PORTS"
echo ""
echo "📋 VNIC Status:"
sudo dpdk-vnic-tool -l $CORES --socket-mem $MEMORY -- list-vnics
