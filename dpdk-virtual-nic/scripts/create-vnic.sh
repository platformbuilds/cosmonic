#!/bin/bash

# DPDK VNIC Creation Script

VNIC_NAME="vnic0"
PHYSICAL_PORTS="0,1,2,3"  # Use first 4 NICs
IP_ADDRESS="192.168.100.10/24"
ENABLE_JUMBO="--jumbo"
CORES="0-3"
MEMORY="2048"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--name)
            VNIC_NAME="$2"
            shift 2
            ;;
        -p|--ports)
            PHYSICAL_PORTS="$2"
            shift 2
            ;;
        -i|--ip)
            IP_ADDRESS="$2"
            shift 2
            ;;
        -c|--cores)
            CORES="$2"
            shift 2
            ;;
        -m|--memory)
            MEMORY="$2"
            shift 2
            ;;
        --no-jumbo)
            ENABLE_JUMBO=""
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  -n, --name     VNIC name (default: vnic0)"
            echo "  -p, --ports    Physical ports (default: 0,1,2,3)"
            echo "  -i, --ip       IP address (default: 192.168.100.10/24)"
            echo "  -c, --cores    CPU cores (default: 0-3)"
            echo "  -m, --memory   Memory in MB (default: 2048)"
            echo "  --no-jumbo     Disable jumbo frames"
            echo "  -h, --help     Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo "Creating DPDK Virtual NIC: $VNIC_NAME"
echo "Physical ports: $PHYSICAL_PORTS"
echo "IP Address: $IP_ADDRESS"
echo "Jumbo frames: ${ENABLE_JUMBO:-disabled}"
echo "CPU cores: $CORES"
echo "Memory: ${MEMORY}MB"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root (use sudo)"
    exit 1
fi

# Step 1: Create VNIC
echo "Step 1: Creating VNIC..."
dpdk-vnic-tool -l $CORES --socket-mem $MEMORY -- \
    create $VNIC_NAME $PHYSICAL_PORTS $ENABLE_JUMBO

if [ $? -ne 0 ]; then
    echo "Failed to create VNIC"
    exit 1
fi

# Step 2: Configure IP
echo "Step 2: Configuring IP address..."
dpdk-vnic-tool -l $CORES --socket-mem $MEMORY -- \
    config $VNIC_NAME $IP_ADDRESS

if [ $? -ne 0 ]; then
    echo "Failed to configure IP address"
    exit 1
fi

# Step 3: Enable VNIC
echo "Step 3: Enabling VNIC..."
dpdk-vnic-tool -l $CORES --socket-mem $MEMORY -- \
    enable $VNIC_NAME

if [ $? -ne 0 ]; then
    echo "Failed to enable VNIC"
    exit 1
fi

# Step 4: Show status
echo "Step 4: VNIC Status:"
dpdk-vnic-tool -l $CORES --socket-mem $MEMORY -- \
    show $VNIC_NAME

echo "✅ VNIC creation completed successfully!"
