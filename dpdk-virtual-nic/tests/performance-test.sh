#!/bin/bash

# Performance test for DPDK VNIC

echo "⚡ DPDK VNIC Performance Test"

CORES="0-3"
MEMORY="4096"
TEST_VNIC="perf-test-vnic"

echo "🔧 Setting up test environment..."

# Create high-performance VNIC with jumbo frames
sudo dpdk-vnic-tool -l $CORES --socket-mem $MEMORY -- \
    create $TEST_VNIC 0,1,2,3 --jumbo

sudo dpdk-vnic-tool -l $CORES --socket-mem $MEMORY -- \
    config $TEST_VNIC 10.0.1.100/24

sudo dpdk-vnic-tool -l $CORES --socket-mem $MEMORY -- \
    enable $TEST_VNIC

echo "📊 Performance test completed - check your monitoring tools for metrics"
echo "🧹 Cleaning up..."

sudo dpdk-vnic-tool -l $CORES --socket-mem $MEMORY -- \
    delete $TEST_VNIC

echo "✅ Performance test finished"
