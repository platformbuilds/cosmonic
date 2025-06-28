#!/bin/bash

# Unit tests for DPDK VNIC Tool

echo "🧪 Running DPDK VNIC Tool Unit Tests"

CORES="0-1"
MEMORY="1024"
TEST_VNIC="test-vnic"
FAILED_TESTS=0

run_test() {
    local test_name="$1"
    local command="$2"
    
    echo -n "Testing: $test_name... "
    
    if eval "$command" >/dev/null 2>&1; then
        echo "✅ PASS"
    else
        echo "❌ FAIL"
        ((FAILED_TESTS++))
    fi
}

# Test 1: List physical ports
run_test "List physical ports" \
    "dpdk-vnic-tool -l $CORES --socket-mem $MEMORY -- list-ports"

# Test 2: Create VNIC
run_test "Create VNIC" \
    "dpdk-vnic-tool -l $CORES --socket-mem $MEMORY -- create $TEST_VNIC 0"

# Test 3: Configure IP
run_test "Configure IP address" \
    "dpdk-vnic-tool -l $CORES --socket-mem $MEMORY -- config $TEST_VNIC 192.168.100.10/24"

# Test 4: Show VNIC info
run_test "Show VNIC information" \
    "dpdk-vnic-tool -l $CORES --socket-mem $MEMORY -- show $TEST_VNIC"

# Test 5: Enable VNIC
run_test "Enable VNIC" \
    "dpdk-vnic-tool -l $CORES --socket-mem $MEMORY -- enable $TEST_VNIC"

# Test 6: List VNICs
run_test "List VNICs" \
    "dpdk-vnic-tool -l $CORES --socket-mem $MEMORY -- list-vnics"

# Test 7: Disable VNIC
run_test "Disable VNIC" \
    "dpdk-vnic-tool -l $CORES --socket-mem $MEMORY -- disable $TEST_VNIC"

# Test 8: Delete VNIC
run_test "Delete VNIC" \
    "dpdk-vnic-tool -l $CORES --socket-mem $MEMORY -- delete $TEST_VNIC"

echo ""
if [ $FAILED_TESTS -eq 0 ]; then
    echo "✅ All tests passed!"
    exit 0
else
    echo "❌ $FAILED_TESTS tests failed!"
    exit 1
fi
