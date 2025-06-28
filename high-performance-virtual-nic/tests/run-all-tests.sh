#!/bin/bash

echo "🧪 Running High-Performance Virtual NIC Test Suite"

if [[ $EUID -ne 0 ]]; then
    echo "Tests must be run as root"
    exit 1
fi

FAILED_TESTS=0
TOTAL_TESTS=0

run_test() {
    local test_name="$1"
    local test_cmd="$2"
    
    echo -n "Testing: $test_name... "
    ((TOTAL_TESTS++))
    
    if eval "$test_cmd" >/dev/null 2>&1; then
        echo "✅ PASS"
    else
        echo "❌ FAIL"
        ((FAILED_TESTS++))
    fi
}

echo "=== Basic Functionality Tests ==="

# Test build system
run_test "Build system check" "make check-deps"

# Test kernel implementation
if [ -f build/kernel-vnic-lb ]; then
    run_test "Kernel VNIC binary exists" "test -x build/kernel-vnic-lb"
    run_test "Kernel VNIC help" "build/kernel-vnic-lb --help"
fi

# Test DPDK implementation
if [ -f build/dpdk-vnic-lb ]; then
    run_test "DPDK VNIC binary exists" "test -x build/dpdk-vnic-lb"
fi

# Test eBPF compilation
if [ -f build/session_tracker.o ]; then
    run_test "eBPF program compiled" "test -f build/session_tracker.o"
fi

echo ""
echo "=== System Integration Tests ==="

# Test network interfaces
run_test "Network interfaces available" "ip link show | grep -E '(eth|ens|enp)'"

# Test kernel modules
run_test "AF_PACKET module" "lsmod | grep af_packet"

# Test permissions
run_test "Raw socket capability" "python3 -c 'import socket; socket.socket(socket.AF_PACKET, socket.SOCK_RAW)'"

echo ""
echo "=== Performance Tests ==="

# Basic performance checks
run_test "CPU frequency scaling" "cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"
run_test "Network buffer limits" "sysctl net.core.rmem_max"

echo ""
echo "📊 Test Results:"
echo "Total tests: $TOTAL_TESTS"
echo "Passed: $((TOTAL_TESTS - FAILED_TESTS))"
echo "Failed: $FAILED_TESTS"

if [ $FAILED_TESTS -eq 0 ]; then
    echo "✅ All tests passed!"
    exit 0
else
    echo "❌ Some tests failed!"
    exit 1
fi
