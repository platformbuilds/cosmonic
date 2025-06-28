#!/bin/bash

echo "🧪 Running Linux Virtual NIC Tool Unit Tests"

if [[ $EUID -ne 0 ]]; then
    echo "Tests must be run as root (use sudo)"
    exit 1
fi

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

run_test "List physical interfaces" "vnic-tool list-ports"
run_test "List VNICs" "vnic-tool list-vnics"

echo ""
if [ $FAILED_TESTS -eq 0 ]; then
    echo "✅ All tests passed!"
    exit 0
else
    echo "❌ $FAILED_TESTS tests failed!"
    exit 1
fi
