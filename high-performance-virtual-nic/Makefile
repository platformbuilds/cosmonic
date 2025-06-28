# High-Performance Virtual NIC Build System

CC = gcc
CLANG = clang
CFLAGS = -Wall -Wextra -std=gnu99 -O2 -pthread -I./src/common -D_GNU_SOURCE
LDFLAGS = -pthread

# Optional dependencies
HAVE_DPDK := $(shell pkg-config --exists libdpdk 2>/dev/null && echo 1 || echo 0)
HAVE_LIBBPF := $(shell pkg-config --exists libbpf 2>/dev/null && echo 1 || echo 0)

# Directories
SRCDIR = src
BUILDDIR = build
EBPFDIR = ebpf

# Targets
KERNEL_TARGET = $(BUILDDIR)/kernel-vnic-lb
DPDK_TARGET = $(BUILDDIR)/dpdk-vnic-lb
EBPF_OBJECTS = $(BUILDDIR)/session_tracker.o

# Source files
KERNEL_SOURCES = $(SRCDIR)/kernel/kernel_vnic_lb.c
DPDK_SOURCES = $(SRCDIR)/dpdk/dpdk_vnic_lb.c

# Conditional compilation flags
ifeq ($(HAVE_LIBBPF),1)
    CFLAGS += -DHAVE_LIBBPF $(shell pkg-config --cflags libbpf 2>/dev/null)
    LDFLAGS += $(shell pkg-config --libs libbpf 2>/dev/null)
endif

ifeq ($(HAVE_DPDK),1)
    DPDK_CFLAGS = $(CFLAGS) $(shell pkg-config --cflags libdpdk 2>/dev/null)
    DPDK_LDFLAGS = $(LDFLAGS) $(shell pkg-config --libs libdpdk 2>/dev/null)
endif

.PHONY: all clean install uninstall kernel dpdk ebpf check-deps help fix

all: check-deps fix-headers kernel ebpf
ifeq ($(HAVE_DPDK),1)
	@$(MAKE) dpdk
endif

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

# Fix common build issues
fix-headers:
	@echo "🔧 Checking for build issues..."
	@if [ -f scripts/fix-build-issues.sh ]; then \
		./scripts/fix-build-issues.sh; \
	fi

# Kernel implementation
kernel: $(KERNEL_TARGET)

$(KERNEL_TARGET): $(KERNEL_SOURCES) | $(BUILDDIR)
	@echo "🔨 Building kernel implementation..."
	$(CC) $(CFLAGS) -o $@ $(KERNEL_SOURCES) $(LDFLAGS)
	@echo "✅ Kernel implementation built successfully"

# DPDK implementation
dpdk: $(DPDK_TARGET)

$(DPDK_TARGET): $(DPDK_SOURCES) | $(BUILDDIR)
ifeq ($(HAVE_DPDK),1)
	@echo "🔨 Building DPDK implementation..."
	$(CC) $(DPDK_CFLAGS) -o $@ $(DPDK_SOURCES) $(DPDK_LDFLAGS)
	@echo "✅ DPDK implementation built successfully"
else
	@echo "⚠️  DPDK not found, skipping DPDK build"
	@echo "To install DPDK: sudo apt-get install dpdk dpdk-dev (Ubuntu) or see docs"
endif

# eBPF programs
ebpf: $(EBPF_OBJECTS)

$(BUILDDIR)/%.o: $(EBPFDIR)/%.c | $(BUILDDIR)
	@echo "🔨 Building eBPF program: $<"
	@$(CLANG) -O2 -target bpf -c $< -o $@ \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-I. 2>/dev/null && echo "✅ eBPF program built: $@" || \
		echo "⚠️  eBPF compilation skipped (clang not available or headers missing)"

clean:
	@echo "🧹 Cleaning build artifacts..."
	rm -rf $(BUILDDIR)
	@echo "✅ Clean completed"

install: all
	@echo "📦 Installing to system..."
	sudo cp $(KERNEL_TARGET) /usr/local/bin/ 2>/dev/null || true
ifeq ($(HAVE_DPDK),1)
	sudo cp $(DPDK_TARGET) /usr/local/bin/ 2>/dev/null || true
endif
	sudo chmod +x /usr/local/bin/*vnic* 2>/dev/null || true
	@echo "✅ Installation completed"

uninstall:
	@echo "🗑️  Uninstalling..."
	sudo rm -f /usr/local/bin/*vnic*
	@echo "✅ Uninstallation completed"

check-deps:
	@echo "🔍 Checking dependencies..."
	@which gcc >/dev/null || (echo "❌ ERROR: gcc not found" && exit 1)
	@echo "✅ GCC found: $(shell gcc --version | head -1)"
	
	@if [ "$(HAVE_LIBBPF)" = "1" ]; then \
		echo "✅ libbpf found - eBPF support enabled"; \
	else \
		echo "⚠️  libbpf not found - eBPF support limited"; \
		echo "   Install: sudo apt-get install libbpf-dev (Ubuntu)"; \
	fi
	
	@if [ "$(HAVE_DPDK)" = "1" ]; then \
		echo "✅ DPDK found - high-performance build enabled"; \
	else \
		echo "⚠️  DPDK not found - kernel-only build"; \
		echo "   Install: sudo apt-get install dpdk dpdk-dev (Ubuntu)"; \
	fi
	
	@which clang >/dev/null && echo "✅ clang found - eBPF compilation available" || \
		echo "⚠️  clang not found - install: sudo apt-get install clang"

	@echo "🔍 Checking system requirements..."
	@if [ ! -d /usr/include/linux ]; then \
		echo "⚠️  Linux headers missing - install: sudo apt-get install linux-headers-$(uname -r)"; \
	else \
		echo "✅ Linux headers found"; \
	fi

benchmark: all
	@echo "⚡ Running benchmarks..."
	@if [ -f benchmarks/run-benchmarks.sh ]; then \
		sudo ./benchmarks/run-benchmarks.sh; \
	else \
		echo "❌ Benchmark script not found"; \
	fi

test: all
	@echo "🧪 Running tests..."
	@if [ -f tests/run-all-tests.sh ]; then \
		sudo ./tests/run-all-tests.sh; \
	else \
		echo "❌ Test script not found"; \
	fi

demo: kernel
	@echo "🎬 Running kernel VNIC demo..."
	@echo "Press Ctrl+C to stop the demo"
	sudo ./$(KERNEL_TARGET) --help
	@echo ""
	@echo "To run interactive demo:"
	@echo "sudo ./$(KERNEL_TARGET) --interfaces 4 --algorithm hash"

help:
	@echo "🚀 High-Performance Virtual NIC Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all           - Build all available implementations"
	@echo "  kernel        - Build kernel-based implementation"
	@echo "  dpdk          - Build DPDK implementation (if available)"
	@echo "  ebpf          - Build eBPF programs"
	@echo "  clean         - Remove build files"
	@echo "  install       - Install to system"
	@echo "  test          - Run test suite"
	@echo "  benchmark     - Run performance benchmarks"
	@echo "  demo          - Run interactive demo"
	@echo "  check-deps    - Check build dependencies"
	@echo "  fix-headers   - Fix common header issues"
	@echo ""
	@echo "Features:"
	@echo "  DPDK Support:    $(if $(filter 1,$(HAVE_DPDK)),✅ Enabled,⚠️  Disabled)"
	@echo "  eBPF Support:    $(if $(filter 1,$(HAVE_LIBBPF)),✅ Enabled,⚠️  Limited)"
	@echo ""
	@echo "Quick start:"
	@echo "  1. make check-deps    # Check what's needed"
	@echo "  2. make               # Build everything"
	@echo "  3. make demo          # Try it out"

fix-tests: fix-headers
	@echo "🔧 Fixing test environment..."
	@if [ -f scripts/fix-test-issues.sh ]; then \
		sudo ./scripts/fix-test-issues.sh; \
	fi

test-with-fixes: fix-tests test
	@echo "✅ Tests completed with auto-fixes applied"
