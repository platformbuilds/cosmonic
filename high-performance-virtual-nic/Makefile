# High-Performance Virtual NIC Build System

CC = gcc
CLANG = clang
CFLAGS = -Wall -Wextra -std=gnu99 -O2 -pthread -I./src/common
LDFLAGS = -pthread

# Optional dependencies
HAVE_DPDK := $(shell pkg-config --exists libdpdk && echo 1 || echo 0)
HAVE_LIBBPF := $(shell pkg-config --exists libbpf && echo 1 || echo 0)

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
    CFLAGS += -DHAVE_LIBBPF $(shell pkg-config --cflags libbpf)
    LDFLAGS += $(shell pkg-config --libs libbpf)
endif

ifeq ($(HAVE_DPDK),1)
    DPDK_CFLAGS = $(CFLAGS) $(shell pkg-config --cflags libdpdk)
    DPDK_LDFLAGS = $(LDFLAGS) $(shell pkg-config --libs libdpdk)
endif

.PHONY: all clean install uninstall kernel dpdk ebpf check-deps help

all: check-deps kernel ebpf
ifeq ($(HAVE_DPDK),1)
	@$(MAKE) dpdk
endif

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

# Kernel implementation
kernel: $(KERNEL_TARGET)

$(KERNEL_TARGET): $(KERNEL_SOURCES) | $(BUILDDIR)
	$(CC) $(CFLAGS) -o $@ $(KERNEL_SOURCES) $(LDFLAGS)

# DPDK implementation
dpdk: $(DPDK_TARGET)

$(DPDK_TARGET): $(DPDK_SOURCES) | $(BUILDDIR)
ifeq ($(HAVE_DPDK),1)
	$(CC) $(DPDK_CFLAGS) -o $@ $(DPDK_SOURCES) $(DPDK_LDFLAGS)
else
	@echo "DPDK not found, skipping DPDK build"
endif

# eBPF programs
ebpf: $(EBPF_OBJECTS)

$(BUILDDIR)/%.o: $(EBPFDIR)/%.c | $(BUILDDIR)
	$(CLANG) -O2 -target bpf -c $< -o $@ \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-I. 2>/dev/null || echo "eBPF compilation skipped"

clean:
	rm -rf $(BUILDDIR)

install: all
	sudo cp $(KERNEL_TARGET) /usr/local/bin/ 2>/dev/null || true
ifeq ($(HAVE_DPDK),1)
	sudo cp $(DPDK_TARGET) /usr/local/bin/ 2>/dev/null || true
endif
	sudo chmod +x /usr/local/bin/*vnic* 2>/dev/null || true

uninstall:
	sudo rm -f /usr/local/bin/*vnic*

check-deps:
	@echo "Checking dependencies..."
	@which gcc >/dev/null || (echo "ERROR: gcc not found" && exit 1)
	@echo "✓ GCC found"
	
	@if [ "$(HAVE_LIBBPF)" = "1" ]; then \
		echo "✓ libbpf found - eBPF support enabled"; \
	else \
		echo "⚠ libbpf not found - eBPF support limited"; \
	fi
	
	@if [ "$(HAVE_DPDK)" = "1" ]; then \
		echo "✓ DPDK found - high-performance build enabled"; \
	else \
		echo "⚠ DPDK not found - kernel-only build"; \
	fi
	
	@which clang >/dev/null && echo "✓ clang found - eBPF compilation available" || echo "⚠ clang not found"

benchmark: all
	@echo "Running benchmarks..."
	sudo ./benchmarks/run-benchmarks.sh

test: all
	@echo "Running tests..."
	sudo ./tests/run-all-tests.sh

help:
	@echo "High-Performance Virtual NIC Build System"
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
	@echo "  check-deps    - Check build dependencies"
	@echo ""
	@echo "Features:"
	@echo "  DPDK Support:    $(if $(filter 1,$(HAVE_DPDK)),Enabled,Disabled)"
	@echo "  eBPF Support:    $(if $(filter 1,$(HAVE_LIBBPF)),Enabled,Limited)"
