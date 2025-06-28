# DPDK Virtual NIC Tool Makefile

# Binary name
APP = dpdk-vnic-tool

# Source files
SRCS = src/dpdk-vnic-tool.c

# DPDK configuration
PKGCONF ?= pkg-config

# Check for DPDK installation
PC_FILE := $(shell $(PKGCONF) --path libdpdk 2>/dev/null)
CFLAGS += -O3 $(shell $(PKGCONF) --cflags libdpdk)
LDFLAGS += $(shell $(PKGCONF) --libs libdpdk)

# Additional flags
CFLAGS += -Wall -Wextra -std=c99
CFLAGS += -DALLOW_EXPERIMENTAL_API

# Build targets
build/$(APP): $(SRCS) Makefile | build
	$(CC) $(CFLAGS) $(SRCS) -o $@ $(LDFLAGS)

build:
	@mkdir -p $@

.PHONY: clean
clean:
	rm -rf build

.PHONY: install
install: build/$(APP)
	sudo cp build/$(APP) /usr/local/bin/
	sudo chmod +x /usr/local/bin/$(APP)

.PHONY: uninstall
uninstall:
	sudo rm -f /usr/local/bin/$(APP)

# Setup hugepages and permissions
.PHONY: setup-hugepages
setup-hugepages:
	@echo "Setting up hugepages..."
	sudo mkdir -p /mnt/huge
	sudo mount -t hugetlbfs nodev /mnt/huge
	echo 1024 | sudo tee /sys/devices/system/node/node*/hugepages/hugepages-2048kB/nr_hugepages

# Bind NICs to DPDK-compatible driver
.PHONY: bind-nics
bind-nics:
	@echo "Binding NICs to VFIO-PCI driver..."
	sudo modprobe vfio-pci
	sudo dpdk-devbind.py --bind=vfio-pci $(NIC_PCI_ADDRESSES)

# Show available NICs
.PHONY: show-nics
show-nics:
	sudo dpdk-devbind.py --status-dev net

# Help target
.PHONY: help
help:
	@echo "DPDK Virtual NIC Tool Build System"
	@echo ""
	@echo "Targets:"
	@echo "  build/$(APP)    - Build the application"
	@echo "  clean          - Clean build files"
	@echo "  install        - Install to system"
	@echo "  uninstall      - Remove from system"
	@echo "  setup-hugepages- Configure hugepages"
	@echo "  bind-nics      - Bind NICs to DPDK (set NIC_PCI_ADDRESSES)"
	@echo "  show-nics      - Show available network devices"
	@echo ""
	@echo "Example:"
	@echo "  make NIC_PCI_ADDRESSES=\"0000:01:00.0 0000:01:00.1\""
	@echo "  make bind-nics NIC_PCI_ADDRESSES=\"0000:01:00.0 0000:01:00.1\""

# Check DPDK installation
.PHONY: check-dpdk
check-dpdk:
ifeq ($(PC_FILE),)
	@echo "ERROR: DPDK not found. Please install DPDK first."
	@echo "See installation instructions in this file."
	@exit 1
else
	@echo "DPDK found: $(PC_FILE)"
	@echo "CFLAGS: $(CFLAGS)"
	@echo "LDFLAGS: $(LDFLAGS)"
endif
