CC = gcc
CFLAGS = -Wall -Wextra -std=gnu99 -O2 -pthread
LDFLAGS = -pthread

SRCDIR = src
EBPFDIR = ebpf
BUILDDIR = build
TARGET = $(BUILDDIR)/vnic-tool
SOURCES = $(SRCDIR)/vnic-tool.c

HAVE_XDP := $(shell pkg-config --exists libbpf && echo 1 || echo 0)
ifeq ($(HAVE_XDP),1)
    CFLAGS += -DHAVE_XDP $(shell pkg-config --cflags libbpf)
    LDFLAGS += $(shell pkg-config --libs libbpf)
endif

EBPF_SOURCES = $(EBPFDIR)/vnic_filter.c
EBPF_OBJECTS = $(BUILDDIR)/vnic_filter.o

.PHONY: all clean install uninstall ebpf check-deps

all: check-deps $(TARGET) ebpf

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

$(TARGET): $(SOURCES) | $(BUILDDIR)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $(LDFLAGS)

ebpf: $(EBPF_OBJECTS)

$(BUILDDIR)/%.o: $(EBPFDIR)/%.c | $(BUILDDIR)
	clang -O2 -target bpf -c $< -o $@ \
		-I/usr/include/$(shell uname -m)-linux-gnu 2>/dev/null || \
		echo "eBPF compilation skipped (clang not available)"

clean:
	rm -rf $(BUILDDIR)

install: $(TARGET)
	sudo cp $(TARGET) /usr/local/bin/
	sudo chmod +x /usr/local/bin/vnic-tool

uninstall:
	sudo rm -f /usr/local/bin/vnic-tool

check-deps:
	@echo "Checking dependencies..."
	@which gcc >/dev/null || (echo "ERROR: gcc not found" && exit 1)
	@echo "✓ gcc found"

help:
	@echo "Linux Virtual NIC Tool Build System"
	@echo "Targets: all, clean, install, uninstall, ebpf, check-deps"
