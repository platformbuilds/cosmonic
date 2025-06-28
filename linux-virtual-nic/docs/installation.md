# Installation Guide

## Quick Install

```bash
sudo ./scripts/setup-environment.sh
make
sudo make install
```

## Manual Installation

### Dependencies
- GCC compiler
- Linux kernel headers
- libbpf-dev (optional, for eBPF support)

### Ubuntu/Debian
```bash
sudo apt-get install build-essential linux-headers-$(uname -r) libbpf-dev
```

### CentOS/RHEL/Fedora
```bash
sudo dnf install gcc kernel-devel libbpf-devel
```

## Verification

```bash
sudo vnic-tool list-ports
```

If you see your network interfaces listed, the installation was successful.
