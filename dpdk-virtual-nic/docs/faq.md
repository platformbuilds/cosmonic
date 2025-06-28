# Frequently Asked Questions

## General Questions

### Q: What is the DPDK Virtual NIC Tool?

A: The DPDK Virtual NIC Tool is a high-performance virtual network interface implementation that uses DPDK (Data Plane Development Kit) to create virtual NICs with hardware-level performance, supporting multiple physical NICs, jumbo frames, and failover capabilities.

### Q: How does it differ from standard Linux networking?

A: Unlike standard Linux networking that goes through the kernel, DPDK bypasses the kernel entirely and communicates directly with hardware. This provides:
- 10x lower latency (microseconds vs milliseconds)
- 5-10x higher throughput
- Deterministic performance
- Zero-copy packet processing

### Q: What hardware do I need?

A: You need:
- Multi-core CPU with IOMMU support (Intel VT-d or AMD-Vi)
- Minimum 8GB RAM (16GB+ recommended)
- Multiple network interface cards
- DPDK-compatible NICs (Intel, Mellanox, Broadcom)

## Installation Questions

### Q: Do I need to compile DPDK separately?

A: No, the setup script automatically downloads, compiles, and installs DPDK. However, you can use an existing DPDK installation if you have one.

### Q: Can I run this on a virtual machine?

A: Yes, but with limitations:
- VM must support IOMMU passthrough
- Physical NICs must be passed through to VM
- Performance will be reduced compared to bare metal
- Hugepages must be configured in VM

### Q: What Linux distributions are supported?

A: Tested on:
- Ubuntu 18.04, 20.04, 22.04
- CentOS 7, 8
- RHEL 7, 8, 9
- Debian 10, 11

Should work on any modern Linux distribution with kernel 4.4+.

## Configuration Questions

### Q: How many VNICs can I create?

A: The current limit is 16 VNICs per system, but this can be increased by modifying `MAX_VNICS` in the source code and recompiling.

### Q: Can I use all 8 NICs for a single VNIC?

A: Yes, you can assign all available NICs to a single VNIC for maximum bandwidth aggregation:
```bash
sudo dpdk-vnic-tool -l 0-7 --socket-mem 4096 -- create mega-vnic 0,1,2,3,4,5,6,7 --jumbo
```

### Q: What's the maximum frame size supported?

A: The tool supports jumbo frames up to 9018 bytes (including headers). This is configurable in the source code if you need larger frames.

### Q: Can I change the IP address of an existing VNIC?

A: Yes, use the config command:
```bash
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- config vnic0 10.0.1.100/24
```

## Performance Questions

### Q: What performance should I expect?

A: Typical performance:
- **Throughput**: Line rate on 10/25/100GbE
- **Latency**: 1-10 microseconds
- **Packet Rate**: Up to 148.8 Mpps on 100GbE
- **CPU Efficiency**: 100% CPU utilization but maximum performance

### Q: How do I optimize for low latency?

A: Follow these steps:
1. Disable CPU idle states and frequency scaling
2. Use dedicated CPU cores
3. Configure 1GB hugepages
4. Disable interrupts on DPDK cores
5. Use the performance optimization script

### Q: Can I run multiple applications with different VNICs?

A: Each VNIC is independent, but DPDK applications typically require exclusive access to CPU cores and memory. You can run multiple applications on different core sets.

## Troubleshooting Questions

### Q: I get "No Ethernet ports available" error

A: This usually means:
1. NICs aren't bound to DPDK drivers
2. IOMMU isn't enabled
3. VFIO modules aren't loaded

Check with:
```bash
sudo dpdk-devbind.py --status
```

### Q: How do I recover if something goes wrong?

A: To reset everything:
```bash
# Kill DPDK processes
sudo pkill dpdk-vnic-tool

# Unbind NICs from DPDK
sudo dpdk-devbind.py --bind=ixgbe 0000:01:00.0  # or appropriate driver

# Restart networking
sudo systemctl restart networking
```

### Q: Can I use this with containers/Docker?

A: Yes, with careful configuration:
- Use `--privileged` mode or specific capabilities
- Mount hugepage filesystem
- Pass through required devices
- Consider using SR-IOV for better isolation

## Failover Questions

### Q: How fast is the failover?

A: Failover typically occurs within 100 milliseconds to 1 second, depending on:
- Detection method (link state vs. active probing)
- Network topology
- Switch convergence time

### Q: Do I lose existing TCP connections during failover?

A: The current implementation provides basic failover. For stateful TCP connection preservation, you would need to implement the TCP state tracking features from the original design document.

### Q: Can I manually trigger failover for testing?

A: Currently, failover is automatic based on link state. For manual testing, you can:
```bash
# Disable a physical interface
sudo ip link set eth0 down

# Or disconnect the cable
```

## Advanced Questions

### Q: How do I integrate this with existing network infrastructure?

A: Consider:
- VLAN configuration on switches
- Routing table updates
- Load balancer configuration
- Monitoring system integration

### Q: Can I modify the source code for custom features?

A: Yes, the code is designed to be extensible:
- Add custom packet processing hooks
- Implement custom failover algorithms
- Add protocol-specific optimizations
- Integrate with monitoring systems

### Q: How do I monitor performance in production?

A: Use:
- Built-in statistics from `show` command
- System monitoring tools (htop, iotop)
- Network monitoring (iftop, nload)
- Custom application metrics
- DPDK telemetry framework

### Q: Is this production-ready?

A: The tool provides a solid foundation but may need customization for production:
- Add comprehensive logging
- Implement health monitoring
- Add configuration validation
- Test thoroughly in your environment
- Consider security implications

## Licensing Questions

### Q: What license is this released under?

A: MIT License - you can use, modify, and distribute freely.

### Q: Are there any patent issues with DPDK?

A: DPDK is open source and widely used in commercial products. Intel and other contributors have made patent pledges for DPDK use.

### Q: Can I use this in commercial products?

A: Yes, the MIT license allows commercial use without restrictions.

## Support Questions

### Q: Where can I get help?

A: In order of preference:
1. Check this FAQ and troubleshooting guide
2. Search existing GitHub issues
3. Create a new GitHub issue with details
4. Consult DPDK community resources
5. Consider commercial support options

### Q: How do I contribute improvements?

A: We welcome contributions:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

### Q: Is there commercial support available?

A: This is an open-source project. For commercial support, consider:
- Consulting with DPDK specialists
- Engaging with hardware vendors
- Custom development services

Remember to always test thoroughly in your specific environment before production deployment!
