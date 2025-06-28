# Contributing to DPDK Virtual NIC Tool

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally
3. **Create a branch** for your feature or bugfix
4. **Make your changes**
5. **Test thoroughly**
6. **Submit a pull request**

## Development Setup

```bash
# Clone your fork
git clone https://github.com/your-username/dpdk-virtual-nic.git
cd dpdk-virtual-nic

# Set up environment
sudo ./scripts/setup-environment.sh

# Build and test
make
sudo ./tests/unit-tests.sh
```

## Coding Standards

### C Code Style
- Follow Linux kernel coding style
- Use 4-space indentation
- Maximum line length: 80 characters
- Function names: `snake_case`
- Structure names: `snake_case`
- Constants: `UPPER_CASE`

### Documentation
- Update README.md for new features
- Add inline comments for complex logic
- Update user manual for new commands
- Include examples in documentation

### Testing
- Add unit tests for new functionality
- Test on multiple hardware configurations
- Verify performance impact
- Test error conditions

## Submitting Changes

### Pull Request Process
1. **Update documentation** for any new features
2. **Add tests** that cover your changes
3. **Run the test suite** and ensure all tests pass
4. **Update CHANGELOG.md** with your changes
5. **Submit pull request** with clear description

### Pull Request Guidelines
- **Clear title** describing the change
- **Detailed description** of what and why
- **Link to issues** if applicable
- **Test results** and performance impact
- **Screenshots** for UI changes

### Commit Messages
Use clear, descriptive commit messages:
```
Add support for custom MTU sizes

- Allow MTU configuration up to 9000 bytes
- Update validation logic for jumbo frames
- Add tests for MTU edge cases

Fixes #123
```

## Types of Contributions

### Bug Fixes
- **Report bugs** using GitHub issues
- **Include system information** and reproduction steps
- **Test the fix** on affected systems
- **Add regression tests** if possible

### New Features
- **Discuss first** by opening an issue
- **Consider impact** on existing functionality
- **Maintain backward compatibility** when possible
- **Update documentation** thoroughly

### Performance Improvements
- **Benchmark before and after** changes
- **Test on multiple hardware** configurations
- **Document performance gains**
- **Consider trade-offs** (memory vs. speed, etc.)

### Documentation
- **Fix typos** and improve clarity
- **Add examples** for complex features
- **Update installation guides**
- **Improve troubleshooting** information

## Development Guidelines

### Code Organization
```
src/           # Source code
docs/          # Documentation
scripts/       # Utility scripts
examples/      # Example configurations
tests/         # Test suite
systemd/       # System service files
```

### Adding New Features

1. **Design phase**
   - Consider architecture impact
   - Design for extensibility
   - Plan for testing

2. **Implementation phase**
   - Follow coding standards
   - Add error handling
   - Include logging

3. **Testing phase**
   - Unit tests
   - Integration tests
   - Performance tests
   - Manual testing

4. **Documentation phase**
   - Update user manual
   - Add examples
   - Update troubleshooting guide

### Performance Considerations
- **Profile your changes** with realistic workloads
- **Consider memory usage** and allocation patterns
- **Test with different CPU counts** and NUMA topologies
- **Benchmark against baseline** performance

### Security Considerations
- **Validate all inputs** from users and network
- **Check bounds** on arrays and buffers
- **Use secure functions** (strncpy vs strcpy)
- **Consider privilege escalation** risks

## Testing

### Required Tests
Before submitting:
```bash
# Build tests
make clean && make

# Unit tests
sudo ./tests/unit-tests.sh

# Performance tests
sudo ./tests/performance-test.sh

# Manual testing with real hardware
sudo dpdk-vnic-tool -l 0-1 --socket-mem 1024 -- list-ports
```

### Test Environments
Test on different:
- **Hardware platforms** (Intel, AMD, different NICs)
- **Linux distributions** (Ubuntu, CentOS, RHEL)
- **DPDK versions** (current LTS, latest stable)
- **Configuration scenarios** (single NIC, multiple NICs, jumbo frames)

## Documentation Standards

### User Documentation
- **Clear instructions** for common tasks
- **Complete examples** that work
- **Troubleshooting sections** for known issues
- **Performance tuning** guidance

### Code Documentation
```c
/**
 * Brief description of function
 *
 * Detailed description if needed, including:
 * - Parameters and their meanings
 * - Return values and error conditions
 * - Side effects or special considerations
 * - Thread safety information
 *
 * @param port_id Physical port identifier
 * @param config Configuration structure
 * @return 0 on success, negative on error
 */
int configure_physical_port(uint16_t port_id, struct port_config *config);
```

## Review Process

### What We Look For
- **Correctness** - Does it work as intended?
- **Performance** - Any negative impact?
- **Security** - Are there security implications?
- **Maintainability** - Is the code readable and well-structured?
- **Testing** - Are there adequate tests?
- **Documentation** - Is it properly documented?

### Review Timeline
- **Initial response** within 48 hours
- **Detailed review** within 1 week
- **Follow-up** on requested changes
- **Merge** when approved by maintainers

## Getting Help

### Development Questions
- **GitHub Discussions** for general questions
- **GitHub Issues** for bugs and feature requests
- **DPDK Community** for DPDK-specific questions

### Resources
- [DPDK Documentation](https://doc.dpdk.org/)
- [Linux Kernel Coding Style](https://www.kernel.org/doc/html/latest/process/coding-style.html)
- [Git Best Practices](https://git-scm.com/book/en/v2)

## Recognition

Contributors will be:
- **Listed in CONTRIBUTORS.md**
- **Credited in release notes**
- **Mentioned in significant commits**

Thank you for contributing to make DPDK Virtual NIC Tool better!
