# utiputils - Rust Networking Toolkit

This is a Rust reimplementation of Linux networking tools, including ping, arping, clockdiff, and other utilities.

#### Project Structure

- `src/bin/ping.rs` - ping command implementation
- `src/ping/` - core ping functionality modules
- `src/common/` - shared networking utility functions
- `tests/` - integration tests

#### Build

```bash
cargo build --release
```

#### Run

```bash
# Basic ping command
sudo ./target/release/utping 127.0.0.1

# Use custom pattern
sudo ./target/release/utping -p 1234 -c 3 127.0.0.1
```

#### Test

Run the test suite:
```bash
cargo test
```

**Note**: Some tests require:

- sudo privileges (for creating raw sockets)
- tcpdump tool (for network packet verification tests)

Tests include:
- **Unit tests**: 15 module-internal function tests
- **Integration tests**: 41 complete functionality tests, verifying all ping options and behaviors
- **Network packet verification**: 1 deep verification test ensuring patterns are correctly written into ICMP packets

#### Features

- ✅ Complete ping functionality implementation
- ✅ IPv4 and IPv6 support
- ✅ Custom pattern support (including odd-length hex strings)
- ✅ Fully compatible with native ping behavior
- ✅ Detailed error handling and user feedback
- ✅ Comprehensive test coverage (41 integration tests + 1 network packet verification test)

#### Pattern Functionality

utping supports pattern functionality fully compatible with native ping:

```bash
# Standard even-length pattern
sudo ./target/release/utping -p abcd 127.0.0.1

# Odd-length pattern (automatic padding handling)
sudo ./target/release/utping -p 123 127.0.0.1   # becomes 1203
sudo ./target/release/utping -p a 127.0.0.1     # becomes 0a

# Single-byte pattern
sudo ./target/release/utping -p ff 127.0.0.1
```

#### Code Architecture

The project follows these design principles:
- **First Principles**: Built from the most fundamental network protocols
- **DRY Principle**: Avoid code duplication
- **KISS Principle**: Keep it simple and straightforward
- **SOLID Principles**: Good module separation and dependency management
- **YAGNI Principle**: Don't implement unneeded functionality

#### Testing Architecture

- **Unit tests**: Basic function verification within each module
- **Integration tests**: Verify complete command-line tool behavior
- **Network packet verification**: Use tcpdump to verify actual network packet content
- **Concurrency safety**: Network tests use global locks to ensure serial execution

#### Contributing

1. Fork this repository
2. Create a new Feat_xxx branch
3. Commit your code
4. Create a Pull Request

#### Open Source License

utiputils is released under [GPL-2.0-or-later](LICENSE)