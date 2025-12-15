# Async Port Scanner

⚠️ **EDUCATIONAL PURPOSE ONLY** - This tool is designed for authorized security testing and educational purposes. Only use on systems you own or have explicit written authorization to test.

## Overview

A high-performance asynchronous TCP port scanner built with Python's `asyncio` for fast network reconnaissance. Features include CIDR support, banner grabbing, rate limiting, and comprehensive JSON reporting.

## Features

- **Async Performance**: High-speed concurrent port scanning using asyncio
- **CIDR Support**: Scan entire network ranges efficiently
- **Banner Grabbing**: Automatically grab service banners (first 128 bytes)
- **Rate Limiting**: Configurable concurrency to prevent network overload
- **Safety Controls**: Blocks public IP ranges by default (requires explicit flag)
- **JSON Output**: Machine-readable results for automation
- **Table Display**: Human-readable table output for quick review

## Installation

### Requirements

- Python 3.8+
- Standard library only (no external dependencies!)

### Setup

```bash
# Clone the repository
git clone https://github.com/5h4d0wn1k/async-port-scanner.git
cd async-port-scanner

# No installation needed - uses standard library only!
python port_scanner.py --help
```

## Usage

### Basic Usage

```bash
# Scan specific ports on a network
python port_scanner.py --cidr 192.168.1.0/24 --ports 22,80,443

# Scan port range
python port_scanner.py --cidr 192.168.1.0/24 --ports 1-1024

# Single host scan
python port_scanner.py --cidr 192.168.1.100/32 --ports 1-65535
```

### Advanced Usage

```bash
# Custom concurrency and timeout
python port_scanner.py \
  --cidr 192.168.1.0/24 \
  --ports 1-1024 \
  --concurrency 500 \
  --timeout 5.0

# Disable banner grabbing for faster scans
python port_scanner.py \
  --cidr 192.168.1.0/24 \
  --ports 22,80,443 \
  --no-banner

# Save results to JSON file
python port_scanner.py \
  --cidr 192.168.1.0/24 \
  --ports 1-1024 \
  --json-out scan_results.json

# Quiet mode (JSON only, no table)
python port_scanner.py \
  --cidr 192.168.1.0/24 \
  --ports 1-1024 \
  --json-out results.json \
  --quiet
```

### Public IP Scanning (Authorized Only)

```bash
# Requires explicit authorization flag
python port_scanner.py \
  --cidr 8.8.8.0/24 \
  --ports 53 \
  --allow-public
```

## Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--cidr` | Target network in CIDR notation (required) | - |
| `--ports` | Ports to scan (comma-separated or range) | - |
| `--concurrency` | Max concurrent connections | 200 |
| `--timeout` | Per-connection timeout (seconds) | 3.0 |
| `--allow-public` | Allow scanning public IP ranges | False |
| `--no-banner` | Disable banner grabbing | False |
| `--json-out` | Save results to JSON file | stdout |
| `--quiet` | Suppress table output | False |

## Port Specification

Ports can be specified in multiple formats:

```bash
# Single ports
--ports 22,80,443

# Port ranges
--ports 1-1024

# Mixed format
--ports 22,80,443,8000-8100,9000
```

## Output Format

### Table Output

```
HOST          | PORT | STATUS | BANNER/ERROR
--------------+------+--------+------------------
192.168.1.1   | 22   | open   | SSH-2.0-OpenSSH_8.0
192.168.1.1   | 80   | open   | HTTP/1.1 200 OK
192.168.1.1   | 443  | open   | HTTP/1.1 200 OK
```

### JSON Output

```json
[
  {
    "host": "192.168.1.1",
    "port": 22,
    "status": "open",
    "banner": "SSH-2.0-OpenSSH_8.0",
    "error": null
  },
  {
    "host": "192.168.1.1",
    "port": 80,
    "status": "open",
    "banner": "HTTP/1.1 200 OK",
    "error": null
  }
]
```

## Examples

### Example 1: Quick Network Scan

```bash
# Scan common ports on local network
python port_scanner.py \
  --cidr 192.168.1.0/24 \
  --ports 22,80,443,8080,8443 \
  --json-out quick_scan.json
```

### Example 2: Comprehensive Port Scan

```bash
# Full port scan with banner grabbing
python port_scanner.py \
  --cidr 192.168.1.100/32 \
  --ports 1-65535 \
  --concurrency 1000 \
  --timeout 2.0 \
  --json-out full_scan.json
```

### Example 3: Fast Discovery Scan

```bash
# Fast scan without banners
python port_scanner.py \
  --cidr 192.168.1.0/24 \
  --ports 1-1024 \
  --no-banner \
  --concurrency 500 \
  --quiet \
  --json-out discovery.json
```

## Performance Tips

1. **Concurrency**: Increase `--concurrency` for faster scans (default: 200)
2. **Timeout**: Reduce `--timeout` for faster results on closed ports (default: 3.0)
3. **Banner Grabbing**: Use `--no-banner` for faster scans when banners aren't needed
4. **Port Selection**: Scan specific ports instead of ranges when possible

## Safety Features

- **Private IP Only**: By default, only scans private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- **CIDR Size Limit**: Maximum /16 network size (65,536 hosts)
- **Rate Limiting**: Built-in concurrency control prevents network overload
- **Explicit Authorization**: Public IP scanning requires `--allow-public` flag

## Use Cases

- **Network Discovery**: Identify open ports on your network
- **Security Audits**: Check for unauthorized services
- **Penetration Testing**: Authorized security assessments
- **Educational Purposes**: Learn about network scanning techniques

## Legal Disclaimer

⚠️ **IMPORTANT**: This tool is for authorized security testing and educational purposes only. Unauthorized port scanning is illegal in many jurisdictions and may result in criminal prosecution.

- Only scan networks you own or have explicit written authorization to test
- Respect rate limits and don't overload target systems
- Follow responsible disclosure practices
- Comply with all applicable laws and regulations

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

This project is for educational purposes only. Use responsibly and ethically.

## Author

Created for educational and authorized security testing purposes.

## Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Follow responsible disclosure practices
- Use only for authorized testing

---

**Remember**: Always get explicit authorization before scanning any network!
