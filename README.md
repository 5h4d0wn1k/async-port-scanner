> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# Async Port Scanner — High-Performance TCP Scanner

A high-performance **asynchronous TCP port scanner** built on Python's
`asyncio` for fast **network reconnaissance** and authorized security testing.
Supports CIDR ranges, service-banner grabbing, automatic service detection,
rate-limited concurrency, and JSON/CSV table reporting — standard library only,
no external dependencies.

[![CI](https://img.shields.io/github/actions/workflow/status/5h4d0wn1k/async-port-scanner/ci.yml?label=ci)](https://github.com/5h4d0wn1k/async-port-scanner/actions)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Stars](https://img.shields.io/github/stars/5h4d0wn1k/async-port-scanner)](https://github.com/5h4d0wn1k/async-port-scanner/stargazers)
[![Last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/async-port-scanner)](https://github.com/5h4d0wn1k/async-port-scanner/commits)
[![Issues](https://img.shields.io/github/issues/5h4d0wn1k/async-port-scanner)](https://github.com/5h4d0wn1k/async-port-scanner/issues)

500+ hosts scanned asynchronously with banner grabbing and service detection —
built for lab reconciliation, security audits, and learning how fast
concurrent TCP scanning works.

## Why this scanner

Port scanning is the first step of any network assessment: it answers "what is
running here?" before anything else. This project shows how to do that at speed
with asyncio — fanning out thousands of TCP connects under a concurrency
semaphore — while staying safe to run: it refuses non-private ranges unless you
pass an explicit authorization flag, it caps scan size, and it defaults to a
moderate concurrency so a lab network isn't slammed. That makes it a solid
teaching tool for network security and a genuinely fast audit utility for your
own infrastructure.

## Features

- **Async speed** — asyncio-based concurrent scanning with a configurable
  `--concurrency` semaphore (default 200).
- **CIDR targeting** — full CIDR ranges; private ranges only by default,
  `--allow-public` required (authorized use) for anything else; scans capped
  at `/16`.
- **Port lists & ranges** — `--ports 22,80,443` or `--ports 1-1024`, validated
  against 1–65535.
- **Banner grabbing** — reads the first 128 bytes of service responses
  (`reader.read(128)`), toggleable with `--no-banner`.
- **Service detection** — maps common ports and banner patterns to service
  names (`detect_service`).
- **Reporting** — human-readable table (HOST/PORT/SERVICE/STATUS/BANNER),
  `--json-out`, and `--csv-out` outputs.
- **Tunable** — `--timeout`, `--verbose/-v`, `--quiet` (JSON-only mode).
- **Zero dependencies** — Python 3.8+ standard library only.

## Quickstart

```bash
# Scan common ports on a local subnet
python port_scanner.py --cidr 192.168.1.0/24 --ports 22,80,443

# Single-host full scan with banner grabbing
python port_scanner.py --cidr 192.168.1.100/32 --ports 1-65535

# Faster, quieter scan writing JSON
python port_scanner.py --cidr 192.168.1.0/24 --ports 1-1024 \
  --concurrency 500 --timeout 2.0 --no-banner --quiet --json-out scan.json

# CSV export with service labels
python port_scanner.py --cidr 192.168.1.0/24 --ports 22,80,443 --csv-out scan.csv

# Authorized-only public ranges (never without written permission)
python port_scanner.py --cidr 8.8.8.0/24 --ports 53 --allow-public
```

Run `python port_scanner.py --help` for the full CLI reference.

## Project structure

```
port_scanner.py   async scanning engine + CLI (iter_hosts, probe, detect_service, print_table, save_csv/json)
LICENSE           MIT license
CHANGELOG.md      version history (semantic versioning)
requirements.txt  (empty — stdlib only, listed for completeness)
.gitignore / VERSION / docs (ETHICS, SCOPE, SECURITY)  supporting files
```

## Documentation

- [ETHICS.md](ETHICS.md) and [SCOPE.md](SCOPE.md) — authorized-use rules.
- [SECURITY.md](SECURITY.md) — responsible disclosure.
- [CONTRIBUTING.md](CONTRIBUTING.md) / [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
  — contribution guidelines.
- [CHANGELOG.md](CHANGELOG.md) — release notes.

## License

[MIT](LICENSE). For **educational and authorized security testing only** — scan
only networks you own or have explicit written permission to assess.