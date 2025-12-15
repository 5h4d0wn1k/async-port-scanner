"""
Async TCP port scanner with safety rails for lab/authorized targets only.

Features:
- CIDR validation; blocks non-private ranges unless --allow-public is set.
- Configurable concurrency (rate limiting) and per-connection timeout.
- Optional banner grab (first 128 bytes).
- JSON output (stdout or file) and simple table for open ports.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import logging
import socket
from dataclasses import dataclass, asdict
from typing import Iterable, List, Optional, Tuple

LOG = logging.getLogger("port_scanner")


@dataclass
class ScanResult:
    host: str
    port: int
    status: str  # "open" or "closed"
    banner: Optional[str] = None
    error: Optional[str] = None


def parse_ports(spec: str) -> List[int]:
    """
    Parse port specification string into list of port numbers.
    
    Supports multiple formats:
    - Single ports: "80"
    - Multiple ports: "22,80,443"
    - Port ranges: "1-1024"
    - Mixed: "22,80-82,443"
    
    Args:
        spec: Port specification string.
        
    Returns:
        Sorted list of unique port numbers.
        
    Raises:
        ValueError: If port specification is invalid or empty.
        
    Examples:
        >>> parse_ports("80")
        [80]
        >>> parse_ports("22,80,443")
        [22, 80, 443]
        >>> parse_ports("1-5")
        [1, 2, 3, 4, 5]
    """
    ports: List[int] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start, end = int(start_s), int(end_s)
            if start < 1 or end > 65535 or start > end:
                raise ValueError(f"Invalid range: {part}")
            ports.extend(range(start, end + 1))
        else:
            val = int(part)
            if val < 1 or val > 65535:
                raise ValueError(f"Invalid port: {val}")
            ports.append(val)
    result = sorted(set(ports))
    if not result:
        raise ValueError("No ports parsed.")
    return result


def iter_hosts(cidr: str, allow_public: bool) -> Iterable[str]:
    """
    Generate host IP addresses from CIDR notation.
    
    By default, only private networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    are allowed. Public networks require explicit authorization via allow_public flag.
    
    Args:
        cidr: Network in CIDR notation (e.g., "192.168.1.0/24").
        allow_public: If True, allow scanning public IP ranges (authorized use only).
        
    Yields:
        Host IP addresses as strings.
        
    Raises:
        ValueError: If CIDR is invalid, not private (without flag), or too large.
        
    Examples:
        >>> list(iter_hosts("192.168.1.0/30", False))
        ['192.168.1.1', '192.168.1.2']
    """
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid CIDR: {cidr}") from exc
    if not allow_public and not net.is_private:
        raise ValueError(
            f"CIDR {cidr} is not private. Use --allow-public only with explicit authorization."
        )
    if net.num_addresses > 65536:
        raise ValueError("CIDR too large; please scan <= /16.")
    return (str(ip) for ip in net.hosts())


async def probe(
    host: str,
    port: int,
    timeout: float,
    sem: asyncio.Semaphore,
    grab_banner: bool
) -> ScanResult:
    """
    Probe a single host:port combination.
    
    Attempts to establish a TCP connection and optionally grab service banner.
    Uses semaphore for rate limiting and respects timeout.
    
    Args:
        host: Target host IP address or hostname.
        port: Target port number.
        timeout: Connection timeout in seconds.
        sem: Semaphore for rate limiting.
        grab_banner: If True, attempt to read service banner (first 128 bytes).
        
    Returns:
        ScanResult object with connection status and optional banner/error.
    """
    async with sem:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
            banner = None
            if grab_banner:
                try:
                    data = await asyncio.wait_for(reader.read(128), timeout=1.0)
                    if data:
                        banner = data.decode(errors="ignore").strip()
                except Exception as banner_exc:  # noqa: BLE001
                    LOG.debug("Banner grab failed %s:%s: %s", host, port, banner_exc)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
            return ScanResult(host=host, port=port, status="open", banner=banner)
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError, socket.gaierror) as exc:
            return ScanResult(host=host, port=port, status="closed", error=str(exc))
        except Exception as exc:  # noqa: BLE001
            LOG.exception("Unexpected error on %s:%s", host, port)
            return ScanResult(host=host, port=port, status="closed", error=str(exc))


async def run_scan(
    hosts: Iterable[str],
    ports: List[int],
    timeout: float,
    concurrency: int,
    grab_banner: bool
) -> List[ScanResult]:
    """
    Run port scan across multiple hosts and ports.
    
    Scans all combinations of hosts and ports concurrently, respecting
    the specified concurrency limit and timeout.
    
    Args:
        hosts: Iterable of host IP addresses or hostnames.
        ports: List of port numbers to scan.
        timeout: Per-connection timeout in seconds.
        concurrency: Maximum concurrent connections.
        grab_banner: If True, attempt to grab service banners.
        
    Returns:
        List of ScanResult objects for all scanned host:port combinations.
    """
    sem = asyncio.Semaphore(concurrency)
    tasks = [asyncio.create_task(probe(h, p, timeout, sem, grab_banner)) for h in hosts for p in ports]
    results: List[ScanResult] = []
    for coro in asyncio.as_completed(tasks):
        results.append(await coro)
    return results


def detect_service(port: int, banner: Optional[str] = None) -> Optional[str]:
    """
    Detect service based on port number and banner.
    
    Uses common port numbers and banner patterns to identify services.
    
    Args:
        port: Port number.
        banner: Optional service banner.
        
    Returns:
        Service name if detected, None otherwise.
    """
    # Common port mappings
    port_services = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        8080: "HTTP-Proxy",
        8443: "HTTPS-Alt",
    }
    
    # Check port mapping first
    service = port_services.get(port)
    
    # Refine with banner if available
    if banner:
        banner_lower = banner.lower()
        if "ssh" in banner_lower:
            return "SSH"
        elif "http" in banner_lower:
            return "HTTP"
        elif "ftp" in banner_lower:
            return "FTP"
        elif "smtp" in banner_lower:
            return "SMTP"
    
    return service


def print_table(results: List[ScanResult]) -> None:
    """
    Print scan results as a formatted table.
    
    Displays open ports in a human-readable table format with
    host, port, status, and banner/error information.
    
    Args:
        results: List of ScanResult objects to display.
    """
    open_res = [r for r in results if r.status == "open"]
    if not open_res:
        print("No open ports found.")
        return
    
    # Add service detection
    headers = ("HOST", "PORT", "SERVICE", "STATUS", "BANNER")
    rows: List[Tuple[str, str, str, str, str]] = []
    for r in open_res:
        service = detect_service(r.port, r.banner) or "Unknown"
        detail = r.banner or (r.error or "")
        rows.append((r.host, str(r.port), service, r.status, detail))
    
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    
    def fmt(row_cells: Tuple[str, str, str, str, str]) -> str:
        return " | ".join(cell.ljust(widths[i]) for i, cell in enumerate(row_cells))
    
    sep = "-+-".join("-" * w for w in widths)
    print(fmt(headers))
    print(sep)
    for row in rows:
        print(fmt(row))


def save_json(results: List[ScanResult], path: Optional[str]) -> None:
    """
    Save scan results to JSON file or stdout.
    
    Args:
        results: List of ScanResult objects to save.
        path: Optional file path. If None, prints to stdout.
    """
    data = [asdict(r) for r in results]
    if path:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    else:
        print(json.dumps(data, indent=2))


def save_csv(results: List[ScanResult], path: str) -> None:
    """
    Save scan results to CSV file.
    
    Args:
        results: List of ScanResult objects to save.
        path: Output file path.
    """
    import csv
    
    open_res = [r for r in results if r.status == "open"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Host", "Port", "Service", "Status", "Banner", "Error"])
        for r in open_res:
            service = detect_service(r.port, r.banner) or "Unknown"
            writer.writerow([r.host, r.port, service, r.status, r.banner or "", r.error or ""])


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Async TCP port scanner for authorized/lab use only.")
    p.add_argument("--cidr", required=True, help="Target CIDR (private by default).")
    p.add_argument("--ports", required=True, help="Ports list, e.g., 22,80,443 or 1-1024.")
    p.add_argument("--concurrency", type=int, default=200, help="Max concurrent connections (default 200).")
    p.add_argument("--timeout", type=float, default=3.0, help="Per-connection timeout seconds (default 3.0).")
    p.add_argument("--allow-public", action="store_true", help="Allow non-private CIDR (authorized only).")
    p.add_argument("--no-banner", action="store_true", help="Disable banner grabbing.")
    p.add_argument("--json-out", help="Path to write JSON results; stdout if omitted.")
    p.add_argument("--csv-out", help="Path to write CSV results.")
    p.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging.")
    p.add_argument("--quiet", action="store_true", help="Suppress table output (JSON only).")
    return p


def main() -> None:
    """
    Main entry point for port scanner.
    
    Parses arguments, validates targets, runs scan, and outputs results.
    """
    parser = build_parser()
    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )

    print("⚠️  Authorized use only. Do not scan networks you do not own or lack permission to test.")
    
    try:
        ports = parse_ports(args.ports)
        hosts = list(iter_hosts(args.cidr, args.allow_public))
    except ValueError as exc:
        parser.error(str(exc))
        return

    LOG.info(f"Scanning {len(hosts)} host(s) across {len(ports)} port(s)...")
    
    results = asyncio.run(
        run_scan(
            hosts=hosts,
            ports=ports,
            timeout=args.timeout,
            concurrency=args.concurrency,
            grab_banner=not args.no_banner,
        )
    )

    # Output results
    if not args.quiet:
        print_table(results)
    
    # Save to files
    if args.json_out:
        save_json(results, args.json_out)
        LOG.info(f"JSON results saved to {args.json_out}")
    elif not args.csv_out:
        save_json(results, None)  # Print to stdout
    
    if args.csv_out:
        save_csv(results, args.csv_out)
        LOG.info(f"CSV results saved to {args.csv_out}")
    
    # Summary
    open_count = sum(1 for r in results if r.status == "open")
    LOG.info(f"Scan complete: {open_count} open port(s) found out of {len(results)} total scans.")


if __name__ == "__main__":
    main()
