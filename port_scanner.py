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


async def probe(host: str, port: int, timeout: float, sem: asyncio.Semaphore, grab_banner: bool) -> ScanResult:
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
            return ScanResult(host, port, "open", banner=banner)
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError, socket.gaierror) as exc:
            return ScanResult(host, port, "closed", error=str(exc))
        except Exception as exc:  # noqa: BLE001
            LOG.exception("Unexpected error on %s:%s", host, port)
            return ScanResult(host, port, "closed", error=str(exc))


async def run_scan(hosts: Iterable[str], ports: List[int], timeout: float, concurrency: int, grab_banner: bool) -> List[ScanResult]:
    sem = asyncio.Semaphore(concurrency)
    tasks = [asyncio.create_task(probe(h, p, timeout, sem, grab_banner)) for h in hosts for p in ports]
    results: List[ScanResult] = []
    for coro in asyncio.as_completed(tasks):
        results.append(await coro)
    return results


def print_table(results: List[ScanResult]) -> None:
    open_res = [r for r in results if r.status == "open"]
    if not open_res:
        print("No open ports found.")
        return
    headers = ("HOST", "PORT", "STATUS", "BANNER/ERROR")
    rows: List[Tuple[str, str, str, str]] = []
    for r in open_res:
        detail = r.banner or (r.error or "")
        rows.append((r.host, str(r.port), r.status, detail))
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    def fmt(row_cells: Tuple[str, str, str, str]) -> str:
        return " | ".join(cell.ljust(widths[i]) for i, cell in enumerate(row_cells))
    sep = "-+-".join("-" * w for w in widths)
    print(fmt(headers))
    print(sep)
    for row in rows:
        print(fmt(row))


def save_json(results: List[ScanResult], path: Optional[str]) -> None:
    data = [asdict(r) for r in results]
    if path:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    else:
        print(json.dumps(data, indent=2))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Async TCP port scanner for authorized/lab use only.")
    p.add_argument("--cidr", required=True, help="Target CIDR (private by default).")
    p.add_argument("--ports", required=True, help="Ports list, e.g., 22,80,443 or 1-1024.")
    p.add_argument("--concurrency", type=int, default=200, help="Max concurrent connections (default 200).")
    p.add_argument("--timeout", type=float, default=3.0, help="Per-connection timeout seconds (default 3.0).")
    p.add_argument("--allow-public", action="store_true", help="Allow non-private CIDR (authorized only).")
    p.add_argument("--no-banner", action="store_true", help="Disable banner grabbing.")
    p.add_argument("--json-out", help="Path to write JSON results; stdout if omitted.")
    p.add_argument("--quiet", action="store_true", help="Suppress table output (JSON only).")
    return p


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    parser = build_parser()
    args = parser.parse_args()

    print("⚠️  Authorized use only. Do not scan networks you do not own or lack permission to test.")
    try:
        ports = parse_ports(args.ports)
        hosts = list(iter_hosts(args.cidr, args.allow_public))
    except ValueError as exc:
        parser.error(str(exc))
        return

    results = asyncio.run(
        run_scan(
            hosts=hosts,
            ports=ports,
            timeout=args.timeout,
            concurrency=args.concurrency,
            grab_banner=not args.no_banner,
        )
    )

    if not args.quiet:
        print_table(results)
    save_json(results, args.json_out)


if __name__ == "__main__":
    main()
