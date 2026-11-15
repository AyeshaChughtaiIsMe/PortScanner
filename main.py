"""
main.py
-------
Port Scanner CLI.

Examples
--------
    python main.py 127.0.0.1 -p 1-1024
    python main.py 127.0.0.1 -p 22,80,443 --scan-type syn
    python main.py scanme.nmap.org -p 1-1000 --workers 200 --output results.json

FOR AUTHORIZED TESTING ONLY. Do not scan hosts you do not own
or have explicit written permission to test.
"""

import argparse
import json
import logging
import socket
import sys
import time
from datetime import datetime
from pathlib import Path

from src.scanner import scan_port_range, syn_scan, udp_scan
from src.banner import identify_service

BANNER_TEXT = r"""
 ____            _     ____
|  _ \ ___  _ __| |_  / ___|  ___ __ _ _ __  _ __   ___ _ __
| |_) / _ \| '__| __| \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
|  __/ (_) | |  | |_   ___) | (_| (_| | | | | | | |  __/ |
|_|   \___/|_|   \__| |____/ \___\__,_|_| |_|_| |_|\___|_|
                Authorized testing only. Be ethical.
"""


def validate_host(host: str) -> bool:
    """
    Return True if the host resolves to an IP, otherwise print a clear
    error and return False. Prevents the scanner from silently treating
    an invalid hostname as 'all ports closed'.
    """
    try:
        socket.gethostbyname(host)
        return True
    except socket.gaierror:
        print(f"[!] Could not resolve hostname: {host}", file=sys.stderr)
        return False


def parse_ports(port_str: str) -> list[int]:
    """
    Parse a port specification like "22,80,443,1000-2000" into a sorted
    list of unique integers.
    """
    ports: set[int] = set()
    for part in port_str.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                start_i, end_i = int(start), int(end)
            except ValueError:
                raise argparse.ArgumentTypeError(f"Invalid port range: {part}")
            if not (0 < start_i <= end_i <= 65535):
                raise argparse.ArgumentTypeError(f"Port range out of bounds: {part}")
            ports.update(range(start_i, end_i + 1))
        else:
            try:
                p = int(part)
            except ValueError:
                raise argparse.ArgumentTypeError(f"Invalid port: {part}")
            if not (0 < p <= 65535):
                raise argparse.ArgumentTypeError(f"Port out of bounds: {part}")
            ports.add(p)
    if not ports:
        raise argparse.ArgumentTypeError("No valid ports specified.")
    return sorted(ports)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Port Scanner - for authorized security testing only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument(
        "-p", "--ports", default="1-1024",
        help="Ports to scan (e.g. '22,80,443' or '1-1024'). Default: 1-1024",
    )
    parser.add_argument(
        "-t", "--scan-type", choices=["tcp", "syn", "udp"], default="tcp",
        help="Scan technique. Default: tcp (syn requires root/admin)",
    )
    parser.add_argument(
        "--timeout", type=float, default=1.0,
        help="Per-port timeout in seconds. Default: 1.0",
    )
    parser.add_argument(
        "--workers", type=int, default=100,
        help="Concurrent worker threads. Default: 100",
    )
    parser.add_argument(
        "-o", "--output",
        help="Write JSON results to this path (e.g. results.json)",
    )
    parser.add_argument(
        "--no-banner", action="store_true",
        help="Skip banner grabbing (faster)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable verbose (DEBUG) logging",
    )
    return parser


def run_scan(host: str, ports: list[int], args) -> list[dict]:
    """
    Execute the scan for the chosen technique and enrich results.
    """
    results: list[dict] = []

    if args.scan_type == "tcp":
        print(f"[+] TCP connect scan against {host} ({len(ports)} ports)")
        open_ports = scan_port_range(
            host, ports[0], ports[-1],  # includes gaps; fine for concurrency
            timeout=args.timeout, max_workers=args.workers,
        )
        # Filter to only the requested ports if the range had gaps
        requested = set(ports)
        open_ports = [p for p in open_ports if p in requested]

        for port in open_ports:
            entry = {"port": port, "protocol": "tcp", "state": "open",
                     "service": "unknown", "banner": ""}
            if not args.no_banner:
                info = identify_service(host, port, "tcp")
                entry.update({"service": info["service"],
                              "banner": info["banner"]})
            else:
                from src.banner import get_service_name
                entry["service"] = get_service_name(port, "tcp")
            results.append(entry)

    elif args.scan_type == "syn":
        print(f"[+] SYN scan against {host} ({len(ports)} ports) "
              f"[requires root/admin]")
        for port in ports:
            state = syn_scan(host, port, timeout=args.timeout)
            if state == "open":
                from src.banner import get_service_name
                results.append({
                    "port": port, "protocol": "tcp", "state": state,
                    "service": get_service_name(port, "tcp"), "banner": "",
                })

    elif args.scan_type == "udp":
        print(f"[+] UDP scan against {host} ({len(ports)} ports)")
        for port in ports:
            state = udp_scan(host, port, timeout=args.timeout)
            results.append({
                "port": port, "protocol": "udp", "state": state,
                "service": "unknown", "banner": "",
            })

    return results


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    print(BANNER_TEXT)

    try:
        ports = parse_ports(args.ports)
    except argparse.ArgumentTypeError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    if not validate_host(args.target):
        return 2

    start = time.perf_counter()
    try:
        results = run_scan(args.target, ports, args)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        return 130
    elapsed = time.perf_counter() - start

    print(f"\n[+] Scan complete in {elapsed:.2f}s — "
          f"{len(results)} open port(s) found\n")

    # Pretty print
    if results:
        print(f"{'PORT':<8}{'PROTO':<7}{'STATE':<14}{'SERVICE':<15}BANNER")
        print("-" * 80)
        for r in results:
            print(f"{r['port']:<8}{r['protocol']:<7}{r['state']:<14}"
                  f"{r['service']:<15}{r['banner'][:40]}")
    else:
        print("    No open ports found in the specified range.")

    # Optional JSON output
    if args.output:
        payload = {
            "target": args.target,
            "scan_type": args.scan_type,
            "started_at": datetime.now().isoformat(),
            "elapsed_seconds": round(elapsed, 2),
            "results": results,
        }
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(payload, indent=2))
        print(f"\n[+] Results written to {out_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())