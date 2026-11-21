"""
cli.py
------
Command-line interface.

Examples
--------
    portscan 127.0.0.1 -p 1-1024
    portscan 127.0.0.1 -p 22,80,443 --scan-type syn
    portscan scanme.nmap.org --top-ports 100 --output results.json
    portscan 192.168.1.0/24 -p 22,80,443 -o lan.csv

FOR AUTHORIZED TESTING ONLY. Do not scan hosts you do not own
or have explicit written permission to test.
"""

import argparse
import logging
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from . import discovery, output, scanner, targets
from .banner import get_service_name, identify_service
from .models import HostResult, PortResult
from .ports import parse_ports, top_ports
from .scanner import OPEN, RateLimiter, ScanError
from .targets import TargetError

BANNER_TIMEOUT = 2.0
DEFAULT_PORTS = "1-1024"
SCAN_LABELS = {"tcp": "TCP connect", "syn": "SYN", "udp": "UDP"}

BANNER_TEXT = r"""
 ____            _     ____
|  _ \ ___  _ __| |_  / ___|  ___ __ _ _ __  _ __   ___ _ __
| |_) / _ \| '__| __| \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
|  __/ (_) | |  | |_   ___) | (_| (_| | | | | | | |  __/ |
|_|   \___/|_|   \__| |____/ \___\__,_|_| |_|_| |_|\___|_|
                Authorized testing only. Be ethical.
"""

EXIT_OK, EXIT_SCAN_ERROR, EXIT_USAGE, EXIT_INTERRUPTED = 0, 1, 2, 130


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
def positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be 1 or more")
    return number


def positive_float(value: str) -> float:
    number = float(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return number


def non_negative_int(value: str) -> int:
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("must be 0 or more")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="portscan",
        description="Port Scanner - for authorized security testing only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    target = parser.add_argument_group("targets")
    target.add_argument(
        "targets", nargs="*", metavar="target",
        help="Hostname, IP address, CIDR block (192.168.1.0/24) or "
             "last-octet range (192.168.1.10-20). Several may be given.",
    )
    target.add_argument(
        "-iL", "--targets-file", metavar="FILE",
        help="Read targets from FILE, one per line",
    )
    target.add_argument(
        "-6", "--ipv6", action="store_true",
        help="Prefer IPv6 addresses when a hostname has both",
    )
    target.add_argument(
        "--skip-discovery", action="store_true",
        help="Scan every target without first checking that it is up "
             "(discovery only runs when there is more than one target)",
    )

    scan = parser.add_argument_group("scan")
    port_group = scan.add_mutually_exclusive_group()
    port_group.add_argument(
        "-p", "--ports",
        help="Ports to scan (e.g. '22,80,443' or '1-1024'). "
             f"Default: {DEFAULT_PORTS}",
    )
    port_group.add_argument(
        "--top-ports", type=positive_int, metavar="N",
        help="Scan the N most commonly open TCP ports (1-100)",
    )
    scan.add_argument(
        "-t", "--scan-type", choices=sorted(SCAN_LABELS), default="tcp",
        help="Scan technique. Default: tcp (syn requires root/admin)",
    )
    scan.add_argument(
        "--timeout", type=positive_float, default=1.0,
        help="Per-port timeout in seconds. Default: 1.0",
    )
    scan.add_argument(
        "--workers", type=positive_int, default=100,
        help="Concurrent worker threads. Default: 100",
    )
    scan.add_argument(
        "--retries", type=non_negative_int, default=0,
        help="Extra attempts for ports that give no answer. Default: 0",
    )
    scan.add_argument(
        "--rate", type=positive_float, metavar="PER_SECOND",
        help="Maximum probes per second (tcp/udp). Default: unlimited",
    )
    scan.add_argument(
        "--no-banner", action="store_true",
        help="Skip banner grabbing (faster)",
    )

    report = parser.add_argument_group("output")
    report.add_argument(
        "--show-all", action="store_true",
        help="List closed and filtered ports too, not only open ones",
    )
    report.add_argument(
        "-o", "--output",
        help="Write results to this path (e.g. results.json). The format "
             "follows the extension: .json, .csv or .xml",
    )
    report.add_argument(
        "--format", choices=output.FORMATS,
        help="Output file format, overriding the extension",
    )
    report.add_argument(
        "--no-progress", action="store_true",
        help="Do not show the live progress counter",
    )
    report.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable verbose (DEBUG) logging",
    )
    return parser


def select_ports(args) -> list[int]:
    """The ports to scan, from --top-ports, -p or the default range."""
    if args.top_ports:
        return top_ports(args.top_ports)
    return parse_ports(args.ports or DEFAULT_PORTS)


def resolve_targets(args) -> list[tuple[str, str]]:
    """
    Expand the target arguments and resolve each to an address, once.

    Returns (name, ip) pairs. Names that do not resolve are reported and
    left out; raises TargetError if nothing usable remains.
    """
    pairs = []
    for name in targets.expand_targets(args.targets, args.targets_file):
        try:
            pairs.append((name, targets.resolve(name, args.ipv6)))
        except TargetError as exc:
            print(f"[!] {exc}", file=sys.stderr)
    if not pairs:
        raise TargetError("No target could be resolved.")
    return pairs


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------
def make_progress(enabled: bool):
    """Return a progress(done, total) callback that redraws one stderr line."""
    if not enabled or not sys.stderr.isatty():
        return None
    last_draw = 0.0

    def progress(done: int, total: int) -> None:
        nonlocal last_draw
        now = time.monotonic()
        if done < total and now - last_draw < 0.1:
            return
        last_draw = now
        end = "\n" if done == total else ""
        print(f"\r    {done}/{total} ports probed", end=end,
              file=sys.stderr, flush=True)

    return progress


def scan_host(ip: str, ports: list[int], args, server_name: str | None = None,
              progress=None) -> list[PortResult]:
    """
    Scan one host with the chosen technique.

    Returns one result per probed port (every state), sorted by port, with
    service names filled in and banners grabbed for open TCP ports.
    """
    limiter = RateLimiter(args.rate) if args.rate else None
    protocol = "udp" if args.scan_type == "udp" else "tcp"

    if args.scan_type == "tcp":
        states = scanner.tcp_scan(
            ip, ports, timeout=args.timeout, max_workers=args.workers,
            retries=args.retries, rate_limiter=limiter, progress=progress)
    elif args.scan_type == "syn":
        states = scanner.syn_scan_ports(
            ip, ports, timeout=args.timeout, retries=args.retries,
            progress=progress)
    else:
        states = scanner.udp_scan_ports(
            ip, ports, timeout=args.timeout, max_workers=args.workers,
            retries=args.retries, rate_limiter=limiter, progress=progress)

    results = [
        PortResult(port, protocol, states[port],
                   get_service_name(port, protocol))
        for port in sorted(states)
    ]

    open_tcp = [r for r in results if r.state == OPEN and protocol == "tcp"]
    if open_tcp and not args.no_banner:
        def enrich(result: PortResult) -> None:
            info = identify_service(ip, result.port, "tcp",
                                    timeout=BANNER_TIMEOUT,
                                    server_name=server_name)
            result.service = info["service"]
            result.banner = info["banner"]

        workers = min(args.workers, len(open_tcp))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            list(pool.map(enrich, open_tcp))

    return results


def scan_all(pairs: list[tuple[str, str]], ports: list[int],
             args) -> list[HostResult]:
    """Run discovery (for several targets) and scan every live host."""
    if args.scan_type == "syn":
        scanner.check_syn_scan_ready()

    many = len(pairs) > 1
    up = None
    if many and not args.skip_discovery:
        print(f"[+] Checking which of {len(pairs)} hosts are up")
        up = discovery.discover_hosts(
            {ip for _name, ip in pairs},
            timeout=args.timeout, max_workers=args.workers)
        print(f"    {len(up)} up. Hosts that drop all traffic look down; "
              "use --skip-discovery to scan them anyway.")

    hosts = []
    for name, ip in pairs:
        host = HostResult(name, ip)
        hosts.append(host)
        if up is not None and ip not in up:
            host.state = "down"
            continue
        if not many:
            print(f"[+] {SCAN_LABELS[args.scan_type]} scan against "
                  f"{display_name(host)}, {len(ports)} port(s)")
        host.ports = scan_host(
            ip, ports, args, server_name=name,
            progress=make_progress(not args.no_progress and not many))
        if many:
            print(f"\n[+] {display_name(host)}: "
                  f"{summarise_states(host.summary())}")
            print_table(listed_ports(host, args.show_all), empty_text=None)
    return hosts


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def display_name(host: HostResult) -> str:
    if host.target == host.ip:
        return host.ip
    return f"{host.target} ({host.ip})"


def summarise_states(summary: dict) -> str:
    """'2 open, 97 closed, 1 filtered' - open always first."""
    parts = [f"{summary.get(OPEN, 0)} open"]
    parts += [f"{count} {state}" for state, count in sorted(summary.items())
              if state != OPEN]
    return ", ".join(parts)


def listed_ports(host: HostResult, show_all: bool) -> list[PortResult]:
    return [p for p in host.ports if show_all or p.state == OPEN]


def print_table(results: list[PortResult],
                empty_text: str | None = "    No open ports found in the "
                                          "specified range.") -> None:
    if not results:
        if empty_text:
            print(empty_text)
        return
    print(f"{'PORT':<8}{'PROTO':<7}{'STATE':<15}{'SERVICE':<15}BANNER")
    print("-" * 80)
    for r in results:
        print(f"{r.port:<8}{r.protocol:<7}{r.state:<15}"
              f"{r.service:<15}{r.banner[:60]}")


def print_summary(hosts: list[HostResult], elapsed: float,
                  show_all: bool) -> None:
    scanned = [h for h in hosts if h.state == "up"]
    open_count = sum(h.summary().get(OPEN, 0) for h in scanned)

    if len(hosts) > 1:
        print(f"\n[+] Scan complete in {elapsed:.2f}s — "
              f"{open_count} open port(s) found on {len(scanned)} host(s) "
              f"({len(hosts) - len(scanned)} down)")
    else:
        host = hosts[0]
        print(f"\n[+] Scan complete in {elapsed:.2f}s — "
              f"{open_count} open port(s) found "
              f"({summarise_states(host.summary())})\n")
        print_table(listed_ports(host, show_all))

    if not show_all and any(len(listed_ports(h, False)) < len(h.ports)
                            for h in scanned):
        print("\n    Use --show-all to list closed and filtered ports.")


def build_report(hosts: list[HostResult], args, started_at: datetime,
                 elapsed: float) -> dict:
    only = None if args.show_all else {OPEN}
    return {
        "scan_type": args.scan_type,
        "started_at": started_at.isoformat(),
        "finished_at": datetime.now().isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "hosts": [host.to_dict(only) for host in hosts],
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    print(BANNER_TEXT)

    try:
        ports = select_ports(args)
        pairs = resolve_targets(args)
    except (argparse.ArgumentTypeError, TargetError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return EXIT_USAGE

    started_at = datetime.now()
    start = time.perf_counter()
    try:
        hosts = scan_all(pairs, ports, args)
    except ScanError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return EXIT_SCAN_ERROR
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        return EXIT_INTERRUPTED
    elapsed = time.perf_counter() - start

    print_summary(hosts, elapsed, args.show_all)

    if args.output:
        report = build_report(hosts, args, started_at, elapsed)
        out_path = output.write_report(report, args.output, args.format)
        print(f"\n[+] Results written to {out_path}")

    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
