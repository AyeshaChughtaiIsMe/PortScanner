"""
scanner.py
----------
Core port scanning engine.

Three scan techniques, each reporting a state per port:
  1. TCP connect - full handshake via socket (no privileges needed)
  2. SYN         - half-open scan via scapy (root/admin needed)
  3. UDP         - protocol-aware probes via socket (best-effort)

Port states
-----------
  open            the port answered
  closed          the host actively refused (TCP RST / ICMP port unreachable)
  filtered        no answer at all - usually a firewall dropping packets
  open|filtered   UDP only: silence means either
  unknown         the probe itself failed

FOR AUTHORIZED TESTING ONLY.
"""

import errno
import logging
import os
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

OPEN = "open"
CLOSED = "closed"
FILTERED = "filtered"
OPEN_FILTERED = "open|filtered"
UNKNOWN = "unknown"

_REFUSED_CODES = {errno.ECONNREFUSED, getattr(errno, "WSAECONNREFUSED", -1)}
# Failures on this machine (e.g. no IPv6 here) say nothing about the target.
_LOCAL_ERROR_CODES = {errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL}


class ScanError(Exception):
    """A scan could not be carried out at all (not a per-port result)."""


# ---------------------------------------------------------------------------
# Rate limiting and concurrency helpers
# ---------------------------------------------------------------------------
class RateLimiter:
    """Thread-safe limiter: at most `rate` calls to wait() per second."""

    def __init__(self, rate: float):
        if rate <= 0:
            raise ValueError("rate must be positive")
        self._interval = 1.0 / rate
        self._lock = threading.Lock()
        self._next_slot = time.monotonic()

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            slot = max(now, self._next_slot)
            self._next_slot = slot + self._interval
        delay = slot - now
        if delay > 0:
            time.sleep(delay)


def _run_concurrent(probe, ports, max_workers, rate_limiter=None,
                    progress=None) -> dict[int, str]:
    """
    Run probe(port) -> state for every port on a thread pool.

    progress, if given, is called as progress(done, total) after each port.
    """
    ports = sorted(set(ports))
    results: dict[int, str] = {}
    total = len(ports)
    if total == 0:
        return results

    def task(port: int) -> str:
        if rate_limiter is not None:
            rate_limiter.wait()
        return probe(port)

    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, total))) as pool:
        futures = {pool.submit(task, port): port for port in ports}
        try:
            for done, future in enumerate(as_completed(futures), start=1):
                port = futures[future]
                try:
                    results[port] = future.result()
                except Exception as exc:
                    logger.debug("Worker exception on port %d: %s", port, exc)
                    results[port] = UNKNOWN
                if progress is not None:
                    progress(done, total)
        except KeyboardInterrupt:
            pool.shutdown(wait=False, cancel_futures=True)
            raise
    return results


def _family_of(host: str) -> int:
    """AF_INET6 for an IPv6 literal, otherwise AF_INET."""
    return socket.AF_INET6 if ":" in host else socket.AF_INET


# ---------------------------------------------------------------------------
# TCP connect scan
# ---------------------------------------------------------------------------
def tcp_probe(host: str, port: int, timeout: float = 1.0,
              retries: int = 0) -> str:
    """
    Full TCP handshake against one port.

    Returns "open", "closed" (connection refused), "filtered" (no answer
    within the timeout, or host/network unreachable) or "unknown".
    Only "filtered" is retried: a refusal or an accept is a definite answer.
    """
    state = UNKNOWN
    for _attempt in range(retries + 1):
        try:
            with socket.socket(_family_of(host), socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                code = sock.connect_ex((host, port))
        except socket.timeout:
            state = FILTERED
            continue
        except socket.gaierror as exc:
            logger.debug("TCP probe: cannot resolve %s - %s", host, exc)
            return UNKNOWN
        except OSError as exc:
            logger.debug("TCP probe error on %s:%s - %s", host, port, exc)
            if exc.errno in _LOCAL_ERROR_CODES:
                return UNKNOWN
            state = FILTERED
            continue
        if code == 0:
            return OPEN
        if code in _REFUSED_CODES:
            return CLOSED
        if code in _LOCAL_ERROR_CODES:
            return UNKNOWN
        state = FILTERED  # timed out or unreachable
    return state


def tcp_connect_scan(host: str, port: int, timeout: float = 1.0) -> bool:
    """Return True if the port is open, False otherwise."""
    return tcp_probe(host, port, timeout) == OPEN


def tcp_scan(host: str, ports, timeout: float = 1.0, max_workers: int = 100,
             retries: int = 0, rate_limiter: RateLimiter | None = None,
             progress=None) -> dict[int, str]:
    """Concurrent TCP connect scan. Returns {port: state}."""
    return _run_concurrent(
        lambda port: tcp_probe(host, port, timeout, retries),
        ports, max_workers, rate_limiter, progress,
    )


def scan_ports(host: str, ports, timeout: float = 1.0,
               max_workers: int = 100) -> list[int]:
    """Scan exactly the given ports; return a sorted list of open ones."""
    states = tcp_scan(host, ports, timeout=timeout, max_workers=max_workers)
    return sorted(port for port, state in states.items() if state == OPEN)


def scan_port_range(host: str, start_port: int, end_port: int,
                    timeout: float = 1.0, max_workers: int = 100) -> list[int]:
    """Scan every port from start_port to end_port inclusive."""
    return scan_ports(host, range(start_port, end_port + 1),
                      timeout=timeout, max_workers=max_workers)


# ---------------------------------------------------------------------------
# SYN scan (scapy-based half-open scan)
# ---------------------------------------------------------------------------
def has_raw_socket_privileges() -> bool:
    """True if this process may send raw packets (root / Administrator)."""
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    try:  # Windows
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def check_syn_scan_ready() -> None:
    """Raise ScanError if a SYN scan cannot work on this machine."""
    try:
        import scapy.all  # noqa: F401
    except ImportError:
        raise ScanError("SYN scan needs scapy. Run: pip install scapy")
    if not has_raw_socket_privileges():
        raise ScanError("SYN scan requires root/administrator privileges.")


def _classify_syn_reply(reply, tcp_layer) -> str:
    """Map a reply packet to a port state."""
    if reply.haslayer(tcp_layer):
        flags = int(reply[tcp_layer].flags)
        if flags & 0x12 == 0x12:  # SYN-ACK
            return OPEN
        if flags & 0x04:          # RST
            return CLOSED
        return UNKNOWN
    # Anything else that matched our probe is an ICMP error
    # (administratively prohibited, host unreachable, ...).
    return FILTERED


def syn_scan_ports(host: str, ports, timeout: float = 1.0, retries: int = 0,
                   progress=None, batch_size: int = 256) -> dict[int, str]:
    """
    Half-open scan of many ports. Returns {port: state}.

    Probes are sent in batches and the replies collected together, so the
    cost is roughly one timeout per batch rather than one per port. No RST
    is sent by hand: the local kernel never opened these connections, so it
    answers each SYN-ACK with a RST by itself.
    """
    check_syn_scan_ready()
    from scapy.all import IP, IPv6, TCP, RandShort, conf, sr

    ports = sorted(set(ports))
    results = {port: FILTERED for port in ports}  # silence => filtered
    is_v6 = ":" in host
    network = IPv6(dst=host) if is_v6 else IP(dst=host)

    l3socket = conf.L3socket
    if not is_v6 and host.startswith("127.") and os.name == "posix":
        # Loopback has no link layer for scapy's default socket to use.
        try:
            from scapy.all import L3RawSocket
            l3socket = L3RawSocket
        except ImportError:
            pass

    done = 0
    for start in range(0, len(ports), batch_size):
        batch = ports[start:start + batch_size]
        probe = network / TCP(sport=RandShort(), dport=batch, flags="S")
        previous, conf.L3socket = conf.L3socket, l3socket
        try:
            answered, _unanswered = sr(probe, timeout=timeout, retry=retries,
                                       verbose=0)
        except PermissionError:
            raise ScanError("SYN scan requires root/administrator privileges.")
        finally:
            conf.L3socket = previous
        for sent, reply in answered:
            results[sent[TCP].dport] = _classify_syn_reply(reply, TCP)
        done += len(batch)
        if progress is not None:
            progress(done, len(ports))
    return results


def syn_scan(host: str, port: int, timeout: float = 1.0) -> str:
    """SYN-scan a single port. Returns its state."""
    return syn_scan_ports(host, [port], timeout=timeout)[port]


# ---------------------------------------------------------------------------
# UDP scan (best-effort)
# ---------------------------------------------------------------------------
# A UDP service only answers a datagram it understands, so well-known
# ports get a real request for their protocol.
_DNS_QUERY = (b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"  # header
              b"\x00\x00\x02\x00\x01")                              # . NS IN
_NTP_REQUEST = b"\x1b" + b"\x00" * 47                               # v3 client
_SNMP_GET = bytes.fromhex(                                          # v1 public
    "302902010004067075626c6963a01c020413371337020100020100"
    "300e300c06082b060102010101000500")                             # sysDescr.0
_SSDP_SEARCH = (b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
                b'MAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n')
_NBSTAT_QUERY = (b"\x13\x37\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                 b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01")

UDP_PAYLOADS = {
    53: _DNS_QUERY,
    123: _NTP_REQUEST,
    137: _NBSTAT_QUERY,
    161: _SNMP_GET,
    1900: _SSDP_SEARCH,
    5353: _DNS_QUERY,
}
DEFAULT_UDP_PAYLOAD = b"\x00"


def udp_scan(host: str, port: int, timeout: float = 2.0,
             retries: int = 0) -> str:
    """
    Probe one UDP port.

      - any reply                      => "open"
      - ICMP port unreachable          => "closed"
      - silence after all attempts     => "open|filtered"

    The socket is connected so the OS reports ICMP errors back to us.
    """
    payload = UDP_PAYLOADS.get(port, DEFAULT_UDP_PAYLOAD)
    try:
        with socket.socket(_family_of(host), socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))
            for _attempt in range(retries + 1):
                try:
                    sock.send(payload)
                    sock.recv(1024)
                    return OPEN
                except socket.timeout:
                    continue
                except (ConnectionRefusedError, ConnectionResetError):
                    return CLOSED
            return OPEN_FILTERED
    except OSError as exc:
        logger.debug("UDP probe error on %s:%s - %s", host, port, exc)
        return UNKNOWN


def udp_scan_ports(host: str, ports, timeout: float = 2.0,
                   max_workers: int = 100, retries: int = 0,
                   rate_limiter: RateLimiter | None = None,
                   progress=None) -> dict[int, str]:
    """Concurrent UDP scan. Returns {port: state}."""
    return _run_concurrent(
        lambda port: udp_scan(host, port, timeout, retries),
        ports, max_workers, rate_limiter, progress,
    )
