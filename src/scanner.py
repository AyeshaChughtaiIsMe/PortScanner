"""
scanner.py
----------
Core port scanning engine.

Provides three scan techniques:
  1. tcp_connect_scan  - Full TCP handshake via socket (no root needed)
  2. syn_scan          - Half-open TCP scan via scapy (root/admin needed)
  3. udp_scan          - UDP probe via socket (unreliable, best-effort)

FOR AUTHORIZED TESTING ONLY.
"""

import socket
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# TCP Connect Scan (socket-based)
# ---------------------------------------------------------------------------
def tcp_connect_scan(host: str, port: int, timeout: float = 1.0) -> bool:
    """
    Perform a full TCP connect scan on a single port.

    Returns True if the port is open, False otherwise.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((host, port)) == 0
    except (socket.gaierror, OSError) as exc:
        logger.debug("TCP scan error on %s:%s - %s", host, port, exc)
        return False


# ---------------------------------------------------------------------------
# Concurrent TCP scan across a port range
# ---------------------------------------------------------------------------
def scan_port_range(
    host: str,
    start_port: int,
    end_port: int,
    timeout: float = 1.0,
    max_workers: int = 100,
) -> list[int]:
    """
    Scan a port range concurrently using ThreadPoolExecutor.

    Returns a sorted list of open ports.
    """
    open_ports: list[int] = []
    total = end_port - start_port + 1
    logger.info("Scanning %s ports %d-%d with %d workers",
                host, start_port, end_port, max_workers)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(tcp_connect_scan, host, port, timeout): port
            for port in range(start_port, end_port + 1)
        }
        completed = 0
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            completed += 1
            if completed % 100 == 0 or completed == total:
                logger.debug("Progress: %d/%d ports scanned", completed, total)
            try:
                if future.result():
                    open_ports.append(port)
            except Exception as exc:
                logger.debug("Worker exception on port %d: %s", port, exc)

    return sorted(open_ports)


# ---------------------------------------------------------------------------
# SYN Scan (scapy-based half-open scan)
# ---------------------------------------------------------------------------
def syn_scan(host: str, port: int, timeout: float = 1.0) -> str:
    """
    Perform a SYN (half-open) scan on a single port using scapy.

    Returns one of: "open", "closed", "filtered", "unknown".
    Requires root / administrator privileges.
    """
    try:
        from scapy.all import IP, TCP, sr1  # imported lazily to avoid cost
    except ImportError:
        logger.error("scapy is not installed. Run: pip install scapy")
        return "unknown"

    try:
        packet = IP(dst=host) / TCP(dport=port, flags="S")
        response = sr1(packet, timeout=timeout, verbose=0)

        if response is None:
            return "filtered"

        if response.haslayer(TCP):
            flags = response[TCP].flags
            if flags == 0x12:  # SYN-ACK
                # Send RST to close gracefully (avoid logging a full connection)
                sr1(IP(dst=host) / TCP(dport=port, flags="R"),
                    timeout=timeout, verbose=0)
                return "open"
            if flags == 0x14:  # RST-ACK
                return "closed"
        return "unknown"
    except PermissionError:
        logger.error("SYN scan requires root/admin privileges.")
        return "unknown"
    except Exception as exc:
        logger.debug("SYN scan error on %s:%s - %s", host, port, exc)
        return "unknown"


# ---------------------------------------------------------------------------
# UDP Scan (best-effort)
# ---------------------------------------------------------------------------
def udp_scan(host: str, port: int, timeout: float = 2.0) -> str:
    """
    Best-effort UDP scan.

    UDP is stateless, so absence of a response is ambiguous:
      - ICMP port-unreachable => "closed"
      - No response            => "open|filtered"
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(b"\x00", (host, port))
            try:
                sock.recvfrom(1024)
                return "open"
            except socket.timeout:
                return "open|filtered"
            except ConnectionRefusedError:
                return "closed"
    except OSError:
        return "unknown"