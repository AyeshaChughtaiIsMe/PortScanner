"""
banner.py
---------
Service identification for open ports.

Two techniques:
  1. Static IANA service lookup (socket.getservbyport)
  2. Active banner grabbing (connect and read the greeting)
"""

import socket
import logging

logger = logging.getLogger(__name__)


def get_service_name(port: int, protocol: str = "tcp") -> str:
    """
    Look up the IANA-registered service for a port.
    Returns "unknown" if the port has no standard assignment.
    """
    try:
        return socket.getservbyport(port, protocol)
    except OSError:
        return "unknown"


def grab_banner(host: str, port: int, timeout: float = 2.0) -> str:
    """
    Attempt to read the service banner from an open port.

    Sends a generic probe (\r\n) to trigger responses from protocols
    that require input before revealing the banner. Best-effort.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))
            try:
                sock.send(b"\r\n")
            except OSError:
                pass  # Some services don't accept input; still try to read
            banner = sock.recv(1024)
            # Decode leniently; strip control chars
            text = banner.decode("utf-8", errors="ignore").strip()
            return " ".join(text.split())  # normalize whitespace
    except Exception as exc:
        logger.debug("Banner grab failed on %s:%d - %s", host, port, exc)
        return ""


def identify_service(host: str, port: int, protocol: str = "tcp") -> dict:
    """
    Combine static lookup and banner grabbing into a single report entry.
    """
    name = get_service_name(port, protocol)
    banner = grab_banner(host, port) if protocol == "tcp" else ""
    return {
        "port": port,
        "protocol": protocol,
        "service": name,
        "banner": banner,
    }