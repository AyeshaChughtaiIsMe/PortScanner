"""
banner.py
---------
Service identification for open ports.

Techniques, in order:
  1. Static IANA service lookup (socket.getservbyport)
  2. Passive banner read - services such as SSH, FTP and SMTP speak first
  3. HTTP probe - web servers stay silent until asked, so send a HEAD request
  4. TLS probe - complete a TLS handshake, then ask the same HTTP question
"""

import ipaddress
import logging
import socket
import ssl

logger = logging.getLogger(__name__)

# Ports that are normally TLS from the first byte.
TLS_PORTS = {443, 465, 636, 853, 993, 995, 8443, 9443}

GREETING_WAIT = 1.0   # seconds to wait for a service that speaks first
MAX_BANNER_LEN = 200


# Used when the operating system has no services database (minimal
# containers often lack /etc/services).
FALLBACK_SERVICES = {
    ("tcp", 21): "ftp", ("tcp", 22): "ssh", ("tcp", 23): "telnet",
    ("tcp", 25): "smtp", ("tcp", 53): "domain", ("tcp", 80): "http",
    ("tcp", 110): "pop3", ("tcp", 111): "sunrpc", ("tcp", 135): "epmap",
    ("tcp", 139): "netbios-ssn", ("tcp", 143): "imap", ("tcp", 389): "ldap",
    ("tcp", 443): "https", ("tcp", 445): "microsoft-ds",
    ("tcp", 465): "smtps", ("tcp", 587): "submission", ("tcp", 993): "imaps",
    ("tcp", 995): "pop3s", ("tcp", 1433): "ms-sql-s", ("tcp", 3306): "mysql",
    ("tcp", 3389): "ms-wbt-server", ("tcp", 5432): "postgresql",
    ("tcp", 5900): "vnc", ("tcp", 6379): "redis", ("tcp", 8080): "http-alt",
    ("tcp", 8443): "https-alt",
    ("udp", 53): "domain", ("udp", 67): "bootps", ("udp", 68): "bootpc",
    ("udp", 69): "tftp", ("udp", 123): "ntp", ("udp", 137): "netbios-ns",
    ("udp", 161): "snmp", ("udp", 500): "isakmp", ("udp", 514): "syslog",
    ("udp", 1900): "ssdp", ("udp", 5353): "mdns",
}


def get_service_name(port: int, protocol: str = "tcp") -> str:
    """
    Name the service usually found on a port: the operating system's
    services database first, then a small built-in table.
    Returns "unknown" if neither knows the port.
    """
    try:
        return socket.getservbyport(port, protocol)
    except OSError:
        return FALLBACK_SERVICES.get((protocol, port), "unknown")


def _recv(sock) -> bytes:
    try:
        return sock.recv(2048)
    except (socket.timeout, ssl.SSLError, OSError):
        return b""


def _http_head(server_name: str) -> bytes:
    return (f"HEAD / HTTP/1.0\r\nHost: {server_name}\r\n"
            "User-Agent: portscanner\r\nAccept: */*\r\n\r\n").encode("ascii", "ignore")


def summarise_banner(data: bytes) -> str:
    """
    Turn raw bytes from a service into one readable line.

    HTTP responses are reduced to the status line plus the Server header;
    anything else has its whitespace normalised.
    """
    text = data.decode("utf-8", errors="ignore").strip()
    if text.startswith("HTTP/"):
        lines = text.splitlines()
        parts = [lines[0].strip()]
        for line in lines[1:]:
            if not line.strip():
                break
            if line.lower().startswith("server:"):
                parts.append("Server: " + line.split(":", 1)[1].strip())
                break
        return " | ".join(parts)[:MAX_BANNER_LEN]
    printable = "".join(ch if ch.isprintable() else " " for ch in text)
    return " ".join(printable.split())[:MAX_BANNER_LEN]


def _is_ip_literal(name: str) -> bool:
    try:
        ipaddress.ip_address(name)
        return True
    except ValueError:
        return False


def _plain_banner(host, port, timeout, server_name) -> str:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(min(timeout, GREETING_WAIT))
        data = _recv(sock)
        if not data:
            sock.settimeout(timeout)
            sock.sendall(_http_head(server_name))
            data = _recv(sock)
    return summarise_banner(data)


def _tls_banner(host, port, timeout, server_name) -> str:
    # Identification only: nothing sensitive is sent, so the certificate
    # is deliberately not verified (self-signed services must still be
    # identifiable).
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    sni = None if _is_ip_literal(server_name) else server_name
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=sni) as tls:
            version = tls.version() or "TLS"
            tls.settimeout(min(timeout, GREETING_WAIT))
            data = _recv(tls)
            if not data:
                tls.settimeout(timeout)
                try:
                    tls.sendall(_http_head(server_name))
                    data = _recv(tls)
                except OSError:
                    data = b""
    detail = summarise_banner(data)
    return f"{version} | {detail}" if detail else version


def grab_banner(host: str, port: int, timeout: float = 2.0,
                server_name: str | None = None) -> str:
    """
    Identify what is listening on an open TCP port. Best-effort: returns
    "" if the service gives nothing away.

    server_name is the hostname the user asked for (used for the HTTP Host
    header and TLS SNI); it defaults to host.
    """
    server_name = server_name or host
    probes = [_plain_banner, _tls_banner]
    if port in TLS_PORTS:
        probes.reverse()
    for probe in probes:
        try:
            banner = probe(host, port, timeout, server_name)
        except Exception as exc:
            logger.debug("%s failed on %s:%d - %s",
                         probe.__name__, host, port, exc)
            continue
        if banner:
            return banner
    return ""


def refine_service(name: str, banner: str) -> str:
    """Use the banner to name a service the port number did not identify."""
    if name != "unknown" or not banner:
        return name
    lowered = banner.lower()
    if lowered.startswith("ssh-"):
        return "ssh"
    if lowered.startswith("tls") and "http/" in lowered:
        return "https"
    if lowered.startswith("tls"):
        return "tls"
    if lowered.startswith("http/"):
        return "http"
    if lowered.startswith("220") and "ftp" in lowered:
        return "ftp"
    if lowered.startswith("220") and "smtp" in lowered:
        return "smtp"
    return name


def identify_service(host: str, port: int, protocol: str = "tcp",
                     timeout: float = 2.0,
                     server_name: str | None = None) -> dict:
    """
    Combine static lookup and banner grabbing into a single report entry.
    """
    name = get_service_name(port, protocol)
    banner = ""
    if protocol == "tcp":
        banner = grab_banner(host, port, timeout, server_name)
    return {
        "port": port,
        "protocol": protocol,
        "service": refine_service(name, banner),
        "banner": banner,
    }
