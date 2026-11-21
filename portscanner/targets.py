"""
targets.py
----------
Turning what the user typed into a list of hosts to scan.

Accepted target forms:
  - hostname              scanme.nmap.org
  - IPv4 / IPv6 address   192.168.1.10, ::1
  - CIDR block            192.168.1.0/24, fd00::/120
  - last-octet range      192.168.1.10-20
  - a file with one of the above per line (blank lines and # comments ok)
"""

import ipaddress
import re
import socket
from pathlib import Path

# Refuse to expand anything bigger than a /16 in one run: almost always
# a typo (10.0.0.0/8), and far outside what this tool is built for.
MAX_TARGETS = 65536

_OCTET_RANGE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})-(\d{1,3})$")


class TargetError(ValueError):
    """The target specification cannot be used."""


def expand_spec(spec: str) -> list[str]:
    """Expand one target specification into individual hosts."""
    spec = spec.strip()
    if not spec:
        return []

    if "/" in spec:
        try:
            network = ipaddress.ip_network(spec, strict=False)
        except ValueError:
            raise TargetError(f"Invalid network: {spec}")
        if network.num_addresses > MAX_TARGETS:
            raise TargetError(
                f"{spec} contains {network.num_addresses} addresses; "
                f"the limit is {MAX_TARGETS} per run")
        # hosts() leaves out the network and broadcast addresses.
        return [str(ip) for ip in network.hosts()] or [str(network.network_address)]

    match = _OCTET_RANGE.match(spec)
    if match:
        prefix, first, last = match.group(1), int(match.group(2)), int(match.group(3))
        try:
            ipaddress.ip_address(f"{prefix}.{first}")
            ipaddress.ip_address(f"{prefix}.{last}")
        except ValueError:
            raise TargetError(f"Invalid address range: {spec}")
        if first > last:
            raise TargetError(f"Invalid address range: {spec}")
        return [f"{prefix}.{octet}" for octet in range(first, last + 1)]

    return [spec]


def read_targets_file(path: str) -> list[str]:
    """Read target specifications from a file, one per line."""
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise TargetError(f"Cannot read targets file {path}: {exc.strerror}")
    specs = []
    for line in lines:
        line = line.split("#", 1)[0].strip()
        if line:
            specs.append(line)
    return specs


def expand_targets(specs, targets_file: str | None = None) -> list[str]:
    """
    Expand every specification (and the optional file) into a list of
    hosts, keeping first-seen order and dropping duplicates.
    """
    all_specs = list(specs)
    if targets_file:
        all_specs += read_targets_file(targets_file)

    hosts: dict[str, None] = {}
    for spec in all_specs:
        for host in expand_spec(spec):
            hosts.setdefault(host)
            if len(hosts) > MAX_TARGETS:
                raise TargetError(
                    f"Too many targets; the limit is {MAX_TARGETS} per run")
    if not hosts:
        raise TargetError("No targets specified.")
    return list(hosts)


def resolve(host: str, prefer_ipv6: bool = False) -> str:
    """
    Resolve a hostname or address literal to one IP address, once.

    IPv4 is preferred unless prefer_ipv6 is set; the other family is used
    if the preferred one has no address. Raises TargetError if the name
    does not resolve.
    """
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        raise TargetError(f"Could not resolve hostname: {host}")
    wanted = socket.AF_INET6 if prefer_ipv6 else socket.AF_INET
    addresses = {socket.AF_INET: [], socket.AF_INET6: []}
    for family, _type, _proto, _canon, sockaddr in infos:
        if family in addresses:
            addresses[family].append(sockaddr[0])
    for family in (wanted, *[f for f in addresses if f != wanted]):
        if addresses[family]:
            return addresses[family][0]
    raise TargetError(f"Could not resolve hostname: {host}")
