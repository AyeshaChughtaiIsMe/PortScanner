"""
discovery.py
------------
Host discovery: find out which targets are alive before scanning them,
so a /24 does not spend its time timing out on empty addresses.

A host counts as up if any of a few common TCP ports answers at all -
an accepted connection or a refusal both prove something is there. This
needs no privileges. A host that silently drops all of those ports looks
down; use --skip-discovery to scan it anyway.
"""

from concurrent.futures import ThreadPoolExecutor

from .scanner import CLOSED, OPEN, tcp_probe

DISCOVERY_PORTS = (80, 443, 22, 445)


def is_host_up(ip: str, timeout: float = 1.0,
               ports=DISCOVERY_PORTS) -> bool:
    """True if the host answers on any discovery port."""
    with ThreadPoolExecutor(max_workers=len(ports)) as pool:
        states = pool.map(lambda port: tcp_probe(ip, port, timeout), ports)
        return any(state in (OPEN, CLOSED) for state in states)


def discover_hosts(ips, timeout: float = 1.0, max_workers: int = 100,
                   ports=DISCOVERY_PORTS) -> set[str]:
    """Return the subset of ips that are up."""
    ips = list(ips)
    if not ips:
        return set()
    workers = max(1, min(max_workers, len(ips)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        flags = pool.map(lambda ip: is_host_up(ip, timeout, ports), ips)
        return {ip for ip, up in zip(ips, flags) if up}
