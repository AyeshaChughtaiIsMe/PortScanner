"""
ports.py
--------
Port specifications: parsing "-p" strings and the built-in common-port list.
"""

import argparse

# 100 TCP ports most often found open, most common first. The first 20
# follow Nmap's published frequency ranking; the rest are the remainder
# of its well-known top-100 set in numerical order.
TOP_PORTS = [
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139,
    143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
    7, 9, 13, 26, 37, 79, 81, 88, 106, 113,
    119, 144, 179, 199, 389, 427, 444, 465, 513, 514,
    515, 543, 544, 548, 554, 587, 631, 646, 873, 990,
    1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1755, 1900,
    2000, 2001, 2049, 2121, 2717, 3000, 3128, 3986, 4899, 5000,
    5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800,
    6000, 6001, 6646, 7070, 8000, 8008, 8009, 8081, 8443, 8888,
    9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157,
]


def top_ports(count: int) -> list[int]:
    """Return the `count` most common ports, sorted numerically."""
    if not 1 <= count <= len(TOP_PORTS):
        raise argparse.ArgumentTypeError(
            f"--top-ports must be between 1 and {len(TOP_PORTS)}")
    return sorted(TOP_PORTS[:count])


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
