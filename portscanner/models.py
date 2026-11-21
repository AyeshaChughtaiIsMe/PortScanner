"""
models.py
---------
The shapes scan results travel in, from the engine to the report writers.
"""

from collections import Counter
from dataclasses import asdict, dataclass, field


@dataclass
class PortResult:
    """What was learned about one port."""
    port: int
    protocol: str            # "tcp" or "udp"
    state: str               # see scanner.py for the possible states
    service: str = "unknown"
    banner: str = ""


@dataclass
class HostResult:
    """One target and the ports probed on it."""
    target: str              # what the user asked for
    ip: str                  # the address actually scanned
    state: str = "up"        # "up", or "down" if discovery skipped it
    ports: list[PortResult] = field(default_factory=list)

    def summary(self) -> dict[str, int]:
        """Number of ports in each state, e.g. {"open": 2, "closed": 98}."""
        return dict(Counter(result.state for result in self.ports))

    def to_dict(self, only_states: set[str] | None = None) -> dict:
        """
        Report form. The summary always counts every probed port;
        only_states limits which ports are listed individually.
        """
        listed = [asdict(p) for p in self.ports
                  if only_states is None or p.state in only_states]
        return {"target": self.target, "ip": self.ip, "state": self.state,
                "summary": self.summary(), "ports": listed}
