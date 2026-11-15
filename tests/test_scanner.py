"""
Unit tests for src/scanner.py

Run with: pytest -v
"""

import socket
import pytest

from src.scanner import tcp_connect_scan, scan_port_range
from src.banner import get_service_name


# ---------------------------------------------------------------------------
# Real-socket tests (fast, localhost only)
# ---------------------------------------------------------------------------
def test_scan_localhost_open_port():
    """A listener we open ourselves must be detected as open."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    try:
        assert tcp_connect_scan("127.0.0.1", port) is True
    finally:
        listener.close()


def test_scan_closed_port():
    """Port 1 on localhost is essentially always closed."""
    assert tcp_connect_scan("127.0.0.1", 1) is False


def test_scan_port_range_returns_only_open():
    """scan_port_range should return a sorted list of open ports only."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    try:
        open_ports = scan_port_range(
            "127.0.0.1", port, port, timeout=0.5, max_workers=1
        )
        assert open_ports == [port]
    finally:
        listener.close()


# ---------------------------------------------------------------------------
# Service lookup tests
# ---------------------------------------------------------------------------
def test_service_lookup_http():
    assert get_service_name(80) == "http"


def test_service_lookup_ssh():
    assert get_service_name(22) == "ssh"


def test_service_lookup_unknown_port():
    assert get_service_name(54321) == "unknown"


# ---------------------------------------------------------------------------
# Mock-based tests - no real network traffic
# ---------------------------------------------------------------------------
def test_open_port_mocked():
    """connect_ex returning 0 => open."""
    from unittest.mock import patch
    with patch("socket.socket") as mock_sock:
        instance = mock_sock.return_value.__enter__.return_value
        instance.connect_ex.return_value = 0
        assert tcp_connect_scan("127.0.0.1", 80) is True


def test_closed_port_mocked():
    """connect_ex returning non-zero => closed."""
    from unittest.mock import patch
    with patch("socket.socket") as mock_sock:
        instance = mock_sock.return_value.__enter__.return_value
        instance.connect_ex.return_value = 111  # ECONNREFUSED
        assert tcp_connect_scan("127.0.0.1", 80) is False


def test_gaierror_returns_false_mocked():
    """A DNS failure must be swallowed and reported as False, not raised."""
    from unittest.mock import patch
    with patch("socket.socket") as mock_sock:
        instance = mock_sock.return_value.__enter__.return_value
        instance.connect_ex.side_effect = socket.gaierror
        assert tcp_connect_scan("does-not-exist.invalid", 80) is False