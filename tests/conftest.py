"""Shared fixtures: small real services on 127.0.0.1 for the scanner to find."""

import http.server
import socket
import threading

import pytest

# Windows takes about two seconds to refuse a connection to a closed
# loopback port, so tests that need a real "closed" answer allow three.
# Elsewhere the refusal is immediate and the longer timeout costs nothing.
REFUSAL_TIMEOUT = 3.0
REFUSAL_ARGS = ["--timeout", str(REFUSAL_TIMEOUT)]


@pytest.fixture
def listener():
    """An open TCP port that accepts but never speaks."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(16)
    yield sock.getsockname()[1]
    sock.close()


@pytest.fixture
def closed_port():
    """A TCP/UDP port number with nothing listening on it."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _serve(sock, handler):
    def loop():
        while True:
            try:
                conn, _addr = sock.accept()
            except OSError:
                return
            try:
                handler(conn)
            except OSError:
                pass
            finally:
                conn.close()
    threading.Thread(target=loop, daemon=True).start()


@pytest.fixture
def greeting_server():
    """A service that speaks first, like SSH."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(16)
    _serve(sock, lambda conn: conn.sendall(b"SSH-2.0-TestServer_1.0\r\n"))
    yield sock.getsockname()[1]
    sock.close()


class _QuietHandler(http.server.BaseHTTPRequestHandler):
    server_version = "TestHTTP/1.0"
    sys_version = ""

    def do_HEAD(self):
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture
def http_server():
    """A web server: silent until it receives a request."""
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _QuietHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


@pytest.fixture
def udp_echo():
    """A UDP service that answers every datagram. Yields (port, received)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    received = []

    def loop():
        while True:
            try:
                data, addr = sock.recvfrom(2048)
            except OSError:
                return
            received.append(data)
            sock.sendto(b"pong", addr)

    threading.Thread(target=loop, daemon=True).start()
    yield sock.getsockname()[1], received
    sock.close()


@pytest.fixture
def listener_v6():
    """An open TCP port on ::1; skips where IPv6 loopback is unavailable."""
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.bind(("::1", 0))
    except OSError:
        pytest.skip("IPv6 loopback not available on this machine")
    sock.listen(16)
    yield sock.getsockname()[1]
    sock.close()
