"""Tests for port states, retries, rate limiting, UDP, SYN and banners."""

import errno
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import types
from unittest.mock import MagicMock, patch

import pytest

from portscanner import cli
from portscanner import banner, scanner
from portscanner.ports import TOP_PORTS, top_ports
from tests.conftest import REFUSAL_ARGS, REFUSAL_TIMEOUT
from portscanner.scanner import CLOSED, FILTERED, OPEN, OPEN_FILTERED, UNKNOWN


# ---------------------------------------------------------------------------
# TCP port states
# ---------------------------------------------------------------------------
def test_tcp_probe_open(listener):
    assert scanner.tcp_probe("127.0.0.1", listener) == OPEN


def test_tcp_probe_closed(closed_port):
    assert scanner.tcp_probe("127.0.0.1", closed_port,
                             REFUSAL_TIMEOUT) == CLOSED


def _mock_connect(result=None, side_effect=None):
    mock_sock = MagicMock()
    instance = mock_sock.return_value.__enter__.return_value
    if side_effect is not None:
        instance.connect_ex.side_effect = side_effect
    else:
        instance.connect_ex.return_value = result
    return mock_sock, instance


@pytest.mark.parametrize("code", [errno.EAGAIN, errno.ETIMEDOUT,
                                  errno.EHOSTUNREACH])
def test_tcp_probe_no_answer_is_filtered(code):
    mock_sock, _ = _mock_connect(result=code)
    with patch("socket.socket", mock_sock):
        assert scanner.tcp_probe("10.0.0.1", 80) == FILTERED


def test_tcp_probe_timeout_exception_is_filtered():
    mock_sock, _ = _mock_connect(side_effect=socket.timeout)
    with patch("socket.socket", mock_sock):
        assert scanner.tcp_probe("10.0.0.1", 80) == FILTERED


def test_tcp_probe_dns_failure_is_unknown():
    mock_sock, _ = _mock_connect(side_effect=socket.gaierror)
    with patch("socket.socket", mock_sock):
        assert scanner.tcp_probe("nope.invalid", 80) == UNKNOWN


def test_filtered_ports_are_retried_and_can_recover():
    mock_sock, instance = _mock_connect(side_effect=[errno.EAGAIN, errno.EAGAIN, 0])
    with patch("socket.socket", mock_sock):
        assert scanner.tcp_probe("10.0.0.1", 80, retries=2) == OPEN
    assert instance.connect_ex.call_count == 3


def test_closed_ports_are_not_retried():
    mock_sock, instance = _mock_connect(result=errno.ECONNREFUSED)
    with patch("socket.socket", mock_sock):
        assert scanner.tcp_probe("10.0.0.1", 80, retries=3) == CLOSED
    assert instance.connect_ex.call_count == 1


def test_tcp_scan_reports_every_port(listener, closed_port):
    states = scanner.tcp_scan("127.0.0.1", [listener, closed_port],
                              timeout=REFUSAL_TIMEOUT)
    assert states == {listener: OPEN, closed_port: CLOSED}


def test_progress_callback_reaches_total(closed_port):
    calls = []
    scanner.tcp_scan("127.0.0.1", [closed_port, closed_port + 1],
                     progress=lambda done, total: calls.append((done, total)))
    assert calls[-1] == (2, 2)


def test_worker_exception_becomes_unknown():
    def boom(port):
        raise RuntimeError("probe blew up")
    assert scanner._run_concurrent(boom, [1, 2], 2) == {1: UNKNOWN, 2: UNKNOWN}


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------
def test_rate_limiter_spaces_out_calls():
    limiter = scanner.RateLimiter(50)  # 20 ms apart
    start = time.monotonic()
    for _ in range(6):
        limiter.wait()
    assert time.monotonic() - start >= 0.09


def test_rate_limiter_is_shared_across_threads():
    limiter = scanner.RateLimiter(100)
    start = time.monotonic()
    threads = [threading.Thread(target=limiter.wait) for _ in range(11)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert time.monotonic() - start >= 0.09


def test_rate_limiter_rejects_zero():
    with pytest.raises(ValueError):
        scanner.RateLimiter(0)


# ---------------------------------------------------------------------------
# UDP
# ---------------------------------------------------------------------------
def test_udp_open_when_service_replies(udp_echo):
    port, _received = udp_echo
    assert scanner.udp_scan("127.0.0.1", port, timeout=1.0) == OPEN


def test_udp_closed_when_port_unreachable(closed_port):
    assert scanner.udp_scan("127.0.0.1", closed_port,
                            timeout=REFUSAL_TIMEOUT) == CLOSED


def _mock_udp(recv_side_effect):
    mock_sock = MagicMock()
    instance = mock_sock.return_value.__enter__.return_value
    instance.recv.side_effect = recv_side_effect
    return mock_sock, instance


def test_udp_silence_is_open_or_filtered_after_retries():
    mock_sock, instance = _mock_udp(socket.timeout)
    with patch("socket.socket", mock_sock):
        assert scanner.udp_scan("10.0.0.1", 9999, retries=2) == OPEN_FILTERED
    assert instance.send.call_count == 3


@pytest.mark.parametrize("port", sorted(scanner.UDP_PAYLOADS))
def test_udp_well_known_ports_get_protocol_payload(port):
    mock_sock, instance = _mock_udp([b"reply"])
    with patch("socket.socket", mock_sock):
        scanner.udp_scan("10.0.0.1", port)
    instance.send.assert_called_once_with(scanner.UDP_PAYLOADS[port])
    assert scanner.UDP_PAYLOADS[port] != scanner.DEFAULT_UDP_PAYLOAD


def test_udp_payloads_are_well_formed():
    snmp = scanner.UDP_PAYLOADS[161]
    assert snmp[0] == 0x30 and snmp[1] == len(snmp) - 2   # ASN.1 SEQUENCE
    assert len(scanner.UDP_PAYLOADS[123]) == 48           # NTP packet size
    assert len(scanner.UDP_PAYLOADS[53]) == 12 + 5        # header + question


def test_udp_scan_ports_concurrent(udp_echo, closed_port):
    port, _ = udp_echo
    states = scanner.udp_scan_ports("127.0.0.1", [port, closed_port],
                                    timeout=REFUSAL_TIMEOUT)
    assert states == {port: OPEN, closed_port: CLOSED}


# ---------------------------------------------------------------------------
# SYN scan (scapy replaced by a fake: no raw packets are sent)
# ---------------------------------------------------------------------------
class FakeLayer:
    def __init__(self, **fields):
        self.__dict__.update(fields)


class FakePacket:
    def __init__(self, layers):
        self.layers = layers

    def haslayer(self, layer):
        return layer in self.layers

    def __getitem__(self, layer):
        return self.layers[layer]


def fake_scapy(replies):
    """Build a stand-in scapy.all whose sr() answers from `replies`
    ({port: tcp_flags | "icmp"}); ports not listed stay unanswered."""
    module = types.ModuleType("scapy.all")
    module.sent_batches = []

    class TCP:
        def __init__(self, **kw):
            self.kw = kw

    class Net:
        def __init__(self, dst):
            self.dst = dst

        def __truediv__(self, tcp):
            return tcp

    def sr(probe, timeout, retry, verbose):
        batch = probe.kw["dport"]
        module.sent_batches.append(list(batch))
        answered = []
        for port in batch:
            if port not in replies:
                continue
            sent = FakePacket({TCP: FakeLayer(dport=port)})
            if replies[port] == "icmp":
                reply = FakePacket({})
            else:
                reply = FakePacket({TCP: FakeLayer(flags=replies[port])})
            answered.append((sent, reply))
        return answered, []

    module.IP = module.IPv6 = Net
    module.TCP = TCP
    module.RandShort = lambda: 12345
    module.conf = types.SimpleNamespace(L3socket=None)
    module.L3RawSocket = object
    module.sr = sr
    return module


@pytest.fixture
def scapy_stub():
    def install(replies):
        module = fake_scapy(replies)
        package = types.ModuleType("scapy")
        package.all = module
        patcher = patch.dict(sys.modules, {"scapy": package,
                                           "scapy.all": module})
        patcher.start()
        installed.append(patcher)
        return module
    installed = []
    with patch.object(scanner, "has_raw_socket_privileges", return_value=True):
        yield install
    for patcher in installed:
        patcher.stop()


def test_syn_scan_classifies_replies(scapy_stub):
    scapy_stub({22: 0x12, 23: 0x14, 24: 0x04, 25: "icmp", 27: 0x52})
    states = scanner.syn_scan_ports("192.0.2.1", [22, 23, 24, 25, 26, 27])
    assert states == {
        22: OPEN,       # SYN-ACK
        23: CLOSED,     # RST-ACK
        24: CLOSED,     # bare RST
        25: FILTERED,   # ICMP unreachable
        26: FILTERED,   # silence
        27: OPEN,       # SYN-ACK with ECN bits set
    }


def test_syn_scan_sends_ports_in_batches(scapy_stub):
    module = scapy_stub({})
    scanner.syn_scan_ports("192.0.2.1", range(1, 601), batch_size=256)
    assert [len(b) for b in module.sent_batches] == [256, 256, 88]


def test_syn_scan_single_port_wrapper(scapy_stub):
    scapy_stub({80: 0x12})
    assert scanner.syn_scan("192.0.2.1", 80) == OPEN


def test_syn_scan_without_scapy_raises():
    with patch.dict(sys.modules, {"scapy": None, "scapy.all": None}):
        with pytest.raises(scanner.ScanError, match="scapy"):
            scanner.syn_scan_ports("192.0.2.1", [80])


# ---------------------------------------------------------------------------
# Banners
# ---------------------------------------------------------------------------
def test_banner_from_service_that_speaks_first(greeting_server):
    assert banner.grab_banner("127.0.0.1", greeting_server) == \
        "SSH-2.0-TestServer_1.0"


def test_banner_from_http_server_needs_a_request(http_server):
    text = banner.grab_banner("127.0.0.1", http_server)
    assert text.startswith("HTTP/1.0 200")
    assert "Server: TestHTTP/1.0" in text


def test_banner_empty_for_silent_service(listener):
    assert banner.grab_banner("127.0.0.1", listener, timeout=0.3) == ""


def test_banner_empty_for_closed_port(closed_port):
    assert banner.grab_banner("127.0.0.1", closed_port, timeout=0.3) == ""


def test_summarise_http_keeps_status_and_server_only():
    raw = (b"HTTP/1.1 301 Moved Permanently\r\nDate: today\r\n"
           b"Server: nginx/1.24.0\r\nLocation: https://x/\r\n\r\n<html>")
    assert banner.summarise_banner(raw) == \
        "HTTP/1.1 301 Moved Permanently | Server: nginx/1.24.0"


def test_summarise_strips_control_characters_and_truncates():
    assert banner.summarise_banner(b"220\x00 hello\r\n\tworld\x07") == \
        "220 hello world"
    assert len(banner.summarise_banner(b"A" * 5000)) == banner.MAX_BANNER_LEN


@pytest.mark.parametrize("name,text,expected", [
    ("unknown", "SSH-2.0-OpenSSH_9.6", "ssh"),
    ("unknown", "HTTP/1.1 200 OK | Server: nginx", "http"),
    ("unknown", "TLSv1.3 | HTTP/1.1 200 OK", "https"),
    ("unknown", "TLSv1.3", "tls"),
    ("unknown", "220 ProFTPD FTP Server ready", "ftp"),
    ("unknown", "220 mail.example ESMTP Postfix", "smtp"),
    ("unknown", "", "unknown"),
    ("mysql", "SSH-2.0-OpenSSH_9.6", "mysql"),   # port lookup wins
])
def test_refine_service(name, text, expected):
    assert banner.refine_service(name, text) == expected


@pytest.fixture
def tls_server(tmp_path):
    """An HTTPS-like server with a throwaway self-signed certificate."""
    if shutil.which("openssl") is None:
        pytest.skip("openssl command not available")
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "1",
         "-subj", "/CN=localhost"],
        check=True, capture_output=True)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(16)

    def loop():
        while True:
            try:
                conn, _addr = sock.accept()
            except OSError:
                return
            try:
                conn.settimeout(3)
                with context.wrap_socket(conn, server_side=True) as tls:
                    tls.recv(2048)
                    tls.sendall(b"HTTP/1.0 200 OK\r\nServer: TLSTest\r\n\r\n")
            except OSError:
                pass

    threading.Thread(target=loop, daemon=True).start()
    yield sock.getsockname()[1]
    sock.close()


def test_banner_falls_back_to_tls_on_unusual_port(tls_server):
    text = banner.grab_banner("127.0.0.1", tls_server, timeout=2.0,
                              server_name="localhost")
    assert text.startswith("TLSv1.")
    assert text.endswith("HTTP/1.0 200 OK | Server: TLSTest")


def test_identify_service_refines_unknown_port(greeting_server):
    info = banner.identify_service("127.0.0.1", greeting_server)
    assert info["service"] == "ssh"
    assert info["banner"].startswith("SSH-2.0")


# ---------------------------------------------------------------------------
# Port lists and CLI behaviour
# ---------------------------------------------------------------------------
def test_top_ports_list_is_100_unique_valid_ports():
    assert len(TOP_PORTS) == len(set(TOP_PORTS)) == 100
    assert all(0 < p <= 65535 for p in TOP_PORTS)


def test_top_ports_takes_most_common_first():
    assert top_ports(3) == [23, 80, 443]


@pytest.mark.parametrize("count", [0, 101])
def test_top_ports_out_of_range(count):
    import argparse
    with pytest.raises(argparse.ArgumentTypeError):
        top_ports(count)


def test_cli_top_ports(capsys):
    with patch.object(scanner, "tcp_probe", return_value=CLOSED) as probe:
        assert cli.main(["127.0.0.1", "--top-ports", "10"]) == 0
    assert probe.call_count == 10
    assert "0 open, 10 closed" in capsys.readouterr().out


def test_cli_ports_and_top_ports_are_exclusive(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["127.0.0.1", "-p", "80", "--top-ports", "10"])
    assert exc.value.code == 2


def test_cli_default_lists_only_open_ports(listener, closed_port, capsys):
    cli.main(["127.0.0.1", "-p", f"{listener},{closed_port}", "--no-banner",
              *REFUSAL_ARGS])
    out = capsys.readouterr().out
    assert "1 open, 1 closed" in out
    assert f"{listener:<8}tcp" in out
    assert f"{closed_port:<8}tcp" not in out
    assert "--show-all" in out


def test_cli_show_all_lists_closed_ports(listener, closed_port, capsys):
    cli.main(["127.0.0.1", "-p", f"{listener},{closed_port}", "--no-banner",
              "--show-all", *REFUSAL_ARGS])
    out = capsys.readouterr().out
    assert f"{closed_port:<8}tcp    closed" in out


def test_cli_grabs_banners_for_open_ports(greeting_server, http_server, capsys):
    cli.main(["127.0.0.1", "-p", f"{greeting_server},{http_server}"])
    out = capsys.readouterr().out
    assert "SSH-2.0-TestServer_1.0" in out
    assert "Server: TestHTTP/1.0" in out


def test_cli_udp_scan(udp_echo, closed_port, capsys):
    port, _ = udp_echo
    assert cli.main(["127.0.0.1", "-p", f"{port},{closed_port}",
                     "-t", "udp", "--show-all", *REFUSAL_ARGS]) == 0
    out = capsys.readouterr().out
    assert "1 open, 1 closed" in out
    assert f"{port:<8}udp    open" in out


def test_cli_syn_scan(scapy_stub, capsys):
    scapy_stub({22: 0x12, 23: 0x14})
    assert cli.main(["127.0.0.1", "-p", "22-24", "-t", "syn",
                     "--no-banner"]) == 0
    out = capsys.readouterr().out
    assert "1 open, 1 closed, 1 filtered" in out
    assert "22      tcp    open           ssh" in out


@pytest.mark.parametrize("flag,value", [("--timeout", "0"), ("--workers", "0"),
                                        ("--retries", "-1"), ("--rate", "0")])
def test_cli_rejects_nonsense_numbers(flag, value):
    with pytest.raises(SystemExit) as exc:
        cli.main(["127.0.0.1", flag, value])
    assert exc.value.code == 2
