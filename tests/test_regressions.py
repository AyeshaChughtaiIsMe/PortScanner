"""Regression tests for bugs fixed in the first improvement pass."""

import json
import socket
from datetime import datetime
from unittest.mock import patch

import pytest

from portscanner import cli
from portscanner import scanner


def test_sparse_port_list_only_probes_requested_ports():
    """-p 22,65000 must probe two ports, not the 64,979 in between."""
    probed = []

    def fake_probe(host, port, timeout, retries=0):
        probed.append(port)
        return "closed"

    with patch.object(scanner, "tcp_probe", fake_probe):
        scanner.scan_ports("127.0.0.1", [22, 65000])
    assert sorted(probed) == [22, 65000]


def test_cli_sparse_ports_end_to_end(listener, capsys):
    with patch.object(scanner, "tcp_probe",
                      wraps=scanner.tcp_probe) as probe:
        code = cli.main(["127.0.0.1", "-p", f"1,{listener}", "--no-banner",
                         "--timeout", "0.5"])
    assert code == 0
    assert probe.call_count == 2
    assert "1 open port(s) found" in capsys.readouterr().out


def test_hostname_resolved_once_and_ip_is_scanned(capsys):
    seen_hosts = set()

    def fake_probe(host, port, timeout, retries=0):
        seen_hosts.add(host)
        return "closed"

    with patch.object(cli.targets, "resolve",
                      return_value="127.0.0.1") as resolve, \
         patch.object(scanner, "tcp_probe", fake_probe):
        assert cli.main(["example.test", "-p", "1-20", "--no-banner"]) == 0
    assert resolve.call_count == 1
    assert seen_hosts == {"127.0.0.1"}


def test_unresolvable_host_exits_2(capsys):
    with patch.object(cli.targets.socket, "getaddrinfo",
                      side_effect=socket.gaierror):
        assert cli.main(["nope.invalid", "-p", "80"]) == 2
    assert "Could not resolve" in capsys.readouterr().err


def test_started_at_is_taken_before_the_scan(tmp_path, listener):
    out = tmp_path / "scan.json"
    before = datetime.now()
    cli.main(["127.0.0.1", "-p", str(listener), "--no-banner",
              "-o", str(out)])
    data = json.loads(out.read_text())
    started = datetime.fromisoformat(data["started_at"])
    assert before <= started
    # started_at + elapsed must not be in the future: it is a start time.
    assert (datetime.now() - started).total_seconds() >= data["elapsed_seconds"] - 0.01


def test_syn_scan_without_privileges_is_an_error_not_zero_results(capsys):
    with patch.object(scanner, "has_raw_socket_privileges",
                      return_value=False), \
         patch.dict("sys.modules", {"scapy": object(), "scapy.all": object()}):
        code = cli.main(["127.0.0.1", "-p", "80", "--scan-type", "syn"])
    captured = capsys.readouterr()
    assert code == 1
    assert "requires root" in captured.err
    assert "open port(s) found" not in captured.out


def test_udp_summary_counts_only_open_ports(capsys):
    states = {1: "closed", 2: "open|filtered", 3: "open"}
    with patch.object(scanner, "udp_scan",
                      side_effect=lambda host, port, timeout, retries: states[port]):
        cli.main(["127.0.0.1", "-p", "1-3", "--scan-type", "udp"])
    assert "1 open port(s) found" in capsys.readouterr().out
