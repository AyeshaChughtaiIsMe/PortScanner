"""Tests for target expansion, resolution, host discovery and exports."""

import csv
import errno
import io
import json
import socket
import xml.etree.ElementTree as ET
from unittest.mock import MagicMock, patch

import pytest

from portscanner import cli
from portscanner import discovery, output, scanner, targets
from portscanner.scanner import CLOSED, FILTERED, OPEN, UNKNOWN
from portscanner.targets import TargetError
from tests.conftest import REFUSAL_TIMEOUT


# ---------------------------------------------------------------------------
# Target expansion
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("spec,expected", [
    ("example.org", ["example.org"]),
    ("192.168.1.7", ["192.168.1.7"]),
    ("::1", ["::1"]),
    ("192.168.1.0/30", ["192.168.1.1", "192.168.1.2"]),   # no net/broadcast
    ("192.168.1.5/30", ["192.168.1.5", "192.168.1.6"]),   # host bits allowed
    ("192.168.1.0/31", ["192.168.1.0", "192.168.1.1"]),
    ("192.168.1.9/32", ["192.168.1.9"]),
    ("192.168.1.10-12", ["192.168.1.10", "192.168.1.11", "192.168.1.12"]),
    ("fd00::/127", ["fd00::", "fd00::1"]),
    ("  ", []),
])
def test_expand_spec(spec, expected):
    assert targets.expand_spec(spec) == expected


def test_expand_slash_24_has_254_hosts():
    assert len(targets.expand_spec("10.1.2.0/24")) == 254


@pytest.mark.parametrize("spec", [
    "10.0.0.0/8",          # far too many hosts
    "::/0",
    "192.168.1.0/33",
    "not-a-net/24",
    "192.168.1.20-10",     # backwards
    "192.168.1.250-300",   # octet out of range
])
def test_expand_spec_rejects(spec):
    with pytest.raises(TargetError):
        targets.expand_spec(spec)


def test_targets_file_skips_comments_and_blanks(tmp_path):
    path = tmp_path / "targets.txt"
    path.write_text("# lab hosts\n10.0.0.1\n\n10.0.0.8/30  # router block\n"
                    "example.org\n")
    assert targets.expand_targets([], str(path)) == \
        ["10.0.0.1", "10.0.0.9", "10.0.0.10", "example.org"]


def test_missing_targets_file():
    with pytest.raises(TargetError, match="Cannot read"):
        targets.expand_targets([], "/no/such/file.txt")


def test_expand_targets_merges_and_deduplicates(tmp_path):
    path = tmp_path / "t.txt"
    path.write_text("10.0.0.2\n10.0.0.3\n")
    assert targets.expand_targets(["10.0.0.1-2", "10.0.0.1"], str(path)) == \
        ["10.0.0.1", "10.0.0.2", "10.0.0.3"]


def test_expand_targets_requires_something():
    with pytest.raises(TargetError, match="No targets"):
        targets.expand_targets([])


def test_expand_targets_total_cap():
    with pytest.raises(TargetError, match="Too many"):
        targets.expand_targets(["10.0.0.0/16", "10.1.0.0/16"])


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------
def _addrinfo(*addresses):
    out = []
    for address in addresses:
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        out.append((family, socket.SOCK_STREAM, 6, "", (address, 0)))
    return out


def test_resolve_prefers_ipv4_by_default():
    with patch.object(targets.socket, "getaddrinfo",
                      return_value=_addrinfo("2001:db8::1", "192.0.2.5")):
        assert targets.resolve("dual.test") == "192.0.2.5"


def test_resolve_prefers_ipv6_when_asked():
    with patch.object(targets.socket, "getaddrinfo",
                      return_value=_addrinfo("192.0.2.5", "2001:db8::1")):
        assert targets.resolve("dual.test", prefer_ipv6=True) == "2001:db8::1"


def test_resolve_falls_back_to_the_other_family():
    with patch.object(targets.socket, "getaddrinfo",
                      return_value=_addrinfo("2001:db8::1")):
        assert targets.resolve("v6only.test") == "2001:db8::1"


def test_resolve_failure_raises_target_error():
    with patch.object(targets.socket, "getaddrinfo",
                      side_effect=socket.gaierror):
        with pytest.raises(TargetError, match="Could not resolve"):
            targets.resolve("nope.invalid")


def test_resolve_ip_literals_without_dns():
    assert targets.resolve("127.0.0.1") == "127.0.0.1"


# ---------------------------------------------------------------------------
# IPv6 scanning
# ---------------------------------------------------------------------------
def test_ipv6_literal_uses_an_ipv6_socket():
    mock_sock = MagicMock()
    mock_sock.return_value.__enter__.return_value.connect_ex.return_value = 0
    with patch("socket.socket", mock_sock):
        assert scanner.tcp_probe("2001:db8::1", 80) == OPEN
    assert mock_sock.call_args[0][0] == socket.AF_INET6


def test_no_local_ipv6_is_unknown_not_filtered():
    mock_sock = MagicMock()
    mock_sock.return_value.__enter__.return_value.connect_ex.return_value = \
        errno.EADDRNOTAVAIL
    with patch("socket.socket", mock_sock):
        assert scanner.tcp_probe("2001:db8::1", 80) == UNKNOWN


def test_scan_real_ipv6_loopback(listener_v6, capsys):
    assert scanner.tcp_probe("::1", listener_v6) == OPEN
    assert cli.main(["::1", "-p", str(listener_v6), "--no-banner"]) == 0
    assert "1 open port(s) found" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Host discovery
# ---------------------------------------------------------------------------
def test_host_is_up_when_a_discovery_port_is_open(listener):
    assert discovery.is_host_up("127.0.0.1", ports=(listener,))


def test_host_is_up_when_it_refuses(closed_port):
    """A refusal still proves the host exists."""
    assert discovery.is_host_up("127.0.0.1", REFUSAL_TIMEOUT,
                                ports=(closed_port,))


def test_host_is_down_when_nothing_answers():
    with patch.object(discovery, "tcp_probe", return_value=FILTERED):
        assert not discovery.is_host_up("192.0.2.1")


def test_discover_hosts_returns_only_live_ones():
    def fake_probe(ip, port, timeout):
        return CLOSED if ip == "10.0.0.2" else FILTERED
    with patch.object(discovery, "tcp_probe", fake_probe):
        assert discovery.discover_hosts(["10.0.0.1", "10.0.0.2", "10.0.0.3"]) \
            == {"10.0.0.2"}
    assert discovery.discover_hosts([]) == set()


# ---------------------------------------------------------------------------
# Report writers
# ---------------------------------------------------------------------------
REPORT = {
    "scan_type": "tcp",
    "started_at": "2026-01-02T03:04:05",
    "finished_at": "2026-01-02T03:04:07",
    "elapsed_seconds": 2.0,
    "hosts": [
        {"target": "web.test", "ip": "192.0.2.10", "state": "up",
         "summary": {"open": 2, "closed": 1},
         "ports": [
             {"port": 22, "protocol": "tcp", "state": "open",
              "service": "ssh", "banner": "SSH-2.0-OpenSSH_9.6"},
             {"port": 80, "protocol": "tcp", "state": "open",
              "service": "http", "banner": 'nginx, "quoted" <tag> & more'},
         ]},
        {"target": "2001:db8::5", "ip": "2001:db8::5", "state": "down",
         "summary": {}, "ports": []},
    ],
}


@pytest.mark.parametrize("path,explicit,expected", [
    ("out.json", None, "json"), ("out.CSV", None, "csv"),
    ("out.xml", None, "xml"), ("out.txt", None, "json"),
    ("out", None, "json"), ("out.json", "csv", "csv"),
])
def test_format_for(path, explicit, expected):
    assert output.format_for(path, explicit) == expected


def test_json_report_round_trips(tmp_path):
    path = output.write_report(REPORT, str(tmp_path / "deep" / "r.json"))
    assert json.loads(path.read_text()) == REPORT


def test_csv_report_has_one_row_per_port(tmp_path):
    path = output.write_report(REPORT, str(tmp_path / "r.csv"))
    rows = list(csv.DictReader(io.StringIO(path.read_text())))
    assert [r["port"] for r in rows] == ["22", "80"]
    assert rows[1] == {"target": "web.test", "ip": "192.0.2.10", "port": "80",
                       "protocol": "tcp", "state": "open", "service": "http",
                       "banner": 'nginx, "quoted" <tag> & more'}


def test_xml_report_structure_and_escaping(tmp_path):
    path = output.write_report(REPORT, str(tmp_path / "r.xml"))
    root = ET.fromstring(path.read_text())
    assert root.tag == "nmaprun"
    up, down = root.findall("host")
    assert up.find("status").get("state") == "up"
    assert up.find("address").attrib == {"addr": "192.0.2.10",
                                         "addrtype": "ipv4"}
    assert up.find("hostnames/hostname").get("name") == "web.test"
    ports = up.findall("ports/port")
    assert [p.get("portid") for p in ports] == ["22", "80"]
    assert ports[0].find("state").get("state") == "open"
    assert ports[0].find("service").get("name") == "ssh"
    assert ports[1].find("script").get("output") == \
        'nginx, "quoted" <tag> & more'
    assert down.find("address").get("addrtype") == "ipv6"
    assert down.find("hostnames") is None
    assert root.find("runstats/hosts").attrib == {"up": "1", "down": "1",
                                                  "total": "2"}


# ---------------------------------------------------------------------------
# CLI: several targets
# ---------------------------------------------------------------------------
def test_cli_scans_every_host_in_a_cidr(listener, capsys, tmp_path):
    out = tmp_path / "r.json"
    code = cli.main(["127.0.0.0/30", "-p", str(listener), "--no-banner",
                     "--skip-discovery", "-o", str(out)])
    assert code == 0
    report = json.loads(out.read_text())
    assert [h["ip"] for h in report["hosts"]] == ["127.0.0.1", "127.0.0.2"]
    assert report["hosts"][0]["ports"][0]["port"] == listener
    assert "on 2 host(s)" in capsys.readouterr().out


def test_cli_discovery_skips_down_hosts(capsys, tmp_path):
    out = tmp_path / "r.json"
    with patch.object(discovery, "discover_hosts",
                      return_value={"10.0.0.2"}) as discover, \
         patch.object(scanner, "tcp_probe", return_value=CLOSED) as probe:
        assert cli.main(["10.0.0.1-3", "-p", "80,443", "-o", str(out)]) == 0
    assert discover.call_args[0][0] == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}
    assert {call.args[0] for call in probe.call_args_list} == {"10.0.0.2"}
    states = {h["ip"]: h["state"]
              for h in json.loads(out.read_text())["hosts"]}
    assert states == {"10.0.0.1": "down", "10.0.0.2": "up",
                      "10.0.0.3": "down"}
    assert "(2 down)" in capsys.readouterr().out


def test_cli_single_target_never_runs_discovery():
    with patch.object(discovery, "discover_hosts") as discover, \
         patch.object(scanner, "tcp_probe", return_value=CLOSED):
        cli.main(["10.0.0.1", "-p", "80"])
    discover.assert_not_called()


def test_cli_skip_discovery_flag():
    with patch.object(discovery, "discover_hosts") as discover, \
         patch.object(scanner, "tcp_probe", return_value=CLOSED) as probe:
        cli.main(["10.0.0.1", "10.0.0.2", "-p", "80", "--skip-discovery"])
    discover.assert_not_called()
    assert probe.call_count == 2


def test_cli_continues_past_an_unresolvable_target(capsys):
    def fake_resolve(name, prefer_ipv6=False):
        if name == "bad.invalid":
            raise TargetError("Could not resolve hostname: bad.invalid")
        return "10.0.0.9"
    with patch.object(targets, "resolve", fake_resolve), \
         patch.object(scanner, "tcp_probe", return_value=CLOSED) as probe:
        assert cli.main(["bad.invalid", "good.test", "-p", "80"]) == 0
    assert probe.call_count == 1
    assert "bad.invalid" in capsys.readouterr().err


def test_cli_targets_file(tmp_path, listener, capsys):
    path = tmp_path / "targets.txt"
    path.write_text("127.0.0.1\n")
    assert cli.main(["-iL", str(path), "-p", str(listener),
                     "--no-banner"]) == 0
    assert "1 open port(s) found" in capsys.readouterr().out


def test_cli_ipv6_flag_reaches_the_resolver():
    with patch.object(targets, "resolve", return_value="::1") as resolve, \
         patch.object(scanner, "tcp_probe", return_value=CLOSED):
        cli.main(["dual.test", "-6", "-p", "80"])
    assert resolve.call_args[0] == ("dual.test", True)


@pytest.mark.parametrize("argv", [
    ["-p", "80"],                 # no target at all
    ["10.0.0.0/8"],               # too large
    ["-iL", "/no/such/file"],
])
def test_cli_bad_targets_exit_2(argv, capsys):
    assert cli.main(argv) == 2
    assert capsys.readouterr().err.startswith("[!]")


def test_cli_writes_csv_by_extension(listener, tmp_path):
    out = tmp_path / "r.csv"
    cli.main(["127.0.0.1", "-p", str(listener), "--no-banner", "-o", str(out)])
    rows = list(csv.DictReader(io.StringIO(out.read_text())))
    assert rows == [{"target": "127.0.0.1", "ip": "127.0.0.1",
                     "port": str(listener), "protocol": "tcp",
                     "state": "open",
                     "service": rows[0]["service"], "banner": ""}]


def test_cli_format_flag_overrides_extension(listener, tmp_path):
    out = tmp_path / "r.json"
    cli.main(["127.0.0.1", "-p", str(listener), "--no-banner",
              "-o", str(out), "--format", "xml"])
    assert ET.fromstring(out.read_text()).tag == "nmaprun"
