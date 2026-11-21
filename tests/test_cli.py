"""
Unit tests for argument parsing / validation in main.py

Run with: pytest -v
"""

import pytest
import argparse

from portscanner.ports import parse_ports


def test_parse_single_port():
    assert parse_ports("80") == [80]


def test_parse_port_list():
    assert parse_ports("22,80,443") == [22, 80, 443]


def test_parse_port_range():
    assert parse_ports("1-5") == [1, 2, 3, 4, 5]


def test_parse_mixed_spec():
    assert parse_ports("22,80,100-102") == [22, 80, 100, 101, 102]


@pytest.mark.parametrize("bad_input", ["0", "70000", "abc", "100-50", ""])
def test_parse_invalid_input_raises(bad_input):
    with pytest.raises(argparse.ArgumentTypeError):
        parse_ports(bad_input)

# ---------------------------------------------------------------------------
# Entry points, progress display and error paths
# ---------------------------------------------------------------------------
import runpy
import subprocess
import sys
from unittest.mock import patch

from portscanner import cli, models, scanner


def test_default_port_range_is_1_to_1024():
    args = cli.build_parser().parse_args(["127.0.0.1"])
    assert cli.select_ports(args) == list(range(1, 1025))


def test_python_dash_m_runs_the_scanner(listener):
    done = subprocess.run(
        [sys.executable, "-m", "portscanner", "127.0.0.1",
         "-p", str(listener), "--no-banner"],
        capture_output=True, text=True, timeout=60)
    assert done.returncode == 0
    assert "1 open port(s) found" in done.stdout


def test_main_py_shim_runs_the_scanner(listener, capsys):
    argv = ["main.py", "127.0.0.1", "-p", str(listener), "--no-banner"]
    with patch.object(sys, "argv", argv), pytest.raises(SystemExit) as exc:
        runpy.run_path("main.py", run_name="__main__")
    assert exc.value.code == 0
    assert "1 open port(s) found" in capsys.readouterr().out


def test_ctrl_c_exits_130(capsys):
    with patch.object(scanner, "tcp_scan", side_effect=KeyboardInterrupt):
        assert cli.main(["127.0.0.1", "-p", "80"]) == 130
    assert "Interrupted" in capsys.readouterr().out


def test_progress_is_silent_when_not_a_terminal():
    with patch.object(sys.stderr, "isatty", return_value=False):
        assert cli.make_progress(True) is None


def test_progress_draws_and_finishes_with_a_newline(capsys):
    with patch.object(sys.stderr, "isatty", return_value=True):
        progress = cli.make_progress(True)
        assert cli.make_progress(False) is None
    progress(1, 3)
    progress(2, 3)   # within 0.1s of the last draw: skipped
    progress(3, 3)   # the final update is always drawn
    err = capsys.readouterr().err
    assert "1/3 ports probed" in err
    assert "2/3" not in err
    assert err.endswith("3/3 ports probed\n")


def test_verbose_flag_is_accepted(listener):
    assert cli.main(["127.0.0.1", "-p", str(listener), "--no-banner",
                     "-v"]) == 0


def test_summarise_states_puts_open_first():
    assert cli.summarise_states({"filtered": 1, "closed": 5, "open": 2}) == \
        "2 open, 5 closed, 1 filtered"
    assert cli.summarise_states({"closed": 3}) == "0 open, 3 closed"


def test_host_result_summary_counts_all_but_lists_selected():
    host = models.HostResult("web.test", "192.0.2.1", ports=[
        models.PortResult(22, "tcp", "open", "ssh"),
        models.PortResult(23, "tcp", "closed", "telnet"),
        models.PortResult(24, "tcp", "closed"),
    ])
    report = host.to_dict(only_states={"open"})
    assert report["summary"] == {"open": 1, "closed": 2}
    assert [p["port"] for p in report["ports"]] == [22]
    assert len(host.to_dict()["ports"]) == 3


def test_raw_socket_privilege_check_on_posix():
    with patch.object(scanner.os, "geteuid", return_value=0, create=True):
        assert scanner.has_raw_socket_privileges() is True
    with patch.object(scanner.os, "geteuid", return_value=1000, create=True):
        assert scanner.has_raw_socket_privileges() is False


def test_syn_scan_reports_permission_error_from_the_os(capsys):
    """Root check passed but the OS still refused the raw socket."""
    import types
    module = types.ModuleType("scapy.all")

    class Layer:
        def __init__(self, **kw):
            pass

        def __truediv__(self, other):
            return other

    def sr(*args, **kwargs):
        raise PermissionError

    module.IP = module.IPv6 = module.TCP = Layer
    module.RandShort = lambda: 1
    module.conf = types.SimpleNamespace(L3socket=None)
    module.sr = sr
    package = types.ModuleType("scapy")
    package.all = module
    with patch.dict(sys.modules, {"scapy": package, "scapy.all": module}), \
         patch.object(scanner, "has_raw_socket_privileges", return_value=True):
        assert cli.main(["192.0.2.1", "-p", "80", "-t", "syn"]) == 1
    assert "requires root" in capsys.readouterr().err
