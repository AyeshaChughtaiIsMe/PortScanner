"""
Unit tests for argument parsing / validation in main.py

Run with: pytest -v
"""

import pytest
import argparse

from main import parse_ports


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