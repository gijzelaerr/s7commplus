"""Tests must not start emulators on fixed TCP ports.

A fixed port lets two test runs at once (two checkouts, or CI jobs sharing a
host) start emulators on the same port, so a client can reach the other run's
emulator and fail at random. Start the emulator with ``start(port=0)`` and
connect to its ``port`` instead; ``get_free_tcp_port()`` from
``tests/conftest.py`` is only for a port that nothing should listen on.
"""

import re
from pathlib import Path

import pytest

TESTS = Path(__file__).parent

# ``port=11120`` in a call, or ``SOME_PORT = 11120`` at any indentation. Port 102,
# the S7 default for real PLCs, has three digits and does not match.
FIXED_PORT = re.compile(r"\bport\s*=\s*\d{4,5}\b|^\s*\w*PORT\w*\s*=\s*\d{4,5}\b", re.IGNORECASE | re.MULTILINE)


def _fixed_ports(source: str) -> list[str]:
    return [match.group().strip() for match in FIXED_PORT.finditer(source)]


def test_no_test_uses_a_fixed_port() -> None:
    offenders = [
        f"{path.relative_to(TESTS)}: {found}"
        for path in sorted(TESTS.rglob("*.py"))
        if path.name != Path(__file__).name
        for found in _fixed_ports(path.read_text(encoding="utf-8"))
    ]
    assert offenders == []


@pytest.mark.parametrize(
    "line",
    [
        "TEST_PORT = 11120",
        "    RST_PORT = 11122",
        "srv.start(port=11191)",
        'client.connect("127.0.0.1", port=11120)',
    ],
)
def test_the_check_finds_fixed_ports(line: str) -> None:
    assert _fixed_ports(line)


@pytest.mark.parametrize(
    "line",
    [
        "TEST_PORT = get_free_tcp_port()",
        "TEST_PORT, SESSION_KEY_PORT, RST_PORT = get_free_tcp_ports(3)",
        'client.connect("192.168.0.1", port=102)',
        "srv.start(port=TEST_PORT)",
        '("1;6ES7 672-7FC01-0YA0;V21.9", ("6", 2109)),',
    ],
)
def test_the_check_allows_chosen_ports_and_the_s7_default(line: str) -> None:
    assert not _fixed_ports(line)
