"""The connection's hex-dump debug lines are formatted only when DEBUG is on."""

import logging
from unittest.mock import patch

import pytest

from s7commplus import connection
from s7commplus.connection import _HexDump


def test_hex_dump_formats_spaced_hex() -> None:
    assert str(_HexDump(b"\x72\x03\x00\x1f")) == "72 03 00 1f"
    assert "%s" % _HexDump(b"") == ""


def test_hex_dump_is_not_formatted_when_debug_is_off(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.INFO, logger=connection.logger.name), patch.object(_HexDump, "__str__") as formatted:
        connection.logger.debug("  Full frame (%d bytes): %s", 2, _HexDump(b"\x72\x03"))

    formatted.assert_not_called()
    assert caplog.records == []


def test_hex_dump_is_formatted_when_debug_is_on(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG, logger=connection.logger.name):
        connection.logger.debug("  Full frame (%d bytes): %s", 2, _HexDump(b"\x72\x03"))

    assert caplog.messages == ["  Full frame (2 bytes): 72 03"]
