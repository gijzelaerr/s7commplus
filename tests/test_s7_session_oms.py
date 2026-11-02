"""Negotiated OMS session version (SystemOMS / ProjectOMS)."""

from __future__ import annotations

import struct
import time
from collections.abc import Generator

import pytest

from s7commplus.async_client import S7CommPlusAsyncClient
from s7commplus.client import S7CommPlusClient
from s7commplus.connection import S7CommPlusConnection
from s7commplus.legitimation import (
    SESSION_VERSION_PROJECT_OMS_ID,
    SESSION_VERSION_SYSTEM_OMS_ID,
    extract_session_oms_version,
)
from s7commplus.protocol import DataType
from s7commplus.server import S7CommPlusServer
from s7commplus.vlq import encode_uint32_vlq


def _session_version_struct(system_oms: int, project_oms: int | None) -> bytes:
    """A ServerSessionVersion struct value with elements 315/316."""
    buf = bytearray()
    buf += bytes([0x00, DataType.STRUCT])
    buf += struct.pack(">I", 314)  # struct id, fixed UInt32 on the wire
    buf += encode_uint32_vlq(SESSION_VERSION_SYSTEM_OMS_ID)
    buf += bytes([0x00, DataType.UDINT])
    buf += encode_uint32_vlq(system_oms)
    if project_oms is not None:
        buf += encode_uint32_vlq(SESSION_VERSION_PROJECT_OMS_ID)
        buf += bytes([0x00, DataType.UDINT])
        buf += encode_uint32_vlq(project_oms)
    buf += encode_uint32_vlq(0)  # struct terminator
    return bytes(buf)


class TestExtractSessionOmsVersion:
    def test_reads_both_versions(self) -> None:
        raw = _session_version_struct(128, 128)
        assert extract_session_oms_version(raw) == (128, 128)

    def test_project_oms_zero_means_no_project(self) -> None:
        raw = _session_version_struct(64, 0)
        assert extract_session_oms_version(raw) == (64, 0)

    def test_absent_project_oms_is_none_not_zero(self) -> None:
        # Absent element 316 must not read as "no project loaded"; only an
        # explicit 0 does.
        raw = _session_version_struct(448, None)
        assert extract_session_oms_version(raw) == (448, None)

    def test_lookalike_bytes_inside_another_element_are_not_matched(self) -> None:
        # A byte sequence shaped like element 315 inside a WString's content
        # must be skipped by element boundaries, not matched by a byte scan.
        lookalike = encode_uint32_vlq(SESSION_VERSION_SYSTEM_OMS_ID) + bytes([0x00, DataType.UDINT]) + encode_uint32_vlq(64)
        buf = bytearray()
        buf += bytes([0x00, DataType.STRUCT])
        buf += struct.pack(">I", 314)
        buf += encode_uint32_vlq(SESSION_VERSION_SYSTEM_OMS_ID)
        buf += bytes([0x00, DataType.UDINT]) + encode_uint32_vlq(320)
        buf += encode_uint32_vlq(319)
        buf += bytes([0x00, DataType.WSTRING]) + encode_uint32_vlq(len(lookalike)) + lookalike
        buf += encode_uint32_vlq(SESSION_VERSION_PROJECT_OMS_ID)
        buf += bytes([0x00, DataType.UDINT]) + encode_uint32_vlq(5)
        buf += encode_uint32_vlq(0)
        assert extract_session_oms_version(bytes(buf)) == (320, 5)

    def test_paom_string_between_the_version_elements_is_skipped(self) -> None:
        # Real PLCs send the PAOM string (element 319) between 315 and 316.
        paom = b"1;6ES7 215-1AG40-0XB0;V4.2"
        buf = bytearray()
        buf += bytes([0x00, DataType.STRUCT])
        buf += struct.pack(">I", 314)
        buf += encode_uint32_vlq(SESSION_VERSION_SYSTEM_OMS_ID)
        buf += bytes([0x00, DataType.UDINT]) + encode_uint32_vlq(128)
        buf += encode_uint32_vlq(319)
        buf += bytes([0x00, DataType.WSTRING]) + encode_uint32_vlq(len(paom)) + paom
        buf += encode_uint32_vlq(SESSION_VERSION_PROJECT_OMS_ID)
        buf += bytes([0x00, DataType.UDINT]) + encode_uint32_vlq(128)
        buf += encode_uint32_vlq(0)
        assert extract_session_oms_version(bytes(buf)) == (128, 128)

    def test_bare_udint_returns_none(self) -> None:
        # Older PLCs and the plain emulator send ServerSessionVersion as a
        # bare UDINT, not a struct.
        assert extract_session_oms_version(bytes([0x00, DataType.UDINT, 0x40])) is None

    def test_empty_returns_none(self) -> None:
        assert extract_session_oms_version(b"") is None


class TestProperties:
    def test_connection_property_reads_versions(self) -> None:
        connection = S7CommPlusConnection("127.0.0.1")
        assert connection.session_oms_version is None
        connection._server_session_version = _session_version_struct(192, 192)
        assert connection.session_oms_version == (192, 192)
        # Cached on the raw value, so a second read is stable.
        assert connection.session_oms_version == (192, 192)

    def test_sync_client_property(self) -> None:
        client = S7CommPlusClient()
        assert client.session_oms_version is None

    @pytest.mark.asyncio
    async def test_async_client_property(self) -> None:
        client = S7CommPlusAsyncClient()
        assert client.session_oms_version is None
        client._server_session_version = _session_version_struct(256, 0)
        assert client.session_oms_version == (256, 0)


@pytest.fixture()
def emulator() -> Generator[tuple[S7CommPlusServer, int], None, None]:
    srv = S7CommPlusServer()
    srv.register_db(1, {"temperature": ("Real", 0)})
    srv.start(port=0)
    port = srv.port
    time.sleep(0.1)
    yield srv, port
    srv.stop()


class TestEndToEnd:
    def test_plain_emulator_reports_none(self, emulator: tuple[S7CommPlusServer, int]) -> None:
        # The plain emulator sends a bare-UDINT ServerSessionVersion, so the
        # property is None and the connection works exactly as before.
        _srv, port = emulator
        client = S7CommPlusClient()
        client.connect("127.0.0.1", port=port)
        try:
            assert client.connected
            assert client.session_oms_version is None
        finally:
            client.disconnect()


class TestOmsSessionVersionName:
    def test_known_versions(self) -> None:
        from s7commplus.legitimation import oms_session_version_name

        assert oms_session_version_name(64) == "V1"
        assert oms_session_version_name(128) == "V2"
        assert oms_session_version_name(448) == "V7"

    def test_unknown_values_degrade(self) -> None:
        from s7commplus.legitimation import oms_session_version_name

        assert oms_session_version_name(512) == "OMS 512"
        assert oms_session_version_name(0) == "OMS 0"
        assert oms_session_version_name(65) == "OMS 65"  # between versions

    def test_version_values_are_the_documented_steps(self) -> None:
        from s7commplus.legitimation import OMS_SESSION_VERSION_VALUES

        assert OMS_SESSION_VERSION_VALUES == {f"V{i}": 64 * i for i in range(1, 8)}
