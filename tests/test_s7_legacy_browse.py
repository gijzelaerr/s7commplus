"""Wire-level regression tests for opt-in S7-1500 FW 2.6 browse compatibility."""

import hashlib
import hmac
import json
import struct
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest

from s7commplus import Client
from s7commplus.client import _parse_read_response
from s7commplus.connection import S7CommPlusConnection
from s7commplus.protocol import DataType, FunctionCode, ProtocolVersion
from s7commplus.v1_session_key.keys import KeyFamily
from s7commplus.error import S7ConnectionError, S7IntegrityError

_KEY = bytes(range(24))
# Captured application payloads: session HMAC/header excluded. No credentials.
_RID_VALUE = bytes.fromhex("00 01 00 12 92 00 00 01 00 00 0b 00 00 00 00")
_REAL_VALUE = bytes.fromhex("00 01 00 0e 40 49 0f d0 00 00 0f 00 00 00 00")
_STRUCTURED_EXPLORE = bytes.fromhex("00 00 00 03 00 01 01 00 00 02 81 69 93 59 00 00 00 00 00")
_WILDCARD_EXPLORE = bytes.fromhex("8a 11 ff ff 00 01 00 01 00 00 0a 00 00 00 00 00")


def _connection(enabled: bool = True, *, key: bool = True) -> S7CommPlusConnection:
    conn = S7CommPlusConnection("127.0.0.1", legacy_s7_1500=enabled)
    conn._session_key = _KEY if key else None
    conn._protocol_version = ProtocolVersion.V1
    conn._connected = True
    return conn


def _frame(protected: bytes, version: int = ProtocolVersion.V3) -> bytes:
    return struct.pack(">BBH", 0x72, version, len(protected)) + protected


def _protected(data: bytes) -> bytes:
    return b"\x20" + hmac.new(_KEY, data, hashlib.sha256).digest() + data


def _legacy_fragments() -> list[bytes]:
    path = Path(__file__).parent / "fixtures/s7commplus/legacy_fragment_hmac.json"
    return [
        b"\x20" + bytes.fromhex(v["digest"]) + bytes((i * 13 + v["size"]) % 256 for i in range(v["size"]))
        for v in json.loads(path.read_text())[:3]
    ]


@pytest.mark.parametrize("override, expected", [(None, True), (True, True), (False, False)])
@pytest.mark.parametrize("key", [False, True])
def test_profile_is_automatic_for_v1_session_key_and_can_be_overridden(override: bool | None, expected: bool, key: bool) -> None:
    conn = S7CommPlusConnection("127.0.0.1", legacy_s7_1500=override)
    conn._session_key = _KEY if key else None
    conn._protocol_version = ProtocolVersion.V1
    assert conn.legacy_s7_1500 is (expected and key)


@pytest.mark.parametrize("version", [ProtocolVersion.V2, ProtocolVersion.V3])
def test_profile_never_applies_outside_v1(version: int) -> None:
    conn = S7CommPlusConnection("127.0.0.1")
    conn._session_key = _KEY
    conn._protocol_version = version
    assert conn.legacy_s7_1500 is False


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("key", [False, True])
def test_datablock_discovery_preserves_default_wire_layout(enabled: bool, key: bool) -> None:
    client = Client()
    conn = _connection(enabled, key=key)
    client._connection = conn
    conn.send_request = Mock(return_value=b"\x00")
    assert client.list_datablocks() == []
    expected = _WILDCARD_EXPLORE if key and not enabled else _STRUCTURED_EXPLORE
    conn.send_request.assert_called_once_with(FunctionCode.EXPLORE, expected, integrity_tail=5, reassemble=True)


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("multi", [False, True])
def test_symbolic_reads_use_profile_qualifier(enabled: bool, multi: bool) -> None:
    client = Client()
    conn = _connection(enabled)
    client._connection = conn
    conn.send_request = Mock(return_value=_RID_VALUE)
    if multi:
        assert client.read_symbolic_multi([(0x8A0E0001, [1])]) == [bytes.fromhex("92 00 00 01")]
    else:
        assert client.read_symbolic(0x8A0E0001, [1]) == bytes.fromhex("92 00 00 01")
    payload = conn.send_request.call_args.args[1]
    # Qualifier tail: UDINT key + terminator, followed by the request's UInt32 fill.
    expected = bytes.fromhex("89 6b 00 04") + bytes(6 if enabled else 8)
    assert payload.endswith(expected)
    assert len(payload) == (43 if enabled else 45)


@pytest.mark.parametrize("reassemble", [False, True])
@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("value", [_RID_VALUE, _REAL_VALUE])
def test_return_value_survives_framing(value: bytes, enabled: bool, reassemble: bool) -> None:
    conn = _connection(enabled)
    # Default convention has a prefix; opt-in captured replies start at ReturnValue.
    payload = value if enabled else b"\x07" + value
    header = struct.pack(">BHHHHB", 0x32, 0, FunctionCode.GET_MULTI_VARIABLES, 0, 0, 0x34)
    conn._send_s7_data = Mock()
    conn._recv_s7_data = Mock(return_value=_frame(_protected(header + payload)) + b"\x72\x03\0\0")
    response = conn.send_request(FunctionCode.GET_MULTI_VARIABLES, b"", reassemble=reassemble)
    assert response == value
    assert _parse_read_response(response) == [value[4:8]]


def test_session_challenge_prefix_behavior_is_unchanged() -> None:
    payload = b"\x07\x00\x10\x02\x14" + bytes(range(20))
    for enabled in (False, True):
        assert _connection(enabled)._response_payload(FunctionCode.GET_VAR_SUBSTREAMED, payload) == payload[1:]


def test_profile_does_not_hide_plc_read_errors() -> None:
    client = Client()
    conn = _connection()
    client._connection = conn
    conn.send_request = Mock(return_value=b"\x01")
    with pytest.raises(RuntimeError, match="Symbolic read failed"):
        client.read_symbolic(0x8A0E0001, [1])


@pytest.mark.parametrize("enabled", [False, True])
def test_reconnect_preserves_profile(enabled: bool) -> None:
    with patch("s7commplus.client.S7CommPlusConnection") as factory:
        client = Client()
        client.connect("127.0.0.1", legacy_s7_1500=enabled)
        client._open_connection()
        assert factory.call_count == 2
        for call in factory.call_args_list:
            assert call.kwargs == {"host": "127.0.0.1", "port": 102, "legacy_s7_1500": enabled, "connection_type": None}


def test_incompatible_tls_option_fails_before_network_io() -> None:
    with patch("s7commplus.client.S7CommPlusConnection") as factory:
        with pytest.raises(ValueError, match="use_tls=False"):
            Client().connect("127.0.0.1", use_tls=True, legacy_s7_1500=True)
        factory.assert_not_called()
    conn = _connection()
    conn._iso_conn.connect = Mock()
    with pytest.raises(ValueError, match="use_tls=False"):
        conn.connect(use_tls=True)
    conn._iso_conn.connect.assert_not_called()


@pytest.mark.parametrize("split", [1, 4, 37, 1024, 10000])
def test_legacy_reassembly_across_transport_chunk_boundaries(split: int) -> None:
    fragments = _legacy_fragments()
    wire = b"".join(_frame(f) for f in fragments) + b"\x72\x03\0\0"
    conn = _connection()
    conn._recv_s7_data = Mock(side_effect=[wire[i : i + split] for i in range(split, len(wire), split)])
    assert conn._recv_reassembled_payload(wire[:split]) == b"".join(f[33:] for f in fragments)


def test_default_mode_does_not_enable_legacy_hashing() -> None:
    fragments = _legacy_fragments()
    conn = _connection(False)
    with pytest.raises(S7IntegrityError, match="integrity"):
        conn._recv_reassembled_payload(b"".join(_frame(f) for f in fragments) + b"\x72\x03\0\0")


def test_independent_hmac_reassembly_still_works() -> None:
    conn = _connection(True)
    wire = _frame(_protected(b"first")) + _frame(_protected(b"second")) + b"\x72\x03\0\0"
    assert conn._recv_reassembled_payload(wire) == b"firstsecond"


@pytest.mark.parametrize("fragment_index", [0, 1, 2])
def test_reassembly_rejects_corrupted_fragments(fragment_index: int) -> None:
    fragments = _legacy_fragments()
    bad = bytearray(fragments[fragment_index])
    bad[-1] ^= 1
    fragments[fragment_index] = bytes(bad)
    with pytest.raises(S7IntegrityError, match="HMAC"):
        _connection()._recv_reassembled_payload(b"".join(_frame(f) for f in fragments) + b"\x72\x03\0\0")


@pytest.mark.parametrize("trailer", [False, True])
def test_reassembly_rejects_version_downgrade(trailer: bool) -> None:
    first = _frame(_legacy_fragments()[0])
    tail = b"\x72\x02\0\0" if trailer else _frame(b"unauthenticated", ProtocolVersion.V2)
    with pytest.raises(S7IntegrityError, match="V2"):
        _connection()._recv_reassembled_payload(first + tail)


def test_reassembly_rejects_truncated_response() -> None:
    conn = _connection()
    conn._recv_s7_data = Mock(return_value=b"")
    with pytest.raises(S7ConnectionError, match="closed"):
        conn._recv_reassembled_payload(_frame(_legacy_fragments()[0])[:-1])


def test_reassembly_still_enforces_size_limit() -> None:
    conn = _connection()
    conn._MAX_REASSEMBLED_BYTES = 8
    with pytest.raises(S7ConnectionError, match="exceeds limits"):
        conn._recv_reassembled_payload(_frame(_legacy_fragments()[0]) + b"\x72\x03\0\0")


_DB_READ_ITEM = (10, 0, 4)


@pytest.mark.parametrize("enabled", [False, True])
def test_raw_db_reads_and_writes_use_profile_qualifier(enabled: bool) -> None:
    from s7commplus.client import _build_read_payload, _build_write_payload

    client = Client()
    conn = _connection(enabled)
    client._connection = conn
    version = ProtocolVersion.V2 if enabled else ProtocolVersion.V1
    conn.send_request = Mock(return_value=_RID_VALUE)
    client.db_read(*_DB_READ_ITEM)
    assert conn.send_request.call_args.args[1] == _build_read_payload([_DB_READ_ITEM], version)
    conn.send_request = Mock(return_value=b"\x00")
    client.db_write(10, 0, b"\x3f\x80\x00\x00")
    assert conn.send_request.call_args.args[1] == _build_write_payload([(10, 0, b"\x3f\x80\x00\x00", DataType.BLOB)], version)


@pytest.mark.parametrize("enabled", [False, True])
async def test_async_raw_db_reads_use_profile_qualifier(enabled: bool) -> None:
    from s7commplus.async_client import S7CommPlusAsyncClient
    from s7commplus.client import _build_read_payload

    client = S7CommPlusAsyncClient()
    client._connection._connected = True
    client._connection._legacy_s7_1500 = enabled
    client._connection._session_key = _KEY
    client._connection._protocol_version = ProtocolVersion.V1
    client._connection.send_request = AsyncMock(return_value=_RID_VALUE)  # type: ignore[method-assign]
    await client.db_read(*_DB_READ_ITEM)
    version = ProtocolVersion.V2 if enabled else ProtocolVersion.V1
    assert client._connection.send_request.call_args.args[1] == _build_read_payload([_DB_READ_ITEM], version)


@pytest.mark.parametrize("family, skipped", [(KeyFamily.S7_1200, 1), (KeyFamily.S7_1500, 0)])
def test_s7_1200_legitimation_skips_one_integrity_id(family: KeyFamily, skipped: int) -> None:
    """Applies to family 01 under the V1 SessionKey profile only."""
    from s7commplus.async_client import S7CommPlusAsyncClient

    async_client = S7CommPlusAsyncClient()
    async_client._connection._session_key = _KEY
    async_client._connection._protocol_version = ProtocolVersion.V1
    for client in (_connection(), async_client._connection):
        client._v1_session_key_family = family
        client._integrity_id_read, client._integrity_id_write = 1, 2
        client._skip_integrity_ids_after_legitimation()
        assert (client._integrity_id_read, client._integrity_id_write) == (1 + skipped, 2 + skipped)


async def test_async_system_event_between_fragments_is_skipped() -> None:
    from s7commplus.async_client import S7CommPlusAsyncClient

    def frag(data: bytes) -> bytes:
        return _frame(data, ProtocolVersion.V2)

    event = bytes([0x72, ProtocolVersion.SYSTEM_EVENT, 0x00, 0x10]) + bytes(16)
    client = S7CommPlusAsyncClient()
    client._connection._recv_cotp_dt = AsyncMock(side_effect=[frag(b"abc"), event, frag(b"de") + b"\x72\x02\0\0"])  # type: ignore[method-assign]
    assert await client._connection._recv_reassembled_payload() == b"abcde"


@pytest.mark.parametrize("enabled", [False, True])
def test_classic_override_does_not_skip_integrity_ids(enabled: bool) -> None:
    conn = _connection(enabled)
    conn._v1_session_key_family = KeyFamily.S7_1200
    conn._integrity_id_read = conn._integrity_id_write = 1
    conn._skip_integrity_ids_after_legitimation()
    assert conn._integrity_id_read == (2 if enabled else 1)
