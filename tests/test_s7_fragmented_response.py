"""A response the PLC splits over several PDUs is reassembled, not truncated.

PLCSIM Advanced (CPU 1511, FW V2.9) answers a GetMultiVariables of 19 String[254] in
several PDUs; reading only the first returned 4 items and left the rest in the stream.
"""

from __future__ import annotations

import json
import struct
import time
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from s7commplus.async_client import S7CommPlusAsyncClient
from s7commplus.client import _LEGACY_KEY_CACHE, S7CommPlusClient
from s7commplus.codec import encode_header
from s7commplus.connection import S7CommPlusConnection, _response_continues
from s7commplus.error import S7ConnectionError
from s7commplus.protocol import FunctionCode, Opcode, ProtocolVersion
from s7commplus.server import S7CommPlusServer
from tests.conftest import get_free_tcp_port

FRAGMENT_PORT = 11191

TEST_FINGERPRINT = "01:BD426B091F08731A"
TEST_CHALLENGE = bytes(range(20))
TEST_SESSION_KEY = bytes(range(24))

V2_TRAILER = struct.pack(">BBH", 0x72, ProtocolVersion.V2, 0)


def _v2_pdu(data: bytes, trailer: bool = True) -> bytes:
    return encode_header(ProtocolVersion.V2, len(data)) + data + (V2_TRAILER if trailer else b"")


def _response(sequence: int, body: bytes = b"") -> bytes:
    return struct.pack(">BHHHHB", Opcode.RESPONSE, 0, FunctionCode.GET_MULTI_VARIABLES, 0, sequence, 0x34) + body


def test_response_continues_detects_a_missing_trailer() -> None:
    data = b"\x31" + bytes(20)
    complete = encode_header(ProtocolVersion.V2, len(data)) + data + V2_TRAILER
    assert not _response_continues(complete)
    assert not _response_continues(complete + b"\x72\x02\x00\x05")  # bytes after the trailer are not judged
    assert _response_continues(complete[:-4])  # a fragment: more PDUs follow
    assert _response_continues(complete[:-2])  # a partial trailer: the rest is still to come
    assert not _response_continues(b"\x72")  # too short to judge: let the normal path report it


def test_response_continues_compares_the_trailer_bytes() -> None:
    # Four or more bytes after the data are only a trailer if they are 72 <ver> 00 00;
    # anything else goes to reassembly, which validates it.
    data = b"\x31" + bytes(20)
    fragment = encode_header(ProtocolVersion.V2, len(data)) + data
    assert _response_continues(fragment + b"\x72\x02\x00\x10" + bytes(16))  # the next fragment's header
    assert _response_continues(fragment + b"\x72\x01\x00\x00")  # a trailer of another version
    assert _response_continues(fragment + bytes(4))


@pytest.fixture()
def fragmenting_server() -> Iterator[S7CommPlusServer]:
    server = S7CommPlusServer(max_response_pdu=64)
    server.register_raw_db(2, bytearray(range(256)))
    server.start(port=FRAGMENT_PORT)
    time.sleep(0.1)
    yield server
    server.stop()


def test_server_rejects_a_non_positive_response_pdu() -> None:
    with pytest.raises(ValueError, match="max_response_pdu"):
        S7CommPlusServer(max_response_pdu=0)


def test_sync_reads_a_response_split_over_several_pdus(fragmenting_server: S7CommPlusServer) -> None:
    client = S7CommPlusClient()
    client.connect("127.0.0.1", port=FRAGMENT_PORT)
    try:
        assert client.db_read(2, 0, 200) == bytes(range(200))
        # The session stays in step: the next request gets its own response.
        assert client.db_read_multi([(2, 10, 2), (2, 250, 6)]) == [bytes([10, 11]), bytes(range(250, 256))]
    finally:
        client.disconnect()


@pytest.mark.asyncio
async def test_async_reads_a_response_split_over_several_pdus(fragmenting_server: S7CommPlusServer) -> None:
    client = S7CommPlusAsyncClient()
    await client.connect("127.0.0.1", port=FRAGMENT_PORT)
    try:
        assert await client.db_read(2, 0, 200) == bytes(range(200))
        assert await client.db_read_multi([(2, 10, 2), (2, 250, 6)]) == [bytes([10, 11]), bytes(range(250, 256))]
    finally:
        await client.disconnect()


@pytest.fixture()
def tiny_pdu_server_port() -> Iterator[int]:
    # Smaller than the InitSSL, CreateObject and session setup replies, which the
    # clients read as one PDU: the emulator splits only the responses after them.
    server = S7CommPlusServer(max_response_pdu=8)
    server.register_raw_db(2, bytearray(range(256)))
    port = get_free_tcp_port()
    server.start(port=port)
    time.sleep(0.1)
    yield port
    server.stop()


def test_sync_session_setup_replies_are_not_split(tiny_pdu_server_port: int) -> None:
    client = S7CommPlusClient()
    client.connect("127.0.0.1", port=tiny_pdu_server_port)
    try:
        assert client.db_read(2, 0, 40) == bytes(range(40))
    finally:
        client.disconnect()


@pytest.mark.asyncio
async def test_async_session_setup_replies_are_not_split(tiny_pdu_server_port: int) -> None:
    client = S7CommPlusAsyncClient()
    await client.connect("127.0.0.1", port=tiny_pdu_server_port)
    try:
        assert await client.db_read(2, 0, 40) == bytes(range(40))
    finally:
        await client.disconnect()


# --- Authenticated (V3) responses: later fragments carry the legacy continuation digest ---


def test_emulator_signs_v3_fragments_as_the_openssl_vectors() -> None:
    # The vectors were generated with OpenSSL, independently of library code
    # (fixtures/s7commplus/generate_legacy_hmac_vectors.py).
    vectors = json.loads((Path(__file__).parent / "fixtures/s7commplus/legacy_fragment_hmac.json").read_text())
    pieces = [bytes((i * 13 + vector["size"]) % 256 for i in range(vector["size"])) for vector in vectors]
    protected = S7CommPlusServer._protect_v3_fragments(bytes(range(24)), pieces)
    assert [fragment[:1] for fragment in protected] == [b"\x20"] * len(vectors)
    assert [fragment[1:33].hex() for fragment in protected] == [vector["digest"] for vector in vectors]
    assert [fragment[33:] for fragment in protected] == pieces


@pytest.fixture()
def fragmenting_v3_server(monkeypatch: pytest.MonkeyPatch) -> Iterator[int]:
    # As in test_s7_async_session_key: the emulator cannot recover the client's key
    # from a blob encrypted for a real PLC, so pin the client side of the exchange.
    from s7commplus.v1_session_key import handshake

    monkeypatch.setattr(handshake, "authenticate_real_plc", lambda *_args: (bytes(180), TEST_SESSION_KEY))
    _LEGACY_KEY_CACHE.clear()
    server = S7CommPlusServer(
        public_key_fingerprint=TEST_FINGERPRINT,
        session_challenge=TEST_CHALLENGE,
        session_key=TEST_SESSION_KEY,
        max_response_pdu=64,
    )
    server.register_raw_db(2, bytearray(range(256)))
    port = get_free_tcp_port()
    server.start(port=port)
    time.sleep(0.1)
    yield port
    server.stop()
    _LEGACY_KEY_CACHE.clear()


def test_sync_reads_an_authenticated_response_split_over_several_pdus(fragmenting_v3_server: int) -> None:
    client = S7CommPlusClient()
    client.connect("127.0.0.1", port=fragmenting_v3_server)
    try:
        connection = client._connection
        assert connection is not None
        assert connection._session_key == TEST_SESSION_KEY
        reassembled: list[bytes] = []
        reassemble = connection._recv_reassembled_payload

        def spy(initial_data: bytes = b"") -> bytes:
            reassembled.append(initial_data)
            return reassemble(initial_data)

        connection._recv_reassembled_payload = spy  # type: ignore[method-assign]
        assert client.db_read(2, 0, 200) == bytes(range(200))
        assert [frame[1] for frame in reassembled] == [ProtocolVersion.V3]
        assert client.db_read_multi([(2, 10, 2), (2, 250, 6)]) == [bytes([10, 11]), bytes(range(250, 256))]
    finally:
        client.disconnect()


@pytest.mark.asyncio
async def test_async_reads_an_authenticated_response_split_over_several_pdus(fragmenting_v3_server: int) -> None:
    client = S7CommPlusAsyncClient()
    await client.connect("127.0.0.1", port=fragmenting_v3_server)
    try:
        assert client._session_key == TEST_SESSION_KEY
        reassembled: list[bytes] = []
        reassemble = client._recv_reassembled_payload

        async def spy(initial_data: bytes = b"") -> bytes:
            reassembled.append(initial_data)
            return await reassemble(initial_data)

        client._recv_reassembled_payload = spy  # type: ignore[method-assign]
        assert await client.db_read(2, 0, 200) == bytes(range(200))
        assert [frame[1] for frame in reassembled] == [ProtocolVersion.V3]
        assert await client.db_read_multi([(2, 10, 2), (2, 250, 6)]) == [bytes([10, 11]), bytes(range(250, 256))]
    finally:
        await client.disconnect()


# --- Stream handling around a split response ---


def _sync_connection(*frames: bytes) -> S7CommPlusConnection:
    conn = S7CommPlusConnection("127.0.0.1")
    conn._connected = True
    conn._protocol_version = ProtocolVersion.V2
    conn._sequence_number = 5
    conn._send_s7_data = MagicMock()  # type: ignore[method-assign]
    conn._recv_s7_data = MagicMock(side_effect=list(frames))  # type: ignore[method-assign]
    return conn


def _async_client(*frames: bytes) -> S7CommPlusAsyncClient:
    client = S7CommPlusAsyncClient()
    client._connected = True
    client._reader = MagicMock()
    client._writer = MagicMock()
    client._protocol_version = ProtocolVersion.V2
    client._sequence_number = 5
    client._send_cotp_dt = AsyncMock()  # type: ignore[method-assign]
    client._recv_cotp_dt = AsyncMock(side_effect=list(frames))  # type: ignore[method-assign]
    return client


# A stale response (sequence 4) split over two PDUs, then the awaited one (sequence 5).
STALE_SPLIT = (_v2_pdu(_response(4, b"\x01\x02"), trailer=False), _v2_pdu(b"\xee" * 12))
CURRENT = _v2_pdu(_response(5, b"\xaa\xbb"))


def test_sync_drains_a_split_stale_response() -> None:
    conn = _sync_connection(*STALE_SPLIT, CURRENT)
    assert conn.send_request(FunctionCode.GET_MULTI_VARIABLES) == b"\xaa\xbb"
    assert conn._recv_s7_data.call_count == 3  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_async_drains_a_split_stale_response() -> None:
    client = _async_client(*STALE_SPLIT, CURRENT)
    assert await client._send_request(FunctionCode.GET_MULTI_VARIABLES, b"") == b"\xaa\xbb"
    assert client._recv_cotp_dt.await_count == 3  # type: ignore[attr-defined]


# The first read carries a whole fragment and the start of the next one: what follows
# the first fragment's data is a fragment header, not the trailer.
_SPLIT_DATA = _response(5, bytes(range(40)))
_SECOND = encode_header(ProtocolVersion.V2, len(_SPLIT_DATA) - 20) + _SPLIT_DATA[20:]
RUN_ON_READS = (encode_header(ProtocolVersion.V2, 20) + _SPLIT_DATA[:20] + _SECOND[:10], _SECOND[10:] + V2_TRAILER)


def test_sync_reassembles_when_the_next_fragment_follows_in_the_same_read() -> None:
    conn = _sync_connection(*RUN_ON_READS)
    assert conn.send_request(FunctionCode.GET_MULTI_VARIABLES) == bytes(range(40))


@pytest.mark.asyncio
async def test_async_reassembles_when_the_next_fragment_follows_in_the_same_read() -> None:
    client = _async_client(*RUN_ON_READS)
    assert await client._send_request(FunctionCode.GET_MULTI_VARIABLES, b"") == bytes(range(40))


# A fragment followed by a "trailer" that names another protocol version.
WRONG_VERSION_TRAILER = _v2_pdu(_response(5, b"\xaa\xbb"), trailer=False) + b"\x72\x01\x00\x00"


def test_sync_reassembly_rejects_a_trailer_of_another_version() -> None:
    conn = _sync_connection()
    with pytest.raises(S7ConnectionError, match="fragment version"):
        conn._recv_reassembled_payload(WRONG_VERSION_TRAILER)


@pytest.mark.asyncio
async def test_async_reassembly_rejects_a_trailer_of_another_version() -> None:
    client = _async_client()
    with pytest.raises(S7ConnectionError, match="fragment version"):
        await client._recv_reassembled_payload(WRONG_VERSION_TRAILER)
