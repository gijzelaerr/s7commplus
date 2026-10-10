"""V1 SessionKey support in the async client, mirroring the synchronous tests."""

from __future__ import annotations

import asyncio
import inspect
import struct
import time
from collections.abc import Generator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from s7commplus.async_client import S7CommPlusAsyncClient
from s7commplus.client import _LEGACY_KEY_CACHE, S7CommPlusClient
from s7commplus.codec import encode_header
from s7commplus.connection import (
    FamilyOnlyFingerprintError,
    SessionKeyCandidateRejectedError,
    _frame_request,
)
from s7commplus.error import S7ConnectionError, S7IntegrityError
from s7commplus.protocol import DataType, FunctionCode, LegitimationId, Opcode, ProtocolVersion
from s7commplus.server import S7CommPlusServer
from s7commplus.v1_session_key.keys import KeyFamily
from s7commplus.vlq import encode_uint32_vlq
from tests.conftest import get_free_tcp_port

TEST_FINGERPRINT = "01:BD426B091F08731A"
TEST_CHALLENGE = bytes(range(20))
TEST_SESSION_KEY = bytes(range(24))


@pytest.fixture(autouse=True)
def clear_key_cache() -> None:
    _LEGACY_KEY_CACHE.clear()


# --- Against the SessionKey emulator ---


@pytest.fixture()
def session_key_server(monkeypatch: pytest.MonkeyPatch) -> Generator[tuple[S7CommPlusServer, int], None, None]:
    # The emulator does not own Siemens' private key, so make the client-side
    # key exchange deterministic and configure the matching negotiated key.
    from s7commplus.v1_session_key import handshake, legitimation

    def authenticate(challenge: bytes, public_key: bytes, family: int) -> tuple[bytes, bytes]:
        assert challenge == TEST_CHALLENGE
        assert public_key
        assert int(family) == 1
        return bytes(180), TEST_SESSION_KEY

    monkeypatch.setattr(handshake, "authenticate_real_plc", authenticate)
    monkeypatch.setattr(legitimation, "solve_legitimate_challenge_real_plc", lambda *args: bytes(248))
    srv = S7CommPlusServer(
        public_key_fingerprint=TEST_FINGERPRINT,
        session_challenge=TEST_CHALLENGE,
        session_key=TEST_SESSION_KEY,
    )
    srv.register_db(1, {"temperature": ("Real", 0)})
    db1 = srv.get_db(1)
    assert db1 is not None
    struct.pack_into(">f", db1.data, 0, 23.5)
    port = get_free_tcp_port()
    srv.start(port=port)
    time.sleep(0.1)
    yield srv, port
    srv.stop()


@pytest.mark.asyncio
async def test_async_session_setup_installs_the_session_key(session_key_server: tuple[S7CommPlusServer, int]) -> None:
    server, port = session_key_server
    client = S7CommPlusAsyncClient()
    await client.connect("127.0.0.1", port=port)
    try:
        assert client.connected
        assert client.session_setup_ok
        assert client._session_key == TEST_SESSION_KEY
        assert client._v1_session_key_family == KeyFamily.S7_1200
        assert server._accepted_session_key_setups == 1
    finally:
        await client.disconnect()
    assert client._session_key is None


@pytest.mark.asyncio
async def test_async_connect_without_password_skips_legitimation(
    session_key_server: tuple[S7CommPlusServer, int],
) -> None:
    # An S7-1200 (key family 01) rejects an empty-password legitimation but serves
    # reads without one, so no password must mean no legitimation is sent.
    _, port = session_key_server
    client = S7CommPlusAsyncClient()
    with patch.object(S7CommPlusAsyncClient, "_post_auth_legitimation", new_callable=AsyncMock) as legit:
        await client.connect("127.0.0.1", port=port)
        try:
            legit.assert_not_awaited()
            assert len(await client.db_read(1, 0, 4)) == 4
        finally:
            await client.disconnect()


@pytest.mark.asyncio
async def test_async_connect_with_password_sends_legitimation(session_key_server: tuple[S7CommPlusServer, int]) -> None:
    _, port = session_key_server
    client = S7CommPlusAsyncClient()
    with patch.object(S7CommPlusAsyncClient, "_post_auth_legitimation", new_callable=AsyncMock) as legit:
        await client.connect("127.0.0.1", port=port, password="secret")
        try:
            legit.assert_awaited_once_with("secret")
        finally:
            await client.disconnect()


def test_sync_connect_without_password_skips_legitimation(session_key_server: tuple[S7CommPlusServer, int]) -> None:
    _, port = session_key_server
    client = S7CommPlusClient()
    with patch("s7commplus.connection.S7CommPlusConnection._post_auth_legitimation") as legit:
        client.connect("127.0.0.1", port=port)
        try:
            legit.assert_not_called()
            assert len(client.db_read(1, 0, 4)) == 4
        finally:
            client.disconnect()


@pytest.mark.asyncio
async def test_async_read_write_after_session_setup(session_key_server: tuple[S7CommPlusServer, int]) -> None:
    _, port = session_key_server
    client = S7CommPlusAsyncClient()
    await client.connect("127.0.0.1", port=port)
    try:
        assert abs(struct.unpack(">f", await client.db_read(1, 0, 4))[0] - 23.5) < 0.001
        await client.db_write(1, 0, struct.pack(">f", 42.0))
        assert abs(struct.unpack(">f", await client.db_read(1, 0, 4))[0] - 42.0) < 0.001
    finally:
        await client.disconnect()


@pytest.mark.asyncio
async def test_async_explore_after_session_setup(session_key_server: tuple[S7CommPlusServer, int]) -> None:
    """Explore reassembly verifies the V3 HMAC and removes the response IntegrityId."""
    _, port = session_key_server
    client = S7CommPlusAsyncClient()
    await client.connect("127.0.0.1", port=port)
    try:
        assert await client.list_datablocks() == [
            {
                "name": "DB1",
                "number": 1,
                "rid": 0x8A0E0001,
                "language": None,
                "knowhow_protected": False,
                "unlinked": False,
            }
        ]
    finally:
        await client.disconnect()


@pytest.mark.asyncio
async def test_async_unknown_fingerprint_cannot_bypass_session_key_setup() -> None:
    srv = S7CommPlusServer(
        public_key_fingerprint="01:0000000000000000",
        session_challenge=TEST_CHALLENGE,
        session_key=TEST_SESSION_KEY,
    )
    port = get_free_tcp_port()
    srv.start(port=port)
    time.sleep(0.1)
    client = S7CommPlusAsyncClient()
    try:
        with pytest.raises(S7ConnectionError, match="session setup was rejected"):
            await client.connect("127.0.0.1", port=port)
        assert client._session_key is None
        assert not client.session_setup_ok
        assert srv._accepted_session_key_setups == 0
    finally:
        await client.disconnect()
        srv.stop()


# --- Same-family key fallback, as in test_s7_family_key_fallback ---


def _fallback_client(effect) -> tuple[S7CommPlusAsyncClient, list[str | None]]:  # type: ignore[no-untyped-def]
    client = S7CommPlusAsyncClient()
    attempts: list[str | None] = []

    async def open_once(fingerprint: str | None = None) -> None:
        attempts.append(fingerprint)
        effect(fingerprint)

    client._open_connection_once = open_once  # type: ignore[method-assign]
    return client, attempts


@pytest.mark.asyncio
async def test_async_complete_fingerprint_path_does_not_probe() -> None:
    client, attempts = _fallback_client(lambda _fingerprint: None)
    await client.connect("plc")
    assert attempts == [None]


@pytest.mark.asyncio
async def test_async_family_only_identifier_tries_same_family_candidates() -> None:
    def effect(fingerprint: str | None) -> None:
        if fingerprint is None:
            raise FamilyOnlyFingerprintError(KeyFamily.S7_1200)
        if fingerprint != "01:GOOD":
            raise SessionKeyCandidateRejectedError("rejected")

    client, attempts = _fallback_client(effect)
    with patch("s7commplus.v1_session_key.keys.fingerprints_for_family", return_value=("01:BAD", "01:GOOD")):
        await client.connect("plc")

    assert attempts == [None, "01:BAD", "01:GOOD"]
    assert _LEGACY_KEY_CACHE[("plc", 102)] == "01:GOOD"


@pytest.mark.asyncio
async def test_async_rejected_cached_candidate_probes_the_rest_of_the_family() -> None:
    _LEGACY_KEY_CACHE[("plc", 102)] = "01:BD426B091F08731A"

    def effect(fingerprint: str | None) -> None:
        if fingerprint == "01:BD426B091F08731A":
            raise SessionKeyCandidateRejectedError("rejected")

    client, attempts = _fallback_client(effect)
    with patch("s7commplus.v1_session_key.keys.fingerprints_for_family", return_value=("01:BD426B091F08731A", "01:OTHER")):
        await client.connect("plc")

    assert attempts == ["01:BD426B091F08731A", "01:OTHER"]
    assert _LEGACY_KEY_CACHE[("plc", 102)] == "01:OTHER"


@pytest.mark.asyncio
async def test_async_disabled_fallback_fails_without_probing() -> None:
    def effect(_fingerprint: str | None) -> None:
        raise FamilyOnlyFingerprintError(KeyFamily.S7_1500)

    client, attempts = _fallback_client(effect)
    with pytest.raises(S7ConnectionError, match="legacy key fallback is disabled"):
        await client.connect("plc", allow_legacy_key_fallback=False)
    assert attempts == [None]
    assert client._connect_params is None


# --- Framing, integrity and renewal on an authenticated session ---


def _authenticated_client() -> S7CommPlusAsyncClient:
    client = S7CommPlusAsyncClient()
    client._connected = True
    client._session_ready = True
    client._transport_connected = True
    client._reader = MagicMock()
    client._writer = MagicMock()
    client._writer.wait_closed = AsyncMock()
    client._protocol_version = ProtocolVersion.V1
    client._session_id = 0x70000FDC
    client._session_key = b"o" * 24
    client._v1_session_key_public_key = b"p" * 40
    client._v1_session_key_family = KeyFamily.S7_1500
    client._delete_session = AsyncMock()  # type: ignore[method-assign]
    return client


@pytest.mark.asyncio
async def test_async_session_key_request_frame_matches_the_sync_layout() -> None:
    client = _authenticated_client()
    client._send_cotp_dt = AsyncMock()  # type: ignore[method-assign]
    client._recv_cotp_dt = AsyncMock(side_effect=OSError("no reply"))  # type: ignore[method-assign]

    with pytest.raises(OSError, match="no reply"):
        await client._send_request(FunctionCode.GET_VARIABLE, bytes(4))

    request = struct.pack(">BHHHHIB", Opcode.REQUEST, 0, FunctionCode.GET_VARIABLE, 0, 0, 0x70000FDC, 0x34)
    request += bytes(4)
    frame = client._send_cotp_dt.call_args[0][0]
    assert frame == _frame_request(request, ProtocolVersion.V1, b"o" * 24)
    assert frame[:4] == encode_header(ProtocolVersion.V3, len(frame) - 8)
    assert frame[4] == 0x20  # hash-length marker before the 32-byte HMAC digest


@pytest.mark.asyncio
async def test_async_forged_response_invalidates_the_session() -> None:
    client = _authenticated_client()
    client._send_cotp_dt = AsyncMock()  # type: ignore[method-assign]
    response = bytes([Opcode.RESPONSE, 0, 0]) + struct.pack(">HHH", FunctionCode.GET_VARIABLE, 0, 0) + bytes([0x00])
    protected = bytes([0x20]) + bytes(32) + response  # wrong digest
    frame = encode_header(ProtocolVersion.V3, len(protected)) + protected
    client._recv_cotp_dt = AsyncMock(return_value=frame)  # type: ignore[method-assign]

    with pytest.raises(S7IntegrityError):
        await client._send_request(FunctionCode.GET_VARIABLE, bytes(4))
    assert not client._session_ready
    assert client._session_key is None
    assert client._writer is None


@pytest.mark.asyncio
async def test_async_renewal_installs_key_only_after_accepted_old_key_response() -> None:
    client = _authenticated_client()
    challenge_response = bytes([0x00, 0x00, 0x10, DataType.USINT, len(TEST_CHALLENGE)]) + TEST_CHALLENGE
    old_key = client._session_key
    keys_during_exchange: list[bytes | None] = []

    async def exchange(*_args: object) -> bytes:
        keys_during_exchange.append(client._session_key)
        return challenge_response if len(keys_during_exchange) == 1 else b"\x00"

    client._send_request_locked = AsyncMock(side_effect=exchange)  # type: ignore[method-assign]
    with patch("s7commplus.v1_session_key.handshake.authenticate_real_plc", return_value=(b"b" * 180, b"n" * 24)):
        await client._renew_session_key_locked()

    assert keys_during_exchange == [old_key, old_key]
    assert client._session_key == b"n" * 24
    renewal_call = client._send_request_locked.call_args_list[1]
    assert renewal_call.args[0] == FunctionCode.SET_VARIABLE
    assert encode_uint32_vlq(LegitimationId.SESSION_SETUP_LEGITIMATION) in renewal_call.args[1]


@pytest.mark.asyncio
async def test_async_rejected_renewal_never_installs_generated_key() -> None:
    client = _authenticated_client()
    challenge_response = bytes([0x00, 0x00, 0x10, DataType.USINT, len(TEST_CHALLENGE)]) + TEST_CHALLENGE
    old_key = client._session_key
    client._send_request_locked = AsyncMock(side_effect=[challenge_response, encode_uint32_vlq(0x8104)])  # type: ignore[method-assign]

    with (
        patch("s7commplus.v1_session_key.handshake.authenticate_real_plc", return_value=(b"b" * 180, b"n" * 24)),
        pytest.raises(S7ConnectionError, match="return_value=0x8104"),
    ):
        await client._renew_session_key_locked()
    assert client._session_key == old_key


@pytest.mark.asyncio
async def test_async_short_interval_renews_and_disconnect_stops_it() -> None:
    client = _authenticated_client()
    client._session_key_refresh_interval = 0.01
    renewed = asyncio.Event()
    client._renew_session_key_locked = AsyncMock(side_effect=renewed.set)  # type: ignore[method-assign]
    client._schedule_session_key_refresh()

    await asyncio.wait_for(renewed.wait(), 1)
    task = client._session_key_refresh_task
    assert task is not None
    await client.disconnect()
    await asyncio.sleep(0)
    assert task.cancelled() or task.done()
    assert client._session_key_refresh_task is None


@pytest.mark.asyncio
async def test_async_refresh_failure_is_terminal_and_surfaces_on_next_request() -> None:
    client = _authenticated_client()
    client._session_key_refresh_interval = 0.01
    client._renew_session_key_locked = AsyncMock(side_effect=S7ConnectionError("PLC rejected key"))  # type: ignore[method-assign]
    client._schedule_session_key_refresh()
    task = client._session_key_refresh_task
    assert task is not None
    await asyncio.wait_for(task, 1)

    assert not client.connected
    client._delete_session.assert_not_awaited()
    with pytest.raises(S7ConnectionError, match="renewal failed: PLC rejected key"):
        await client._send_request(FunctionCode.GET_VARIABLE, bytes(4))


@pytest.mark.asyncio
async def test_async_plcsim_family_does_not_schedule_renewal() -> None:
    from s7commplus.v1_session_key.keys import KeyFamily

    client = _authenticated_client()
    client._v1_session_key_family = KeyFamily.PLCSIM
    client._session_key_refresh_interval = 0.01
    client._schedule_session_key_refresh()
    # PLCSIM resets the connection on a renewal SecurityKey write.
    assert client._session_key_refresh_task is None


# --- Public API parity ---


def test_async_connect_accepts_the_sync_connect_options() -> None:
    sync_options = set(inspect.signature(S7CommPlusClient.connect).parameters) - {"self"}
    async_options = set(inspect.signature(S7CommPlusAsyncClient.connect).parameters) - {"self"}
    assert sync_options <= async_options


@pytest.mark.asyncio
async def test_async_connect_validates_like_the_sync_client() -> None:
    client = S7CommPlusAsyncClient()
    with pytest.raises(ValueError, match="legacy_s7_1500 requires use_tls=False"):
        await client.connect("plc", use_tls=True, legacy_s7_1500=True)
    with pytest.raises(ValueError, match="positive or None"):
        await client.connect("plc", legacy_session_key_refresh_interval=0)
