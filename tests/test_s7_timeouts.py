"""Connect, request, EXPLORE and notification timeouts, and what a timeout leaves of the session.

A request timeout or a frame cut off part-way closes the session (the stream
position is unknown); a notification wait that runs out before any byte of the
next frame arrived keeps it.
"""

from __future__ import annotations

import asyncio
import math
import socket
import struct
import threading
import time
from collections.abc import Iterator
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from s7commplus.async_client import S7CommPlusAsyncClient
from s7commplus.client import S7CommPlusClient
from s7commplus.codec import encode_header, encode_pvalue_blob
from s7commplus.connection import S7CommPlusConnection
from s7commplus.error import S7ConnectionError, S7TimeoutError
from s7commplus.protocol import FunctionCode, Opcode, ProtocolVersion
from s7commplus.server import S7CommPlusServer
from s7commplus.subscription import SubscriptionItem, SubscriptionRegistry
from s7commplus.transport import ISOTCPConnection, _configure_tcp_socket
from s7commplus.vlq import encode_uint32_vlq
from tests.conftest import get_free_tcp_port

# The header of a TPKT frame announcing 32 bytes; sent alone, the frame stops part-way.
PARTIAL_FRAME = b"\x03\x00\x00\x20"
COTP_CC = bytes([3, 0, 0, 11, 6, 0xD0, 0, 1, 0, 1, 0])

BAD_TIMEOUTS = [0, -1.0, math.nan, math.inf]


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise OSError("closed")
        data += chunk
    return data


class _Pipe:
    """One relayed connection; can withhold what the emulator sends, or inject bytes."""

    def __init__(self, client: socket.socket, upstream: socket.socket) -> None:
        self.client = client
        self.upstream = upstream
        self._passed: Optional[int] = None
        self._delay = 0.0
        self._lock = threading.Lock()
        for src, dst, from_server in ((client, upstream, False), (upstream, client, True)):
            threading.Thread(target=self._forward, args=(src, dst, from_server), daemon=True).start()

    def withhold_replies(self, after: int = 0) -> None:
        """Pass only the first ``after`` bytes the emulator sends from now on."""
        with self._lock:
            self._passed = after

    def delay_replies(self, seconds: float) -> None:
        """Hold back each chunk the emulator sends from now on for ``seconds``, like a slow PLC."""
        with self._lock:
            self._delay = seconds

    def inject(self, data: bytes) -> None:
        self.client.sendall(data)

    def _forward(self, src: socket.socket, dst: socket.socket, from_server: bool) -> None:
        while True:
            try:
                data = src.recv(65536)
            except OSError:
                break
            if not data:
                break
            if from_server:
                with self._lock:
                    delay = self._delay
                    if self._passed is not None:
                        data, self._passed = data[: self._passed], max(0, self._passed - len(data))
                if not data:
                    continue
                if delay:
                    time.sleep(delay)
            try:
                dst.sendall(data)
            except OSError:
                break
        self.close()

    def close(self) -> None:
        for sock in (self.client, self.upstream):
            try:
                sock.close()
            except OSError:
                pass


class _Proxy:
    """A TCP relay in front of the emulator, to make it stall like a hung PLC."""

    def __init__(self, target_port: int) -> None:
        self._target_port = target_port
        self._listener = socket.create_server(("127.0.0.1", 0))
        self.port: int = self._listener.getsockname()[1]
        self._pipes: list[_Pipe] = []
        threading.Thread(target=self._accept, daemon=True).start()

    @property
    def pipe(self) -> _Pipe:
        """The most recent connection."""
        return self._pipes[-1]

    def _accept(self) -> None:
        while True:
            try:
                client, _ = self._listener.accept()
            except OSError:
                return
            self._pipes.append(_Pipe(client, socket.create_connection(("127.0.0.1", self._target_port))))

    def close(self) -> None:
        self._listener.close()
        for pipe in self._pipes:
            pipe.close()


@pytest.fixture()
def emulator() -> Iterator[int]:
    port = get_free_tcp_port()
    server = S7CommPlusServer()
    server.register_raw_db(1, bytearray(16))
    server.start(port=port)
    time.sleep(0.1)
    yield port
    server.stop()


@pytest.fixture()
def proxy(emulator: int) -> Iterator[_Proxy]:
    relay = _Proxy(emulator)
    yield relay
    relay.close()


@pytest.fixture()
def silent_peer() -> Iterator[int]:
    """A TCP peer that accepts connections and never sends a byte."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(5)
    yield listener.getsockname()[1]
    listener.close()


@pytest.fixture()
def cotp_only_peer() -> Iterator[int]:
    """A peer that confirms the COTP connection and then never answers."""
    listener = socket.create_server(("127.0.0.1", 0))
    accepted: list[socket.socket] = []

    def serve() -> None:
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            accepted.append(conn)
            try:
                (length,) = struct.unpack(">H", _recv_exact(conn, 4)[2:])
                _recv_exact(conn, length - 4)
                conn.sendall(COTP_CC)
            except OSError:
                pass

    threading.Thread(target=serve, daemon=True).start()
    yield listener.getsockname()[1]
    listener.close()
    for conn in accepted:
        conn.close()


@pytest.fixture()
def socket_pair() -> Iterator[tuple[ISOTCPConnection, socket.socket]]:
    """A connected ISOTCPConnection and the peer socket feeding it."""
    listener = socket.create_server(("127.0.0.1", 0))
    client_sock = socket.create_connection(listener.getsockname())
    peer, _ = listener.accept()
    listener.close()
    conn = ISOTCPConnection("127.0.0.1")
    conn.socket = client_sock
    conn.connected = True
    yield conn, peer
    conn.disconnect()
    peer.close()


# --- Validation ---------------------------------------------------------------------------------


@pytest.mark.parametrize("value", BAD_TIMEOUTS)
@pytest.mark.parametrize("name", ["timeout", "request_timeout", "explore_timeout", "notification_timeout"])
def test_sync_connect_rejects_a_timeout_that_is_not_positive_and_finite(name: str, value: float) -> None:
    client = S7CommPlusClient()
    with pytest.raises(ValueError, match=f"^{name} must"):
        client.connect("127.0.0.1", port=1, **{name: value})
    assert client._connect_params is None


@pytest.mark.parametrize("value", BAD_TIMEOUTS)
@pytest.mark.parametrize("name", ["timeout", "request_timeout", "explore_timeout", "notification_timeout"])
def test_connection_connect_rejects_a_timeout_that_is_not_positive_and_finite(name: str, value: float) -> None:
    conn = S7CommPlusConnection("127.0.0.1", port=1)
    with patch.object(conn._iso_conn, "connect") as iso_connect, pytest.raises(ValueError, match=f"^{name} must"):
        conn.connect(**{name: value})
    iso_connect.assert_not_called()


@pytest.mark.parametrize("value", BAD_TIMEOUTS)
@pytest.mark.parametrize("name", ["timeout", "request_timeout", "explore_timeout", "notification_timeout"])
async def test_async_connect_rejects_a_timeout_that_is_not_positive_and_finite(name: str, value: float) -> None:
    client = S7CommPlusAsyncClient()
    with pytest.raises(ValueError, match=f"^{name} must"):
        await client.connect("127.0.0.1", port=1, **{name: value})
    assert client._connect_params is None


def test_connect_timeout_cannot_be_none() -> None:
    with pytest.raises(ValueError, match="^timeout must"):
        S7CommPlusClient().connect("127.0.0.1", port=1, timeout=None)  # type: ignore[arg-type]


# --- Plumbing -----------------------------------------------------------------------------------


def test_isotcp_connect_timeout_is_the_request_timeout_until_set() -> None:
    conn = ISOTCPConnection("127.0.0.1")
    with patch.object(conn, "_tcp_connect"), patch.object(conn, "_iso_connect"):
        conn.connect(3.0)
    assert conn.timeout == 3.0
    assert conn.request_timeout == 3.0
    conn.set_request_timeout(7.5)
    assert conn.request_timeout == 7.5


def test_client_forwards_the_timeouts_to_the_connection() -> None:
    client = S7CommPlusClient()
    with patch("s7commplus.client.S7CommPlusConnection") as factory:
        client.connect("plc", timeout=1.5, request_timeout=2.5, explore_timeout=4.5, notification_timeout=3.5)

    kwargs = factory.return_value.connect.call_args.kwargs
    assert kwargs["timeout"] == 1.5
    assert kwargs["request_timeout"] == 2.5
    assert kwargs["explore_timeout"] == 4.5
    assert kwargs["notification_timeout"] == 3.5


def test_the_request_timeout_applies_once_connected(emulator: int) -> None:
    client = S7CommPlusClient()
    client.connect("127.0.0.1", port=emulator, timeout=1.5, request_timeout=2.5)
    try:
        assert client._connection is not None
        assert client._connection._request_timeout == 2.5
        assert client._connection._iso_conn.request_timeout == 2.5
    finally:
        client.disconnect()


def test_configure_tcp_socket_enables_nodelay_and_tuned_keepalive() -> None:
    sock = MagicMock()
    _configure_tcp_socket(sock)
    options = {call.args[:2]: call.args[2] for call in sock.setsockopt.call_args_list}
    assert options[(socket.IPPROTO_TCP, socket.TCP_NODELAY)] == 1
    assert options[(socket.SOL_SOCKET, socket.SO_KEEPALIVE)] == 1
    if hasattr(socket, "TCP_KEEPIDLE"):
        assert options[(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE)] == 60


async def test_async_connect_tunes_the_socket_like_the_sync_transport(emulator: int) -> None:
    # Regression: the async client set SO_KEEPALIVE only, so a dead peer went
    # unnoticed for the OS default of about two hours.
    client = S7CommPlusAsyncClient()
    with patch("s7commplus.async_client._configure_tcp_socket") as configure:
        await client.connect("127.0.0.1", port=emulator)
    try:
        configure.assert_called_once()
    finally:
        await client.disconnect()


# --- Transport: which timeouts close the connection ---------------------------------------------


def test_receive_data_that_times_out_closes_the_connection(socket_pair: tuple[ISOTCPConnection, socket.socket]) -> None:
    conn, _ = socket_pair
    with pytest.raises(S7TimeoutError):
        conn.receive_data(0.2)
    assert not conn.connected
    assert conn.socket is None


def test_an_idle_wait_that_runs_out_keeps_the_connection(socket_pair: tuple[ISOTCPConnection, socket.socket]) -> None:
    conn, peer = socket_pair
    with pytest.raises(S7TimeoutError):
        conn.receive_data(0.2, idle_ok=True)
    assert conn.connected

    peer.sendall(bytes([3, 0, 0, 8, 2, 0xF0, 0x80, 0x72]))
    assert conn.receive_data(1.0) == b"\x72"


def test_a_frame_cut_off_part_way_closes_the_connection(socket_pair: tuple[ISOTCPConnection, socket.socket]) -> None:
    conn, peer = socket_pair
    peer.sendall(PARTIAL_FRAME)
    with pytest.raises(S7TimeoutError):
        conn.receive_data(0.3, idle_ok=True)
    assert not conn.connected


# --- Handshake ----------------------------------------------------------------------------------


def test_sync_connect_times_out_on_a_silent_peer(silent_peer: int) -> None:
    start = time.monotonic()
    with pytest.raises(S7TimeoutError):
        S7CommPlusClient().connect("127.0.0.1", port=silent_peer, timeout=0.3)
    assert time.monotonic() - start < 3


async def test_async_connect_times_out_on_a_silent_peer(silent_peer: int) -> None:
    # Regression: the async client had no timeout at all, so the COTP handshake
    # with a peer that never answered waited forever.
    start = time.monotonic()
    with pytest.raises(S7TimeoutError):
        await asyncio.wait_for(S7CommPlusAsyncClient().connect("127.0.0.1", port=silent_peer, timeout=0.3), timeout=5)
    assert time.monotonic() - start < 3


def test_sync_handshake_runs_under_the_connect_timeout(cotp_only_peer: int) -> None:
    # Regression: the socket switched to the request timeout right after COTP,
    # so InitSSL, TLS and CreateObject waited request_timeout instead.
    start = time.monotonic()
    with pytest.raises(S7TimeoutError):
        S7CommPlusClient().connect("127.0.0.1", port=cotp_only_peer, timeout=0.5, request_timeout=30.0)
    assert time.monotonic() - start < 3


async def test_async_handshake_runs_under_the_connect_timeout(cotp_only_peer: int) -> None:
    start = time.monotonic()
    with pytest.raises(S7TimeoutError):
        await asyncio.wait_for(
            S7CommPlusAsyncClient().connect("127.0.0.1", port=cotp_only_peer, timeout=0.5, request_timeout=30.0),
            timeout=10,
        )
    assert time.monotonic() - start < 3


# --- Requests: a timeout closes the session -----------------------------------------------------


@pytest.mark.parametrize("passed", [0, 4], ids=["no-reply", "reply-cut-off"])
def test_sync_request_timeout_closes_the_session(proxy: _Proxy, passed: int) -> None:
    # Regression: the transport went dead on a timeout while connected stayed
    # True, so every later request failed with "Not connected".
    client = S7CommPlusClient()
    client.connect("127.0.0.1", port=proxy.port, request_timeout=0.3)
    try:
        assert client.db_read(1, 0, 2) == b"\x00\x00"
        proxy.pipe.withhold_replies(after=passed)

        start = time.monotonic()
        with pytest.raises(S7TimeoutError):
            client.db_read(1, 0, 2)
        assert time.monotonic() - start < 3
        assert not client.connected
        assert client._connect_params is not None
        # Closed like a dropped connection, so a reconnect wrapper can take over.
        assert client._connection is not None
        with pytest.raises(S7ConnectionError, match="Not connected"):
            client.db_read(1, 0, 2)

        client._reconnect()
        assert client.db_read(1, 0, 2) == b"\x00\x00"
    finally:
        client.disconnect()


@pytest.mark.parametrize("passed", [0, 4], ids=["no-reply", "reply-cut-off"])
async def test_async_request_timeout_closes_the_session(proxy: _Proxy, passed: int) -> None:
    # Regression: an async request to a PLC that stopped answering waited forever;
    # with a timeout around it, a reply cut off after its header desynchronised
    # the stream while the session stayed open.
    client = S7CommPlusAsyncClient()
    await client.connect("127.0.0.1", port=proxy.port, request_timeout=0.3)
    try:
        assert await client.db_read(1, 0, 2) == b"\x00\x00"
        client._subscriptions.register(
            0x70400025,
            [SubscriptionItem.from_access_sequence("8A0E0007.A")],
            change_counter=1,
            credit_limit=-1,
            credit_step=0,
            queue_size=2,
        )
        client._alarm_subscription_ids.add(0x70400026)
        proxy.pipe.withhold_replies(after=passed)

        start = time.monotonic()
        with pytest.raises(S7TimeoutError):
            await asyncio.wait_for(client.db_read(1, 0, 2), timeout=5)
        assert time.monotonic() - start < 3
        assert not client.connected
        assert client._connect_params is not None
        # Closed like a dropped connection: the bookkeeping a reconnect needs stays.
        assert client._subscriptions.subscription_ids == (0x70400025,)
        assert client._subscriptions.pending_restore == ()
        assert client._alarm_subscription_ids == {0x70400026}
        with pytest.raises(S7ConnectionError, match="Not connected"):
            await client.db_read(1, 0, 2)

        await client._reconnect()
        assert await client.db_read(1, 0, 2) == b"\x00\x00"
    finally:
        await client.disconnect()


async def test_async_reassembly_times_out_when_the_plc_stops_mid_response() -> None:
    # Regression: only the first PDU of a response was bounded; a PLC that stopped
    # after it left the await hanging on the next fragment.
    client = S7CommPlusAsyncClient()
    client._request_timeout = 0.2
    client._connected = True

    async def silent() -> bytes:
        await asyncio.sleep(10)
        return b""

    client._recv_cotp_dt = silent  # type: ignore[method-assign]
    with pytest.raises(S7TimeoutError):
        await asyncio.wait_for(client._recv_reassembled_payload(b"\x72\x02\x00\x10"), timeout=5)
    assert not client.connected


async def test_async_send_the_plc_does_not_accept_times_out_and_closes_the_session() -> None:
    # Regression: drain() waited forever on a peer that stopped reading.
    client = S7CommPlusAsyncClient()
    client._request_timeout = 0.2
    client._connected = True
    client._transport_connected = True

    async def never() -> None:
        await asyncio.sleep(10)

    writer = MagicMock()
    writer.drain = never
    client._writer = writer
    client._reader = MagicMock()
    with pytest.raises(S7TimeoutError):
        await asyncio.wait_for(client._send_cotp_raw(b"\x72"), timeout=5)
    writer.transport.abort.assert_called_once_with()
    assert not client.connected
    assert client._writer is None


# --- EXPLORE timeout: a longer bound for each wait of an EXPLORE reply ---------------------------
#
# An EXPLORE reply can be large: on a CPU 1215C (FW V4.2, 6802 variables) the
# type-info EXPLORE of browse() took 5.9 to 7.0 s in total.

EXPLORE_DEFAULTS = [
    ({}, 5.0, 30.0),
    ({"request_timeout": 2.5}, 2.5, 30.0),
    ({"explore_timeout": 45.0}, 5.0, 45.0),
    ({"request_timeout": 2.5, "explore_timeout": None}, 2.5, 2.5),
    ({"timeout": 1.5, "explore_timeout": None}, 1.5, 1.5),
]


def _two_part_reply(function_code: int, sequence: int) -> list[bytes]:
    """A reply whose data comes in two parts, the second followed by the trailer, as a large EXPLORE reply does."""
    header = struct.pack(">BHHHHB", Opcode.RESPONSE, 0, function_code, 0, sequence, 0)
    first, second = header + bytes(6), bytes(6)
    trailer = bytes([0x72, ProtocolVersion.V2, 0, 0])
    return [
        encode_header(ProtocolVersion.V2, len(first)) + first,
        encode_header(ProtocolVersion.V2, len(second)) + second + trailer,
    ]


@pytest.mark.parametrize(("kwargs", "request_wait", "explore_wait"), EXPLORE_DEFAULTS)
def test_sync_explore_timeout_defaults_to_30_s_and_none_uses_the_request_timeout(
    emulator: int, kwargs: dict[str, Optional[float]], request_wait: float, explore_wait: float
) -> None:
    client = S7CommPlusClient()
    client.connect("127.0.0.1", port=emulator, **kwargs)  # type: ignore[arg-type]
    try:
        assert client._connection is not None
        assert client._connection._reply_timeout(FunctionCode.GET_MULTI_VARIABLES) == request_wait
        assert client._connection._reply_timeout(FunctionCode.EXPLORE) == explore_wait
    finally:
        client.disconnect()


@pytest.mark.parametrize(("kwargs", "request_wait", "explore_wait"), EXPLORE_DEFAULTS)
async def test_async_explore_timeout_defaults_to_30_s_and_none_uses_the_request_timeout(
    emulator: int, kwargs: dict[str, Optional[float]], request_wait: float, explore_wait: float
) -> None:
    client = S7CommPlusAsyncClient()
    await client.connect("127.0.0.1", port=emulator, **kwargs)  # type: ignore[arg-type]
    try:
        assert client._reply_timeout(FunctionCode.GET_MULTI_VARIABLES) == request_wait
        assert client._reply_timeout(FunctionCode.EXPLORE) == explore_wait
    finally:
        await client.disconnect()


def test_sync_explore_timeout_survives_a_reconnect(emulator: int) -> None:
    client = S7CommPlusClient()
    client.connect("127.0.0.1", port=emulator, request_timeout=2.5, explore_timeout=45.0)
    try:
        client._reconnect()
        assert client._connection is not None
        assert client._connection._reply_timeout(FunctionCode.EXPLORE) == 45.0
        assert client._connection._reply_timeout(FunctionCode.GET_MULTI_VARIABLES) == 2.5
    finally:
        client.disconnect()


async def test_async_explore_timeout_survives_a_reconnect(emulator: int) -> None:
    client = S7CommPlusAsyncClient()
    await client.connect("127.0.0.1", port=emulator, request_timeout=2.5, explore_timeout=45.0)
    try:
        await client._reconnect()
        assert client._reply_timeout(FunctionCode.EXPLORE) == 45.0
        assert client._reply_timeout(FunctionCode.GET_MULTI_VARIABLES) == 2.5
    finally:
        await client.disconnect()


def test_sync_explore_waits_for_the_explore_timeout_while_other_requests_do_not(proxy: _Proxy) -> None:
    # Regression: an EXPLORE reply had the 5 s of any other reply, too short
    # for a large browse() on a busy CPU.
    client = S7CommPlusClient()
    client.connect("127.0.0.1", port=proxy.port, request_timeout=0.3, explore_timeout=5.0)
    try:
        proxy.pipe.delay_replies(0.8)
        start = time.monotonic()
        assert [block["number"] for block in client.list_datablocks()] == [1]
        assert time.monotonic() - start > 0.7  # well past the request timeout
        assert client.connected

        start = time.monotonic()
        with pytest.raises(S7TimeoutError):
            client.db_read(1, 0, 2)
        assert time.monotonic() - start < 3
        assert not client.connected
    finally:
        client.disconnect()


async def test_async_explore_waits_for_the_explore_timeout_while_other_requests_do_not(proxy: _Proxy) -> None:
    client = S7CommPlusAsyncClient()
    await client.connect("127.0.0.1", port=proxy.port, request_timeout=0.3, explore_timeout=5.0)
    try:
        proxy.pipe.delay_replies(0.8)
        start = time.monotonic()
        assert [block["number"] for block in await asyncio.wait_for(client.list_datablocks(), timeout=10)] == [1]
        assert time.monotonic() - start > 0.7  # well past the request timeout
        assert client.connected

        start = time.monotonic()
        with pytest.raises(S7TimeoutError):
            await asyncio.wait_for(client.db_read(1, 0, 2), timeout=5)
        assert time.monotonic() - start < 3
        assert not client.connected
    finally:
        await client.disconnect()


def test_sync_explore_timeout_none_gives_explore_the_request_timeout(proxy: _Proxy) -> None:
    client = S7CommPlusClient()
    client.connect("127.0.0.1", port=proxy.port, request_timeout=0.3, explore_timeout=None)
    try:
        proxy.pipe.delay_replies(0.8)
        start = time.monotonic()
        with pytest.raises(S7TimeoutError):
            client.list_datablocks()
        assert time.monotonic() - start < 3
        assert not client.connected
    finally:
        client.disconnect()


async def test_async_explore_timeout_none_gives_explore_the_request_timeout(proxy: _Proxy) -> None:
    client = S7CommPlusAsyncClient()
    await client.connect("127.0.0.1", port=proxy.port, request_timeout=0.3, explore_timeout=None)
    try:
        proxy.pipe.delay_replies(0.8)
        start = time.monotonic()
        with pytest.raises(S7TimeoutError):
            await asyncio.wait_for(client.list_datablocks(), timeout=5)
        assert time.monotonic() - start < 3
        assert not client.connected
    finally:
        await client.disconnect()


def test_sync_every_part_of_an_explore_reply_gets_the_explore_timeout() -> None:
    conn = S7CommPlusConnection("127.0.0.1")
    conn._connected = True
    conn._request_timeout = 0.5
    conn._explore_timeout = 9.0
    conn._send_s7_data = MagicMock()  # type: ignore[method-assign]
    parts = _two_part_reply(FunctionCode.EXPLORE, 0) + _two_part_reply(FunctionCode.GET_MULTI_VARIABLES, 1)
    waits: list[Optional[float]] = []

    def receive(timeout: Optional[float] = None, *, idle_ok: bool = False) -> bytes:
        waits.append(timeout)
        return parts.pop(0)

    conn._recv_s7_data = receive  # type: ignore[method-assign]
    conn.send_request(FunctionCode.EXPLORE, bytes(8), integrity_tail=5, reassemble=True)
    conn.send_request(FunctionCode.GET_MULTI_VARIABLES, bytes(8), reassemble=True)

    assert not parts and None not in waits
    first, second, other_first, other_second = waits
    assert 4.5 < first <= 9.0 and second == 9.0
    assert 0.25 < other_first <= 0.5 and other_second == 0.5


async def test_async_every_part_of_an_explore_reply_gets_the_explore_timeout() -> None:
    client = S7CommPlusAsyncClient()
    client._connected = client._transport_connected = True
    client._writer = MagicMock()
    client._reader = MagicMock()
    client._send_cotp_dt = AsyncMock()  # type: ignore[method-assign]
    client._request_timeout = 0.2
    client._explore_timeout = 5.0
    parts = _two_part_reply(FunctionCode.EXPLORE, 0) + _two_part_reply(FunctionCode.GET_MULTI_VARIABLES, 1)

    async def slow_part() -> bytes:
        await asyncio.sleep(0.4)  # longer than the request timeout, well within the EXPLORE timeout
        return parts.pop(0)

    client._recv_cotp_dt = slow_part  # type: ignore[method-assign]
    await asyncio.wait_for(client._send_request(FunctionCode.EXPLORE, bytes(8), integrity_tail=5, reassemble=True), timeout=5)
    assert len(parts) == 2
    assert client.connected

    with pytest.raises(S7TimeoutError):
        await asyncio.wait_for(client._send_request(FunctionCode.GET_MULTI_VARIABLES, bytes(8), reassemble=True), timeout=5)
    assert not client.connected


def test_collect_explore_frames_waits_for_the_explore_timeout() -> None:
    conn = S7CommPlusConnection("127.0.0.1")
    conn._connected = True
    conn._explore_timeout = 9.0
    receive = MagicMock(return_value=bytes([0x72, ProtocolVersion.V2, 0, 0]))
    conn._recv_s7_data = receive  # type: ignore[method-assign]
    assert conn.collect_explore_frames(b"first") == b"first"
    receive.assert_called_once_with(9.0)


# --- Notification waits: clean unless a frame was cut off ---------------------------------------
#
# The emulator never sends an unsolicited frame, so every wait below runs out.


def test_sync_notification_wait_that_runs_out_keeps_the_session(emulator: int) -> None:
    # Regression: an expired notification wait left connected True while the
    # transport was dead, so the next request failed with "Not connected".
    client = S7CommPlusClient()
    client.connect("127.0.0.1", port=emulator, request_timeout=0.3)
    try:
        start = time.monotonic()
        with pytest.raises(S7TimeoutError):
            client.receive_subscription_notification()
        assert time.monotonic() - start < 3
        assert client.connected
        assert client.db_read(1, 0, 2) == b"\x00\x00"
    finally:
        client.disconnect()


def test_sync_notification_cut_off_part_way_closes_the_session(proxy: _Proxy) -> None:
    client = S7CommPlusClient()
    client.connect("127.0.0.1", port=proxy.port, request_timeout=0.3)
    try:
        proxy.pipe.inject(PARTIAL_FRAME)
        with pytest.raises(S7TimeoutError):
            client.receive_subscription_notification()
        assert not client.connected
    finally:
        client.disconnect()


async def test_async_notification_wait_that_runs_out_keeps_the_session(emulator: int) -> None:
    client = S7CommPlusAsyncClient()
    await client.connect("127.0.0.1", port=emulator)
    try:
        with pytest.raises(S7TimeoutError):
            await client.receive_subscription_notification(timeout=0.3)
        assert client.connected
        assert await client.db_read(1, 0, 2) == b"\x00\x00"
    finally:
        await client.disconnect()


async def test_async_notification_cut_off_part_way_closes_the_session(proxy: _Proxy) -> None:
    # Regression: the timeout cancelled the read between the TPKT header and the
    # body, dropping the header while the session stayed open.
    client = S7CommPlusAsyncClient()
    await client.connect("127.0.0.1", port=proxy.port)
    try:
        proxy.pipe.inject(PARTIAL_FRAME)
        with pytest.raises(S7TimeoutError):
            await client.receive_subscription_notification(timeout=0.3)
        assert not client.connected
    finally:
        await client.disconnect()


async def test_async_read_cancelled_part_way_closes_the_session(proxy: _Proxy) -> None:
    client = S7CommPlusAsyncClient()
    await client.connect("127.0.0.1", port=proxy.port, request_timeout=30.0)
    try:
        proxy.pipe.inject(PARTIAL_FRAME)
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(client.receive_subscription_notification(), timeout=0.5)
        assert not client.connected
    finally:
        await client.disconnect()


async def test_async_read_cancelled_before_a_frame_keeps_the_session(emulator: int) -> None:
    client = S7CommPlusAsyncClient()
    await client.connect("127.0.0.1", port=emulator, request_timeout=30.0)
    try:
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(client.receive_subscription_notification(), timeout=0.3)
        assert client.connected
        assert await client.db_read(1, 0, 2) == b"\x00\x00"
    finally:
        await client.disconnect()


# --- Notification timeout: per call, else notification_timeout, else the request timeout --------

SUBSCRIPTION_A = 0x70400025
SUBSCRIPTION_B = 0x70400026
RECEIVERS = ["receive_subscription_notification", "receive_alarm_notification"]


def _data_notification(subscription_id: int, sequence_number: int = 1) -> bytes:
    data = bytearray([Opcode.NOTIFICATION])
    data += struct.pack(">IHHH", subscription_id, 4, 0, 0)
    data += bytes([3]) + encode_uint32_vlq(sequence_number) + bytes([1])
    data += b"\x92" + struct.pack(">I", 7) + encode_pvalue_blob(b"\x12\x34")
    data += b"\x00\xaa"
    return encode_header(ProtocolVersion.V2, len(data)) + bytes(data) + bytes([0x72, ProtocolVersion.V2, 0, 0])


def _register(registry: SubscriptionRegistry, *subscription_ids: int) -> None:
    for subscription_id in subscription_ids:
        registry.register(
            subscription_id,
            [SubscriptionItem.from_access_sequence("8A0E0007.A")],
            change_counter=1,
            credit_limit=-1,
            credit_step=0,
            queue_size=2,
        )


@pytest.mark.parametrize("value", BAD_TIMEOUTS)
@pytest.mark.parametrize("receiver", RECEIVERS)
def test_sync_receivers_reject_a_bad_per_call_timeout(receiver: str, value: float) -> None:
    client = S7CommPlusClient()
    client._connection = MagicMock()
    with pytest.raises(ValueError, match="^timeout must"):
        getattr(client, receiver)(timeout=value)
    client._connection.receive_notification.assert_not_called()


@pytest.mark.parametrize("value", BAD_TIMEOUTS)
@pytest.mark.parametrize("receiver", RECEIVERS)
async def test_async_receivers_reject_a_bad_per_call_timeout(receiver: str, value: float) -> None:
    client = S7CommPlusAsyncClient()
    client._connected = True
    receive = AsyncMock()
    client._recv_cotp_dt = receive  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="^timeout must"):
        await getattr(client, receiver)(timeout=value)
    receive.assert_not_awaited()


@pytest.mark.parametrize("value", BAD_TIMEOUTS)
def test_connection_receive_notification_rejects_a_bad_timeout(value: float) -> None:
    conn = S7CommPlusConnection("127.0.0.1")
    conn._connected = True
    receive = MagicMock()
    conn._recv_s7_data = receive  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="^timeout must"):
        conn.receive_notification(timeout=value)
    receive.assert_not_called()


def test_connection_notification_wait_falls_back_to_the_request_timeout() -> None:
    conn = S7CommPlusConnection("127.0.0.1")
    conn._connected = True
    receive = MagicMock(return_value=_data_notification(SUBSCRIPTION_A))
    conn._recv_s7_data = receive  # type: ignore[method-assign]
    conn._request_timeout = 4.0
    conn.receive_notification()
    conn._notification_timeout = 9.0
    conn.receive_notification()
    conn.receive_notification(timeout=1.5)
    assert [call.args[0] for call in receive.call_args_list] == [4.0, 9.0, 1.5]
    assert all(call.kwargs == {"idle_ok": True} for call in receive.call_args_list)


def test_sync_notification_timeout_takes_precedence_over_the_request_timeout(emulator: int) -> None:
    client = S7CommPlusClient()
    client.connect("127.0.0.1", port=emulator, request_timeout=30.0, notification_timeout=0.3)
    try:
        start = time.monotonic()
        with pytest.raises(S7TimeoutError):
            client.receive_subscription_notification()
        with pytest.raises(S7TimeoutError):
            client.receive_alarm_notification()
        assert time.monotonic() - start < 4
        assert client.db_read(1, 0, 2) == b"\x00\x00"
    finally:
        client.disconnect()


def test_sync_per_call_timeout_takes_precedence_over_notification_timeout(emulator: int) -> None:
    # Regression: the sync alarm receiver took no timeout at all.
    client = S7CommPlusClient()
    client.connect("127.0.0.1", port=emulator, notification_timeout=30.0)
    try:
        start = time.monotonic()
        with pytest.raises(S7TimeoutError):
            client.receive_subscription_notification(timeout=0.2)
        with pytest.raises(S7TimeoutError):
            client.receive_alarm_notification(timeout=0.2)
        assert time.monotonic() - start < 4
    finally:
        client.disconnect()


def test_sync_per_call_timeout_applies_to_that_call_only() -> None:
    client = S7CommPlusClient()
    client._connect_params = {"timeout": 5.0, "request_timeout": None, "notification_timeout": 7.0}
    connection = MagicMock()
    connection.receive_notification.side_effect = S7TimeoutError("no notification")
    client._connection = connection
    for receiver in RECEIVERS:
        with pytest.raises(S7TimeoutError):
            getattr(client, receiver)(timeout=0.5)
        with pytest.raises(S7TimeoutError):
            getattr(client, receiver)()
    waits = [call.args[0] for call in connection.receive_notification.call_args_list]
    assert 0 < waits[0] <= 0.5 and 6.5 < waits[1] <= 7.0
    assert 0 < waits[2] <= 0.5 and 6.5 < waits[3] <= 7.0


async def test_async_notification_wait_defaults_to_the_request_timeout(emulator: int) -> None:
    # Regression: without a timeout the async waits never ended, although the
    # docs (and the sync client) use the request timeout.
    client = S7CommPlusAsyncClient()
    await client.connect("127.0.0.1", port=emulator, request_timeout=0.3)
    try:
        start = time.monotonic()
        with pytest.raises(S7TimeoutError):
            await asyncio.wait_for(client.receive_subscription_notification(), timeout=5)
        with pytest.raises(S7TimeoutError):
            await asyncio.wait_for(client.receive_alarm_notification(), timeout=5)
        assert time.monotonic() - start < 4
        assert client.connected
    finally:
        await client.disconnect()


async def test_async_notification_timeout_and_per_call_timeout_take_precedence(emulator: int) -> None:
    client = S7CommPlusAsyncClient()
    await client.connect("127.0.0.1", port=emulator, request_timeout=30.0, notification_timeout=0.3)
    try:
        start = time.monotonic()
        with pytest.raises(S7TimeoutError):
            await asyncio.wait_for(client.receive_alarm_notification(), timeout=5)
        with pytest.raises(S7TimeoutError):
            await asyncio.wait_for(client.receive_subscription_notification(timeout=0.2), timeout=5)
        assert time.monotonic() - start < 4
    finally:
        await client.disconnect()


@pytest.mark.parametrize("receiver", RECEIVERS)
def test_sync_notification_wait_bounds_the_whole_call(receiver: str) -> None:
    # Regression: the wait restarted with every frame, so a wait for one
    # subscription never ended while another one kept notifying.
    client = S7CommPlusClient()
    _register(client._subscriptions, SUBSCRIPTION_A, SUBSCRIPTION_B)
    frames = 0

    def other_subscription(timeout: float) -> bytes:
        nonlocal frames
        frames += 1
        assert frames < 200, "the wait never ended"
        time.sleep(0.02)
        return _data_notification(SUBSCRIPTION_B, frames)

    connection = MagicMock()
    connection.receive_notification.side_effect = other_subscription
    client._connection = connection
    start = time.monotonic()
    with pytest.raises(S7TimeoutError):
        if receiver == RECEIVERS[0]:
            client.receive_subscription_notification(SUBSCRIPTION_A, timeout=0.3)
        else:
            client.receive_alarm_notification(timeout=0.3)
    assert time.monotonic() - start < 3


@pytest.mark.parametrize("receiver", RECEIVERS)
async def test_async_notification_wait_bounds_the_whole_call(receiver: str) -> None:
    client = S7CommPlusAsyncClient()
    client._connected = True
    _register(client._subscriptions, SUBSCRIPTION_A, SUBSCRIPTION_B)
    frames = 0

    async def other_subscription() -> bytes:
        nonlocal frames
        frames += 1
        await asyncio.sleep(0.02)
        return _data_notification(SUBSCRIPTION_B, frames)

    client._recv_cotp_dt = other_subscription  # type: ignore[method-assign]
    start = time.monotonic()
    with pytest.raises(S7TimeoutError):
        if receiver == RECEIVERS[0]:
            await asyncio.wait_for(client.receive_subscription_notification(SUBSCRIPTION_A, timeout=0.3), timeout=5)
        else:
            await asyncio.wait_for(client.receive_alarm_notification(timeout=0.3), timeout=5)
    assert time.monotonic() - start < 3
    assert client.connected
