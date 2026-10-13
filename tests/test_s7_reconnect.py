"""reconnect(): rebuild the session with the parameters of the last connect()."""

from __future__ import annotations

import asyncio
import os
import time
from collections.abc import Iterator
from contextlib import ExitStack
from unittest.mock import AsyncMock, patch

import pytest

from s7commplus.async_client import S7CommPlusAsyncClient
from s7commplus.client import S7CommPlusClient
from s7commplus.error import S7ConnectionError
from s7commplus.protocol import LegitimationType, ProtocolVersion
from s7commplus.server import S7CommPlusServer
from tests.conftest import get_free_tcp_port
from tests.test_s7_tls import _generate_self_signed_cert

DB1 = b"\x01\x02\x03\x04"


def _start(srv: S7CommPlusServer, port: int, **kwargs: object) -> None:
    srv.start(host="127.0.0.1", port=port, **kwargs)  # type: ignore[arg-type]
    time.sleep(0.1)


@pytest.fixture()
def server() -> Iterator[tuple[S7CommPlusServer, int]]:
    port = get_free_tcp_port()
    srv = S7CommPlusServer()
    srv.register_raw_db(1, bytearray(DB1))
    _start(srv, port)
    yield srv, port
    srv.stop()


@pytest.fixture()
def tls_server() -> Iterator[tuple[int, str]]:
    cert_path, key_path = _generate_self_signed_cert()
    port = get_free_tcp_port()
    srv = S7CommPlusServer(protocol_version=ProtocolVersion.V2)
    srv.register_raw_db(1, bytearray(DB1))
    _start(srv, port, use_tls=True, tls_cert=cert_path, tls_key=key_path)
    yield port, cert_path
    srv.stop()
    os.unlink(cert_path)
    os.unlink(key_path)


def test_sync_reconnect_rebuilds_the_session(server: tuple[S7CommPlusServer, int]) -> None:
    _, port = server
    client = S7CommPlusClient()
    client.connect("127.0.0.1", port=port)
    try:
        first_session = client.session_id
        assert client.connection_generation == 0
        client.reconnect()
        assert client.connection_generation == 1
        assert client.connected and client.session_id != first_session
        assert client.db_read(1, 0, 4) == DB1
    finally:
        client.disconnect()


async def test_async_reconnect_rebuilds_the_session(server: tuple[S7CommPlusServer, int]) -> None:
    _, port = server
    client = S7CommPlusAsyncClient()
    await client.connect("127.0.0.1", port=port)
    try:
        first_session = client.session_id
        assert client.connection_generation == 0
        await client.reconnect()
        assert client.connection_generation == 1
        assert client.connected and client.session_id != first_session
        assert await client.db_read(1, 0, 4) == DB1
    finally:
        await client.disconnect()


def test_sync_reconnect_without_connect_raises() -> None:
    with pytest.raises(RuntimeError, match="Not connected"):
        S7CommPlusClient().reconnect()


async def test_async_reconnect_without_connect_raises() -> None:
    with pytest.raises(RuntimeError, match="Not connected"):
        await S7CommPlusAsyncClient().reconnect()


def test_sync_failed_reconnect_keeps_the_parameters(server: tuple[S7CommPlusServer, int]) -> None:
    srv, port = server
    client = S7CommPlusClient()
    client.connect("127.0.0.1", port=port)
    try:
        srv.stop()  # the PLC goes down...
        with pytest.raises(S7ConnectionError):
            client.reconnect()
        _start(srv, port)  # ...and comes back
        client.reconnect()
        assert client.connection_generation == 1
        assert client.db_read(1, 0, 4) == DB1
    finally:
        client.disconnect()


async def test_async_failed_reconnect_keeps_the_parameters(server: tuple[S7CommPlusServer, int]) -> None:
    # Regression: the failed attempt went through connect(), which cleared the
    # parameters, so every later reconnect raised "Not connected".
    srv, port = server
    client = S7CommPlusAsyncClient()
    await client.connect("127.0.0.1", port=port)
    try:
        srv.stop()  # the PLC goes down...
        with pytest.raises((S7ConnectionError, OSError)):
            await client.reconnect()
        _start(srv, port)  # ...and comes back
        await client.reconnect()
        assert client.connection_generation == 1
        assert await client.db_read(1, 0, 4) == DB1
    finally:
        await client.disconnect()


def _legitimation(client: S7CommPlusAsyncClient, level_after: int) -> ExitStack:
    """Stub the legitimation exchange; the PLC then reports ``level_after``."""
    stack = ExitStack()
    stack.enter_context(patch.object(client, "_decide_legitimation_mode", return_value=LegitimationType.LEGACY))
    stack.enter_context(patch.object(client, "_get_legitimation_challenge", AsyncMock(return_value=bytes(20))))
    stack.enter_context(patch.object(client, "_send_legitimation_legacy", AsyncMock()))
    stack.enter_context(patch.object(client, "_get_effective_protection_level", AsyncMock(return_value=level_after)))
    return stack


async def test_async_refused_authenticate_keeps_the_stored_credentials() -> None:
    client = S7CommPlusAsyncClient()
    client._connect_params = {"password": "known", "username": ""}
    client._connected = True
    client._tls_active = True
    client._protection_level = 3
    with _legitimation(client, level_after=3), pytest.raises(S7ConnectionError, match="refused"):
        await client.authenticate("wrong", "intruder")  # the PLC refuses the password
    assert client._connect_params == {"password": "known", "username": ""}


async def test_async_reconnect_reuses_the_password_and_username_of_authenticate(tls_server: tuple[int, str]) -> None:
    port, cert_path = tls_server
    client = S7CommPlusAsyncClient()
    await client.connect("127.0.0.1", port=port, use_tls=True, tls_ca=cert_path)
    try:
        client._protection_level = 3
        with _legitimation(client, level_after=1):
            await client.authenticate("secret", "operator")  # the PLC accepts the password

        with patch.object(client, "authenticate", AsyncMock()) as legitimate:
            await client.reconnect()
        legitimate.assert_awaited_once_with("secret", "operator")
        assert client.connection_generation == 1
    finally:
        await client.disconnect()


async def test_async_requests_wait_out_another_tasks_rebuild(server: tuple[S7CommPlusServer, int]) -> None:
    """While a reconnect owns the stream, other tasks get "Not connected" instead of interleaving."""
    _, port = server
    client = S7CommPlusAsyncClient()
    await client.connect("127.0.0.1", port=port)
    rebuilding = asyncio.create_task(asyncio.sleep(60))  # stands in for the reconnecting task
    try:
        client._rebuild_task = rebuilding
        with pytest.raises(S7ConnectionError, match="Not connected"):
            await client.db_read(1, 0, 4)
        client._rebuild_task = None
        assert await client.db_read(1, 0, 4) == DB1
    finally:
        rebuilding.cancel()
        await client.disconnect()


async def test_async_concurrent_reconnects_run_one_after_the_other(server: tuple[S7CommPlusServer, int]) -> None:
    _, port = server
    client = S7CommPlusAsyncClient()
    await client.connect("127.0.0.1", port=port)
    try:
        await asyncio.gather(client.reconnect(), client.reconnect())
        assert client.connection_generation == 2
        assert await client.db_read(1, 0, 4) == DB1
    finally:
        await client.disconnect()
