"""Auto-reconnect: an opt-in retry of reads, never writes, on a fresh session after a dropped connection."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from s7commplus.async_client import S7CommPlusAsyncClient
from s7commplus.catalog import SymbolCatalog
from s7commplus.client import _AUTO_RECONNECT_MIN_INTERVAL, S7CommPlusClient
from s7commplus.codec import encode_pvalue_blob
from s7commplus.error import S7ConnectionError
from s7commplus.protocol import ProtocolVersion
from s7commplus.server import S7CommPlusServer
from s7commplus.vlq import encode_uint32_vlq, encode_uint64_vlq
from tests.conftest import get_free_tcp_port

DB1 = b"\x01\x02\x03\x04"
READS = {
    "db_read",
    "db_read_multi",
    "read_area",
    "read_symbolic",
    "read_symbolic_multi",
    "read_tag",
    "read_tags",
    "browse",
    "get_cpu_state",
}
WRITES = (
    "db_write",
    "db_write_multi",
    "write_multi",
    "write_area",
    "write_symbolic",
    "write_tag",
    "write_tags",
    "set_plc_operating_state",
    "download_block",
)
CLIENTS = (S7CommPlusClient, S7CommPlusAsyncClient)


def _dropped() -> S7ConnectionError:
    return S7ConnectionError("Connection closed by peer")


def _read_response(value: bytes) -> bytes:
    """A GetMultiVariables response payload answering one item with ``value``."""
    return encode_uint64_vlq(0) + encode_uint32_vlq(1) + encode_pvalue_blob(value) + encode_uint32_vlq(0) + encode_uint32_vlq(0)


def _catalog() -> SymbolCatalog:
    return SymbolCatalog.from_browse([{"name": "DB1.Speed", "access_sequence": "8A0E0001.A", "data_type": "REAL"}])


def _sync_client(*answers: bytes | Exception) -> Any:
    """An auto-reconnecting client whose requests get ``answers`` in turn; reconnects are counted, not made."""
    client = S7CommPlusClient()
    client._connect_params = {"host": "127.0.0.1", "port": 102}
    client._connection = MagicMock(requires_substreamed=False, object_qualifier_version=ProtocolVersion.V2)
    client._connection.send_request.side_effect = list(answers)
    client._symbol_catalog = _catalog()
    client.auto_reconnect = True
    client._auto_reconnect_min_interval = 0.0

    def rebuild() -> None:
        client._generation += 1

    client._rebuild_session = MagicMock(side_effect=rebuild)  # type: ignore[method-assign]
    return client


def _async_client(*answers: bytes | Exception) -> Any:
    """The asyncio counterpart of :func:`_sync_client`."""
    client = S7CommPlusAsyncClient()
    client._connect_params = {"host": "127.0.0.1", "port": 102}
    client._send_request = AsyncMock(side_effect=list(answers))  # type: ignore[method-assign]
    client._symbol_catalog = _catalog()
    client.auto_reconnect = True
    client._auto_reconnect_min_interval = 0.0

    async def rebuild() -> None:
        client._generation += 1

    client._rebuild_session = AsyncMock(side_effect=rebuild)  # type: ignore[method-assign]
    return client


def _hold_subscription(client: Any, kind: str) -> None:
    if kind == "data":
        client._subscriptions = SimpleNamespace(subscription_ids=(7,), pending_restore=())
    elif kind == "lost data":
        client._subscriptions = SimpleNamespace(subscription_ids=(), pending_restore=(object(),))
    else:
        client._alarm_subscription_ids.add(7)


def _start(srv: S7CommPlusServer, port: int) -> None:
    srv.start(host="127.0.0.1", port=port)
    time.sleep(0.1)


def _emulator(**kwargs: Any) -> Iterator[tuple[S7CommPlusServer, int]]:
    port = get_free_tcp_port()
    srv = S7CommPlusServer(**kwargs)
    srv.register_raw_db(1, bytearray(DB1))
    _start(srv, port)
    yield srv, port
    srv.stop()


@pytest.fixture()
def server() -> Iterator[tuple[S7CommPlusServer, int]]:
    yield from _emulator()


@pytest.fixture()
def rst_server() -> Iterator[tuple[S7CommPlusServer, int]]:
    """An emulator that closes the socket after answering each GetMultiVariables."""
    yield from _emulator(rst_after_symbolic_read=True)


# -- Which operations are retried -------------------------------------------


@pytest.mark.parametrize("cls", CLIENTS)
def test_only_the_reads_are_wrapped(cls: type) -> None:
    assert {name for name, value in vars(cls).items() if hasattr(value, "__wrapped__")} == READS


@pytest.mark.parametrize("cls", CLIENTS)
@pytest.mark.parametrize("name", WRITES)
def test_writes_are_never_wrapped(cls: type, name: str) -> None:
    assert not hasattr(getattr(cls, name), "__wrapped__")


@pytest.mark.parametrize("cls", CLIENTS)
def test_auto_reconnect_is_off_by_default_with_a_one_second_interval(cls: type) -> None:
    client = cls()
    assert client.auto_reconnect is False
    assert client._auto_reconnect_min_interval == _AUTO_RECONNECT_MIN_INTERVAL == 1.0


# -- The retry (stubbed transport) -------------------------------------------


def test_sync_drop_is_raised_when_auto_reconnect_is_off() -> None:
    client = _sync_client(_dropped())
    client.auto_reconnect = False
    with pytest.raises(S7ConnectionError):
        client.db_read(1, 0, 4)
    assert client._rebuild_session.call_count == 0


async def test_async_drop_is_raised_when_auto_reconnect_is_off() -> None:
    client = _async_client(_dropped())
    client.auto_reconnect = False
    with pytest.raises(S7ConnectionError):
        await client.db_read(1, 0, 4)
    assert client._rebuild_session.await_count == 0


def test_sync_read_is_retried_once_on_a_new_session() -> None:
    client = _sync_client(_dropped(), _read_response(DB1))
    assert client.db_read(1, 0, 4) == DB1
    assert client._rebuild_session.call_count == 1
    assert client.connection_generation == 1


async def test_async_read_is_retried_once_on_a_new_session() -> None:
    client = _async_client(_dropped(), _read_response(DB1))
    assert await client.db_read(1, 0, 4) == DB1
    assert client._rebuild_session.await_count == 1
    assert client.connection_generation == 1


def test_sync_nested_reads_reconnect_once_when_the_retry_fails() -> None:
    # read_tag -> read_tags -> read_symbolic_multi are all wrapped; only read_tag handles the drop.
    client = _sync_client(*(_dropped() for _ in range(6)))
    with pytest.raises(S7ConnectionError):
        client.read_tag("DB1.Speed")
    assert client._rebuild_session.call_count == 1
    assert client._connection.send_request.call_count == 2


async def test_async_nested_reads_reconnect_once_when_the_retry_fails() -> None:
    client = _async_client(*(_dropped() for _ in range(6)))
    with pytest.raises(S7ConnectionError):
        await client.read_tag("DB1.Speed")
    assert client._rebuild_session.await_count == 1
    assert client._send_request.await_count == 2


def test_sync_nested_read_succeeds_after_one_reconnect() -> None:
    client = _sync_client(_dropped(), _read_response(b"\x3f\x80\x00\x00"))
    assert client.read_tag("DB1.Speed") == b"\x3f\x80\x00\x00"
    assert client._rebuild_session.call_count == 1


async def test_async_nested_read_succeeds_after_one_reconnect() -> None:
    client = _async_client(_dropped(), _read_response(b"\x3f\x80\x00\x00"))
    assert await client.read_tag("DB1.Speed") == b"\x3f\x80\x00\x00"
    assert client._rebuild_session.await_count == 1


def _drop_after_a_rebuild_elsewhere(client: Any) -> Any:
    calls = 0

    def answer(*args: Any, **kwargs: Any) -> bytes:
        nonlocal calls
        calls += 1
        if calls == 1:
            client._generation += 1  # another caller rebuilt the session meanwhile
            raise _dropped()
        return _read_response(DB1)

    return answer


def test_sync_read_does_not_tear_down_a_session_rebuilt_meanwhile() -> None:
    client = _sync_client()
    client._connection.send_request.side_effect = _drop_after_a_rebuild_elsewhere(client)
    assert client.db_read(1, 0, 4) == DB1
    assert client._rebuild_session.call_count == 0


async def test_async_read_does_not_tear_down_a_session_rebuilt_meanwhile() -> None:
    client = _async_client()
    client._send_request.side_effect = _drop_after_a_rebuild_elsewhere(client)
    assert await client.db_read(1, 0, 4) == DB1
    assert client._rebuild_session.await_count == 0


def test_sync_automatic_reconnects_keep_a_minimum_interval() -> None:
    client = _sync_client(_dropped(), _read_response(DB1), _dropped())
    client._auto_reconnect_min_interval = 60.0
    assert client.db_read(1, 0, 4) == DB1
    with pytest.raises(S7ConnectionError, match="closed by peer"):
        client.db_read(1, 0, 4)  # too soon after the last attempt: no new one
    assert client._rebuild_session.call_count == 1


async def test_async_automatic_reconnects_keep_a_minimum_interval() -> None:
    client = _async_client(_dropped(), _read_response(DB1), _dropped())
    client._auto_reconnect_min_interval = 60.0
    assert await client.db_read(1, 0, 4) == DB1
    with pytest.raises(S7ConnectionError, match="closed by peer"):
        await client.db_read(1, 0, 4)
    assert client._rebuild_session.await_count == 1


def test_sync_failed_attempt_also_starts_the_interval() -> None:
    client = _sync_client(_dropped(), _dropped())
    client._auto_reconnect_min_interval = 60.0
    client._rebuild_session.side_effect = S7ConnectionError("TCP connection failed")
    with pytest.raises(S7ConnectionError, match="TCP connection failed"):
        client.db_read(1, 0, 4)
    with pytest.raises(S7ConnectionError, match="closed by peer"):
        client.db_read(1, 0, 4)
    assert client._rebuild_session.call_count == 1


async def test_async_failed_attempt_also_starts_the_interval() -> None:
    client = _async_client(_dropped(), _dropped())
    client._auto_reconnect_min_interval = 60.0
    client._rebuild_session.side_effect = S7ConnectionError("TCP connection failed")
    with pytest.raises(S7ConnectionError, match="TCP connection failed"):
        await client.db_read(1, 0, 4)
    with pytest.raises(S7ConnectionError, match="closed by peer"):
        await client.db_read(1, 0, 4)
    assert client._rebuild_session.await_count == 1


DATABLOCKS = [{"name": "DB1", "number": 1, "rid": 0x8A0E0001}]


def test_sync_browse_does_not_retry_its_own_failed_reconnect_at_once() -> None:
    # browse() reconnects by itself between steps; when that attempt fails, the
    # auto-reconnect around browse() must not make a second one straight away.
    client = _sync_client(_dropped())
    client._auto_reconnect_min_interval = 60.0
    client._rebuild_session.side_effect = S7ConnectionError("TCP connection failed")
    client.list_datablocks = MagicMock(return_value=DATABLOCKS)  # type: ignore[method-assign]
    with pytest.raises(S7ConnectionError, match="TCP connection failed"):
        client.browse()
    assert client._rebuild_session.call_count == 1


async def test_async_browse_does_not_retry_its_own_failed_reconnect_at_once() -> None:
    client = _async_client(_dropped())
    client._auto_reconnect_min_interval = 60.0
    client._rebuild_session.side_effect = S7ConnectionError("TCP connection failed")
    client.list_datablocks = AsyncMock(return_value=DATABLOCKS)  # type: ignore[method-assign]
    with pytest.raises(S7ConnectionError, match="TCP connection failed"):
        await client.browse()
    assert client._rebuild_session.await_count == 1


@pytest.mark.parametrize("kind", ["data", "lost data", "alarm"])
def test_sync_auto_reconnect_stands_down_while_subscriptions_depend_on_the_session(kind: str) -> None:
    client = _sync_client(_dropped())
    _hold_subscription(client, kind)
    with pytest.raises(S7ConnectionError, match="subscriptions"):
        client.db_read(1, 0, 4)
    assert client._rebuild_session.call_count == 0


@pytest.mark.parametrize("kind", ["data", "lost data", "alarm"])
async def test_async_auto_reconnect_stands_down_while_subscriptions_depend_on_the_session(kind: str) -> None:
    client = _async_client(_dropped())
    _hold_subscription(client, kind)
    with pytest.raises(S7ConnectionError, match="subscriptions"):
        await client.db_read(1, 0, 4)
    assert client._rebuild_session.await_count == 0


# -- End to end against the emulator ------------------------------------------


def test_sync_auto_reconnect_set_after_connect_outlasts_a_reconnect(server: tuple[S7CommPlusServer, int]) -> None:
    _, port = server
    client = S7CommPlusClient()
    client.connect("127.0.0.1", port=port)
    try:
        client.auto_reconnect = True
        client.reconnect()
        assert client.auto_reconnect is True
    finally:
        client.disconnect()


async def test_async_auto_reconnect_set_after_connect_outlasts_a_reconnect(server: tuple[S7CommPlusServer, int]) -> None:
    # Regression: the async reconnect went through connect(**params), which reset the flag.
    _, port = server
    client = S7CommPlusAsyncClient()
    await client.connect("127.0.0.1", port=port)
    try:
        client.auto_reconnect = True
        await client.reconnect()
        assert client.auto_reconnect is True
    finally:
        await client.disconnect()


def test_sync_read_recovers_after_the_plc_closes_the_socket(rst_server: tuple[S7CommPlusServer, int]) -> None:
    srv, port = rst_server
    client = S7CommPlusClient()
    client.connect("127.0.0.1", port=port, auto_reconnect=True)
    try:
        assert client.db_read(1, 0, 4) == DB1  # answered, then the server closes the socket
        assert client.db_read(1, 0, 4) == DB1  # finds it closed, reconnects and reads again
        assert client.connection_generation == 1
        with pytest.raises(S7ConnectionError):
            client.db_write(1, 0, b"\xff")  # the socket was closed again; a write is not retried
        assert client.connection_generation == 1
        assert bytes(srv.get_db(1).data) == DB1  # type: ignore[union-attr]
    finally:
        client.disconnect()


async def test_async_read_recovers_after_the_plc_closes_the_socket(rst_server: tuple[S7CommPlusServer, int]) -> None:
    srv, port = rst_server
    client = S7CommPlusAsyncClient()
    await client.connect("127.0.0.1", port=port, auto_reconnect=True)
    try:
        assert await client.db_read(1, 0, 4) == DB1  # answered, then the server closes the socket
        assert await client.db_read(1, 0, 4) == DB1  # finds it closed, reconnects and reads again
        assert client.connection_generation == 1
        with pytest.raises(S7ConnectionError):
            await client.db_write(1, 0, b"\xff")  # the socket was closed again; a write is not retried
        assert client.connection_generation == 1
        assert bytes(srv.get_db(1).data) == DB1  # type: ignore[union-attr]
    finally:
        await client.disconnect()


def test_sync_read_recovers_after_the_session_was_closed_internally(server: tuple[S7CommPlusServer, int]) -> None:
    """A session the client closed itself (parameters kept) answers "Not connected", which is a drop."""
    _, port = server
    client = S7CommPlusClient()
    client.connect("127.0.0.1", port=port, auto_reconnect=True)
    try:
        assert client._connection is not None
        client._connection.disconnect()
        assert client.db_read(1, 0, 4) == DB1
        assert client.connection_generation == 1
    finally:
        client.disconnect()


async def test_async_read_recovers_after_the_session_was_closed_internally(server: tuple[S7CommPlusServer, int]) -> None:
    _, port = server
    client = S7CommPlusAsyncClient()
    await client.connect("127.0.0.1", port=port, auto_reconnect=True)
    try:
        await client._close()  # as an integrity failure does, keeping the parameters
        assert await client.db_read(1, 0, 4) == DB1
        assert client.connection_generation == 1
    finally:
        await client.disconnect()


def test_sync_read_reconnects_once_the_plc_is_back(server: tuple[S7CommPlusServer, int]) -> None:
    srv, port = server
    client = S7CommPlusClient()
    client.connect("127.0.0.1", port=port, auto_reconnect=True)
    client._auto_reconnect_min_interval = 0.0
    try:
        srv.stop()  # the PLC goes down and drops the connection
        assert client._connection is not None
        client._connection.disconnect()
        with pytest.raises(S7ConnectionError):
            client.db_read(1, 0, 4)  # the reconnect attempt is refused
        _start(srv, port)  # the PLC is back
        assert client.db_read(1, 0, 4) == DB1
        assert client.connection_generation == 1
    finally:
        client.disconnect()


async def test_async_read_reconnects_once_the_plc_is_back(server: tuple[S7CommPlusServer, int]) -> None:
    srv, port = server
    client = S7CommPlusAsyncClient()
    await client.connect("127.0.0.1", port=port, auto_reconnect=True)
    client._auto_reconnect_min_interval = 0.0
    try:
        srv.stop()  # the PLC goes down and drops the connection
        client._close_failed_stream(client._writer)
        with pytest.raises((S7ConnectionError, OSError)):
            await client.db_read(1, 0, 4)  # the reconnect attempt is refused
        _start(srv, port)  # the PLC is back
        assert await client.db_read(1, 0, 4) == DB1
        assert client.connection_generation == 1
    finally:
        await client.disconnect()


async def test_async_tasks_that_find_the_same_drop_share_one_reconnect(server: tuple[S7CommPlusServer, int]) -> None:
    _, port = server
    client = S7CommPlusAsyncClient()
    await client.connect("127.0.0.1", port=port, auto_reconnect=True)
    client._auto_reconnect_min_interval = 0.0  # only the generation check may prevent extra reconnects
    try:
        client._close_failed_stream(client._writer)
        results = await asyncio.gather(*(client.db_read(1, 0, 4) for _ in range(5)))
        assert results == [DB1] * 5
        assert client.connection_generation == 1
    finally:
        await client.disconnect()
