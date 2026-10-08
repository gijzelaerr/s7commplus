"""Refresh the tag catalog when the PLC's program layout changed."""

from __future__ import annotations

import struct
import time
from collections.abc import Generator
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from s7commplus import typeinfo
from s7commplus.async_client import S7CommPlusAsyncClient
from s7commplus.client import S7CommPlusClient, _block_signature, _type_info_times
from s7commplus.error import S7ConnectionError
from s7commplus.protocol import DataType, Ids
from s7commplus.server import S7CommPlusServer
from s7commplus.vlq import encode_uint32_vlq, encode_uint64_vlq
from tests.conftest import get_free_tcp_port

TIME = Ids.VARIABLE_TYPE_STRUCT_MODIFICATION_TIME
BLOCKS = [{"name": "DB1", "number": 1, "rid": 0x8A0E0001}]
SIGNATURE = [("DB1", 1, 0x8A0E0001)]
TI_RID = 0x90000001


def _object(rid: int, attributes: dict[int, int], children: bytes = b"") -> bytes:
    body = b"\xa1" + struct.pack(">I", rid) + encode_uint32_vlq(Ids.CLASS_TYPE_INFO) + b"\x00\x00"
    for attribute_id, value in attributes.items():
        body += b"\xa3" + encode_uint32_vlq(attribute_id) + bytes([0x00, DataType.ULINT]) + encode_uint64_vlq(value)
    return body + children + b"\xa2"


def _explore_response(*objects: bytes, return_value: int = 0) -> bytes:
    return encode_uint32_vlq(return_value) + b"".join(objects)


def _time(value: int) -> bytes:
    return struct.pack(">Q", value)


# A response nested deeper than the interpreter's recursion limit: each level opens
# another object (0xA1, RelationId, ClassId, ClassFlags, AttributeId) and none closes.
DEEPLY_NESTED = encode_uint32_vlq(0) + (b"\xa1" + struct.pack(">I", TI_RID) + b"\x00\x00\x00") * 5000


def test_find_object_attribute_reads_the_modification_time() -> None:
    response = _explore_response(_object(TI_RID, {Ids.OBJECT_VARIABLE_TYPE_NAME: 1, TIME: 0x1234567890}))
    assert typeinfo.find_object_attribute(response, TI_RID, TIME) == _time(0x1234567890)


def test_find_object_attribute_reads_a_captured_plcsim_response() -> None:
    # EXPLORE(0x92000001, [529]) answered by PLCSIM Advanced V8.0 (CPU 1511, FW V2.9).
    response = bytes.fromhex("000000021909a192000001837f2000a384110005a8dbe6da96e7caf3f6a200000000")
    assert typeinfo.find_object_attribute(response, 0x92000001, TIME) == bytes.fromhex("516f35a2d9e573f6")


def test_find_object_attribute_skips_a_stray_object_tag_in_the_header() -> None:
    response = encode_uint32_vlq(0) + b"\x00\xa1\x09" + _object(TI_RID, {TIME: 7})
    assert typeinfo.find_object_attribute(response, TI_RID, TIME) == _time(7)


def test_find_object_attribute_searches_nested_objects() -> None:
    response = _explore_response(_object(0x1, {}, children=_object(TI_RID, {TIME: 7})))
    assert typeinfo.find_object_attribute(response, TI_RID, TIME) == _time(7)


@pytest.mark.parametrize(
    "response",
    [
        _explore_response(_object(TI_RID, {Ids.OBJECT_VARIABLE_TYPE_NAME: 1})),
        _explore_response(_object(TI_RID + 1, {TIME: 7})),
        _explore_response(_object(TI_RID, {TIME: 7}), return_value=0x8001),
        _explore_response(),
        _explore_response(_object(TI_RID, {TIME: 7}))[:-6],
        b"",
        DEEPLY_NESTED,
    ],
    ids=["attribute-absent", "another-object", "plc-error", "no-object", "truncated-in-value", "empty", "deeply-nested"],
)
def test_find_object_attribute_returns_none_when_nothing_is_learned(response: bytes) -> None:
    assert typeinfo.find_object_attribute(response, TI_RID, TIME) is None


def test_find_object_attribute_tries_a_bounded_number_of_object_starts(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []
    parse = typeinfo.parse_object_list

    def counting_parse(data: bytes, offset: int) -> tuple[list[typeinfo.PObject], int]:
        calls.append(offset)
        return parse(data, offset)

    monkeypatch.setattr(typeinfo, "parse_object_list", counting_parse)

    assert typeinfo.find_object_attribute(DEEPLY_NESTED, TI_RID + 1, TIME) is None
    assert len(calls) == typeinfo._MAX_OBJECT_START_CANDIDATES


def test_type_info_times_keeps_only_reported_root_types() -> None:
    roots = [typeinfo.Node(relation_id=TI_RID), typeinfo.Node(relation_id=TI_RID + 1)]
    objects = [
        typeinfo.PObject(relation_id=TI_RID, attributes={TIME: _time(5)}),
        typeinfo.PObject(relation_id=TI_RID + 1),  # no modification time reported
        typeinfo.PObject(relation_id=TI_RID + 2, attributes={TIME: _time(6)}),  # a nested UDT, not a root
    ]
    assert _type_info_times(roots, objects) == {TI_RID: _time(5)}


# --- The program-change check ----------------------------------------------------------------


def test_sync_refreshes_on_first_call_then_only_on_change() -> None:
    client = S7CommPlusClient()
    client._connection = MagicMock()
    one = [{"name": "DB1", "number": 1, "rid": 0x8A0E0001}]
    client.list_datablocks = MagicMock(return_value=one)  # type: ignore[method-assign]
    client._browse_layout = MagicMock(  # type: ignore[method-assign]
        side_effect=lambda: ([], _block_signature(client.list_datablocks.return_value), {})
    )

    assert client.refresh_caches_if_program_changed() is True  # first call establishes the baseline
    assert client.refresh_caches_if_program_changed() is False  # unchanged
    assert client._browse_layout.call_count == 1

    client.list_datablocks.return_value = one + [{"name": "DB2", "number": 2, "rid": 0x8A0E0002}]
    assert client.refresh_caches_if_program_changed() is True
    assert client._browse_layout.call_count == 2


def test_sync_refresh_requires_a_connection() -> None:
    with pytest.raises(RuntimeError, match="Not connected"):
        S7CommPlusClient().refresh_caches_if_program_changed()


@pytest.mark.asyncio
async def test_async_refresh_requires_a_connection() -> None:
    # Like the async client's other request methods, which raise S7ConnectionError.
    client = S7CommPlusAsyncClient()
    client.list_datablocks = AsyncMock(return_value=BLOCKS)  # type: ignore[method-assign]

    with pytest.raises(S7ConnectionError, match="Not connected"):
        await client.refresh_caches_if_program_changed()
    client.list_datablocks.assert_not_awaited()


@pytest.mark.asyncio
async def test_async_refreshes_only_on_change() -> None:
    client = S7CommPlusAsyncClient()
    client._connected = True
    client.list_datablocks = AsyncMock(return_value=[{"name": "DB1", "number": 1, "rid": 1}])  # type: ignore[method-assign]
    client._browse_layout = AsyncMock(  # type: ignore[method-assign]
        side_effect=lambda: ([], _block_signature(client.list_datablocks.return_value), {})
    )

    assert await client.refresh_caches_if_program_changed() is True
    assert await client.refresh_caches_if_program_changed() is False
    assert client._browse_layout.await_count == 1

    client.list_datablocks.return_value = [{"name": "DB1", "number": 1, "rid": 1}, {"name": "DB2", "number": 2, "rid": 2}]
    assert await client.refresh_caches_if_program_changed() is True
    assert client._browse_layout.await_count == 2


def _layout(times: dict[int, bytes], names: tuple[str, ...] = ("DB1.a",)) -> tuple[list[dict[str, Any]], Any, Any]:
    variables = [{"name": name, "access_sequence": "8A0E0001.1", "data_type": "INT"} for name in names]
    return variables, list(SIGNATURE), dict(times)


def _catalog_client(*layouts: Any) -> S7CommPlusClient:
    """A sync client whose browses return ``layouts`` in turn, with a cached catalog from the first."""
    client = S7CommPlusClient()
    client._connection = MagicMock()
    client._browse_layout = MagicMock(side_effect=list(layouts))  # type: ignore[method-assign]
    client.list_datablocks = MagicMock(return_value=BLOCKS)  # type: ignore[method-assign]
    client.refresh_tag_catalog()
    return client


def test_catalog_refresh_records_the_layout_its_own_browse_returned() -> None:
    client = _catalog_client(_layout({TI_RID: _time(5)}))

    assert client._block_layout_signature == SIGNATURE
    assert client._type_info_times == {TI_RID: _time(5)}
    client._browse_layout.side_effect = [_layout({TI_RID: _time(6)}, ("DB1.b",))]
    assert [variable["name"] for variable in client.browse()] == ["DB1.b"]
    assert client._type_info_times == {TI_RID: _time(5)}  # a plain browse() leaves the catalog's record alone


def test_catalog_refresh_records_the_baseline_so_an_unchanged_program_is_not_rebrowsed() -> None:
    client = _catalog_client(_layout({TI_RID: _time(5)}))
    client._read_type_info_time = MagicMock(return_value=_time(5))  # type: ignore[method-assign]

    assert client.refresh_caches_if_program_changed() is False
    assert client._browse_layout.call_count == 1
    client._read_type_info_time.assert_called_once_with(TI_RID)


def test_changed_modification_time_refreshes_the_catalog() -> None:
    client = _catalog_client(_layout({TI_RID: _time(5)}), _layout({TI_RID: _time(6)}, ("DB1.b",)))
    client._read_type_info_time = MagicMock(return_value=_time(6))  # type: ignore[method-assign]

    assert client.refresh_caches_if_program_changed() is True
    assert client._browse_layout.call_count == 2
    assert client._type_info_times == {TI_RID: _time(6)}
    assert client.resolve_tag("DB1.b").name == "DB1.b"


def test_type_info_that_no_longer_answers_refreshes_the_catalog() -> None:
    # A download replaced the type-info object: the recorded one no longer answers.
    client = _catalog_client(_layout({TI_RID: _time(5)}), _layout({TI_RID + 1: _time(6)}, ("DB1.b",)))
    client._read_type_info_time = MagicMock(side_effect=[None, _time(6)])  # type: ignore[method-assign]

    assert client.refresh_caches_if_program_changed() is True
    assert client._type_info_times == {TI_RID + 1: _time(6)}
    assert client.resolve_tag("DB1.b").name == "DB1.b"

    assert client.refresh_caches_if_program_changed() is False  # consistent again
    assert client._browse_layout.call_count == 2


def test_type_info_that_never_answers_the_check_is_refreshed_once() -> None:
    # The browse reports a time the attribute-filtered EXPLORE never returns: refresh once,
    # then check that block by block list only instead of rebrowsing every time.
    client = _catalog_client(_layout({TI_RID: _time(5)}), _layout({TI_RID: _time(5)}))
    client._read_type_info_time = MagicMock(return_value=None)  # type: ignore[method-assign]

    assert client.refresh_caches_if_program_changed() is True
    assert client._type_info_times == {}
    assert client.refresh_caches_if_program_changed() is False
    assert client._browse_layout.call_count == 2
    client._read_type_info_time.assert_called_once_with(TI_RID)


def test_unreported_modification_time_is_not_checked() -> None:
    client = _catalog_client(_layout({}))
    client._read_type_info_time = MagicMock(return_value=None)  # type: ignore[method-assign]

    assert client.refresh_caches_if_program_changed() is False
    client._read_type_info_time.assert_not_called()
    assert client._browse_layout.call_count == 1


def test_read_type_info_time_sends_an_attribute_filtered_explore() -> None:
    client = S7CommPlusClient()
    client._connection = MagicMock()
    client._connection.send_request.return_value = _explore_response(_object(TI_RID, {TIME: 9}))

    assert client._read_type_info_time(TI_RID) == _time(9)
    function_code, payload = client._connection.send_request.call_args.args
    assert payload[:4] == struct.pack(">I", TI_RID)
    assert encode_uint32_vlq(TIME) in payload


def test_read_type_info_time_of_a_deeply_nested_response_is_none() -> None:
    client = S7CommPlusClient()
    client._connection = MagicMock()
    client._connection.send_request.return_value = DEEPLY_NESTED

    assert client._read_type_info_time(TI_RID) is None


def _record_layout(client: S7CommPlusClient | S7CommPlusAsyncClient) -> None:
    client._symbol_catalog = MagicMock()
    client._block_layout_signature = list(SIGNATURE)
    client._type_info_times = {TI_RID: _time(5)}


def _recorded_layout(client: S7CommPlusClient | S7CommPlusAsyncClient) -> tuple[Any, ...]:
    return client._symbol_catalog, client._block_layout_signature, client._type_info_times


def test_sync_connect_disconnect_and_invalidate_forget_the_recorded_layout() -> None:
    client = S7CommPlusClient()
    client._open_connection = MagicMock()  # type: ignore[method-assign]

    _record_layout(client)
    client.invalidate_tag_catalog()
    assert _recorded_layout(client) == (None, None, {})

    _record_layout(client)
    client.connect("127.0.0.1")
    assert _recorded_layout(client) == (None, None, {})

    _record_layout(client)
    client.disconnect()
    assert _recorded_layout(client) == (None, None, {})


@pytest.mark.asyncio
async def test_async_connect_disconnect_and_invalidate_forget_the_recorded_layout() -> None:
    client = S7CommPlusAsyncClient()
    client._open_connection = AsyncMock()  # type: ignore[method-assign]

    _record_layout(client)
    client.invalidate_tag_catalog()
    assert _recorded_layout(client) == (None, None, {})

    _record_layout(client)
    await client.connect("127.0.0.1")
    assert _recorded_layout(client) == (None, None, {})

    _record_layout(client)
    await client.disconnect()
    assert _recorded_layout(client) == (None, None, {})


@pytest.mark.asyncio
async def test_async_changed_modification_time_refreshes_the_catalog() -> None:
    client = S7CommPlusAsyncClient()
    client._connected = True
    client._browse_layout = AsyncMock(  # type: ignore[method-assign]
        side_effect=[_layout({TI_RID: _time(5)}), _layout({TI_RID: _time(6)})]
    )
    client.list_datablocks = AsyncMock(return_value=BLOCKS)  # type: ignore[method-assign]
    await client.refresh_tag_catalog()
    client._read_type_info_time = AsyncMock(side_effect=[_time(5), _time(6)])  # type: ignore[method-assign]

    assert await client.refresh_caches_if_program_changed() is False
    assert await client.refresh_caches_if_program_changed() is True
    assert client._browse_layout.await_count == 2


@pytest.mark.asyncio
async def test_async_type_info_that_no_longer_answers_refreshes_once() -> None:
    client = S7CommPlusAsyncClient()
    client._connected = True
    client._browse_layout = AsyncMock(  # type: ignore[method-assign]
        side_effect=[_layout({TI_RID: _time(5)}), _layout({TI_RID: _time(5)})]
    )
    client.list_datablocks = AsyncMock(return_value=BLOCKS)  # type: ignore[method-assign]
    await client.refresh_tag_catalog()
    client._read_type_info_time = AsyncMock(return_value=None)  # type: ignore[method-assign]

    assert await client.refresh_caches_if_program_changed() is True
    assert await client.refresh_caches_if_program_changed() is False
    assert client._browse_layout.await_count == 2
    client._read_type_info_time.assert_awaited_once_with(TI_RID)


# --- Against the emulator --------------------------------------------------------------------
# The emulator has no type-info objects (its EXPLORE answers with the data-block list and its
# LID=1 reads return data, not a type-info RID), so these cover the block-list path and the
# PLC's answer for a type-info object that does not exist.


@pytest.fixture()
def emulator() -> Generator[tuple[S7CommPlusServer, int], None, None]:
    server = S7CommPlusServer()
    server.register_raw_db(1, bytearray(16))
    port = get_free_tcp_port()
    server.start(host="127.0.0.1", port=port)
    time.sleep(0.1)
    yield server, port
    server.stop()


def test_emulator_sync_check_finds_a_new_data_block(emulator: tuple[S7CommPlusServer, int]) -> None:
    server, port = emulator
    client = S7CommPlusClient()
    client.connect("127.0.0.1", port=port)
    try:
        assert client.refresh_caches_if_program_changed() is True  # baseline
        assert client.refresh_caches_if_program_changed() is False
        server.register_raw_db(2, bytearray(16))
        assert client.refresh_caches_if_program_changed() is True
        assert client._block_layout_signature == [("DB1", 1, 0x8A0E0001), ("DB2", 2, 0x8A0E0002)]
        assert client.refresh_caches_if_program_changed() is False
        # A type-info object that does not exist (any more) reads as None, i.e. changed.
        assert client._read_type_info_time(TI_RID) is None
    finally:
        client.disconnect()


@pytest.mark.asyncio
async def test_emulator_async_check_finds_a_new_data_block(emulator: tuple[S7CommPlusServer, int]) -> None:
    server, port = emulator
    client = S7CommPlusAsyncClient()
    await client.connect("127.0.0.1", port=port)
    try:
        assert await client.refresh_caches_if_program_changed() is True
        assert await client.refresh_caches_if_program_changed() is False
        server.register_raw_db(2, bytearray(16))
        assert await client.refresh_caches_if_program_changed() is True
        assert client._block_layout_signature == [("DB1", 1, 0x8A0E0001), ("DB2", 2, 0x8A0E0002)]
        assert await client.refresh_caches_if_program_changed() is False
        assert await client._read_type_info_time(TI_RID) is None
    finally:
        await client.disconnect()
