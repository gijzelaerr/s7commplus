"""Check scalar write types at the public API's outgoing request boundary."""

import struct
from unittest.mock import AsyncMock, MagicMock

import pytest

from s7commplus.async_client import S7CommPlusAsyncClient
from s7commplus.catalog import SymbolCatalog, _write_type
from s7commplus.client import S7CommPlusClient, _build_multi_symbolic_write_payload
from s7commplus.codec import PValueArray, encode_pvalue_array, encode_pvalue_blob
from s7commplus.protocol import DataType, FunctionCode, ProtocolVersion
from s7commplus.vlq import decode_uint32_vlq, encode_uint32_vlq, encode_uint64_vlq


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("operation", ["symbolic", "area", "multi"])
@pytest.mark.parametrize(
    ("datatype", "data", "wire_value"),
    [
        (DataType.INT, struct.pack(">h", 77), b"\x00\x4d"),
        (DataType.WORD, struct.pack(">H", 512), b"\x02\x00"),
        (DataType.DINT, struct.pack(">i", -5), b"\x7b"),
        (DataType.UDINT, struct.pack(">I", 300), b"\x82\x2c"),
        (DataType.REAL, struct.pack(">f", 2.0), b"\x40\x00\x00\x00"),
    ],
)
async def test_scalar_write_validates_type_but_raw_access_uses_blob_on_wire(
    asynchronous: bool, operation: str, datatype: DataType, data: bytes, wire_value: bytes
) -> None:
    if asynchronous:
        client = S7CommPlusAsyncClient()
        send = AsyncMock(return_value=b"\x00\x00")
        client._send_request = send
        if operation == "symbolic":
            await client.write_symbolic(0x8A0E0001, [15], data, datatype=datatype)
        elif operation == "area":
            await client.write_area(82, 0, data, datatype=datatype)
        else:
            await client.db_write_multi([(1, 0, data, datatype)])
    else:
        sync_client = S7CommPlusClient()
        connection = MagicMock()
        connection.requires_substreamed = False
        connection.protocol_version = ProtocolVersion.V2
        send = connection.send_request
        send.return_value = b"\x00\x00"
        sync_client._connection = connection
        if operation == "symbolic":
            sync_client.write_symbolic(0x8A0E0001, [15], data, datatype=datatype)
        elif operation == "area":
            sync_client.write_area(82, 0, data, datatype=datatype)
        else:
            sync_client.db_write_multi([(1, 0, data, datatype)])

    function, payload = send.call_args.args
    assert function == FunctionCode.SET_MULTI_VARIABLES
    count, consumed = decode_uint32_vlq(payload, 4)
    assert count == 1
    offset = 4 + consumed
    fields, consumed = decode_uint32_vlq(payload, offset)
    offset += consumed
    for _ in range(fields):
        _, consumed = decode_uint32_vlq(payload, offset)
        offset += consumed
    index, consumed = decode_uint32_vlq(payload, offset)
    assert index == 1
    offset += consumed
    if operation == "symbolic":
        assert payload[offset : offset + 2 + len(wire_value)] == bytes((0, datatype)) + wire_value
    else:
        assert payload[offset : offset + len(encode_pvalue_blob(data))] == encode_pvalue_blob(data)


@pytest.mark.parametrize("substreamed", [False, True])
def test_missing_multi_write_type_rejected_before_any_send(substreamed: bool) -> None:
    client = S7CommPlusClient()
    connection = MagicMock()
    connection.requires_substreamed = substreamed
    client._connection = connection
    with pytest.raises(ValueError, match="require.*datatype"):
        client.db_write_multi([(1, 0, b"\x00\x4d", DataType.INT), (1, 2, b"\x00\x01")])  # type: ignore[list-item]
    connection.send_request.assert_not_called()


async def test_async_missing_multi_write_type_rejected_before_send() -> None:
    client = S7CommPlusAsyncClient()
    send = AsyncMock()
    client._send_request = send
    with pytest.raises(ValueError, match="require.*datatype"):
        await client.db_write_multi([(1, 0, b"\x00\x4d")])  # type: ignore[list-item]
    send.assert_not_called()


@pytest.mark.parametrize("substreamed", [False, True])
def test_invalid_scalar_width_rejected_before_any_send(substreamed: bool) -> None:
    client = S7CommPlusClient()
    connection = MagicMock()
    connection.requires_substreamed = substreamed
    client._connection = connection
    with pytest.raises(ValueError):
        client.db_write_multi([(1, 0, b"\x00\x4d", DataType.INT), (1, 2, b"\x01", DataType.INT)])
    connection.send_request.assert_not_called()


def test_substreamed_area_write_validates_type_but_uses_blob_on_wire() -> None:
    client = S7CommPlusClient()
    connection = MagicMock()
    connection.requires_substreamed = True
    connection.session_id = 0x70000001
    client._connection = connection
    client.write_area(82, 0, struct.pack(">I", 300), datatype=DataType.UDINT)
    function, payload = connection.send_request.call_args.args
    assert function == FunctionCode.SET_VAR_SUBSTREAMED
    assert payload.endswith(encode_pvalue_blob(struct.pack(">I", 300)) + bytes((1, 0, 0, 0, 0)))


# --- Named writes of the types PLCSIM Advanced (CPU 1511, FW V2.9) takes in another form ----

STRING_BROWSE = [
    {"name": "DB.c", "access_sequence": "8A0E0004.1", "data_type": "CHAR"},
    {"name": "DB.s", "access_sequence": "8A0E0004.2", "data_type": "STRING", "string_length": 4},
    {"name": "DB.w", "access_sequence": "8A0E0004.3", "data_type": "WSTRING", "string_length": 2},
    {"name": "DB.dt", "access_sequence": "8A0E0004.4", "data_type": "DATEANDTIME"},
    {"name": "DB.i", "access_sequence": "8A0E0004.5", "data_type": "INT"},
]

# Raw value as read_tags returns it -> the PValue the write must carry.
STRING_WRITES = {
    "DB.c": ("5a", "00025a"),  # CHAR as a USINT, not a BYTE
    "DB.s": ("040268690000", "100206040268690000"),  # STRING[4] "hi": USINT array [4, 2, h, i, 0, 0]
    "DB.w": ("0002000100e40000", "1003040002000100e40000"),  # WSTRING[2] "ä": UINT array [2, 1, ä, 0]
    "DB.dt": ("2610021234561236", "1002082610021234561236"),  # DATE_AND_TIME as its eight BCD USINTs
    "DB.i": ("fb2e", "0007fb2e"),  # unchanged
}


def test_write_types_follow_what_plcsim_accepts() -> None:
    catalog = SymbolCatalog.from_browse(STRING_BROWSE)
    assert _write_type(catalog.resolve("DB.c")) == DataType.USINT
    assert _write_type(catalog.resolve("DB.s")) == PValueArray(DataType.USINT)
    assert _write_type(catalog.resolve("DB.w")) == PValueArray(DataType.UINT)
    assert _write_type(catalog.resolve("DB.dt")) == PValueArray(DataType.USINT)
    assert _write_type(catalog.resolve("DB.i")) == DataType.INT
    dtl = SymbolCatalog.from_browse([{"name": "x", "access_sequence": "8A0E0004.1", "data_type": "DTL"}]).resolve("x")
    assert _write_type(dtl) is None


def test_encode_pvalue_array() -> None:
    assert encode_pvalue_array(DataType.USINT, bytes.fromhex("0a027071")) == bytes.fromhex("1002040a027071")
    assert encode_pvalue_array(DataType.UINT, bytes.fromhex("00fe0001006b")) == bytes.fromhex("10030300fe0001006b")
    with pytest.raises(ValueError, match="multiple of 2"):
        encode_pvalue_array(DataType.UINT, b"\x00")
    with pytest.raises(ValueError, match="not supported"):
        encode_pvalue_array(DataType.UDINT, b"\x00\x00\x00\x00")


def test_symbolic_write_payload_sends_a_string_as_a_usint_array() -> None:
    item = (0x8A0E0004, [0x12], bytes([10, 2]) + b"pq" + bytes(8), 0, PValueArray(DataType.USINT))
    payload = _build_multi_symbolic_write_payload([item], 0)
    assert bytes.fromhex("0110020c0a027071") + bytes(8) in payload


def _assert_string_writes(payload: bytes) -> None:
    for index, (_raw, pvalue) in enumerate(STRING_WRITES.values(), 1):
        assert bytes([index]) + bytes.fromhex(pvalue) in payload


def test_write_tags_sends_strings_chars_and_date_and_time_as_plcsim_accepts() -> None:
    client = S7CommPlusClient()
    client._connection = MagicMock(protocol_version=ProtocolVersion.V2, object_qualifier_version=ProtocolVersion.V2)
    client._connection.send_request.return_value = encode_uint64_vlq(0) + encode_uint32_vlq(0)
    client._symbol_catalog = SymbolCatalog.from_browse(STRING_BROWSE)

    results = client.write_tags({name: bytes.fromhex(raw) for name, (raw, _pvalue) in STRING_WRITES.items()})

    assert all(result.success for result in results)
    _assert_string_writes(client._connection.send_request.call_args.args[1])


async def test_async_write_tags_sends_strings_chars_and_date_and_time_as_plcsim_accepts() -> None:
    client = S7CommPlusAsyncClient()
    client._connected = True
    client._protocol_version = ProtocolVersion.V2
    client._symbol_catalog = SymbolCatalog.from_browse(STRING_BROWSE)
    client._send_request = AsyncMock(return_value=encode_uint64_vlq(0) + encode_uint32_vlq(0))  # type: ignore[method-assign]

    results = await client.write_tags({name: bytes.fromhex(raw) for name, (raw, _pvalue) in STRING_WRITES.items()})

    assert all(result.success for result in results)
    _assert_string_writes(client._send_request.await_args.args[1])


def test_write_tags_rejects_a_wstring_of_odd_length_before_sending() -> None:
    client = S7CommPlusClient()
    client._connection = MagicMock(protocol_version=ProtocolVersion.V2, object_qualifier_version=ProtocolVersion.V2)
    client._symbol_catalog = SymbolCatalog.from_browse(STRING_BROWSE)
    with pytest.raises(ValueError, match="multiple of 2"):
        client.write_tags({"DB.w": bytes.fromhex("00020001e4")})
    client._connection.send_request.assert_not_called()


@pytest.mark.parametrize("asynchronous", [False, True])
async def test_write_tags_splits_strings_by_their_encoded_size(asynchronous: bool) -> None:
    # Request splitting measures the payload actually sent: a STRING[254] is a 256-element USINT array.
    names = [f"DB.s{index}" for index in range(3)]
    catalog = SymbolCatalog.from_browse(
        [
            {"name": name, "access_sequence": f"8A0E0004.{index + 1}", "data_type": "STRING", "string_length": 254}
            for index, name in enumerate(names)
        ]
    )
    raw = bytes([254, 0]) + bytes(254)
    answer = encode_uint64_vlq(0) + encode_uint32_vlq(0)
    send: MagicMock
    if asynchronous:
        async_client = S7CommPlusAsyncClient()
        async_client._connected = True
        async_client._with_integrity_id = True
        async_client._send_request = send = AsyncMock(return_value=answer)  # type: ignore[method-assign]
        async_client._symbol_catalog = catalog
        async_client.max_request_bytes = 700  # two 256-byte strings fit in one frame, three do not
        results = await async_client.write_tags({name: raw for name in names})
    else:
        client = S7CommPlusClient()
        client._connection = MagicMock(object_qualifier_version=0, _with_integrity_id=True, _session_key=None)
        send = client._connection.send_request
        send.return_value = answer
        client._symbol_catalog = catalog
        client.max_request_bytes = 700
        results = client.write_tags({name: raw for name in names})

    assert all(result.success for result in results)
    payloads = [call.args[1] for call in send.call_args_list]
    assert [decode_uint32_vlq(payload, 4)[0] for payload in payloads] == [2, 1]
    assert all(bytes.fromhex("10028200") + raw in payload for payload in payloads)
