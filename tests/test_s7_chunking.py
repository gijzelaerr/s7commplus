"""Multi-item requests are split to the per-request item cap."""

from __future__ import annotations

import inspect
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from s7commplus.async_client import S7CommPlusAsyncClient
from s7commplus.catalog import SymbolCatalog, SymbolicTag
from s7commplus.client import S7CommPlusClient, _chunks, _request_chunks
from s7commplus.codec import encode_pvalue_blob
from s7commplus.error import S7ConnectionError, S7TimeoutError, S7WriteError
from s7commplus.protocol import DataType
from s7commplus.typeinfo import Softdatatype
from s7commplus.vlq import decode_uint32_vlq, encode_uint32_vlq, encode_uint64_vlq

REFUSED = 0x8104  # any non-zero return value refuses a request as a whole


def _read_answer(values: dict[int, bytes], errors: dict[int, int] | None = None) -> bytes:
    """A GetMultiVariables answer: the values, then the per-item errors, by item number."""
    answer = encode_uint64_vlq(0)
    for number, value in values.items():
        answer += encode_uint32_vlq(number) + encode_pvalue_blob(value)
    answer += b"\x00"
    for number, code in (errors or {}).items():
        answer += encode_uint32_vlq(number) + encode_uint64_vlq(code)
    return answer + b"\x00"


def _write_answer(errors: dict[int, int] | None = None) -> bytes:
    """A SetMultiVariables answer refusing ``errors`` (item number -> PLC error)."""
    answer = encode_uint64_vlq(0)
    for number, code in (errors or {}).items():
        answer += encode_uint32_vlq(number) + encode_uint64_vlq(code)
    return answer + b"\x00"


def _refused_answer() -> bytes:
    return encode_uint64_vlq(REFUSED)


class _Client:
    """A sync or async client whose requests are answered from a script."""

    def __init__(self, kind: str, answers: list[Any], max_items: int = 2) -> None:
        self.client: S7CommPlusClient | S7CommPlusAsyncClient
        if kind == "sync":
            sync_client = S7CommPlusClient()
            connection = MagicMock(object_qualifier_version=0, requires_substreamed=False)
            connection.send_request.side_effect = answers
            sync_client._connection = connection
            self.client, self.send = sync_client, connection.send_request
        else:
            async_client = S7CommPlusAsyncClient()
            async_client._connected = True
            async_client._send_request = AsyncMock(side_effect=answers)  # type: ignore[method-assign]
            self.client, self.send = async_client, async_client._send_request
        self.client.max_items_per_request = max_items

    async def call(self, method: str, *args: Any) -> Any:
        result = getattr(self.client, method)(*args)
        return await result if inspect.isawaitable(result) else result

    def item_counts(self) -> list[int]:
        """The item count of each request sent (the VLQ after the 4-byte link id)."""
        return [decode_uint32_vlq(call.args[1], 4)[0] for call in self.send.call_args_list]

    def use_tags(self, count: int) -> list[str]:
        tags = [SymbolicTag(f"DB.tag{index}", 0x8A0E0001, (index + 1,), Softdatatype.INT, DataType.INT) for index in range(count)]
        self.client._symbol_catalog = SymbolCatalog(tags)
        return [tag.name for tag in tags]


kinds = pytest.mark.parametrize("kind", ["sync", "async"])


def test_chunks_splits_and_preserves_order() -> None:
    assert list(_chunks(list(range(5)), 2)) == [[0, 1], [2, 3], [4]]
    assert list(_chunks([1, 2, 3], 0)) == [[1, 2, 3]]
    assert list(_chunks([], 2)) == []


def test_request_chunks_builds_each_payload_once_before_returning() -> None:
    built: list[list[int]] = []

    def build(chunk: list[int]) -> bytes:
        built.append(chunk)
        return bytes(chunk)

    assert _request_chunks([1, 2, 3, 4, 5], 2, build) == [([1, 2], b"\x01\x02"), ([3, 4], b"\x03\x04"), ([5], b"\x05")]
    assert built == [[1, 2], [3, 4], [5]]
    assert _request_chunks([], 2, build) == []


@kinds
async def test_read_symbolic_multi_splits_by_item_cap(kind: str) -> None:
    answers = [
        _read_answer({n: bytes([start + n]) for n in range(1, size + 1)}) for start, size in ((0, 100), (100, 100), (200, 50))
    ]
    plc = _Client(kind, answers, max_items=100)

    results = await plc.call("read_symbolic_multi", [(0x8A0E0001, [index + 1], 0) for index in range(250)])

    assert results == [bytes([(index + 1) & 0xFF]) for index in range(250)]
    assert plc.item_counts() == [100, 100, 50]


@kinds
async def test_db_read_multi_keeps_values_on_their_items_when_a_request_is_refused(kind: str) -> None:
    # Five items at two per request; the PLC refuses the second request as a whole.
    plc = _Client(kind, [_read_answer({1: b"a", 2: b"b"}), _refused_answer(), _read_answer({1: b"e"})])

    results = await plc.call("db_read_multi", [(1, offset, 1) for offset in range(5)])

    assert results == [b"a", b"b", b"", b"", b"e"]
    assert plc.item_counts() == [2, 2, 1]


@kinds
async def test_db_read_multi_keeps_an_item_error_in_place(kind: str) -> None:
    plc = _Client(kind, [_read_answer({2: b"b"}, errors={1: 0x13}), _read_answer({1: b"c"})])

    assert await plc.call("db_read_multi", [(1, offset, 1) for offset in range(3)]) == [b"", b"b", b"c"]


@kinds
async def test_db_read_multi_rejects_an_answer_that_skips_an_item(kind: str) -> None:
    # The PLC answers only item 1 of the first request: the second value must not
    # slide onto item 2.
    plc = _Client(kind, [_read_answer({1: b"a"}), _read_answer({1: b"c"})])

    with pytest.raises(RuntimeError, match="1 of 2 items"):
        await plc.call("db_read_multi", [(1, offset, 1) for offset in range(3)])


@kinds
async def test_db_write_multi_splits_by_item_cap(kind: str) -> None:
    plc = _Client(kind, [_write_answer()] * 3, max_items=100)

    await plc.call("db_write_multi", [(1, 2 * index, b"\x00\x00", DataType.INT) for index in range(250)])

    assert plc.item_counts() == [100, 100, 50]


@kinds
async def test_db_write_multi_reports_refused_items_by_batch_position(kind: str) -> None:
    # Request 2 refuses its first item; request 3 is refused as a whole. Every
    # request is still sent, as the PLC tries every item of a single request.
    plc = _Client(kind, [_write_answer(), _write_answer({1: 0x13}), _refused_answer()])

    with pytest.raises(S7WriteError, match="item 3: error 19") as caught:
        await plc.call("db_write_multi", [(1, index, b"\x00", DataType.BYTE) for index in range(6)])

    assert isinstance(caught.value, RuntimeError)
    assert caught.value.item_errors == {3: 0x13, 5: REFUSED, 6: REFUSED}
    assert not caught.value.unknown and not caught.value.not_sent
    assert plc.send.call_count == 3


@kinds
async def test_db_write_multi_interrupted_after_the_first_request(kind: str) -> None:
    lost = S7ConnectionError("Receive error: connection reset")
    plc = _Client(kind, [_write_answer({2: 0x13}), lost])

    with pytest.raises(S7WriteError, match="after 2 of 7 items") as caught:
        await plc.call("db_write_multi", [(1, index, b"\x00", DataType.BYTE) for index in range(7)])

    assert caught.value.__cause__ is lost
    assert caught.value.item_errors == {2: 0x13}
    assert caught.value.unknown == range(3, 5)
    assert caught.value.not_sent == range(5, 8)
    assert plc.send.call_count == 2


@kinds
async def test_db_write_multi_failure_of_the_first_request_propagates_unchanged(kind: str) -> None:
    plc = _Client(kind, [S7TimeoutError("Receive timeout")])

    with pytest.raises(S7TimeoutError):
        await plc.call("db_write_multi", [(1, index, b"\x00", DataType.BYTE) for index in range(5)])
    assert plc.send.call_count == 1


@kinds
async def test_write_tags_maps_refusals_to_their_tags_across_requests(kind: str) -> None:
    plc = _Client(kind, [_write_answer(), _write_answer({2: 0x13}), _refused_answer()])
    names = plc.use_tags(5)

    results = await plc.call("write_tags", {name: b"\x00\x01" for name in names})

    assert [result.success for result in results] == [True, True, True, False, False]
    assert "DB.tag3" in str(results[3].error) and "PLC error 19" in str(results[3].error)
    assert "return value" in str(results[4].error)
    assert plc.item_counts() == [2, 2, 1]


@kinds
async def test_write_tags_reports_an_interrupted_batch_per_tag(kind: str) -> None:
    lost = S7ConnectionError("Receive error: connection reset")
    plc = _Client(kind, [_write_answer({1: 0x13}), lost])
    names = plc.use_tags(7)

    results = await plc.call("write_tags", {name: b"\x00\x01" for name in names})

    assert results[0].error is not None and results[1].success
    interrupted = results[2].error
    assert isinstance(interrupted, S7WriteError)
    assert all(result.error is interrupted for result in results[2:])
    assert interrupted.__cause__ is lost
    assert interrupted.unknown == range(3, 5)
    assert interrupted.not_sent == range(5, 8)
    assert plc.send.call_count == 2


@kinds
async def test_write_tags_failure_of_the_first_request_propagates_unchanged(kind: str) -> None:
    plc = _Client(kind, [S7ConnectionError("Receive error: connection reset")])
    names = plc.use_tags(3)

    with pytest.raises(S7ConnectionError):
        await plc.call("write_tags", {name: b"\x00\x01" for name in names})
