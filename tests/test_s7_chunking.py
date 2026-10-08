"""Multi-item requests are split to the per-request item cap and request frame size."""

from __future__ import annotations

import inspect
import os
import time
from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from s7commplus.async_client import S7CommPlusAsyncClient
from s7commplus.catalog import SymbolCatalog, SymbolicTag
from s7commplus.client import S7CommPlusClient, _build_read_payload, _chunks, _request_chunks
from s7commplus.codec import encode_pvalue_blob
from s7commplus.connection import _frame_request, _request_frame_overhead
from s7commplus.error import S7ConnectionError, S7Error, S7TimeoutError, S7WriteError
from s7commplus.protocol import DataType, FunctionCode, ProtocolVersion
from s7commplus.server import S7CommPlusServer
from s7commplus.typeinfo import Softdatatype
from s7commplus.vlq import decode_uint32_vlq, encode_uint32_vlq, encode_uint64_vlq
from tests.conftest import get_free_tcp_port
from tests.test_s7_tls import _generate_self_signed_cert

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


def _answer_everything(function_code: int, payload: bytes, *args: Any, **kwargs: Any) -> bytes:
    """Answer any read or write request with every item successful."""
    count = decode_uint32_vlq(payload, 4)[0]
    if function_code == FunctionCode.GET_MULTI_VARIABLES:
        return _read_answer({number: b"\x00" for number in range(1, count + 1)})
    return _write_answer()


class _Client:
    """A sync or async client whose requests are answered from a script, or all successfully.

    Its session sends an IntegrityId and has no SessionKey, so a request frame
    adds 27 bytes to the payload. ``max_request_bytes`` defaults to 0 here, so
    only the item cap splits unless a test sets it.
    """

    def __init__(self, kind: str, answers: list[Any] | None, max_items: int = 2, max_request_bytes: int = 0) -> None:
        side_effect: Any = answers if answers is not None else _answer_everything
        self.client: S7CommPlusClient | S7CommPlusAsyncClient
        if kind == "sync":
            sync_client = S7CommPlusClient()
            connection = MagicMock(
                object_qualifier_version=0, requires_substreamed=False, _with_integrity_id=True, _session_key=None
            )
            connection.send_request.side_effect = side_effect
            sync_client._connection = connection
            self.client, self.send = sync_client, connection.send_request
        else:
            async_client = S7CommPlusAsyncClient()
            async_client._connected = True
            async_client._with_integrity_id = True
            async_client._send_request = AsyncMock(side_effect=side_effect)  # type: ignore[method-assign]
            self.client, self.send = async_client, async_client._send_request
        self.client.max_items_per_request = max_items
        self.client.max_request_bytes = max_request_bytes

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

    assert _request_chunks([1, 2, 3, 4, 5], 2, 0, 0, build) == [([1, 2], b"\x01\x02"), ([3, 4], b"\x03\x04"), ([5], b"\x05")]
    assert built == [[1, 2], [3, 4], [5]]
    assert _request_chunks([], 2, 0, 0, build) == []


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


# --- Requests stay within max_request_bytes -----------------------------------------------


def _ten_bytes_per_item(chunk: list[int]) -> bytes:
    return bytes(4 + 10 * len(chunk))  # a 4-byte fixed part and 10 bytes per item


def test_request_chunks_respects_the_frame_budget() -> None:
    # Overhead 6: a request of k items makes a 10 + 10k byte frame, so 40 bytes hold 3.
    chunks = _request_chunks(list(range(10)), 100, 40, 6, _ten_bytes_per_item)
    assert [chunk for chunk, _ in chunks] == [[0, 1, 2], [3, 4, 5], [6, 7, 8], [9]]
    assert all(len(payload) + 6 <= 40 for _, payload in chunks)


def test_a_frame_exactly_at_the_budget_fits_and_one_byte_more_splits() -> None:
    assert [chunk for chunk, _ in _request_chunks([0, 1, 2], 0, 40, 6, _ten_bytes_per_item)] == [[0, 1, 2]]
    assert [chunk for chunk, _ in _request_chunks([0, 1, 2], 0, 39, 6, _ten_bytes_per_item)] == [[0, 1], [2]]


def test_the_item_cap_still_applies_under_the_budget() -> None:
    assert [len(chunk) for chunk, _ in _request_chunks(list(range(7)), 2, 1000, 6, _ten_bytes_per_item)] == [2, 2, 2, 1]


def test_an_item_over_the_budget_on_its_own_raises() -> None:
    def build(chunk: list[int]) -> bytes:
        return bytes(4 + sum(chunk))

    with pytest.raises(ValueError, match="item 2 alone needs a 110-byte request, over max_request_bytes=100"):
        _request_chunks([10, 100, 10], 0, 100, 6, build)


def test_request_chunks_trims_a_request_whose_vlq_count_outgrows_the_estimate() -> None:
    # A VLQ item count plus one byte per item: the count takes a second byte from
    # 128 items on, which the per-item estimate does not see.
    def build(chunk: list[int]) -> bytes:
        return encode_uint32_vlq(len(chunk)) + bytes(len(chunk))

    chunks = _request_chunks(list(range(300)), 0, 129, 0, build)

    assert [len(chunk) for chunk, _ in chunks] == [127, 127, 46]
    assert [item for chunk, _ in chunks for item in chunk] == list(range(300))
    assert all(len(payload) <= 129 for _, payload in chunks)


def test_request_chunks_is_linear_in_the_number_of_items() -> None:
    calls = 0

    def build(chunk: list[int]) -> bytes:
        nonlocal calls
        calls += 1
        return _ten_bytes_per_item(chunk)

    chunks = _request_chunks(list(range(5000)), 0, 1000, 0, build)

    # One build per item alone, one for a pair, one per request.
    assert calls == 5000 + 1 + len(chunks)


@pytest.mark.parametrize(("with_integrity_id", "session_key"), [(False, None), (True, None), (True, bytes(range(24)))])
def test_request_frame_overhead_matches_the_frame(with_integrity_id: bool, session_key: bytes | None) -> None:
    payload = bytes(100)
    integrity_id = encode_uint32_vlq(0xFFFFFFFF) if with_integrity_id else b""  # the longest IntegrityId
    request = bytes(14) + payload[:-4] + integrity_id + payload[-4:]

    frame = _frame_request(request, ProtocolVersion.V2, session_key)

    assert len(frame) == len(payload) + _request_frame_overhead(with_integrity_id, session_key is not None)


@kinds
async def test_a_batch_whose_frame_is_exactly_max_request_bytes_goes_in_one_request(kind: str) -> None:
    items = [(1, offset, 1) for offset in range(5)]
    frame = len(_build_read_payload(items, 0)) + 27
    whole = _Client(kind, None, max_items=0, max_request_bytes=frame)
    split = _Client(kind, None, max_items=0, max_request_bytes=frame - 1)

    assert whole.client._frame_overhead() == 27
    assert await whole.call("db_read_multi", items) == [b"\x00"] * 5
    assert await split.call("db_read_multi", items) == [b"\x00"] * 5
    assert whole.item_counts() == [5]
    assert split.item_counts() == [4, 1]


@kinds
async def test_the_default_budget_splits_a_large_read(kind: str) -> None:
    plc = _Client(kind, None, max_items=100, max_request_bytes=900)

    await plc.call("read_symbolic_multi", [(0x8A0E0001, [index + 1], 0) for index in range(250)])

    sent = [call.args[1] for call in plc.send.call_args_list]
    assert sum(plc.item_counts()) == 250
    assert len(sent) > 3  # the 100-item cap alone would give 3 requests
    assert all(len(payload) + 27 <= 900 for payload in sent)


@kinds
async def test_an_item_too_large_for_one_request_raises_before_anything_is_sent(kind: str) -> None:
    plc = _Client(kind, None, max_request_bytes=900)
    items = [(1, 0, b"\x00", DataType.BYTE), (1, 2, bytes(1000), DataType.BLOB), (1, 1, b"\x00", DataType.BYTE)]

    with pytest.raises(ValueError, match="item 2 alone"):
        await plc.call("db_write_multi", items)
    with pytest.raises(ValueError, match="item 1 alone"):
        await plc.call("db_write", 1, 0, bytes(1000))

    plc.send.assert_not_called()


@kinds
async def test_write_tags_refuses_a_value_too_large_for_one_request(kind: str) -> None:
    plc = _Client(kind, None, max_request_bytes=900)
    plc.client._symbol_catalog = SymbolCatalog(
        [
            SymbolicTag("DB.short", 0x8A0E0001, (1,), Softdatatype.INT, DataType.INT),
            SymbolicTag("DB.text", 0x8A0E0001, (2,), Softdatatype.WSTRING, DataType.WSTRING),
        ]
    )

    with pytest.raises(ValueError, match="item 2 alone"):
        await plc.call("write_tags", {"DB.short": b"\x00\x01", "DB.text": "x".encode("utf-16-be") * 500})
    plc.send.assert_not_called()


# --- The emulator drops an oversized request like a PLC does ------------------------------

TEST_FINGERPRINT = "01:BD426B091F08731A"
TEST_CHALLENGE = bytes(range(20))
TEST_SESSION_KEY = bytes(range(24))


@pytest.fixture(scope="module")
def tls_files() -> Iterator[tuple[str, str]]:
    cert_path, key_path = _generate_self_signed_cert()
    yield cert_path, key_path
    os.unlink(cert_path)
    os.unlink(key_path)


@pytest.fixture(params=["plain", "tls", "session_key"])
def limited_plc(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch, tls_files: tuple[str, str]
) -> Iterator[tuple[S7CommPlusServer, int, dict[str, Any]]]:
    """An emulator that drops requests over 900 bytes: plain V1, V2 with TLS, or V1 SessionKey (V3 framing)."""
    connect_kwargs: dict[str, Any] = {}
    if request.param == "session_key":
        # The emulator does not hold Siemens' private key: fix the key exchange.
        from s7commplus.v1_session_key import handshake, legitimation

        monkeypatch.setattr(handshake, "authenticate_real_plc", lambda *args: (bytes(180), TEST_SESSION_KEY))
        monkeypatch.setattr(legitimation, "solve_legitimate_challenge_real_plc", lambda *args: bytes(248))
        server = S7CommPlusServer(
            public_key_fingerprint=TEST_FINGERPRINT,
            session_challenge=TEST_CHALLENGE,
            session_key=TEST_SESSION_KEY,
            max_request_bytes=900,
        )
    elif request.param == "tls":
        server = S7CommPlusServer(protocol_version=ProtocolVersion.V2, max_request_bytes=900)
        connect_kwargs = {"use_tls": True, "tls_ca": tls_files[0]}
    else:
        server = S7CommPlusServer(max_request_bytes=900)
    server.register_raw_db(2, bytearray(range(256)))
    port = get_free_tcp_port()
    if request.param == "tls":
        server.start(port=port, use_tls=True, tls_cert=tls_files[0], tls_key=tls_files[1])
    else:
        server.start(port=port)
    time.sleep(0.1)
    yield server, port, connect_kwargs
    server.stop()


class _Live:
    """A sync or async client connected to the emulator, recording the length of each frame it sends."""

    def __init__(self, kind: str) -> None:
        self.kind = kind
        self.client: S7CommPlusClient | S7CommPlusAsyncClient = S7CommPlusClient() if kind == "sync" else S7CommPlusAsyncClient()
        self.frames: list[int] = []

    async def connect(self, port: int, **kwargs: Any) -> None:
        if isinstance(self.client, S7CommPlusClient):
            self.client.connect("127.0.0.1", port=port, **kwargs)
            connection = self.client._connection
            assert connection is not None
            send = connection._send_s7_data

            def record(data: bytes) -> None:
                self.frames.append(len(data))
                send(data)

            connection._send_s7_data = record  # type: ignore[method-assign]
        else:
            await self.client.connect("127.0.0.1", port=port, **kwargs)
            send_async = self.client._send_cotp_dt

            async def record_async(data: bytes) -> None:
                self.frames.append(len(data))
                await send_async(data)

            self.client._send_cotp_dt = record_async  # type: ignore[method-assign]

    async def call(self, method: str, *args: Any) -> Any:
        result = getattr(self.client, method)(*args)
        return await result if inspect.isawaitable(result) else result

    def next_read_integrity_id(self) -> bytes:
        """The IntegrityId the next read will carry, or nothing if the session sends none."""
        if isinstance(self.client, S7CommPlusClient):
            connection = self.client._connection
            assert connection is not None
            return encode_uint32_vlq(connection._integrity_id_read) if connection._with_integrity_id else b""
        return encode_uint32_vlq(self.client._integrity_id_read) if self.client._with_integrity_id else b""

    def object_qualifier_version(self) -> int:
        if isinstance(self.client, S7CommPlusClient):
            assert self.client._connection is not None
            return self.client._connection.object_qualifier_version
        return self.client.object_qualifier_version

    async def close(self) -> None:
        result = self.client.disconnect()
        if inspect.isawaitable(result):
            await result


# A dropped connection raises S7ConnectionError, or on some paths the raw ssl or
# asyncio end-of-stream error.
_DROPPED = (S7Error, OSError, EOFError)


def test_server_rejects_a_non_positive_request_limit() -> None:
    with pytest.raises(ValueError, match="max_request_bytes"):
        S7CommPlusServer(max_request_bytes=0)


@kinds
async def test_emulator_accepts_a_batch_the_client_splits(
    kind: str, limited_plc: tuple[S7CommPlusServer, int, dict[str, Any]]
) -> None:
    _, port, connect_kwargs = limited_plc
    live = _Live(kind)
    await live.connect(port, **connect_kwargs)
    try:
        assert await live.call("db_read_multi", [(2, offset, 1) for offset in range(200)]) == [bytes([n]) for n in range(200)]
        assert len(live.frames) > 1 and max(live.frames) <= 900
    finally:
        await live.close()


@kinds
async def test_emulator_drops_a_request_over_its_limit(
    kind: str, limited_plc: tuple[S7CommPlusServer, int, dict[str, Any]]
) -> None:
    _, port, connect_kwargs = limited_plc
    live = _Live(kind)
    await live.connect(port, **connect_kwargs)
    live.client.max_items_per_request = 0
    live.client.max_request_bytes = 0  # no splitting: one request of about 2.5 KB
    try:
        with pytest.raises(_DROPPED):
            await live.call("db_read_multi", [(2, offset, 1) for offset in range(200)])
    finally:
        await live.close()


@kinds
async def test_emulator_and_client_count_the_same_frame(
    kind: str, limited_plc: tuple[S7CommPlusServer, int, dict[str, Any]]
) -> None:
    """The client's budget and the emulator's limit both bound the frame as sent, before TLS."""
    server, port, connect_kwargs = limited_plc
    live = _Live(kind)
    await live.connect(port, **connect_kwargs)
    items = [(2, offset, 1) for offset in range(20)]
    try:
        payload = _build_read_payload(items, live.object_qualifier_version())
        integrity_id = live.next_read_integrity_id()
        assert await live.call("db_read_multi", items) == [bytes([n]) for n in range(20)]
        frame = live.frames[-1]
        # The client budgets the IntegrityId at its longest, 5 bytes.
        assert frame == len(payload) + live.client._frame_overhead() - (5 - len(integrity_id) if integrity_id else 0)

        server._max_request_bytes = frame  # a frame exactly at the limit passes
        assert await live.call("db_read_multi", items) == [bytes([n]) for n in range(20)]
        assert live.frames[-1] == frame

        server._max_request_bytes = frame - 1  # one byte over is dropped
        with pytest.raises(_DROPPED):
            await live.call("db_read_multi", items)
    finally:
        await live.close()
