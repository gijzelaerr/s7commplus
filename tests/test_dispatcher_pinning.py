"""Pin how both clients sort the frames that arrive while they wait for a reply.

Each case feeds a sequence of frames to a client's raw receive and calls its
reply dispatcher, which skips non-fatal SystemEvents, queues notifications,
drops stale replies and returns the reply. It records what the dispatcher
returned or raised, how many frames it read, what it queued and whether it
closed the session for an integrity failure. The golden file was first
recorded from the two separate implementations, which agreed on all but two
cases; the shared dispatcher takes the length of a SessionKey frame after its
HMAC (as the sync client did) and reads past the V3 envelope of a frame
without a SessionKey (as the async client did), and the file was re-recorded
with those two changes. Set
``S7_RECORD_DISPATCHER=1`` to rewrite it.
"""

from __future__ import annotations

import asyncio
import json
import os
import struct
from pathlib import Path
from typing import Any, Optional

import pytest

from s7commplus.async_connection import S7CommPlusAsyncConnection
from s7commplus.codec import encode_header
from s7commplus.connection import (
    _MAX_STALE_RESPONSES_PER_REQUEST,
    _MAX_SYSTEM_EVENTS_PER_RESPONSE,
    S7CommPlusConnection,
    _frame_request,
)
from s7commplus.protocol import FunctionCode, Opcode, ProtocolVersion

GOLDEN = Path(__file__).parent / "fixtures" / "dispatcher_golden.json"
KEY = bytes(range(24))
EXPECTED = 40

# A non-fatal SystemEvent (16 zero bytes), and the fatal one a CPU 1512C-1 PN FW V2.5
# sent on every SessionKey renewal (#184).
SYSTEM_EVENT = bytes([0x72, ProtocolVersion.SYSTEM_EVENT, 0x00, 0x10]) + bytes(16)
FATAL_PAYLOAD = bytes.fromhex(
    "000000000003610100000000000000000000001700009d6c00009d6d000000080000000200009d6e000000040000038c"
    "00009d6f00000004000004f200009d7000000003060700009d7100000009a2013b000251ff8800009d72000000040000"
    "000000009d7300000004000004f200009d7400000004000004b60000"
)
FATAL_SYSTEM_EVENT = bytes([0x72, ProtocolVersion.SYSTEM_EVENT]) + struct.pack(">H", len(FATAL_PAYLOAD)) + FATAL_PAYLOAD


def _response(sequence: int, opcode: int = Opcode.RESPONSE) -> bytes:
    return struct.pack(">BHHHHB", opcode, 0, FunctionCode.GET_MULTI_VARIABLES, 0, sequence, 0x34) + b"\x00\x01\x02"


def _frame(data: bytes, version: int = ProtocolVersion.V2, key: Optional[bytes] = None) -> bytes:
    return _frame_request(data, version, key)


def _notification() -> bytes:
    return _frame(bytes([Opcode.NOTIFICATION]) + bytes(range(16)))


def _split(data: bytes) -> list[bytes]:
    """``data`` as two PDUs: the first without a trailer, the second with it."""
    half = len(data) // 2
    first = encode_header(ProtocolVersion.V2, half) + data[:half]
    second = encode_header(ProtocolVersion.V2, len(data) - half) + data[half:] + bytes([0x72, ProtocolVersion.V2, 0, 0])
    return [first, second]


def _tampered(frame: bytes) -> bytes:
    damaged = bytearray(frame)
    damaged[6] ^= 0xFF
    return bytes(damaged)


CASES: dict[str, tuple[list[bytes], bool, Optional[int]]] = {
    "reply": ([_frame(_response(EXPECTED))], False, EXPECTED),
    "reply-no_expected_sequence": ([_frame(_response(7))], False, None),
    "reply2_opcode": ([_frame(_response(EXPECTED, Opcode.RESPONSE2))], False, EXPECTED),
    "system_event-then-reply": ([SYSTEM_EVENT, SYSTEM_EVENT, _frame(_response(EXPECTED))], False, EXPECTED),
    "fatal_system_event": ([FATAL_SYSTEM_EVENT, _frame(_response(EXPECTED))], False, EXPECTED),
    "too_many_system_events": ([SYSTEM_EVENT] * (_MAX_SYSTEM_EVENTS_PER_RESPONSE + 1), False, EXPECTED),
    "malformed_system_event": ([bytes([0x72, ProtocolVersion.SYSTEM_EVENT, 0x00, 0x04]) + bytes(4)], False, EXPECTED),
    "notification-then-reply": ([_notification(), _notification(), _frame(_response(EXPECTED))], False, EXPECTED),
    "stale-then-reply": ([_frame(_response(EXPECTED - 1)), _frame(_response(EXPECTED))], False, EXPECTED),
    "split_stale-then-reply": ([*_split(_response(EXPECTED - 1) + bytes(40)), _frame(_response(EXPECTED))], False, EXPECTED),
    "too_many_stale": ([_frame(_response(EXPECTED - 1))] * (_MAX_STALE_RESPONSES_PER_REQUEST + 1), False, EXPECTED),
    "newer_sequence": ([_frame(_response(EXPECTED + 1))], False, EXPECTED),
    "unexpected_opcode": ([_frame(_response(EXPECTED, Opcode.REQUEST))], False, EXPECTED),
    "short_data": ([_frame(b"\x32\x00\x00")], False, EXPECTED),
    "empty_frame": ([b""], False, EXPECTED),
    "v3_unkeyed": ([_frame(_response(EXPECTED), ProtocolVersion.V3, KEY)], False, EXPECTED),
    "keyed-reply": ([_frame(_response(EXPECTED), ProtocolVersion.V3, KEY)], True, EXPECTED),
    "keyed-notification-then-reply": (
        [
            _frame(bytes([Opcode.NOTIFICATION]) + bytes(16), ProtocolVersion.V3, KEY),
            _frame(_response(EXPECTED), ProtocolVersion.V3, KEY),
        ],
        True,
        EXPECTED,
    ),
    "keyed-tampered": ([_tampered(_frame(_response(EXPECTED), ProtocolVersion.V3, KEY))], True, EXPECTED),
    "keyed-unauthenticated_frame": ([_frame(_response(EXPECTED))], True, EXPECTED),
    "keyed-short_data": ([_frame(b"\x32\x00\x00", ProtocolVersion.V3, KEY)], True, EXPECTED),
}


def _prepare(obj: Any, keyed: bool) -> None:
    obj._connected = True
    obj._protocol_version = ProtocolVersion.V3 if keyed else ProtocolVersion.V2
    obj._session_key = KEY if keyed else None


def _outcome(obj: Any, result: Any, frames: list[bytes], total: int, invalidated: list[bool]) -> dict[str, Any]:
    return {
        "result": result,
        "frames_read": total - len(frames),
        "notifications_queued": [frame.hex() for frame in obj._notification_frames],
        "invalidated": bool(invalidated),
    }


def _run_sync(name: str) -> dict[str, Any]:
    frames, keyed, expected = CASES[name]
    frames = list(frames)
    total = len(frames)
    conn = S7CommPlusConnection("127.0.0.1")
    _prepare(conn, keyed)
    invalidated: list[bool] = []

    def recv(timeout: Optional[float] = None, *, idle_ok: bool = False) -> bytes:
        if not frames:
            raise AssertionError("read past the last frame")
        return frames.pop(0)

    conn._recv_s7_data = recv  # type: ignore[method-assign]
    conn._invalidate_integrity_failure = lambda: invalidated.append(True)  # type: ignore[method-assign]
    try:
        result: Any = conn._recv_response_frame(expected, 5.0).hex()
    except Exception as exc:  # recorded, not judged
        result = f"{type(exc).__name__}: {exc}"
    return _outcome(conn, result, frames, total, invalidated)


def _run_async(name: str) -> dict[str, Any]:
    frames, keyed, expected = CASES[name]
    frames = list(frames)
    total = len(frames)
    client = S7CommPlusAsyncConnection()
    _prepare(client, keyed)
    client._reader = object()  # type: ignore[assignment]
    client._writer = object()  # type: ignore[assignment]
    invalidated: list[bool] = []

    async def recv() -> bytes:
        if not frames:
            raise AssertionError("read past the last frame")
        return frames.pop(0)

    async def invalidate() -> None:
        invalidated.append(True)

    client._recv_cotp_dt = recv  # type: ignore[method-assign]
    client._invalidate_integrity_failure = invalidate  # type: ignore[method-assign]
    try:
        result: Any = asyncio.run(client._recv_response_frame(expected)).hex()
    except Exception as exc:  # recorded, not judged
        result = f"{type(exc).__name__}: {exc}"
    return _outcome(client, result, frames, total, invalidated)


def _record() -> dict[str, Any]:
    return {name: {"sync": _run_sync(name), "async": _run_async(name)} for name in CASES}


if os.environ.get("S7_RECORD_DISPATCHER") == "1":  # pragma: no cover - maintenance switch
    GOLDEN.write_text(json.dumps(_record(), indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")

_GOLDEN: dict[str, Any] = json.loads(GOLDEN.read_text(encoding="utf-8")) if GOLDEN.exists() else {}


@pytest.mark.parametrize("name", list(CASES))
def test_sync_dispatcher_matches_the_recording(name: str) -> None:
    assert _run_sync(name) == _GOLDEN[name]["sync"]


@pytest.mark.parametrize("name", list(CASES))
def test_async_dispatcher_matches_the_recording(name: str) -> None:
    assert _run_async(name) == _GOLDEN[name]["async"]


@pytest.mark.parametrize("name", list(CASES))
def test_sync_and_async_dispatchers_agree(name: str) -> None:
    assert _run_sync(name) == _run_async(name)
