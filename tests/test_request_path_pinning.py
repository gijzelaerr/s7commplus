"""Pin what both clients send and return on the request path, against a recorded golden file.

The golden file was first recorded from the separate sync and async
implementations, before they shared their request path. The two then agreed on
every case but the eight that force IntegrityId tracking on for a V1 session
without a SessionKey, where the sync connection added an IntegrityId; the shared
path does not, and the file was re-recorded with that one change. Each case sets up a session's state on
an unconnected client, sends one request with the I/O stubbed out, answers it
with a canned reply frame, and records the frame sent, the payload returned or
the exception raised, and the IntegrityId counters afterwards.

Set ``S7_RECORD_REQUEST_PATH=1`` to rewrite the golden file.
"""

from __future__ import annotations

import asyncio
import itertools
import json
import os
import struct
from pathlib import Path
from typing import Any, Optional

import pytest

from s7commplus.async_client import S7CommPlusAsyncClient
from s7commplus.connection import S7CommPlusConnection, _frame_request
from s7commplus.protocol import FunctionCode, Opcode, ProtocolVersion

GOLDEN = Path(__file__).parent / "fixtures" / "request_path_golden.json"
SESSION_KEY = bytes(range(32))

FUNCTIONS = [
    (FunctionCode.GET_MULTI_VARIABLES, 4),
    (FunctionCode.SET_MULTI_VARIABLES, 4),
    (FunctionCode.EXPLORE, 5),
    (FunctionCode.SET_VARIABLE, 3),
]
VERSIONS = [ProtocolVersion.V1, ProtocolVersion.V2, ProtocolVersion.V3]
REPLIES = ["plain", "v3_tampered", "v1_frame"]


def _reply_frame(function_code: int, sequence: int, version: int, session_key: Optional[bytes], kind: str) -> bytes:
    payload = b"\x05\x00\x01\x02\x03\x00\x00\x00\x00"
    response = struct.pack(">BHHHHB", Opcode.RESPONSE, 0, function_code, 0, sequence, 0x34) + payload
    if kind == "v1_frame":
        return _frame_request(response, ProtocolVersion.V1, None)
    frame = bytearray(_frame_request(response, version, session_key))
    if kind == "v3_tampered" and session_key is not None:
        frame[6] ^= 0xFF  # a byte of the HMAC
    return bytes(frame)


def _cases() -> list[dict[str, Any]]:
    cases = []
    for (function_code, tail), version, keyed, integrity, reply in itertools.product(
        FUNCTIONS, VERSIONS, [False, True], [False, True], REPLIES
    ):
        if reply == "v3_tampered" and not keyed:
            continue
        cases.append(
            {
                "function_code": int(function_code),
                "integrity_tail": tail,
                "version": int(version),
                "keyed": keyed,
                "integrity": integrity,
                "reply": reply,
            }
        )
    return cases


def _case_id(case: dict[str, Any]) -> str:
    return "{function_code:04x}-tail{integrity_tail}-v{version}-key{keyed:d}-iid{integrity:d}-{reply}".format(**case)


def _setup(obj: Any, case: dict[str, Any]) -> None:
    obj._connected = True
    obj._session_id = 0x70000123
    obj._sequence_number = 41
    obj._protocol_version = case["version"]
    obj._session_key = SESSION_KEY if case["keyed"] else None
    obj._with_integrity_id = case["integrity"]
    obj._integrity_id_read = 7
    obj._integrity_id_write = 300


def _outcome(obj: Any, sent: list[bytes], result: Any) -> dict[str, Any]:
    return {
        "sent": [frame.hex() for frame in sent],
        "result": result,
        "integrity_ids": [obj._integrity_id_read, obj._integrity_id_write],
        "sequence_number": obj._sequence_number,
    }


def _run_sync(case: dict[str, Any]) -> dict[str, Any]:
    conn = S7CommPlusConnection("127.0.0.1")
    _setup(conn, case)
    sent: list[bytes] = []
    conn._send_s7_data = sent.append  # type: ignore[method-assign]

    def reply(sequence: int, timeout: float) -> bytes:
        return _reply_frame(case["function_code"], sequence, case["version"], conn._session_key, case["reply"])

    conn._recv_response_frame = reply  # type: ignore[method-assign]
    conn._invalidate_integrity_failure = lambda: None  # type: ignore[method-assign]
    payload = b"\xaa\xbb\xcc\xdd\xee\xff"
    try:
        result: Any = conn._send_request(case["function_code"], payload, case["integrity_tail"], False).hex()
    except Exception as exc:  # recorded, not judged
        result = f"{type(exc).__name__}: {exc}"
    return _outcome(conn, sent, result)


def _run_async(case: dict[str, Any]) -> dict[str, Any]:
    client = S7CommPlusAsyncClient()
    _setup(client, case)
    client._reader = object()  # type: ignore[assignment]
    client._writer = object()  # type: ignore[assignment]
    sent: list[bytes] = []

    async def send(frame: bytes) -> None:
        sent.append(frame)

    async def reply(sequence: Optional[int] = None) -> bytes:
        assert sequence is not None
        return _reply_frame(case["function_code"], sequence, case["version"], client._session_key, case["reply"])

    async def invalidate() -> None:
        return None

    client._send_cotp_dt = send  # type: ignore[method-assign]
    client._recv_response_frame = reply  # type: ignore[method-assign]
    client._invalidate_integrity_failure = invalidate  # type: ignore[method-assign]
    payload = b"\xaa\xbb\xcc\xdd\xee\xff"

    async def run() -> Any:
        return await client._send_request_locked(case["function_code"], payload, case["integrity_tail"], False)

    try:
        result: Any = asyncio.run(run()).hex()
    except Exception as exc:  # recorded, not judged
        result = f"{type(exc).__name__}: {exc}"
    return _outcome(client, sent, result)


def _record() -> dict[str, Any]:
    return {_case_id(case): {"sync": _run_sync(case), "async": _run_async(case)} for case in _cases()}


if os.environ.get("S7_RECORD_REQUEST_PATH") == "1":  # pragma: no cover - maintenance switch
    GOLDEN.parent.mkdir(parents=True, exist_ok=True)
    GOLDEN.write_text(json.dumps(_record(), indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")

_GOLDEN: dict[str, Any] = json.loads(GOLDEN.read_text(encoding="utf-8")) if GOLDEN.exists() else {}


@pytest.mark.parametrize("case", _cases(), ids=_case_id)
def test_sync_request_path_matches_the_recording(case: dict[str, Any]) -> None:
    assert _run_sync(case) == _GOLDEN[_case_id(case)]["sync"]


@pytest.mark.parametrize("case", _cases(), ids=_case_id)
def test_async_request_path_matches_the_recording(case: dict[str, Any]) -> None:
    assert _run_async(case) == _GOLDEN[_case_id(case)]["async"]


@pytest.mark.parametrize("case", _cases(), ids=_case_id)
def test_sync_and_async_request_paths_agree(case: dict[str, Any]) -> None:
    assert _run_sync(case) == _run_async(case)
