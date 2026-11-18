"""Pin how both clients reassemble a reply the PLC split over several PDUs.

Each case starts reassembly with a first chunk and feeds further chunks to the
client's raw receive, the way the transport delivers them, and records what
reassembly returned or raised, how many chunks it read, and whether it closed
the session for an integrity failure. The golden file was first recorded from
the two separate implementations. Set ``S7_RECORD_REASSEMBLY=1`` to rewrite it.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any, Optional

import pytest

from s7commplus.async_client import S7CommPlusAsyncClient
from s7commplus.codec import encode_header
from s7commplus.connection import _MAX_SYSTEM_EVENTS_PER_RESPONSE, S7CommPlusConnection
from s7commplus.protocol import ProtocolVersion

GOLDEN = Path(__file__).parent / "fixtures" / "reassembly_golden.json"
KEY = bytes(range(24))
V2 = ProtocolVersion.V2
V3 = ProtocolVersion.V3
SYSTEM_EVENT = bytes([0x72, ProtocolVersion.SYSTEM_EVENT, 0x00, 0x10]) + bytes(16)
PARTS = [bytes([0x32, 0, 0, 0x05, 0x86, 0, 0, 0, 0x28, 0x34]) + bytes(range(20)), bytes(range(100, 140)), bytes(range(200, 230))]


def _trailer(version: int) -> bytes:
    return bytes([0x72, version, 0, 0])


def _plain(parts: list[bytes], version: int = V2) -> list[bytes]:
    """Each part as a fragment, the last one followed by the trailer."""
    out = [encode_header(version, len(p)) + p for p in parts]
    out[-1] += _trailer(version)
    return out


def _chained(parts: list[bytes]) -> list[bytes]:
    """V3 fragments whose HMAC covers all fragment data so far, as a SessionKey reply carries them."""
    out, seen = [], b""
    for p in parts:
        seen += p
        protected = bytes([0x20]) + hmac.new(KEY, seen, hashlib.sha256).digest() + p
        out.append(encode_header(V3, len(protected)) + protected)
    out[-1] += _trailer(V3)
    return out


def _independent(parts: list[bytes]) -> list[bytes]:
    """V3 fragments with an HMAC over each fragment alone, one dialect the legacy profile accepts."""
    out = []
    for p in parts:
        protected = bytes([0x20]) + hmac.new(KEY, p, hashlib.sha256).digest() + p
        out.append(encode_header(V3, len(protected)) + protected)
    out[-1] += _trailer(V3)
    return out


def _tamper(chunk: bytes) -> bytes:
    damaged = bytearray(chunk)
    damaged[6] ^= 0xFF
    return bytes(damaged)


_three = _plain(PARTS)
_joined = b"".join(_three)
_keyed = _chained(PARTS)

# name: (chunks, session: "plain" | "keyed" | "legacy")
CASES: dict[str, tuple[list[bytes], str]] = {
    "single_pdu": (_plain(PARTS[:1]), "plain"),
    "three_fragments": (_three, "plain"),
    "headers_split_across_chunks": ([_joined[:3], _joined[3:40], _joined[40:]], "plain"),
    "one_chunk_for_all": ([_joined], "plain"),
    "system_event_between_fragments": ([_three[0], SYSTEM_EVENT, _three[1], _three[2]], "plain"),
    "too_many_system_events": ([_three[0]] + [SYSTEM_EVENT] * (_MAX_SYSTEM_EVENTS_PER_RESPONSE + 1), "plain"),
    "standalone_trailer": ([_three[0], _trailer(V2)], "plain"),
    "version_change": ([_three[0], _plain(PARTS[1:], ProtocolVersion.V1)[0]], "plain"),
    "bad_header": ([_three[0], b"\x00\x00\x00\x00"], "plain"),
    "connection_closed": ([_three[0], b""], "plain"),
    "v3_without_key": (_chained(PARTS), "plain"),
    "too_large": ([encode_header(V2, 0xFFFF) + bytes(0xFFFF)] * 4, "plain"),
    "keyed-chained": (_keyed, "keyed"),
    "keyed-tampered_second": ([_keyed[0], _tamper(_keyed[1]), _keyed[2]], "keyed"),
    "keyed-unauthenticated_fragment": ([_keyed[0], _plain(PARTS[1:])[0]], "keyed"),
    "keyed-system_event_between": ([_keyed[0], SYSTEM_EVENT, _keyed[1], _keyed[2]], "keyed"),
    "legacy-independent": (_independent(PARTS), "legacy"),
    "legacy-tampered": ([_independent(PARTS)[0], _tamper(_independent(PARTS)[1])], "legacy"),
}


def _prepare(obj: Any, session: str) -> None:
    obj._connected = True
    obj._protocol_version = ProtocolVersion.V1 if session == "legacy" else (V3 if session == "keyed" else V2)
    obj._session_key = KEY if session in ("keyed", "legacy") else None
    obj._legacy_s7_1500 = None if session == "legacy" else False
    obj._MAX_REASSEMBLED_BYTES = 200_000


def _outcome(
    result: Any, chunks: list[bytes], total: int, invalidated: list[bool], extra: Optional[dict[str, Any]] = None
) -> dict[str, Any]:
    out = {"result": result, "chunks_read": total - len(chunks), "invalidated": bool(invalidated)}
    out.update(extra or {})
    return out


def _run_sync(name: str) -> dict[str, Any]:
    chunks, session = CASES[name]
    first, rest = chunks[0], list(chunks[1:])
    total = len(rest)
    conn = S7CommPlusConnection("127.0.0.1")
    _prepare(conn, session)
    invalidated: list[bool] = []

    def recv(timeout: Optional[float] = None, *, idle_ok: bool = False) -> bytes:
        if not rest:
            raise AssertionError("read past the last chunk")
        return rest.pop(0)

    conn._recv_s7_data = recv  # type: ignore[method-assign]
    conn._invalidate_integrity_failure = lambda: invalidated.append(True)  # type: ignore[method-assign]
    try:
        result: Any = conn._recv_reassembled_payload(first, 5.0).hex()
    except Exception as exc:  # recorded, not judged
        result = f"{type(exc).__name__}: {exc}"
    return _outcome(result, rest, total, invalidated)


def _run_async(name: str) -> dict[str, Any]:
    chunks, session = CASES[name]
    first, rest = chunks[0], list(chunks[1:])
    total = len(rest)
    client = S7CommPlusAsyncClient()
    _prepare(client, session)
    client._reader = object()  # type: ignore[assignment]
    client._writer = object()  # type: ignore[assignment]
    invalidated: list[bool] = []

    async def recv() -> bytes:
        if not rest:
            raise AssertionError("read past the last chunk")
        return rest.pop(0)

    async def invalidate() -> None:
        invalidated.append(True)

    client._recv_cotp_dt = recv  # type: ignore[method-assign]
    client._invalidate_integrity_failure = invalidate  # type: ignore[method-assign]
    try:
        result: Any = asyncio.run(client._recv_reassembled_payload(first, 5.0)).hex()
    except Exception as exc:  # recorded, not judged
        result = f"{type(exc).__name__}: {exc}"
    return _outcome(result, rest, total, invalidated, {"rx_partial": client._rx_partial})


def _record() -> dict[str, Any]:
    return {name: {"sync": _run_sync(name), "async": _run_async(name)} for name in CASES}


if os.environ.get("S7_RECORD_REASSEMBLY") == "1":  # pragma: no cover - maintenance switch
    GOLDEN.write_text(json.dumps(_record(), indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")

_GOLDEN: dict[str, Any] = json.loads(GOLDEN.read_text(encoding="utf-8")) if GOLDEN.exists() else {}


@pytest.mark.parametrize("name", list(CASES))
def test_sync_reassembly_matches_the_recording(name: str) -> None:
    assert _run_sync(name) == _GOLDEN[name]["sync"]


@pytest.mark.parametrize("name", list(CASES))
def test_async_reassembly_matches_the_recording(name: str) -> None:
    assert _run_async(name) == _GOLDEN[name]["async"]


@pytest.mark.parametrize("name", list(CASES))
def test_sync_and_async_reassembly_agree(name: str) -> None:
    # The async client also tracks whether the stream sits inside a reply.
    asynchronous = _run_async(name)
    del asynchronous["rx_partial"]
    assert _run_sync(name) == asynchronous
