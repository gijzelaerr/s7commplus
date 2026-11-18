"""Pin how both clients renew a legacy SessionKey, activate and close a session.

Each case runs one step on an unconnected client with its request sending
stubbed with scripted replies, and records each request sent, what the step
returned or raised, and the state it left: the SessionKey renewal exchange,
the decision whether to schedule a renewal at all, the session activation and
the DeleteObject that closes a session. ``authenticate_session_key`` is
stubbed, so no real key is needed. The golden file was first recorded from the
two separate implementations. Set ``S7_RECORD_RENEWAL=1`` to rewrite it.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any, Callable, Optional
from unittest.mock import patch

import pytest

from s7commplus.async_client import S7CommPlusAsyncClient
from s7commplus.connection import S7CommPlusConnection
from s7commplus.protocol import FunctionCode, ProtocolVersion
from s7commplus.v1_session_key.keys import KeyFamily

GOLDEN = Path(__file__).parent / "fixtures" / "renewal_golden.json"

CHALLENGE = bytes(range(0x30, 0x30 + 20))
CHALLENGE_REPLY = b"\x00\x00\x10\x02\x14" + CHALLENGE + b"\x00"
SHORT_CHALLENGE_REPLY = b"\x00\x00\x10\x02\x05" + CHALLENGE[:5] + b"\x00"
SET_OK = b"\x00\x00"
SET_REFUSED = bytes.fromhex("c082b19080c5edfffe00")
OLD_KEY = bytes(range(24))
NEW_KEY = bytes(range(100, 124))
PUBLIC_KEY = bytes(range(0x80, 0x80 + 64))

# name: (session key, public key, replies)
RENEWAL_CASES: dict[str, tuple[Optional[bytes], bytes, list[bytes]]] = {
    "renewed": (OLD_KEY, PUBLIC_KEY, [CHALLENGE_REPLY, SET_OK]),
    "no_session_key": (None, PUBLIC_KEY, []),
    "no_public_key": (OLD_KEY, b"", []),
    "short_challenge": (OLD_KEY, PUBLIC_KEY, [SHORT_CHALLENGE_REPLY]),
    "refused": (OLD_KEY, PUBLIC_KEY, [CHALLENGE_REPLY, SET_REFUSED]),
}

# name: (interval, session key set, connected, family)
SCHEDULE_CASES: dict[str, tuple[Optional[float], bool, bool, KeyFamily]] = {
    "scheduled": (3600.0, True, True, KeyFamily.S7_1200),
    "no_interval": (None, True, True, KeyFamily.S7_1200),
    "no_session_key": (3600.0, False, True, KeyFamily.S7_1200),
    "not_connected": (3600.0, True, False, KeyFamily.S7_1200),
    "s7_1500_refuses": (3600.0, True, True, KeyFamily.S7_1500),
    "plcsim_refuses": (3600.0, True, True, KeyFamily.PLCSIM),
}


def _authenticate(challenge: bytes, public_key: bytes, family: KeyFamily) -> tuple[bytes, bytes]:
    return bytes([int(family) & 0xFF]) + challenge + bytes(200), NEW_KEY


def _call(run: Callable[[], Any]) -> Any:
    try:
        return run()
    except Exception as exc:  # recorded, not judged
        return f"{type(exc).__name__}: {exc}"


class _Script:
    def __init__(self, replies: list[bytes]) -> None:
        self.replies = list(replies)
        self.sent: list[list[Any]] = []

    def answer(self, function_code: int, payload: bytes, integrity_tail: int) -> bytes:
        self.sent.append([int(function_code), payload.hex(), integrity_tail])
        if not self.replies:
            raise AssertionError("more requests than scripted replies")
        return self.replies.pop(0)


def _prepare(obj: Any, session_key: Optional[bytes], public_key: bytes) -> None:
    obj._connected = True
    obj._protocol_version = ProtocolVersion.V1
    obj._session_id = 0x000003B3
    obj._sequence_number = 12
    obj._session_key = session_key
    obj._v1_session_key_public_key = public_key
    obj._v1_session_key_family = KeyFamily.S7_1200


def _sync_renewal(case: str) -> dict[str, Any]:
    key, public, replies = RENEWAL_CASES[case]
    script = _Script(replies)
    conn = S7CommPlusConnection("127.0.0.1")
    _prepare(conn, key, public)
    conn._send_request = lambda fc, payload, tail=4, reassemble=False: script.answer(fc, payload, tail)  # type: ignore[method-assign]
    with patch("s7commplus.v1_session_key.handshake.authenticate_session_key", _authenticate):
        result = _call(conn._renew_session_key_locked)
    return {"sent": script.sent, "result": result, "session_key": None if conn._session_key is None else conn._session_key.hex()}


def _async_renewal(case: str) -> dict[str, Any]:
    key, public, replies = RENEWAL_CASES[case]
    script = _Script(replies)
    client = S7CommPlusAsyncClient()
    _prepare(client, key, public)

    async def send(fc: int, payload: bytes, integrity_tail: int = 4, reassemble: bool = False) -> bytes:
        return script.answer(fc, payload, integrity_tail)

    client._send_request_locked = send  # type: ignore[method-assign]
    with patch("s7commplus.v1_session_key.handshake.authenticate_session_key", _authenticate):
        result = _call(lambda: asyncio.run(client._renew_session_key_locked()))
    return {
        "sent": script.sent,
        "result": result,
        "session_key": None if client._session_key is None else client._session_key.hex(),
    }


def _schedule_setup(obj: Any, case: str) -> None:
    interval, keyed, connected, family = SCHEDULE_CASES[case]
    obj._session_key_refresh_interval = interval
    obj._session_key = OLD_KEY if keyed else None
    obj._connected = connected
    obj._v1_session_key_family = family


def _sync_schedule(case: str) -> dict[str, Any]:
    conn = S7CommPlusConnection("127.0.0.1")
    _schedule_setup(conn, case)
    conn._schedule_session_key_refresh()
    scheduled = conn._session_key_refresh_timer is not None
    conn._stop_session_key_refresh()
    return {"scheduled": scheduled}


def _async_schedule(case: str) -> dict[str, Any]:
    client = S7CommPlusAsyncClient()
    _schedule_setup(client, case)

    async def run() -> bool:
        client._schedule_session_key_refresh()
        scheduled = client._session_key_refresh_task is not None
        client._stop_session_key_refresh()
        await asyncio.sleep(0)
        return scheduled

    return {"scheduled": asyncio.run(run())}


def _sync_activate(function: int) -> dict[str, Any]:
    script = _Script([SET_OK])
    conn = S7CommPlusConnection("127.0.0.1")
    _prepare(conn, OLD_KEY, PUBLIC_KEY)

    def send(fc: int, payload: bytes = b"", integrity_tail: int = 4, reassemble: bool = False) -> bytes:
        reply = script.answer(fc, payload, integrity_tail)
        conn._last_response_function = function
        return reply

    conn.send_request = send  # type: ignore[method-assign]
    result = _call(conn._session_activate)
    return {"sent": script.sent, "result": result}


def _async_activate(function: int) -> dict[str, Any]:
    script = _Script([SET_OK])
    client = S7CommPlusAsyncClient()
    _prepare(client, OLD_KEY, PUBLIC_KEY)

    async def send(fc: int, payload: bytes, integrity_tail: int = 4, reassemble: bool = False) -> bytes:
        reply = script.answer(fc, payload, integrity_tail)
        client._last_response_function = function
        return reply

    client._send_request_locked = send  # type: ignore[method-assign]
    result = _call(lambda: asyncio.run(client._session_activate()))
    return {"sent": script.sent, "result": result}


def _sync_delete(version: int) -> dict[str, Any]:
    conn = S7CommPlusConnection("127.0.0.1")
    _prepare(conn, OLD_KEY, PUBLIC_KEY)
    conn._protocol_version = version
    sent: list[bytes] = []
    conn._send_s7_data = sent.append  # type: ignore[method-assign]
    conn._recv_s7_data = lambda timeout=None, idle_ok=False: b""  # type: ignore[method-assign]
    result = _call(conn._delete_session)
    return {"sent": [f.hex() for f in sent], "result": result, "sequence_number": conn._sequence_number}


def _async_delete(version: int) -> dict[str, Any]:
    client = S7CommPlusAsyncClient()
    _prepare(client, OLD_KEY, PUBLIC_KEY)
    client._protocol_version = version
    sent: list[bytes] = []

    async def send(frame: bytes) -> None:
        sent.append(frame)

    async def recv() -> bytes:
        return b""

    client._send_cotp_dt = send  # type: ignore[method-assign]
    client._recv_cotp_dt = recv  # type: ignore[method-assign]
    result = _call(lambda: asyncio.run(client._delete_session()))
    return {"sent": [f.hex() for f in sent], "result": result, "sequence_number": client._sequence_number}


ACTIVATE_CASES = {"accepted": FunctionCode.SET_VARIABLE, "generic_error": FunctionCode.ERROR}
DELETE_CASES = {"v1": ProtocolVersion.V1, "v2": ProtocolVersion.V2, "v3": ProtocolVersion.V3}


def _record() -> dict[str, Any]:
    golden: dict[str, Any] = {}
    for case in RENEWAL_CASES:
        golden[f"renewal-{case}"] = {"sync": _sync_renewal(case), "async": _async_renewal(case)}
    for case in SCHEDULE_CASES:
        golden[f"schedule-{case}"] = {"sync": _sync_schedule(case), "async": _async_schedule(case)}
    for case, function in ACTIVATE_CASES.items():
        golden[f"activate-{case}"] = {"sync": _sync_activate(function), "async": _async_activate(function)}
    for case, version in DELETE_CASES.items():
        golden[f"delete-{case}"] = {"sync": _sync_delete(version), "async": _async_delete(version)}
    return golden


if os.environ.get("S7_RECORD_RENEWAL") == "1":  # pragma: no cover - maintenance switch
    GOLDEN.write_text(json.dumps(_record(), indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")

_GOLDEN: dict[str, Any] = json.loads(GOLDEN.read_text(encoding="utf-8")) if GOLDEN.exists() else {}


@pytest.mark.parametrize("case", list(RENEWAL_CASES))
def test_renewal_matches_the_recording(case: str) -> None:
    assert _sync_renewal(case) == _GOLDEN[f"renewal-{case}"]["sync"]
    assert _async_renewal(case) == _GOLDEN[f"renewal-{case}"]["async"]


@pytest.mark.parametrize("case", list(SCHEDULE_CASES))
def test_renewal_schedule_matches_the_recording(case: str) -> None:
    assert _sync_schedule(case) == _GOLDEN[f"schedule-{case}"]["sync"]
    assert _async_schedule(case) == _GOLDEN[f"schedule-{case}"]["async"]


@pytest.mark.parametrize("case", list(ACTIVATE_CASES))
def test_session_activation_matches_the_recording(case: str) -> None:
    assert _sync_activate(ACTIVATE_CASES[case]) == _GOLDEN[f"activate-{case}"]["sync"]
    assert _async_activate(ACTIVATE_CASES[case]) == _GOLDEN[f"activate-{case}"]["async"]


@pytest.mark.parametrize("case", list(DELETE_CASES))
def test_delete_session_matches_the_recording(case: str) -> None:
    assert _sync_delete(DELETE_CASES[case]) == _GOLDEN[f"delete-{case}"]["sync"]
    assert _async_delete(DELETE_CASES[case]) == _GOLDEN[f"delete-{case}"]["async"]


def test_sync_and_async_agree_on_every_recorded_case() -> None:
    for name, sides in _record().items():
        assert sides["sync"] == sides["async"], name
