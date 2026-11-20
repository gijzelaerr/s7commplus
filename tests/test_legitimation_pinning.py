"""Pin the requests both clients send for password legitimation, and what they conclude.

Each case runs ``authenticate()`` (TLS sessions) or ``_post_auth_legitimation()``
(V1 SessionKey sessions) on an unconnected client whose request sending is
stubbed with scripted replies. It records each request sent (function code,
payload, IntegrityId tail), what the call returned or raised, and the state it
left. The challenge solver is stubbed for the SessionKey cases, so no real key
is needed. The golden file was first recorded from the two separate
implementations. Set ``S7_RECORD_LEGITIMATION=1`` to rewrite it.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any, Callable, Optional
from unittest.mock import MagicMock, patch

import pytest

from s7commplus.async_connection import S7CommPlusAsyncConnection
from s7commplus.connection import S7CommPlusConnection
from s7commplus.error import S7ConnectionError
from s7commplus.protocol import ProtocolVersion
from s7commplus.v1_session_key.keys import KeyFamily

GOLDEN = Path(__file__).parent / "fixtures" / "legitimation_golden.json"

# A ServerSessionVersion whose device string picks the legacy, or the new, exchange.
_LEGACY_DEVICE = b"1;6ES7 512-1DK01-0AB0 ;V2.9"
_NEW_DEVICE = b"1;6ES7 512-1DK01-0AB0 ;V3.1"
LEGACY_VERSION = bytes.fromhex("170000013a823f0015") + bytes([len(_LEGACY_DEVICE)]) + _LEGACY_DEVICE + b"\x00"
NEW_VERSION = bytes.fromhex("170000013a823f0015") + bytes([len(_NEW_DEVICE)]) + _NEW_DEVICE + b"\x00"

CHALLENGE = bytes(range(0x30, 0x30 + 20))
CHALLENGE_REPLY = b"\x00\x00\x10\x02\x14" + CHALLENGE + b"\x00"
SHORT_CHALLENGE_REPLY = b"\x00\x00\x10\x02\x05" + CHALLENGE[:5] + b"\x00"
SET_OK = b"\x00\x00"
# A negative return value: the item error the S7-1500 sent in #193.
SET_REFUSED = bytes.fromhex("c082b19080c5edfffe00")


def _level_reply(level: int) -> bytes:
    """A GetVarSubStreamed reply carrying an effective protection level (UDInt)."""
    return bytes([0x00, 0x00, 0x00, 0x04, level, 0x00])


OMS_SECRET = bytes(range(0x50, 0x50 + 32))

# name: (session kind, level before, password, version, replies, oms_secret)
AUTH_CASES: dict[str, tuple[str, Optional[int], str, Optional[bytes], list[Any], Optional[bytes]]] = {
    "not_connected": ("disconnected", 3, "pw", LEGACY_VERSION, [], None),
    "no_tls": ("plain", 3, "pw", LEGACY_VERSION, [], None),
    "no_level": ("tls", None, "pw", LEGACY_VERSION, [], None),
    "full_access": ("tls", 1, "pw", LEGACY_VERSION, [], None),
    "no_password": ("tls", 3, "", LEGACY_VERSION, [], None),
    "no_version": ("tls", 3, "pw", None, [], None),
    "legacy-accepted": ("tls", 3, "pw", LEGACY_VERSION, [CHALLENGE_REPLY, SET_OK, _level_reply(1)], None),
    "legacy-refused": ("tls", 3, "pw", LEGACY_VERSION, [CHALLENGE_REPLY, SET_OK, _level_reply(3)], None),
    "legacy-short_challenge": ("tls", 3, "pw", LEGACY_VERSION, [SHORT_CHALLENGE_REPLY], None),
    "legacy-set_refused": ("tls", 3, "pw", LEGACY_VERSION, [CHALLENGE_REPLY, SET_REFUSED], None),
    "legacy-level_unreadable": (
        "tls",
        3,
        "pw",
        LEGACY_VERSION,
        [CHALLENGE_REPLY, SET_OK, S7ConnectionError("read failed")],
        None,
    ),
    "new-no_oms_secret": ("tls", 3, "pw", NEW_VERSION, [CHALLENGE_REPLY], None),
    "new-accepted": ("tls", 3, "pw", NEW_VERSION, [CHALLENGE_REPLY, SET_OK, _level_reply(1)], OMS_SECRET),
}

# name: (key family, session key set, replies)
POST_AUTH_CASES: dict[str, tuple[KeyFamily, bool, list[Any]]] = {
    "s7_1500-accepted": (KeyFamily.S7_1500, True, [CHALLENGE_REPLY, SET_OK]),
    "s7_1200-accepted": (KeyFamily.S7_1200, True, [CHALLENGE_REPLY, SET_OK]),
    "plcsim-accepted": (KeyFamily.PLCSIM, True, [CHALLENGE_REPLY, SET_OK]),
    "s7_1500-short_challenge": (KeyFamily.S7_1500, True, [SHORT_CHALLENGE_REPLY]),
    "s7_1500-no_session_key": (KeyFamily.S7_1500, False, [CHALLENGE_REPLY]),
    "s7_1500-refused": (KeyFamily.S7_1500, True, [CHALLENGE_REPLY, SET_REFUSED]),
}


def _hexed(value: Optional[bytes]) -> Optional[str]:
    return None if value is None else bytes(value).hex()


def _call(run: Callable[[], Any]) -> Any:
    try:
        return run()
    except Exception as exc:  # recorded, not judged
        return f"{type(exc).__name__}: {exc}"


class _Script:
    """Answers each request with the next scripted reply, raising it if it is an exception."""

    def __init__(self, replies: list[Any]) -> None:
        self.replies = list(replies)
        self.sent: list[list[Any]] = []

    def answer(self, function_code: int, payload: bytes, integrity_tail: int) -> bytes:
        self.sent.append([int(function_code), payload.hex(), integrity_tail])
        if not self.replies:
            raise AssertionError("more requests than scripted replies")
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return bytes(reply)


def _prepare_auth(obj: Any, case: str) -> _Script:
    kind, level, _, version, replies, oms_secret = AUTH_CASES[case]
    obj._connected = kind != "disconnected"
    obj._tls_active = kind == "tls"
    obj._protocol_version = ProtocolVersion.V2
    obj._session_id = 0x70000123
    obj._sequence_number = 9
    obj._protection_level = level
    obj._server_session_version = version
    obj._oms_secret = oms_secret
    return _Script(replies)


def _prepare_post_auth(obj: Any, case: str) -> _Script:
    family, keyed, replies = POST_AUTH_CASES[case]
    obj._connected = True
    obj._protocol_version = ProtocolVersion.V1
    obj._session_id = 0x000003B3
    obj._sequence_number = 5
    obj._session_key = bytes(range(24)) if keyed else None
    obj._v1_session_key_family = family
    obj._v1_session_key_public_key = bytes(range(64))
    return _Script(replies)


def _auth_state(obj: Any) -> dict[str, Any]:
    return {"protection_level": obj._protection_level, "oms_secret": _hexed(obj._oms_secret)}


def _solve(challenge: bytes, public_key: bytes, family: KeyFamily, session_key: bytes, password: str) -> bytes:
    return bytes([int(family) & 0xFF]) + challenge + password.encode()


def _sync_conn(script: _Script) -> S7CommPlusConnection:
    conn = S7CommPlusConnection("127.0.0.1")
    conn.send_request = lambda fc, payload=b"", integrity_tail=4, reassemble=False: script.answer(fc, payload, integrity_tail)  # type: ignore[method-assign]
    # The scripted replies come over a live connection, so an error among them is the PLC's answer, not a lost transport.
    conn._iso_conn.connected = True
    return conn


def _async_client(script: _Script) -> S7CommPlusAsyncConnection:
    client = S7CommPlusAsyncConnection()

    async def send(fc: int, payload: bytes, integrity_tail: int = 4, reassemble: bool = False) -> bytes:
        return script.answer(fc, payload, integrity_tail)

    client.send_request = send  # type: ignore[method-assign]
    client._send_request_locked = send  # type: ignore[method-assign]
    # As for the sync connection: the replies come over a live stream, which nothing here writes to.
    client._writer = MagicMock()
    return client


def _sync_auth(case: str) -> dict[str, Any]:
    script = _Script([])
    conn = _sync_conn(script)
    script.replies = _prepare_auth(conn, case).replies
    password = AUTH_CASES[case][2]
    result = _call(lambda: conn.authenticate(password))
    return {"sent": script.sent, "result": result, "state": _auth_state(conn)}


def _async_auth(case: str) -> dict[str, Any]:
    script = _Script([])
    client = _async_client(script)
    script.replies = _prepare_auth(client, case).replies
    password = AUTH_CASES[case][2]
    result = _call(lambda: asyncio.run(client.authenticate(password)))
    return {"sent": script.sent, "result": result, "state": _auth_state(client)}


def _sync_post_auth(case: str) -> dict[str, Any]:
    script = _Script([])
    conn = _sync_conn(script)
    script.replies = _prepare_post_auth(conn, case).replies
    with patch("s7commplus.v1_session_key.legitimation.solve_legitimate_challenge", _solve):
        result = _call(lambda: conn._post_auth_legitimation("pw"))
    return {"sent": script.sent, "result": result}


def _async_post_auth(case: str) -> dict[str, Any]:
    script = _Script([])
    client = _async_client(script)
    script.replies = _prepare_post_auth(client, case).replies
    with patch("s7commplus.v1_session_key.legitimation.solve_legitimate_challenge", _solve):
        result = _call(lambda: asyncio.run(client._post_auth_legitimation("pw")))
    return {"sent": script.sent, "result": result}


def _record() -> dict[str, Any]:
    golden: dict[str, Any] = {}
    for case in AUTH_CASES:
        golden[f"authenticate-{case}"] = {"sync": _sync_auth(case), "async": _async_auth(case)}
    for case in POST_AUTH_CASES:
        golden[f"post_auth-{case}"] = {"sync": _sync_post_auth(case), "async": _async_post_auth(case)}
    return golden


if os.environ.get("S7_RECORD_LEGITIMATION") == "1":  # pragma: no cover - maintenance switch
    GOLDEN.write_text(json.dumps(_record(), indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")

_GOLDEN: dict[str, Any] = json.loads(GOLDEN.read_text(encoding="utf-8")) if GOLDEN.exists() else {}


@pytest.mark.parametrize("case", list(AUTH_CASES))
def test_sync_authenticate_matches_the_recording(case: str) -> None:
    assert _sync_auth(case) == _GOLDEN[f"authenticate-{case}"]["sync"]


@pytest.mark.parametrize("case", list(AUTH_CASES))
def test_async_authenticate_matches_the_recording(case: str) -> None:
    assert _async_auth(case) == _GOLDEN[f"authenticate-{case}"]["async"]


@pytest.mark.parametrize("case", list(POST_AUTH_CASES))
def test_sync_post_auth_legitimation_matches_the_recording(case: str) -> None:
    assert _sync_post_auth(case) == _GOLDEN[f"post_auth-{case}"]["sync"]


@pytest.mark.parametrize("case", list(POST_AUTH_CASES))
def test_async_post_auth_legitimation_matches_the_recording(case: str) -> None:
    assert _async_post_auth(case) == _GOLDEN[f"post_auth-{case}"]["async"]


@pytest.mark.parametrize("case", [case for case in AUTH_CASES if case != "not_connected"])
def test_sync_and_async_authenticate_agree(case: str) -> None:
    # Only "not connected" differs: the async client raises S7NotConnectedError,
    # a subclass of the sync connection's S7ConnectionError.
    assert _sync_auth(case) == _async_auth(case)


@pytest.mark.parametrize("case", list(POST_AUTH_CASES))
def test_sync_and_async_post_auth_legitimation_agree(case: str) -> None:
    assert _sync_post_auth(case) == _async_post_auth(case)
