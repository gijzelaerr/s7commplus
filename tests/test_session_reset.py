"""Ending a session leaves both clients' session state as a fresh client has it.

The sync connection and the async client used to reset the session in their
own lists of attributes, and the lists drifted: the sync connection kept the
PLC certificate fingerprint after a disconnect, and the async client once had
no public-key checksum at all. Both now call ``SessionCore._clear_session_state``.
This test dirties every session attribute ``SessionCore`` declares, ends the
session, and compares each attribute with a freshly constructed client.
"""

from __future__ import annotations

from collections import deque
from typing import Any

import pytest

from s7commplus._session_core import SessionCore
from s7commplus.async_client import S7CommPlusAsyncClient
from s7commplus.connection import S7CommPlusConnection
from s7commplus.v1_session_key.keys import KeyFamily

# Settings, not session state: they survive the end of a session on purpose.
NOT_SESSION_STATE = {
    "_legacy_s7_1500",
    "_session_key_fingerprint_override",
    "_session_key_refresh_interval",
    "_tls_cert_fingerprint",
    "_last_raw_response_payload",
    "_last_response_function",
}
SESSION_STATE = sorted(name for name in SessionCore.__annotations__ if name not in NOT_SESSION_STATE)


def _dirty(value: Any) -> Any:
    if isinstance(value, bool):
        return not value
    if isinstance(value, KeyFamily):
        return KeyFamily.S7_1200 if value != KeyFamily.S7_1200 else KeyFamily.S7_1500
    if isinstance(value, int):
        return value + 7
    if isinstance(value, bytes):
        return value + b"stale"
    if isinstance(value, deque):
        return value
    return object()


def _snapshot(obj: Any) -> dict[str, Any]:
    return {name: list(v) if isinstance(v := getattr(obj, name), deque) else v for name in SESSION_STATE}


def _dirty_all(obj: Any) -> None:
    for name in SESSION_STATE:
        value = getattr(obj, name)
        if isinstance(value, deque):
            value.append(b"stale notification")
        else:
            setattr(obj, name, _dirty(value))
    obj._session_ready = False  # no DeleteObject to send


def test_every_declared_attribute_exists_on_both_clients() -> None:
    for obj in (S7CommPlusConnection("127.0.0.1"), S7CommPlusAsyncClient()):
        missing = [name for name in SESSION_STATE if not hasattr(obj, name)]
        assert missing == [], type(obj).__name__


def test_sync_disconnect_leaves_a_fresh_session() -> None:
    fresh = _snapshot(S7CommPlusConnection("127.0.0.1"))
    conn = S7CommPlusConnection("127.0.0.1")
    _dirty_all(conn)
    assert _snapshot(conn) != fresh
    conn._disconnect()
    assert _snapshot(conn) == fresh


def test_async_reset_leaves_a_fresh_session() -> None:
    fresh = _snapshot(S7CommPlusAsyncClient())
    client = S7CommPlusAsyncClient()
    _dirty_all(client)
    assert _snapshot(client) != fresh
    client._reset_session()
    assert _snapshot(client) == fresh


@pytest.mark.parametrize("make", [lambda: S7CommPlusConnection("127.0.0.1"), S7CommPlusAsyncClient], ids=["sync", "async"])
def test_both_clients_start_from_the_same_session_state(make: Any) -> None:
    # The same starting values, so a reset to them means the same for both.
    assert _snapshot(make()) == _snapshot(S7CommPlusConnection("127.0.0.1"))
