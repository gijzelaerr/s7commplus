"""Both clients run the steps of connecting in the same order.

``Client.connect`` (through its ``S7CommPlusConnection``) and
``AsyncClient.connect`` each put the shared session steps together around their
own transport, so they cannot be one function. This test stubs every step to record its name and to leave
the state the next step expects, runs ``connect()`` on both clients for each
kind of session, and compares the sequences. A step added to, dropped from or
moved in one client's connect fails it until the other follows.
"""

from __future__ import annotations

import asyncio
from typing import Any, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from s7commplus import Client
from s7commplus.async_client import S7CommPlusAsyncClient
from s7commplus.connection import S7CommPlusConnection
from s7commplus.protocol import ProtocolVersion
from s7commplus.v1_session_key.keys import KeyFamily

# name: (use_tls, key family or None for no SessionKey, password, setup accepted)
SESSIONS: dict[str, tuple[bool, Optional[KeyFamily], str, bool]] = {
    "tls": (True, None, "", True),
    "tls-password": (True, None, "secret", True),
    "v1_key-s7_1500": (False, KeyFamily.S7_1500, "", True),
    "v1_key-s7_1500-password": (False, KeyFamily.S7_1500, "secret", True),
    "v1_key-s7_1200-password": (False, KeyFamily.S7_1200, "secret", True),
    "v1_key-plcsim-password": (False, KeyFamily.PLCSIM, "secret", True),
    "setup_refused": (False, None, "", False),
}

STEPS = (
    "_init_ssl",
    "authenticate",
    "_activate_tls",
    "_create_session",
    "_setup_session",
    "_session_activate",
    "_post_auth_legitimation",
    "_skip_integrity_ids_after_legitimation",
    "_get_effective_protection_level",
    "_schedule_session_key_refresh",
)


def _stub_steps(obj: Any, session: str, run_async: bool) -> list[str]:
    use_tls, family, _, accepted = SESSIONS[session]
    order: list[str] = []

    def effect(name: str) -> Any:
        order.append(name)
        if name == "_activate_tls":
            obj._tls_active = True
        elif name == "_create_session":
            obj._session_id = 0x70000123
            obj._protocol_version = ProtocolVersion.V1
            obj._server_session_version = b"\x17\x00\x00\x01\x00"
        elif name == "_setup_session":
            if family is not None:
                obj._session_key = bytes(24)
                obj._v1_session_key_family = family
            return accepted
        elif name == "_get_effective_protection_level":
            return 1
        return None

    for name in STEPS:
        if run_async and name in ("_skip_integrity_ids_after_legitimation", "_schedule_session_key_refresh"):

            def sync_step(*args: Any, _name: str = name, **kwargs: Any) -> Any:
                return effect(_name)

            setattr(obj, name, sync_step)
        elif run_async:

            async def async_step(*args: Any, _name: str = name, **kwargs: Any) -> Any:
                return effect(_name)

            setattr(obj, name, async_step)
        else:

            def step(*args: Any, _name: str = name, **kwargs: Any) -> Any:
                return effect(_name)

            setattr(obj, name, step)
    return order


def _outcome(order: list[str], run: Any) -> dict[str, Any]:
    try:
        run()
        result = "connected"
    except Exception as exc:  # compared, not judged
        result = type(exc).__name__
    return {"steps": order, "result": result}


def _sync_connect(session: str) -> dict[str, Any]:
    # Through Client.connect: on the sync side it is the client, not the connection,
    # that legitimates a TLS session after connecting, as AsyncClient.connect does.
    use_tls, _, password, _ = SESSIONS[session]
    conn = S7CommPlusConnection("127.0.0.1")
    conn._iso_conn = MagicMock()
    order = _stub_steps(conn, session, run_async=False)

    def build(*args: Any, **kwargs: Any) -> S7CommPlusConnection:
        conn.host = kwargs.get("host", args[0] if args else conn.host)
        return conn

    def run() -> None:
        with patch("s7commplus.client.S7CommPlusConnection", build):
            Client().connect("127.0.0.1", use_tls=use_tls, password=password or None)

    return _outcome(order, run)


def _async_connect(session: str) -> dict[str, Any]:
    use_tls, _, password, _ = SESSIONS[session]
    client = S7CommPlusAsyncClient()
    order = _stub_steps(client._connection, session, run_async=True)
    writer = MagicMock()
    writer.get_extra_info.return_value = None
    writer.wait_closed = AsyncMock(return_value=None)

    async def cotp(*args: Any) -> None:
        return None

    async def open_connection(*args: Any, **kwargs: Any) -> tuple[Any, Any]:
        return MagicMock(), writer

    client._connection._cotp_connect = cotp  # type: ignore[method-assign]

    async def run() -> None:
        with patch("s7commplus.async_connection.asyncio.open_connection", open_connection):
            await client.connect("127.0.0.1", use_tls=use_tls, password=password or None)

    return _outcome(order, lambda: asyncio.run(run()))


@pytest.mark.parametrize("session", list(SESSIONS))
def test_both_clients_connect_in_the_same_order(session: str) -> None:
    assert _sync_connect(session) == _async_connect(session)
