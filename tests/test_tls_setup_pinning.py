"""Pin how both clients start TLS: the InitSSL exchange and the TLS context they build.

The TLS handshake itself is random on the wire, so it is covered end to end by
the emulator tests in ``test_s7_tls.py``. These cases cover what is
deterministic: the InitSSL request each client sends and what it makes of the
reply, and the settings of the context it hands to the handshake. Those
settings depend on the Python and OpenSSL build (options, cipher names), so
they are compared between the two clients rather than recorded. The golden
file was first recorded from the two separate implementations, which agreed
on everything but an InitSSL reply with nine bytes of data: the sync connection
counted the frame trailer as data and accepted it. Both now refuse it, and the
file was re-recorded with that change. Set
``S7_RECORD_TLS_SETUP=1`` to rewrite it.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import ssl
import struct
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from s7commplus.async_connection import S7CommPlusAsyncConnection
from s7commplus.codec import encode_header
from s7commplus.connection import S7CommPlusConnection
from s7commplus.protocol import FunctionCode, Opcode, ProtocolVersion

GOLDEN = Path(__file__).parent / "fixtures" / "tls_setup_golden.json"


def _reply(data: bytes) -> bytes:
    return encode_header(ProtocolVersion.V1, len(data)) + data + bytes([0x72, 1, 0, 0])


_RESPONSE = struct.pack(">BHHHHB", Opcode.RESPONSE, 0, FunctionCode.INIT_SSL, 0, 1, 0x30)
INIT_SSL_REPLIES = {
    "accepted": _reply(_RESPONSE + b"\x00"),
    "header_only": _reply(_RESPONSE),
    "nine_bytes": _reply(_RESPONSE[:9]),
    "empty": _reply(b""),
}


def _call(run: Any) -> Any:
    try:
        return run()
    except Exception as exc:  # recorded, not judged
        return f"{type(exc).__name__}: {exc}"


def _sync_init_ssl(name: str) -> dict[str, Any]:
    conn = S7CommPlusConnection("127.0.0.1")
    conn._connected = True
    sent: list[bytes] = []
    conn._send_s7_data = sent.append  # type: ignore[method-assign]
    conn._recv_s7_data = lambda timeout=None, idle_ok=False: INIT_SSL_REPLIES[name]  # type: ignore[method-assign]
    result = _call(conn._init_ssl)
    return {"sent": [f.hex() for f in sent], "result": result, "sequence_number": conn._sequence_number}


def _async_init_ssl(name: str) -> dict[str, Any]:
    client = S7CommPlusAsyncConnection()
    client._connected = True
    client._reader = object()  # type: ignore[assignment]
    client._writer = object()  # type: ignore[assignment]
    sent: list[bytes] = []

    async def send(frame: bytes) -> None:
        sent.append(frame)

    async def recv() -> bytes:
        return INIT_SSL_REPLIES[name]

    client._send_cotp_dt = send  # type: ignore[method-assign]
    client._recv_cotp_dt = recv  # type: ignore[method-assign]
    result = _call(lambda: asyncio.run(client._init_ssl()))
    return {"sent": [f.hex() for f in sent], "result": result, "sequence_number": client._sequence_number}


class _Captured(Exception):
    """Stops TLS activation once the context reached the handshake."""


def _describe(ctx: ssl.SSLContext) -> dict[str, Any]:
    return {
        "minimum_version": str(ctx.minimum_version),
        "options": int(ctx.options),
        "check_hostname": ctx.check_hostname,
        "verify_mode": str(ctx.verify_mode),
        "ciphers": sorted(c["name"] for c in ctx.get_ciphers()),
    }


def _capture(module: str) -> Any:
    captured: list[ssl.SSLContext] = []

    @contextlib.contextmanager
    def key_log(ctx: ssl.SSLContext) -> Iterator[str]:
        captured.append(ctx)
        raise _Captured
        yield ""  # pragma: no cover

    return captured, patch(f"{module}._tls_key_log", key_log)


def _sync_context() -> dict[str, Any]:
    conn = S7CommPlusConnection("127.0.0.1")
    captured, patcher = _capture("s7commplus.connection")
    with patcher, contextlib.suppress(_Captured):
        conn._activate_tls()
    return _describe(captured[0])


def _async_context() -> dict[str, Any]:
    client = S7CommPlusAsyncConnection()
    client._writer = object()  # type: ignore[assignment]
    captured, patcher = _capture("s7commplus.async_connection")
    with patcher, contextlib.suppress(_Captured):
        asyncio.run(client._activate_tls())
    return _describe(captured[0])


def _record() -> dict[str, Any]:
    golden: dict[str, Any] = {f"init_ssl-{n}": {"sync": _sync_init_ssl(n), "async": _async_init_ssl(n)} for n in INIT_SSL_REPLIES}
    return golden


if os.environ.get("S7_RECORD_TLS_SETUP") == "1":  # pragma: no cover - maintenance switch
    GOLDEN.write_text(json.dumps(_record(), indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")

_GOLDEN: dict[str, Any] = json.loads(GOLDEN.read_text(encoding="utf-8")) if GOLDEN.exists() else {}


@pytest.mark.parametrize("name", list(INIT_SSL_REPLIES))
def test_sync_init_ssl_matches_the_recording(name: str) -> None:
    assert _sync_init_ssl(name) == _GOLDEN[f"init_ssl-{name}"]["sync"]


@pytest.mark.parametrize("name", list(INIT_SSL_REPLIES))
def test_async_init_ssl_matches_the_recording(name: str) -> None:
    assert _async_init_ssl(name) == _GOLDEN[f"init_ssl-{name}"]["async"]


@pytest.mark.parametrize("name", list(INIT_SSL_REPLIES))
def test_sync_and_async_init_ssl_agree(name: str) -> None:
    assert _sync_init_ssl(name) == _async_init_ssl(name)


def test_sync_and_async_tls_contexts_agree() -> None:
    assert _sync_context() == _async_context()
