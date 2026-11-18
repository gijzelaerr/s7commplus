"""Pin what both clients send and keep in the CreateObject and SessionSetup steps of connecting.

Each case runs one handshake step on an unconnected client with its I/O
stubbed out, and records the frame it sent and the state or exception it was
left with. The golden file was first recorded from the two separate
implementations, before they shared these steps. The sync results are
unchanged since; the async client now does what the sync connection did: it
sends the full CreateObject client identification, frames a SessionSetup
without a SessionKey as V2 with the order-number string blanked, keeps the
public-key checksum, and refuses a CreateObject reply without an ObjectId
with ``S7ConnectionError``. Set ``S7_RECORD_HANDSHAKE=1`` to rewrite the
golden file.

The replies come from a real S7-1215C FW V4.2 (#44) where possible.
"""

from __future__ import annotations

import asyncio
import json
import os
import struct
from pathlib import Path
from typing import Any, Callable, Optional

import pytest

from s7commplus.async_connection import S7CommPlusAsyncConnection
from s7commplus.connection import S7CommPlusConnection
from s7commplus.protocol import ProtocolVersion
from s7commplus.v1_session_key.keys import KeyFamily

from .test_s7_real_s7_1200_handshake import CREATE_OBJECT_RESPONSE, SESSION_SETUP_RESPONSE

GOLDEN = Path(__file__).parent / "fixtures" / "handshake_golden.json"

# The 1215C's reply with its ObjectIds cut: ReturnValue 0, no ObjectId.
NO_OBJECT_ID_RESPONSE = bytes.fromhex("7201000c32000004ca0000000136000072010000")
# The same, followed by an empty object: long enough to read a "session id" at bytes 9-12.
NO_OBJECT_ID_LONG_RESPONSE = bytes.fromhex("7201001032000004ca00000001360000a1a2a2a272010000")
SHORT_RESPONSE = bytes.fromhex("720100043200000472010000")

CREATE_REPLIES = {
    "s7_1215c": CREATE_OBJECT_RESPONSE,
    "no_object_id": NO_OBJECT_ID_RESPONSE,
    "no_object_id_long": NO_OBJECT_ID_LONG_RESPONSE,
    "short": SHORT_RESPONSE,
}


def _setup_reply(sequence: int, return_value_byte: int = 0x00) -> bytes:
    """The 1215C's SessionSetup reply, renumbered to ``sequence`` and with its ReturnValue byte set."""
    reply = bytearray(SESSION_SETUP_RESPONSE)
    struct.pack_into(">H", reply, 4 + 7, sequence)
    reply[4 + 10] = return_value_byte
    return bytes(reply)


SETUP_CASES = {
    "v1-no_key-accepted": (ProtocolVersion.V1, False, 0x00),
    "v1-no_key-refused": (ProtocolVersion.V1, False, 0x11),
    "v2-tls-accepted": (ProtocolVersion.V2, False, 0x00),
    "v1-key-accepted": (ProtocolVersion.V1, True, 0x00),
    "v1-key-refused": (ProtocolVersion.V1, True, 0x11),
}

AUTH_RESULT = (bytes(i & 0xFF for i in range(0x40, 0x40 + 0xD0)), bytes(range(0x10, 0x10 + 24)))
PUBLIC_KEY = bytes(range(0x80, 0x80 + 64))


def _state(obj: Any) -> dict[str, Any]:
    def hexed(value: Optional[bytes]) -> Optional[str]:
        return None if value is None else bytes(value).hex()

    return {
        "session_id": obj._session_id,
        "subscription_container_id": obj._subscription_container_id,
        "protocol_version": obj._protocol_version,
        "server_session_version": hexed(obj._server_session_version),
        "public_key_fingerprint": obj._public_key_fingerprint,
        "public_key_checksum": hexed(getattr(obj, "_public_key_checksum", None)),
        "session_challenge": hexed(obj._session_challenge),
        "server_session_role": obj._server_session_role,
        "server_session_roles": obj._server_session_roles,
        "session_key": hexed(obj._session_key),
        "with_integrity_id": obj._with_integrity_id,
        "integrity_ids": [obj._integrity_id_read, obj._integrity_id_write],
        "sequence_number": obj._sequence_number,
    }


def _call(run: Callable[[], Any]) -> Any:
    try:
        return run()
    except Exception as exc:  # recorded, not judged
        return f"{type(exc).__name__}: {exc}"


def _prepare(obj: Any) -> None:
    obj._connected = True
    obj._sequence_number = 1


def _sync_create(reply: bytes) -> dict[str, Any]:
    conn = S7CommPlusConnection("127.0.0.1")
    _prepare(conn)
    sent: list[bytes] = []
    conn._send_s7_data = sent.append  # type: ignore[method-assign]
    conn._recv_s7_data = lambda timeout=None, idle_ok=False: reply  # type: ignore[method-assign]
    result = _call(conn._create_session)
    return {"sent": [f.hex() for f in sent], "result": result, "state": _state(conn)}


def _async_client() -> tuple[S7CommPlusAsyncConnection, list[bytes]]:
    client = S7CommPlusAsyncConnection()
    _prepare(client)
    client._reader = object()  # type: ignore[assignment]
    client._writer = object()  # type: ignore[assignment]
    sent: list[bytes] = []

    async def send(frame: bytes) -> None:
        sent.append(frame)

    client._send_cotp_dt = send  # type: ignore[method-assign]
    return client, sent


def _async_create(reply: bytes) -> dict[str, Any]:
    client, sent = _async_client()

    async def recv() -> bytes:
        return reply

    client._recv_cotp_dt = recv  # type: ignore[method-assign]
    result = _call(lambda: asyncio.run(client._create_session()))
    return {"sent": [f.hex() for f in sent], "result": result, "state": _state(client)}


def _created(obj: Any, version: int, keyed: bool) -> None:
    """Leave ``obj`` as the 1215C's CreateObject reply did, at protocol ``version``."""
    obj._session_id = 0x000004CA
    obj._protocol_version = version
    obj._tls_active = version >= ProtocolVersion.V2
    obj._server_session_version = (
        bytes.fromhex("170000013a823b00048400823c00048300823d00048480c200823e00048480c100823f00151b")
        + b"1;6ES7 215-1AG40-0XB0 ;V4.2"
        + bytes.fromhex("8240001506323b3130373482410003000300")
    )
    if keyed:
        obj._v1_session_key_public_key = PUBLIC_KEY
        obj._v1_session_key_family = KeyFamily.S7_1200
        obj._try_session_key_auth = lambda: AUTH_RESULT
    else:
        obj._try_session_key_auth = lambda: None


def _sync_setup(case: str) -> dict[str, Any]:
    version, keyed, return_value = SETUP_CASES[case]
    conn = S7CommPlusConnection("127.0.0.1")
    _prepare(conn)
    _created(conn, version, keyed)
    sent: list[bytes] = []
    conn._send_s7_data = sent.append  # type: ignore[method-assign]
    conn._recv_response_frame = lambda seq, timeout=None: _setup_reply(seq, return_value)  # type: ignore[method-assign]
    result = _call(conn._setup_session)
    return {"sent": [f.hex() for f in sent], "result": result, "state": _state(conn)}


def _async_setup(case: str) -> dict[str, Any]:
    version, keyed, return_value = SETUP_CASES[case]
    client, sent = _async_client()
    _created(client, version, keyed)

    async def recv() -> bytes:
        return _setup_reply((client._sequence_number - 1) & 0xFFFF, return_value)

    async def recv_response(expected_sequence: Optional[int] = None) -> bytes:
        assert expected_sequence is not None
        return _setup_reply(expected_sequence, return_value)

    client._recv_cotp_dt = recv  # type: ignore[method-assign]
    client._recv_response_frame = recv_response  # type: ignore[method-assign]
    result = _call(lambda: asyncio.run(client._setup_session()))
    return {"sent": [f.hex() for f in sent], "result": result, "state": _state(client)}


def _record() -> dict[str, Any]:
    golden: dict[str, Any] = {}
    for name, reply in CREATE_REPLIES.items():
        golden[f"create_object-{name}"] = {"sync": _sync_create(reply), "async": _async_create(reply)}
    for case in SETUP_CASES:
        golden[f"session_setup-{case}"] = {"sync": _sync_setup(case), "async": _async_setup(case)}
    return golden


if os.environ.get("S7_RECORD_HANDSHAKE") == "1":  # pragma: no cover - maintenance switch
    GOLDEN.write_text(json.dumps(_record(), indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")

_GOLDEN: dict[str, Any] = json.loads(GOLDEN.read_text(encoding="utf-8")) if GOLDEN.exists() else {}


@pytest.mark.parametrize("name", list(CREATE_REPLIES))
def test_sync_create_object_matches_the_recording(name: str) -> None:
    assert _sync_create(CREATE_REPLIES[name]) == _GOLDEN[f"create_object-{name}"]["sync"]


@pytest.mark.parametrize("name", list(CREATE_REPLIES))
def test_async_create_object_matches_the_recording(name: str) -> None:
    assert _async_create(CREATE_REPLIES[name]) == _GOLDEN[f"create_object-{name}"]["async"]


@pytest.mark.parametrize("case", list(SETUP_CASES))
def test_sync_session_setup_matches_the_recording(case: str) -> None:
    assert _sync_setup(case) == _GOLDEN[f"session_setup-{case}"]["sync"]


@pytest.mark.parametrize("case", list(SETUP_CASES))
def test_async_session_setup_matches_the_recording(case: str) -> None:
    assert _async_setup(case) == _GOLDEN[f"session_setup-{case}"]["async"]


@pytest.mark.parametrize("name", list(CREATE_REPLIES))
def test_sync_and_async_create_object_agree(name: str) -> None:
    assert _sync_create(CREATE_REPLIES[name]) == _async_create(CREATE_REPLIES[name])


@pytest.mark.parametrize("case", list(SETUP_CASES))
def test_sync_and_async_session_setup_agree(case: str) -> None:
    assert _sync_setup(case) == _async_setup(case)


# The cases above stub out the reply dispatcher. These feed the 1215C's
# SessionSetup reply to the raw receive instead, so the real dispatcher of each
# client, which routes SystemEvents and stale replies, must accept it.


@pytest.mark.parametrize("keyed", [False, True], ids=["no_key", "key"])
def test_sync_session_setup_accepts_the_real_reply_through_the_dispatcher(keyed: bool) -> None:
    conn = S7CommPlusConnection("127.0.0.1")
    _prepare(conn)
    _created(conn, ProtocolVersion.V1, keyed)
    sent: list[bytes] = []
    conn._send_s7_data = sent.append  # type: ignore[method-assign]
    conn._recv_s7_data = lambda timeout=None, idle_ok=False: _setup_reply(conn._sequence_number - 1)  # type: ignore[method-assign]
    assert conn._setup_session() is True
    assert (conn._session_key is not None) == keyed


@pytest.mark.parametrize("keyed", [False, True], ids=["no_key", "key"])
def test_async_session_setup_accepts_the_real_reply_through_the_dispatcher(keyed: bool) -> None:
    client, sent = _async_client()
    _created(client, ProtocolVersion.V1, keyed)

    async def recv() -> bytes:
        return _setup_reply((client._sequence_number - 1) & 0xFFFF)

    client._recv_cotp_dt = recv  # type: ignore[method-assign]
    assert asyncio.run(client._setup_session()) is True
    assert (client._session_key is not None) == keyed
