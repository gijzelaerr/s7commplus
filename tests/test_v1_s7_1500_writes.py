"""V1 SessionKey S7-1500 (key family 00): write-class IntegrityIds, reply layout and SystemEvents in notification waits.

Found on a CPU 1512SP F-1 PN FW V2.6 against TIA Portal and WinCC panel captures of the same writes.
"""

from __future__ import annotations

import asyncio

import pytest

from s7commplus.async_connection import S7CommPlusAsyncConnection
from s7commplus.connection import S7CommPlusConnection
from s7commplus.error import S7ProtocolError
from s7commplus.protocol import FunctionCode, ProtocolVersion
from s7commplus.v1_session_key.keys import KeyFamily

# A SystemEvent the PLC pushed to a session when another session logged out (WinCC panel capture).
LOGOUT_EVENT = bytes.fromhex("72fe0016000000000000077500000000000000004c4f474f5554") + bytes.fromhex("72fe0000")


def _v1_session(conn: S7CommPlusConnection | S7CommPlusAsyncConnection, family: KeyFamily) -> None:
    conn._session_key = b"k" * 24
    conn._protocol_version = ProtocolVersion.V1
    conn._v1_session_key_family = family
    conn._with_integrity_id = True
    conn._integrity_id_write = 0


@pytest.mark.parametrize("make", [lambda: S7CommPlusConnection("127.0.0.1"), S7CommPlusAsyncConnection])
def test_write_ids_continue_after_the_activation_key_qualifier(make: object) -> None:
    # TIA Portal and a WinCC panel activate with KEY_QUALIFIER 4 and write with IntegrityId 5.
    conn = make()  # type: ignore[operator]
    _v1_session(conn, KeyFamily.S7_1500)
    conn._sequence_number = 3
    conn._session_activate_payload()
    conn._integrity_id_write = 1  # what the activation itself consumed
    conn._session_activated()
    assert conn._integrity_id_write == 4


@pytest.mark.parametrize("family", [KeyFamily.S7_1200, KeyFamily.PLCSIM])
def test_other_families_keep_their_write_ids(family: KeyFamily) -> None:
    conn = S7CommPlusConnection("127.0.0.1")
    _v1_session(conn, family)
    conn._sequence_number = 3
    conn._session_activate_payload()
    conn._integrity_id_write = 1
    conn._session_activated()
    assert conn._integrity_id_write == 1


def test_a_logout_system_event_is_skipped_while_waiting_for_a_notification() -> None:
    conn = S7CommPlusConnection("127.0.0.1")
    _v1_session(conn, KeyFamily.S7_1500)
    assert conn._skippable_system_event(LOGOUT_EVENT) is True
    assert conn._skippable_system_event(bytes.fromhex("7203000000")) is False


def test_a_fatal_system_event_still_raises_while_waiting_for_a_notification() -> None:
    # Rebuilt from the logged fatal event the same PLC sent for a refused subscription
    # (ReturnValue SERVICE_REQUEST_PARSING_ERROR); not a byte-exact capture.
    fatal = bytes.fromhex(
        "72fe0067000000000000072d00000000000000000000001700009d6c00009d6d000000080000000200009d6e00000004"
        "70000cc700009d6f00000004000004ca00009d7000000003000e00009d7100000009a2013b000260ff8800009d72000000"
        "040000000000009d7300000004000004c00000"
    )
    conn = S7CommPlusConnection("127.0.0.1")
    _v1_session(conn, KeyFamily.S7_1500)
    with pytest.raises(S7ProtocolError, match="Fatal"):
        conn._skippable_system_event(fatal)


def test_sync_notification_wait_skips_the_logout_event() -> None:
    from unittest.mock import MagicMock

    from s7commplus.protocol import Opcode

    conn = S7CommPlusConnection("127.0.0.1")
    _v1_session(conn, KeyFamily.S7_1500)
    conn._session_key = None  # no HMAC to check in this unit test
    conn._connected = True
    notification = bytes([0x72, 0x02, 0x00, 0x0B, Opcode.NOTIFICATION]) + bytes(10) + bytes.fromhex("72020000")
    conn._notification_frames.extend([LOGOUT_EVENT, notification])
    conn._incoming_frame_ready = MagicMock(return_value=False)  # type: ignore[method-assign]
    assert conn.receive_notification(timeout=1) == notification


def test_async_skips_the_logout_event_too() -> None:
    conn = S7CommPlusAsyncConnection()
    _v1_session(conn, KeyFamily.S7_1500)
    assert asyncio.run(asyncio.to_thread(conn._skippable_system_event, LOGOUT_EVENT)) is True


@pytest.mark.parametrize("function_code", [FunctionCode.SET_MULTI_VARIABLES, FunctionCode.CREATE_OBJECT])
def test_write_class_reply_keeps_its_return_value_first(function_code: int) -> None:
    conn = S7CommPlusConnection("127.0.0.1")
    _v1_session(conn, KeyFamily.S7_1500)
    reply = bytes.fromhex("00140000 0000".replace(" ", ""))
    assert conn._response_payload(function_code, reply) == reply
