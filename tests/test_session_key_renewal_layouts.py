"""Request layouts for the legacy SessionKey renewal write (issue #184)."""

from __future__ import annotations

import argparse
import importlib.util
import time
from collections.abc import Generator
from pathlib import Path
from types import ModuleType
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from s7commplus.async_client import S7CommPlusAsyncClient
from s7commplus.connection import (
    _SESSION_KEY_RENEWAL_LAYOUTS,
    S7CommPlusConnection,
    _build_session_activate_payload,
    _build_session_key_renewal_request,
    _build_session_setup_frame,
    _build_set_variable_payload,
)
from s7commplus.protocol import DataType, FunctionCode, LegitimationId, ProtocolVersion
from s7commplus.server import S7CommPlusServer
from s7commplus.v1_session_key.keys import KeyFamily

SESSION_ID = 0x70000001
SEQUENCE = 0x05E3
# Stands in for the encoded SecurityKey struct; its content does not matter here.
SECURITY_KEY = bytes.fromhex("00 17 00 00 07 08 8e 09 00 04 00 00")

HEAD = bytes.fromhex("70 00 00 01 01 8e 26")
# ObjectQualifier up to and including the KeyQualifier's flags and datatype.
QUALIFIER = bytes.fromhex("00 00 04 e8 89 69 00 12 00 00 00 00 89 6a 00 13 00 89 6b 00 04")


def _tail(payload: bytes) -> bytes:
    """Everything after the KeyQualifier's datatype."""
    return payload[payload.rindex(QUALIFIER) + len(QUALIFIER) :]


class TestRenewalRequestLayouts:
    def test_reference_is_the_request_an_s7_1500_refused(self) -> None:
        # Request payload of the refused renewal in the debug log on issue #184,
        # with the session id and the key struct replaced.
        function, payload, integrity_tail = _build_session_key_renewal_request("reference", SESSION_ID, SEQUENCE, SECURITY_KEY)

        assert function == FunctionCode.SET_VARIABLE
        assert payload == HEAD + SECURITY_KEY + QUALIFIER + bytes(7)
        assert payload == _build_set_variable_payload(SESSION_ID, LegitimationId.SESSION_SETUP_LEGITIMATION, SECURITY_KEY)
        assert integrity_tail == 4

    def test_v1_sequence_ends_like_the_session_activation(self) -> None:
        function, payload, integrity_tail = _build_session_key_renewal_request("v1-sequence", SESSION_ID, SEQUENCE, SECURITY_KEY)

        assert function == FunctionCode.SET_VARIABLE
        assert payload == HEAD + SECURITY_KEY + QUALIFIER + bytes.fromhex("00 00 05 e3 00 00 00")
        assert _tail(payload) == _tail(_build_session_activate_payload(SESSION_ID, SEQUENCE))
        assert integrity_tail == 3

    def test_v1_zero_has_a_fixed_width_qualifier_and_a_four_byte_fill(self) -> None:
        function, payload, integrity_tail = _build_session_key_renewal_request("v1-zero", SESSION_ID, SEQUENCE, SECURITY_KEY)

        assert function == FunctionCode.SET_VARIABLE
        assert payload == HEAD + SECURITY_KEY + QUALIFIER + bytes(8)
        assert integrity_tail == 4

    def test_multi_ends_like_the_session_setup_request(self) -> None:
        function, payload, integrity_tail = _build_session_key_renewal_request("multi", SESSION_ID, SEQUENCE, SECURITY_KEY)

        assert function == FunctionCode.SET_MULTI_VARIABLES
        assert payload == bytes.fromhex("70 00 00 01 01 01 8e 26 01") + SECURITY_KEY + b"\x00" + QUALIFIER + bytes(8)
        setup = _build_session_setup_frame(SESSION_ID, 2, bytes([0x00, DataType.UDINT, 0x00]), ProtocolVersion.V1, SECURITY_KEY)
        frame_trailer = 4
        assert setup[:-frame_trailer].endswith(b"\x00" + QUALIFIER + bytes(8))
        assert integrity_tail == 4

    def test_multi_v2_carries_the_v2_qualifier(self) -> None:
        function, payload, integrity_tail = _build_session_key_renewal_request("multi-v2", SESSION_ID, SEQUENCE, SECURITY_KEY)

        assert function == FunctionCode.SET_MULTI_VARIABLES
        assert payload == bytes.fromhex("70 00 00 01 01 01 8e 26 01") + SECURITY_KEY + b"\x00" + QUALIFIER + bytes(6)
        assert integrity_tail == 4

    def test_reference_short_drops_the_extra_byte(self) -> None:
        function, payload, integrity_tail = _build_session_key_renewal_request(
            "reference-short", SESSION_ID, SEQUENCE, SECURITY_KEY
        )

        assert function == FunctionCode.SET_VARIABLE
        assert payload == HEAD + SECURITY_KEY + QUALIFIER + bytes(6)
        assert integrity_tail == 4

    def test_every_listed_layout_builds_a_distinct_request(self) -> None:
        requests = {
            _build_session_key_renewal_request(layout, SESSION_ID, SEQUENCE, SECURITY_KEY)
            for layout in _SESSION_KEY_RENEWAL_LAYOUTS
        }

        assert len(requests) == len(_SESSION_KEY_RENEWAL_LAYOUTS)

    def test_unknown_layout_is_refused(self) -> None:
        with pytest.raises(ValueError, match="Unknown SessionKey renewal layout"):
            _build_session_key_renewal_request("nope", SESSION_ID, SEQUENCE, SECURITY_KEY)


class TestRenewalUsesTheSelectedLayout:
    CHALLENGE_RESPONSE = bytes([0x00, 0x00, 0x10, DataType.USINT, 20]) + bytes(range(20))

    @staticmethod
    def _connection() -> S7CommPlusConnection:
        conn = S7CommPlusConnection("127.0.0.1")
        conn._connected = True
        conn._session_ready = True
        conn._session_id = SESSION_ID
        conn._session_key = b"o" * 24
        conn._v1_session_key_public_key = b"p" * 40
        conn._v1_session_key_family = KeyFamily.S7_1500
        conn._sequence_number = SEQUENCE
        return conn

    def _renew(self, conn: S7CommPlusConnection) -> tuple[int, bytes, int]:
        send = MagicMock(side_effect=[self.CHALLENGE_RESPONSE, b"\x00"])
        conn._send_request = send  # type: ignore[method-assign]
        with patch("s7commplus.v1_session_key.handshake.authenticate_session_key", return_value=(b"b" * 180, b"n" * 24)):
            conn._renew_session_key_locked()
        function, payload, integrity_tail, _reassemble = send.call_args_list[1].args
        return function, payload, integrity_tail

    def test_default_layout_is_unchanged(self) -> None:
        conn = self._connection()
        assert conn._session_key_renewal_layout == "reference"

        function, payload, integrity_tail = self._renew(conn)

        security_key = conn._encode_security_key_struct(b"b" * 180, b"n" * 24)
        expected = _build_set_variable_payload(SESSION_ID, LegitimationId.SESSION_SETUP_LEGITIMATION, security_key)
        assert (function, payload, integrity_tail) == (FunctionCode.SET_VARIABLE, expected, 4)

    def test_selected_layout_is_sent_with_the_current_sequence_number(self) -> None:
        conn = self._connection()
        conn._session_key_renewal_layout = "v1-sequence"

        function, payload, integrity_tail = self._renew(conn)

        assert function == FunctionCode.SET_VARIABLE
        assert _tail(payload) == bytes.fromhex("00 00 05 e3 00 00 00")
        assert integrity_tail == 3
        assert conn._session_key == b"n" * 24

    def test_multi_layout_is_sent_as_set_multi_variables(self) -> None:
        conn = self._connection()
        conn._session_key_renewal_layout = "multi"

        function, _payload, integrity_tail = self._renew(conn)

        assert (function, integrity_tail) == (FunctionCode.SET_MULTI_VARIABLES, 4)

    @pytest.mark.asyncio
    async def test_async_client_sends_the_selected_layout(self) -> None:
        client = S7CommPlusAsyncClient()
        assert client._session_key_renewal_layout == "reference"
        client._session_id = SESSION_ID
        client._session_key = b"o" * 24
        client._v1_session_key_public_key = b"p" * 40
        client._v1_session_key_family = KeyFamily.S7_1500
        client._sequence_number = SEQUENCE
        client._session_key_renewal_layout = "multi"
        send = AsyncMock(side_effect=[self.CHALLENGE_RESPONSE, b"\x00"])
        client._send_request_locked = send  # type: ignore[method-assign]

        with patch("s7commplus.v1_session_key.handshake.authenticate_session_key", return_value=(b"b" * 180, b"n" * 24)):
            await client._renew_session_key_locked()

        function, _payload, integrity_tail = send.call_args_list[1].args
        assert (function, integrity_tail) == (FunctionCode.SET_MULTI_VARIABLES, 4)
        assert client._session_key == b"n" * 24


def _load_probe() -> ModuleType:
    path = Path(__file__).resolve().parent.parent / "tools" / "probe_session_key_renewal.py"
    spec = importlib.util.spec_from_file_location("probe_session_key_renewal", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestProbeTool:
    FINGERPRINT = "00:181B7B0847D11694"
    KEY = bytes(range(24))
    NEW_KEY = bytes(range(100, 124))

    @pytest.fixture()
    def server(self, monkeypatch: pytest.MonkeyPatch) -> Generator[S7CommPlusServer, None, None]:
        from s7commplus.v1_session_key import handshake

        keys = iter([self.KEY, self.NEW_KEY])
        monkeypatch.setattr(handshake, "authenticate_real_plc", lambda *_args: (bytes(180), next(keys)))
        srv = S7CommPlusServer(
            public_key_fingerprint=self.FINGERPRINT,
            session_challenge=bytes(range(20)),
            session_key=self.KEY,
            renewal_session_keys=[self.NEW_KEY],
        )
        srv.start(port=0)
        time.sleep(0.1)
        yield srv
        srv.stop()

    @staticmethod
    def _args(port: int) -> argparse.Namespace:
        return argparse.Namespace(plc_ip="127.0.0.1", plc_port=port, tls="off")

    def test_reference_layout_is_accepted_by_the_emulator(self, server: S7CommPlusServer) -> None:
        probe = _load_probe()

        session, verdict, detail = probe.probe_layout("reference", self._args(server.port))

        assert (verdict, detail) == ("accepted", "3 requests answered under the new key")
        assert session.startswith("family 00")
        assert server._accepted_session_key_renewals == 1

    def test_connection_error_is_reported_without_the_address(self) -> None:
        probe = _load_probe()

        session, verdict, detail = probe.probe_layout("reference", self._args(1))

        assert (session, verdict) == ("?", "error")
        assert "127.0.0.1" not in detail

    def test_probe_lists_the_layouts_of_the_connection(self) -> None:
        probe = _load_probe()

        assert probe._SESSION_KEY_RENEWAL_LAYOUTS is _SESSION_KEY_RENEWAL_LAYOUTS
