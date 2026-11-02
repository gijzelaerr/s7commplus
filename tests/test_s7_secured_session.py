"""Detecting that a PLC runs a secured session from ServerSession.Role."""

from __future__ import annotations

from collections.abc import Generator

import pytest

from s7commplus.client import S7CommPlusClient
from s7commplus.codec import (
    SERVER_SESSION_ROLE_ID,
    SERVER_SESSION_ROLE_SECURED_BIT,
    SERVER_SESSION_ROLES_ID,
    parse_create_object_attributes,
)
from s7commplus.protocol import DataType, ElementID
from s7commplus.server import S7CommPlusServer
from s7commplus.vlq import encode_uint32_vlq


def _attribute(attr_id: int, value_bytes: bytes) -> bytes:
    return bytes([ElementID.ATTRIBUTE]) + encode_uint32_vlq(attr_id) + value_bytes


def _udint_attribute(attr_id: int, value: int) -> bytes:
    return _attribute(attr_id, bytes([0x00, DataType.UDINT]) + encode_uint32_vlq(value))


class TestParseServerSessionRole:
    def test_role_attribute_is_extracted(self) -> None:
        payload = _udint_attribute(SERVER_SESSION_ROLE_ID, 1 | SERVER_SESSION_ROLE_SECURED_BIT)
        attrs = parse_create_object_attributes(payload)
        assert attrs.server_session_role == 1 | SERVER_SESSION_ROLE_SECURED_BIT

    def test_unsecured_role_is_extracted(self) -> None:
        payload = _udint_attribute(SERVER_SESSION_ROLE_ID, 1)
        attrs = parse_create_object_attributes(payload)
        assert attrs.server_session_role == 1

    def test_absent_role_stays_none(self) -> None:
        attrs = parse_create_object_attributes(b"")
        assert attrs.server_session_role is None

    def test_array_role_is_ignored(self) -> None:
        # A malformed array-typed role must not crash the parser.
        payload = _attribute(SERVER_SESSION_ROLE_ID, bytes([0x10, DataType.UDINT]) + encode_uint32_vlq(0))
        attrs = parse_create_object_attributes(payload)
        assert attrs.server_session_role is None

    def test_other_udint_attributes_are_not_mistaken_for_the_role(self) -> None:
        payload = _udint_attribute(12345, 0x20000000)
        attrs = parse_create_object_attributes(payload)
        assert attrs.server_session_role is None

    def test_truncated_attribute_header_does_not_crash(self) -> None:
        # An attribute cut off right after its id leaves no room for the
        # typed-value header; the parser must not crash or misread.
        payload = bytes([0xA3]) + bytes.fromhex("8239")  # ATTRIBUTE + key 299, then nothing
        attrs = parse_create_object_attributes(payload)
        assert attrs.server_session_role is None

    def test_truncated_role_value_leaves_role_unset(self) -> None:
        # The role attribute's typed-value header present, its VLQ value cut
        # off: the role stays unset. The scan continues and the parser
        # reports the same malformed-input error as before this attribute
        # existed (the truncation leaves no valid following element).
        payload = bytes([0xA3]) + bytes.fromhex("8239") + bytes([0x00, 0x04])
        with pytest.raises(ValueError):
            parse_create_object_attributes(payload)

        # The same shape for a different attribute must behave identically —
        # the new branch adds no new failure mode.
        payload = bytes([0xA3]) + bytes.fromhex("8a39") + bytes([0x00, 0x04])  # key 12345
        with pytest.raises(ValueError):
            parse_create_object_attributes(payload)


class TestSecuredSessionProperty:
    def test_false_before_connect(self) -> None:
        client = S7CommPlusClient()
        assert client.secured_session is False

    def test_secured_role_sets_property(self) -> None:
        from s7commplus.connection import S7CommPlusConnection

        connection = S7CommPlusConnection("127.0.0.1")
        connection._server_session_role = 1 | SERVER_SESSION_ROLE_SECURED_BIT
        assert connection.secured_session is True

    def test_unsecured_role_keeps_property_false(self) -> None:
        from s7commplus.connection import S7CommPlusConnection

        connection = S7CommPlusConnection("127.0.0.1")
        connection._server_session_role = 1
        assert connection.secured_session is False

    def test_absent_role_keeps_property_false(self) -> None:
        from s7commplus.connection import S7CommPlusConnection

        connection = S7CommPlusConnection("127.0.0.1")
        assert connection.secured_session is False

    @pytest.mark.asyncio
    async def test_async_property_mirrors_sync(self) -> None:
        from s7commplus.async_client import S7CommPlusAsyncClient

        client = S7CommPlusAsyncClient()
        assert client.secured_session is False
        client._server_session_role = SERVER_SESSION_ROLE_SECURED_BIT
        assert client.secured_session is True


@pytest.fixture()
def emulator() -> Generator[tuple[S7CommPlusServer, int], None, None]:
    srv = S7CommPlusServer()
    srv.register_db(1, {"temperature": ("Real", 0)})
    srv.start(port=0)
    port = srv.port
    import time

    time.sleep(0.1)
    yield srv, port
    srv.stop()


class TestEndToEnd:
    def test_unsecured_emulator_reports_false(self, emulator: tuple[S7CommPlusServer, int]) -> None:
        # The plain emulator sends no Role attribute, so the property stays False
        # and the connection succeeds exactly as before.
        _srv, port = emulator
        client = S7CommPlusClient()
        client.connect("127.0.0.1", port=port)
        try:
            assert client.connected
            assert client.secured_session is False
        finally:
            client.disconnect()


class TestServerSessionRoles:
    """The Roles mask (305) parses alongside Role (299)."""

    def test_roles_attribute_is_extracted(self) -> None:
        payload = _udint_attribute(SERVER_SESSION_ROLES_ID, 0x7)
        attrs = parse_create_object_attributes(payload)
        assert attrs.server_session_roles == 0x7

    def test_role_and_roles_together(self) -> None:
        payload = _udint_attribute(SERVER_SESSION_ROLE_ID, 1) + _udint_attribute(SERVER_SESSION_ROLES_ID, 0x1F)
        attrs = parse_create_object_attributes(payload)
        assert attrs.server_session_role == 1
        assert attrs.server_session_roles == 0x1F

    def test_absent_roles_stays_none(self) -> None:
        payload = _udint_attribute(SERVER_SESSION_ROLE_ID, 1)
        attrs = parse_create_object_attributes(payload)
        assert attrs.server_session_roles is None

    def test_truncated_roles_value_does_not_crash(self) -> None:
        payload = bytes([0xA3]) + encode_uint32_vlq(SERVER_SESSION_ROLES_ID) + bytes([0x00, 0x04])
        attrs = parse_create_object_attributes(payload)
        assert attrs.server_session_roles is None

    def test_property_on_connection(self) -> None:
        from s7commplus.connection import S7CommPlusConnection

        connection = S7CommPlusConnection("127.0.0.1")
        assert connection.server_session_roles is None
        connection._server_session_roles = 0x1F
        assert connection.server_session_roles == 0x1F

    @pytest.mark.asyncio
    async def test_property_on_async_client(self) -> None:
        from s7commplus.async_client import S7CommPlusAsyncClient

        client = S7CommPlusAsyncClient()
        assert client.server_session_roles is None
        client._server_session_roles = 7
        assert client.server_session_roles == 7


def test_sync_client_exposes_roles_next_to_secured_session() -> None:
    # Client parity with the connection and async client (#85 review).
    from s7commplus.client import S7CommPlusClient
    from s7commplus.connection import S7CommPlusConnection

    client = S7CommPlusClient()
    assert client.server_session_roles is None
    connection = S7CommPlusConnection("127.0.0.1")
    connection._server_session_roles = 0x1F
    client._connection = connection
    assert client.server_session_roles == 0x1F
