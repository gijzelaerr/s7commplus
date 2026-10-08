"""Tests for S7CommPlus V2 protocol support.

Tests IntegrityId tracking, legitimation helpers, protocol constants,
and V2 connection behavior.
"""

import asyncio
import hashlib
import hmac
import logging
import struct
import threading
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from s7commplus.async_client import S7CommPlusAsyncClient
from s7commplus.client import S7CommPlusClient
from s7commplus.codec import encode_header, encode_object_qualifier
from s7commplus.connection import (
    S7CommPlusConnection,
    _build_get_var_substreamed_payload,
    _build_set_variable_payload,
    _check_set_variable_response,
    _log_create_object_return_value,
    _parse_get_var_substreamed_response,
    _parse_protection_level_response,
)
from s7commplus.legitimation import (
    LegitimationState,
    _build_legitimation_payload,
    _parse_paom_string,
    build_legacy_response,
    build_new_response,
    decide_legitimation_mode,
    derive_legitimation_key,
    extract_session_version_string,
)
from s7commplus.protocol import (
    FLAGS_34_FUNCTION_CODES,
    READ_FUNCTION_CODES,
    AccessLevel,
    DataType,
    FunctionCode,
    Ids,
    LegitimationId,
    LegitimationType,
    ObjectId,
    Opcode,
    ProtocolVersion,
)
from s7commplus.server import S7CommPlusServer
from s7commplus.vlq import decode_uint32_vlq, encode_uint32_vlq
from s7commplus.error import S7ConnectionError, S7ProtocolError


class TestTypeInfoRidErrorHandling:
    def test_sync_returns_rid(self) -> None:
        client = S7CommPlusClient()
        with patch.object(client, "read_symbolic", return_value=struct.pack(">I", 0x12345678)):
            assert client._read_typeinfo_rid(1) == 0x12345678

    def test_sync_returns_zero_for_short_read(self) -> None:
        client = S7CommPlusClient()
        with patch.object(client, "read_symbolic", return_value=b"\x01\x02\x03"):
            assert client._read_typeinfo_rid(1) == 0

    def test_sync_returns_zero_for_unreadable_db(self) -> None:
        client = S7CommPlusClient()
        with patch.object(client, "read_symbolic", side_effect=RuntimeError("Symbolic read failed")):
            assert client._read_typeinfo_rid(1) == 0

    @pytest.mark.parametrize("error", [S7ConnectionError("reset"), S7ProtocolError("fatal event")])
    def test_sync_propagates_transport_and_protocol_errors(self, error: Exception) -> None:
        client = S7CommPlusClient()
        with patch.object(client, "read_symbolic", side_effect=error), pytest.raises(type(error), match=str(error)):
            client._read_typeinfo_rid(1)

    @pytest.mark.asyncio
    async def test_async_returns_rid(self) -> None:
        client = S7CommPlusAsyncClient()
        with patch.object(client, "read_symbolic", new=AsyncMock(return_value=struct.pack(">I", 0x12345678))):
            assert await client._read_typeinfo_rid(1) == 0x12345678

    @pytest.mark.asyncio
    async def test_async_returns_zero_for_short_read(self) -> None:
        client = S7CommPlusAsyncClient()
        with patch.object(client, "read_symbolic", new=AsyncMock(return_value=b"\x01\x02\x03")):
            assert await client._read_typeinfo_rid(1) == 0

    @pytest.mark.asyncio
    async def test_async_returns_zero_for_unreadable_db(self) -> None:
        client = S7CommPlusAsyncClient()
        error = RuntimeError("Symbolic read failed")
        with patch.object(client, "read_symbolic", new=AsyncMock(side_effect=error)):
            assert await client._read_typeinfo_rid(1) == 0

    @pytest.mark.asyncio
    @pytest.mark.parametrize("error", [S7ConnectionError("reset"), S7ProtocolError("fatal event")])
    async def test_async_propagates_transport_and_protocol_errors(self, error: Exception) -> None:
        client = S7CommPlusAsyncClient()
        with (
            patch.object(client, "read_symbolic", new=AsyncMock(side_effect=error)),
            pytest.raises(type(error), match=str(error)),
        ):
            await client._read_typeinfo_rid(1)

    @pytest.mark.asyncio
    async def test_async_reconnect_wrapper_retries_connection_error_once(self) -> None:
        client = S7CommPlusAsyncClient()
        operation = AsyncMock(side_effect=[S7ConnectionError("reset"), 42])
        client._reconnect = AsyncMock()  # type: ignore[method-assign]

        assert await client._with_reconnect(operation) == 42
        client._reconnect.assert_awaited_once()
        assert operation.await_count == 2

    @pytest.mark.asyncio
    async def test_async_reconnect_wrapper_does_not_retry_protocol_error(self) -> None:
        client = S7CommPlusAsyncClient()
        operation = AsyncMock(side_effect=S7ProtocolError("fatal event"))
        client._reconnect = AsyncMock()  # type: ignore[method-assign]

        with pytest.raises(S7ProtocolError, match="fatal event"):
            await client._with_reconnect(operation)
        client._reconnect.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_async_request_disconnected_is_connection_error(self) -> None:
        client = S7CommPlusAsyncClient()
        with pytest.raises(S7ConnectionError, match="Not connected"):
            await client._send_request(FunctionCode.GET_MULTI_VARIABLES, b"")

    @pytest.mark.asyncio
    async def test_async_reconnect_without_parameters_is_connection_error(self) -> None:
        client = S7CommPlusAsyncClient()
        with pytest.raises(S7ConnectionError, match="Not connected"):
            await client._reconnect()

    @pytest.mark.asyncio
    async def test_async_non_data_cotp_frame_is_connection_error(self) -> None:
        client = S7CommPlusAsyncClient()
        client._reader = asyncio.StreamReader()
        payload = bytes.fromhex("02e080")
        client._reader.feed_data(struct.pack(">BBH", 3, 0, len(payload) + 4) + payload)
        client._reader.feed_eof()

        with pytest.raises(S7ConnectionError, match="Expected COTP DT"):
            await client._recv_cotp_raw()


class TestReadFunctionCodes:
    """Test READ_FUNCTION_CODES classification."""

    def test_get_multi_variables_is_read(self) -> None:
        assert FunctionCode.GET_MULTI_VARIABLES in READ_FUNCTION_CODES

    def test_explore_is_read(self) -> None:
        assert FunctionCode.EXPLORE in READ_FUNCTION_CODES

    def test_get_var_substreamed_is_read(self) -> None:
        assert FunctionCode.GET_VAR_SUBSTREAMED in READ_FUNCTION_CODES

    def test_get_link_is_read(self) -> None:
        assert FunctionCode.GET_LINK in READ_FUNCTION_CODES

    def test_get_variable_is_read(self) -> None:
        assert FunctionCode.GET_VARIABLE in READ_FUNCTION_CODES

    def test_get_variables_address_is_read(self) -> None:
        assert FunctionCode.GET_VARIABLES_ADDRESS in READ_FUNCTION_CODES

    def test_set_multi_variables_is_write(self) -> None:
        assert FunctionCode.SET_MULTI_VARIABLES not in READ_FUNCTION_CODES

    def test_set_variable_is_write(self) -> None:
        assert FunctionCode.SET_VARIABLE not in READ_FUNCTION_CODES

    def test_create_object_is_write(self) -> None:
        assert FunctionCode.CREATE_OBJECT not in READ_FUNCTION_CODES

    def test_delete_object_is_write(self) -> None:
        assert FunctionCode.DELETE_OBJECT not in READ_FUNCTION_CODES


class TestFlags34FunctionCodes:
    """Test FLAGS_34_FUNCTION_CODES classification."""

    def test_delete_object_uses_flags_34(self) -> None:
        assert FunctionCode.DELETE_OBJECT in FLAGS_34_FUNCTION_CODES

    def test_explore_uses_flags_34(self) -> None:
        assert FunctionCode.EXPLORE in FLAGS_34_FUNCTION_CODES

    def test_get_multi_variables_uses_flags_34(self) -> None:
        assert FunctionCode.GET_MULTI_VARIABLES in FLAGS_34_FUNCTION_CODES

    def test_get_var_substreamed_uses_flags_34(self) -> None:
        assert FunctionCode.GET_VAR_SUBSTREAMED in FLAGS_34_FUNCTION_CODES

    def test_set_multi_variables_uses_flags_34(self) -> None:
        assert FunctionCode.SET_MULTI_VARIABLES in FLAGS_34_FUNCTION_CODES

    def test_set_variable_uses_flags_34(self) -> None:
        assert FunctionCode.SET_VARIABLE in FLAGS_34_FUNCTION_CODES

    def test_create_object_uses_flags_36(self) -> None:
        assert FunctionCode.CREATE_OBJECT not in FLAGS_34_FUNCTION_CODES

    def test_init_ssl_uses_flags_36(self) -> None:
        assert FunctionCode.INIT_SSL not in FLAGS_34_FUNCTION_CODES

    def test_get_variable_uses_flags_36(self) -> None:
        assert FunctionCode.GET_VARIABLE not in FLAGS_34_FUNCTION_CODES

    def test_get_variables_address_uses_flags_36(self) -> None:
        assert FunctionCode.GET_VARIABLES_ADDRESS not in FLAGS_34_FUNCTION_CODES

    def test_get_link_uses_flags_36(self) -> None:
        assert FunctionCode.GET_LINK not in FLAGS_34_FUNCTION_CODES


class TestLegitimationId:
    """Test legitimation ID constants."""

    def test_server_session_request(self) -> None:
        assert int(LegitimationId.SERVER_SESSION_REQUEST) == 303

    def test_server_session_response(self) -> None:
        assert int(LegitimationId.SERVER_SESSION_RESPONSE) == 304

    def test_legitimate(self) -> None:
        assert int(LegitimationId.LEGITIMATE) == 1846


class TestDeriveKey:
    """Test OMS key derivation."""

    def test_derive_returns_32_bytes(self) -> None:
        secret = b"\x00" * 32
        key = derive_legitimation_key(secret)
        assert len(key) == 32

    def test_derive_is_sha256(self) -> None:
        secret = b"test_oms_secret_material_32byte!"
        key = derive_legitimation_key(secret)
        expected = hashlib.sha256(secret).digest()
        assert key == expected

    def test_different_secrets_different_keys(self) -> None:
        key1 = derive_legitimation_key(b"\x00" * 32)
        key2 = derive_legitimation_key(b"\x01" * 32)
        assert key1 != key2


class TestLegacyResponse:
    """Test legacy legitimation (SHA-1 XOR)."""

    def test_legacy_response_length(self) -> None:
        challenge = b"\x00" * 20
        response = build_legacy_response("password", challenge)
        assert len(response) == 20

    def test_legacy_response_xor(self) -> None:
        password = "test"
        challenge = b"\xff" * 20
        response = build_legacy_response(password, challenge)
        password_hash = hashlib.sha1(password.encode("utf-8")).digest()  # noqa: S324
        # XOR with 0xFF should flip all bits
        expected = bytes(h ^ 0xFF for h in password_hash)
        assert response == expected

    def test_legacy_response_zero_challenge(self) -> None:
        password = "hello"
        challenge = b"\x00" * 20
        response = build_legacy_response(password, challenge)
        # XOR with zeros = original hash
        expected = hashlib.sha1(password.encode("utf-8")).digest()  # noqa: S324
        assert response == expected

    def test_legacy_response_matches_reference_driver(self) -> None:
        """
        SHA-1(password) XOR challenge, against a vector computed by the C# driver.
        The challenge is a genuine 20-byte challenge from an S7-1512 (FW V2.9).
        """
        challenge = bytes.fromhex("7d8f8470d20590efc1d740416b4a073296bf463b")
        response = build_legacy_response("foobar", challenge)
        assert response == bytes.fromhex("f5cc5389f613b1f2283cf9229406e5b3b32c6e43")


class TestExtractSessionVersionString:
    """Test PAOM string extraction from a raw ServerSessionVersion value."""

    @pytest.mark.parametrize(
        "paom_string",
        [
            "1;6ES7 214-1AG40-0XB0 ;V4.5",  # S7-1214C, trailing space
            "1;6ES7 510-1DJ01-0AB0;V2.9",  # S7-1510SP
            "1;6ES7 672-7FC01-0YA0;V21.9",  # S7-1507SF
        ],
    )
    def test_extracts_paom_string(self, paom_string: str) -> None:
        """Device strings from thomas-v2/S7CommPlusDriver, plain and behind a decoy key."""
        text = paom_string.encode("utf-8")
        header = bytes([0x00, DataType.STRUCT]) + struct.pack(">I", ObjectId.SERVER_SESSION_VERSION)
        # [VLQ key][flags][WString][VLQ length][utf-8 text]
        element = encode_uint32_vlq(Ids.SESSION_VERSION_SYSTEM_PAOM_STRING)
        element += bytes([0x00, DataType.WSTRING]) + encode_uint32_vlq(len(text)) + text

        assert extract_session_version_string(header + element) == paom_string

        # The needle also matches payload bytes, so the search must continue past them.
        decoy = encode_uint32_vlq(Ids.EFFECTIVE_PROTECTION_LEVEL) + bytes([0x00, DataType.UDINT])
        decoy += encode_uint32_vlq(Ids.SESSION_VERSION_SYSTEM_PAOM_STRING)
        assert extract_session_version_string(header + decoy + element) == paom_string

    def test_returns_none_when_unusable(self) -> None:
        """Value truncated past the end of the buffer, or no element 319 at all."""
        text = b"1;6ES7 510-1DJ01-0AB0;V2.9"
        value = bytes([0x00, DataType.STRUCT]) + struct.pack(">I", ObjectId.SERVER_SESSION_VERSION)
        value += encode_uint32_vlq(Ids.SESSION_VERSION_SYSTEM_PAOM_STRING)
        value += bytes([0x00, DataType.WSTRING]) + encode_uint32_vlq(len(text)) + text

        assert extract_session_version_string(value[:-1]) is None
        assert extract_session_version_string(value[:2]) is None


# ServerSessionVersion from PLCSIM Advanced V8.0 (instance with a CPU 1511 project,
# 6ES7 511-1AK02-0AB0 FW V2.9), captured on a TLS session on 2026-10-08. Element
# 319, the device string, is "1;6ES7 SIM-01500-APLC;S4.1": PLCSIM reports its own
# order number and version, not the project's CPU.
PLCSIM_ADVANCED_V8_SESSION_VERSION = bytes.fromhex(
    "00170000013a823b00048800823c00048540823d000484818640823e000484818440"
    "823f00151a313b364553372053494d2d30313530302d41504c433b53342e31"
    "8240001508323b38313138323482410003000300"
)


class TestParsePaomString:
    """Device series and firmware number, as the reference's pattern reads them."""

    @pytest.mark.parametrize(
        ("paom_string", "expected"),
        [
            ("1;6ES7 512-1CK01-0AB0;V2.9", ("5", 209)),
            ("1;6ES7 214-1AG40-0XB0 ;V4.5", ("2", 405)),  # S7-1214C, trailing space
            ("1;6ES7 510-1DJ01-0AB0;V2.9", ("5", 209)),  # S7-1510SP
            ("1;6ES7 672-7FC01-0YA0;V21.9", ("6", 2109)),  # S7-1507SF
            ("1;6ES7 212-1HG50-0XB0;V1.0", ("2", 100)),  # S7-1200 G2
            ("1;6ES7 SIM-01500-APLC;S4.1", ("5", 401)),  # PLCSIM Advanced V8.0
            ("1;6es7 511-1ak02-0ab0;v3.1", ("5", 301)),  # the reference ignores case
            ("1;6ES7  512-1CK01-0AB0;V2.9", ("5", 209)),  # two spaces: tolerated here only
            ("1;6ES7 512-1CK01-0AB0;x;V2.9", ("5", 209)),  # the firmware is the last field
            ("1;6ES7 512-1CK01-0AB0;V2.10", ("5", 210)),
            ("1;6ES7 512-1CK01-0AB0;V2.0010", ("5", 210)),  # four minor digits: the most read
            # The last model number in the field wins, overlapping ones included.
            ("1;6ES7 215 7 512;V2.9", ("5", 209)),
            ("1;671234;V2.9", ("2", 209)),  # "7123" and "1234" overlap; "234" is the last
        ],
    )
    def test_reads_series_and_firmware(self, paom_string: str, expected: tuple[str, int]) -> None:
        assert _parse_paom_string(paom_string) == expected

    @pytest.mark.parametrize(
        "paom_string",
        [
            "",
            ";;",
            "1;6ES7 512-1CK01-0AB0",  # no firmware field
            "6ES7 512-1CK01-0AB0;V2.9",  # no PAOM id field
            "1;;V2.9",
            "1;6ES7 5",  # truncated in the order number
            "1;6ES7 512-1CK01-0AB0;",  # truncated before the firmware
            "1;6ES7 512-1CK01-0AB0;V",
            "1;6ES7 512-1CK01-0AB0;V2",
            "1;6ES7 512-1CK01-0AB0;V2.",
            "1;6ES7 512-1CK01-0AB0;V.9",
            "1;6ES7 512-1CK01-0AB0;X2.9",
            "1;6ES7 512-1CK01-0AB0;V123.1",
            "1;6ES7 512-1CK01-0AB0;V2.9a",
            "1;6ES7 512-1CK01-0AB0;V2.9.1",
            "1;6ES7 512-1CK01-0AB0;V2.12345",  # five minor digits
            "1;6ES7 512-1CK01-0AB0;V2.9\n",
            "1;6ES7 512\n-1CK01-0AB0;V2.9",  # the reference's `.` stops at the newline too
            "1\n;6ES7 512-1CK01-0AB0;V2.9",  # rejected here only: a newline anywhere
            "1;6ES7 512-1CK01-0AB0;V2.9 ",
            "1;6ES2 512-1CK01-0AB0;V2.9",  # no 1 or 7 in front of the model number
            "1;6ES7 SIM-0AB0;V2.9",  # no model number at all
            "1;X;7 511;V3.1",  # a model number outside the order number field
        ],
    )
    def test_rejects_malformed_strings(self, paom_string: str) -> None:
        assert _parse_paom_string(paom_string) is None

    def test_long_adversarial_string_is_rejected(self) -> None:
        """Many candidate model numbers and separators: still parsed in linear time."""
        assert _parse_paom_string("1;" + "1000" * 50_000 + ";" * 1000 + "V2") is None
        assert _parse_paom_string("1;" + ("1" + " " * 1000) * 200 + ";V2.9") is None

    def test_huge_minor_version_is_rejected(self) -> None:
        """Thousands of minor digits never reach int(), which raises ValueError past 4300."""
        assert _parse_paom_string("1;6ES7 512-1CK01-0AB0;V2." + "9" * 5000) is None
        assert decide_legitimation_mode("1;6ES7 512-1CK01-0AB0;V2." + "9" * 5000) is None


def _master_parse_paom_string(version_string: str) -> Optional[tuple[str, int]]:
    """``_parse_paom_string`` as it was on master at 07d28d0, before the model-number regex.

    The code is a verbatim copy of ``s7commplus/legitimation.py`` at that commit;
    only the name and this docstring differ.
    """
    fields = version_string.split(";")
    if len(fields) < 3:
        return None

    # The model number ends the order number, behind a vendor prefix whose last
    # digit is 1 or 7: "6ES7 512-1CK01-0AB0" -> prefix "6ES7", model "512".
    order_number = fields[1].split("-")[0].rstrip()
    model, prefix = order_number[-3:], order_number[:-3].rstrip()
    if len(model) != 3 or not model.isdecimal() or prefix[-1:] not in ("1", "7"):
        return None

    firmware = fields[-1]
    if firmware[:1].upper() not in ("V", "S"):
        return None
    major, dot, minor = firmware[1:].partition(".")
    if not dot or not (1 <= len(major) <= 2) or not major.isdecimal() or not minor.isdecimal():
        return None

    return model[0], int(major) * 100 + int(minor)


class TestParsePaomStringMatchesMaster:
    """The model-number regex reads real S7-1200/1500 device strings as master's parser did.

    The order numbers are entries of ``s7commplus.devices.DEVICE_NAMES``. S7-1200
    strings carry the space before the firmware field that a real CPU 1215C sends.
    """

    @pytest.mark.parametrize(
        "paom_string",
        [
            # Read from a real CPU 1215C DC/DC/DC, FW V4.2 (non-TLS V1 SessionKey session).
            "1;6ES7 215-1AG40-0XB0 ;V4.2",
            "1;6ES7 211-1AE40-0XB0 ;V4.2",  # CPU 1211C DC/DC/DC
            "1;6ES7 211-1BE40-0XB0 ;V4.5",  # CPU 1211C AC/DC/Rly
            "1;6ES7 211-1HE40-0XB0 ;V4.6",  # CPU 1211C DC/DC/Rly
            "1;6ES7 214-1AG40-0XB0 ;V4.4",  # CPU 1214C DC/DC/DC
            "1;6ES7 214-1HG40-0XB0 ;V4.6",  # CPU 1214C DC/DC/Rly
            "1;6ES7 215-1BG40-0XB0 ;V4.7",  # CPU 1215C AC/DC/Rly
            "1;6ES7 215-1HG40-0XB0 ;V4.3",  # CPU 1215C DC/DC/Rly
            "1;6ES7 511-1AK01-0AB0;V2.9",  # CPU 1511-1 PN
            "1;6ES7 511-1FK01-0AB0;V2.8",  # CPU 1511F-1 PN
            "1;6ES7 512-1CK00-0AB0;V2.6",  # CPU 1512C-1 PN
            "1;6ES7 512-1DK01-0AB0;V2.9",  # CPU 1512SP-1 PN
            "1;6ES7 515-2AM01-0AB0;V2.9",  # CPU 1515-2 PN
            "1;6ES7 515-2FM01-0AB0;V2.5",  # CPU 1515F-2 PN
            "1;6ES7 517-3AP00-0AB0;V2.8",  # CPU 1517-3 PN/DP
            "1;6ES7 517-3FP00-0AB0;V2.9",  # CPU 1517F-3 PN/DP
        ],
    )
    def test_series_and_firmware_match_master(self, paom_string: str) -> None:
        from s7commplus.devices import device_name

        assert device_name(paom_string) is not None  # a real order number from the table
        expected = _master_parse_paom_string(paom_string)
        assert expected is not None
        assert _parse_paom_string(paom_string) == expected


class TestDecideLegitimationMode:
    """Every firmware boundary of the device table in ``decide_legitimation_mode``."""

    @pytest.mark.parametrize(
        ("paom_string", "expected"),
        [
            # S7-1500: none below V2.9, legacy up to V3.0, new from V3.1.
            ("1;6ES7 513-1AL02-0AB0;V2.8", None),
            ("1;6ES7 513-1AL02-0AB0;V2.9", LegitimationType.LEGACY),
            ("1;6ES7 513-1AL02-0AB0;V3.0", LegitimationType.LEGACY),
            ("1;6ES7 516-3AN02-0AB0;V3.1", LegitimationType.NEW),
            ("1;6ES7 SIM-01500-APLC;S4.1", LegitimationType.NEW),  # PLCSIM Advanced V8.0 (captured)
            # S7-1200: none below V4.3, legacy up to V4.6, new from V4.7.
            ("1;6ES7 217-1AG40-0XB0 ;V4.2", None),
            ("1;6ES7 217-1AG40-0XB0 ;V4.3", LegitimationType.LEGACY),
            ("1;6ES7 211-1AE40-0XB0 ;V4.6", LegitimationType.LEGACY),
            ("1;6ES7 211-1AE40-0XB0 ;V4.7", LegitimationType.NEW),
            ("1;6ES7 214-1AF50-0XB0;V1.1", LegitimationType.NEW),  # S7-1200 G2 ("50-0XB0")
            # S7-1507S software controller: none below V21.9, then legacy.
            ("1;6ES7 672-5DC01-0YA0;V21.8", None),
            ("1;6ES7 672-5DC01-0YA0;V21.9", LegitimationType.LEGACY),
            ("1;6ES7 317-2EK14-0AB0;V3.3", None),  # S7-300: not an S7CommPlus device
        ],
    )
    def test_mode_follows_device_and_firmware(self, paom_string: str, expected: LegitimationType | None) -> None:
        assert decide_legitimation_mode(paom_string) is expected

    def test_unreadable_string_logs_and_returns_none(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING, logger="s7commplus.legitimation"):
            assert decide_legitimation_mode("1;6ES7 SIM-0AB0;S4.1") is None
        assert "Could not extract the firmware version" in caplog.text

    def test_plcsim_capture_selects_new_mode(self) -> None:
        paom_string = extract_session_version_string(PLCSIM_ADVANCED_V8_SESSION_VERSION)
        assert paom_string == "1;6ES7 SIM-01500-APLC;S4.1"
        assert decide_legitimation_mode(paom_string) is LegitimationType.NEW


class TestAuthenticateOnPlcsim:
    """`authenticate()` on the PLCSIM device string takes the new exchange in both clients.

    It used to raise "PLC firmware version does not support legitimation", because
    the device string's order number was not read the way the reference reads it.
    """

    CHALLENGE = bytes(range(20))
    OMS_SECRET = bytes(range(32, 64))

    def _expected_response(self) -> bytes:
        return build_new_response("secret", self.CHALLENGE, self.OMS_SECRET)

    def test_sync(self) -> None:
        conn = S7CommPlusConnection("127.0.0.1")
        conn._connected = True
        conn._tls_active = True
        conn._protection_level = AccessLevel.NO_ACCESS
        conn._oms_secret = self.OMS_SECRET
        conn._server_session_version = PLCSIM_ADVANCED_V8_SESSION_VERSION
        conn._get_legitimation_challenge = MagicMock(return_value=self.CHALLENGE)
        conn._send_legitimation_new = MagicMock()
        conn._send_legitimation_legacy = MagicMock()
        conn._get_effective_protection_level = MagicMock(return_value=AccessLevel.FULL_ACCESS)

        conn.authenticate("secret")

        conn._send_legitimation_new.assert_called_once_with(self._expected_response())
        conn._send_legitimation_legacy.assert_not_called()
        assert conn._protection_level == AccessLevel.FULL_ACCESS

    @pytest.mark.asyncio
    async def test_async(self) -> None:
        client = S7CommPlusAsyncClient()
        client._connected = True
        client._tls_active = True
        client._protection_level = AccessLevel.NO_ACCESS
        client._oms_secret = self.OMS_SECRET
        client._server_session_version = PLCSIM_ADVANCED_V8_SESSION_VERSION
        client._get_legitimation_challenge = AsyncMock(return_value=self.CHALLENGE)
        client._send_legitimation_new = AsyncMock()
        client._send_legitimation_legacy = AsyncMock()
        client._get_effective_protection_level = AsyncMock(return_value=AccessLevel.FULL_ACCESS)

        await client.authenticate("secret")

        client._send_legitimation_new.assert_awaited_once_with(self._expected_response())
        client._send_legitimation_legacy.assert_not_awaited()
        assert client._protection_level == AccessLevel.FULL_ACCESS


def _session_version_with_device_string(device_string: str) -> bytes:
    """A ServerSessionVersion struct whose only element is the device string (319)."""
    encoded = device_string.encode("utf-8")
    return (
        bytes.fromhex("00170000013a")
        + encode_uint32_vlq(Ids.SESSION_VERSION_SYSTEM_PAOM_STRING)
        + bytes([0x00, DataType.WSTRING])
        + encode_uint32_vlq(len(encoded))
        + encoded
        + bytes([0x00])
    )


class TestAuthenticateOnOverlongFirmwareVersion:
    """A device string with thousands of minor-version digits is refused as unsupported.

    The PLC's string is untrusted. Its minor version used to go to int() unbounded,
    so authenticate() raised Python's bare ValueError for more than 4300 digits.
    """

    SESSION_VERSION = _session_version_with_device_string("1;6ES7 512-1CK01-0AB0;V3." + "1" * 5000)

    def test_sync(self) -> None:
        conn = S7CommPlusConnection("127.0.0.1")
        conn._connected = True
        conn._tls_active = True
        conn._protection_level = AccessLevel.NO_ACCESS
        conn._server_session_version = self.SESSION_VERSION
        conn._get_legitimation_challenge = MagicMock()

        with pytest.raises(S7ConnectionError, match="does not support legitimation"):
            conn.authenticate("secret")
        conn._get_legitimation_challenge.assert_not_called()

    @pytest.mark.asyncio
    async def test_async(self) -> None:
        client = S7CommPlusAsyncClient()
        client._connected = True
        client._tls_active = True
        client._protection_level = AccessLevel.NO_ACCESS
        client._server_session_version = self.SESSION_VERSION
        client._get_legitimation_challenge = AsyncMock()

        with pytest.raises(S7ConnectionError, match="does not support legitimation"):
            await client.authenticate("secret")
        client._get_legitimation_challenge.assert_not_awaited()


class TestLegitimationPayload:
    """Test legitimation payload building."""

    def test_payload_without_username(self) -> None:
        payload = _build_legitimation_payload("password")
        assert len(payload) > 0
        # Should contain struct header
        assert payload[1] == 0x17  # DataType.STRUCT

    def test_payload_with_username(self) -> None:
        payload = _build_legitimation_payload("password", "admin")
        assert len(payload) > 0

    def test_payload_legit_type_1_without_username(self) -> None:
        """Without username, legitimation type should be 1 (legacy)."""
        payload = _build_legitimation_payload("password")
        # [flags=0x00, type=0x17, struct id (4 bytes), key VLQ (3 bytes),
        #  flags=0x00, type=UDInt(0x04), legit_type VLQ]
        assert payload[10] == 0x04  # UDInt type for legit_type
        assert payload[11] == 0x01  # legit_type = 1

    def test_payload_legit_type_2_with_username(self) -> None:
        """With username, legitimation type should be 2 (new)."""
        payload = _build_legitimation_payload("password", "admin")
        assert payload[10] == 0x04  # UDInt type for legit_type
        assert payload[11] == 0x02  # legit_type = 2

    def test_password_only_payload_bytes(self) -> None:
        """The layout PLCSIM Advanced V8.0 accepted, live, on 2026-10-08."""
        assert _build_legitimation_payload("x") == bytes.fromhex(
            "0017"
            "00009dd0"  # struct 40400, LegitimationPayloadStruct
            "82bb51 0004 01"  # 40401 type: UDInt 1, legacy-style credentials
            "82bb52 0014 00 00"  # 40402 username: Blob, root id 0, empty
            "82bb53 0014 00 14"  # 40403 password: Blob, root id 0, 20 bytes ...
            "11f6ad8ec52a2984abaafd7c3b516503785c2072"  # ... SHA-1("x")
            "00"  # terminator
        )

    def test_username_payload_bytes(self) -> None:
        assert _build_legitimation_payload("pw", "admin") == bytes.fromhex(
            "0017"
            "00009dd0"
            "82bb51 0004 02"  # type: UDInt 2, username and password
            "82bb52 0014 00 05 61646d696e"  # username: root id 0, "admin"
            "82bb53 0014 00 02 7077"  # password in plain text: root id 0, "pw"
            "00"
        )


class TestLegitimationState:
    """Test LegitimationState tracker."""

    def test_initial_state_not_authenticated(self) -> None:
        state = LegitimationState()
        assert not state.authenticated

    def test_mark_authenticated(self) -> None:
        state = LegitimationState()
        state.mark_authenticated()
        assert state.authenticated

    def test_with_oms_secret(self) -> None:
        state = LegitimationState(oms_secret=b"\x00" * 32)
        assert not state.authenticated

    def test_rotate_key(self) -> None:
        state = LegitimationState(oms_secret=b"\x00" * 32)
        # Should not raise
        state.rotate_key()

    def test_rotate_key_without_secret(self) -> None:
        state = LegitimationState()
        # Should not raise even without OMS secret
        state.rotate_key()


class TestIntegrityIdTracking:
    """Test IntegrityId counter logic in S7CommPlusConnection."""

    def test_initial_counters_zero(self) -> None:
        conn = S7CommPlusConnection("127.0.0.1")
        assert conn.integrity_id_read == 0
        assert conn.integrity_id_write == 0

    def test_connection_attributes(self) -> None:
        conn = S7CommPlusConnection("127.0.0.1")
        assert conn.oms_secret is None
        assert not conn.tls_active

    def test_protocol_version_default(self) -> None:
        conn = S7CommPlusConnection("127.0.0.1")
        assert conn.protocol_version == 0

    def test_tls_v2_response_application_payload_is_not_stripped(self) -> None:
        conn = S7CommPlusConnection("127.0.0.1")
        conn._connected = True
        conn._protocol_version = ProtocolVersion.V2
        conn._session_id = 0x70000001
        conn._with_integrity_id = True

        application_payload = bytes.fromhex("000100100201")
        response = struct.pack(">BHHHHB", 0x32, 0, FunctionCode.GET_MULTI_VARIABLES, 0, 0, 0x34)
        response += application_payload
        frame = encode_header(ProtocolVersion.V2, len(response)) + response
        frame += struct.pack(">BBH", 0x72, ProtocolVersion.V2, 0)

        conn._send_s7_data = MagicMock()
        conn._recv_s7_data = MagicMock(return_value=frame)

        assert conn.send_request(FunctionCode.GET_MULTI_VARIABLES, bytes(4)) == application_payload

        # GetMultiVariables is in FLAGS_34_FUNCTION_CODES
        assert conn._send_s7_data.call_args[0][0][17] == 0x34

    def test_nonfatal_system_event_is_consumed_before_sync_response(self) -> None:
        conn = S7CommPlusConnection("127.0.0.1")
        conn._connected = True
        conn._protocol_version = ProtocolVersion.V3
        conn._session_id = 0x0000039B
        conn._session_key = bytes(range(24))

        confirmation = bytes.fromhex("00000000000002f60000000000000000")
        event_frame = encode_header(ProtocolVersion.SYSTEM_EVENT, len(confirmation)) + confirmation
        application_payload = b"\x00\x01"
        response = struct.pack(">BHHHHB", 0x32, 0, FunctionCode.SET_VAR_SUBSTREAMED, 0, 0, 0x34)
        response += encode_uint32_vlq(0) + application_payload
        digest = hmac.new(conn._session_key, response, hashlib.sha256).digest()
        protected_response = bytes([len(digest)]) + digest + response
        response_frame = encode_header(ProtocolVersion.V3, len(protected_response)) + protected_response
        response_frame += struct.pack(">BBH", 0x72, ProtocolVersion.V3, 0)

        conn._send_s7_data = MagicMock()
        conn._recv_s7_data = MagicMock(side_effect=[event_frame, response_frame])

        assert conn.send_request(FunctionCode.SET_VAR_SUBSTREAMED) == application_payload
        assert conn._recv_s7_data.call_count == 2

    def test_fatal_system_event_raises_protocol_error(self) -> None:
        conn = S7CommPlusConnection("127.0.0.1")
        conn._connected = True
        conn._protocol_version = ProtocolVersion.V3
        conn._session_id = 0x0000039B

        fatal = bytes(16)
        fatal += bytes.fromhex("0000001700009d6c")
        fatal += struct.pack(">I", 40305) + bytes.fromhex("00000009") + (-1).to_bytes(8, "big", signed=True)
        event_frame = encode_header(ProtocolVersion.SYSTEM_EVENT, len(fatal)) + fatal
        conn._send_s7_data = MagicMock()
        conn._recv_s7_data = MagicMock(return_value=event_frame)

        with pytest.raises(S7ProtocolError, match="Fatal S7CommPlus SystemEvent"):
            conn.send_request(FunctionCode.SET_VAR_SUBSTREAMED)

    @pytest.mark.asyncio
    async def test_nonfatal_system_event_is_consumed_before_async_response(self) -> None:
        client = S7CommPlusAsyncClient()
        client._connected = True
        client._reader = MagicMock()
        client._writer = MagicMock()
        client._protocol_version = ProtocolVersion.V2

        confirmation = bytes.fromhex("00000000000002f60000000000000000")
        event_frame = encode_header(ProtocolVersion.SYSTEM_EVENT, len(confirmation)) + confirmation
        response = struct.pack(">BHHHHB", 0x32, 0, FunctionCode.GET_MULTI_VARIABLES, 0, 0, 0x34)
        response += b"\x00\x01"
        response_frame = encode_header(ProtocolVersion.V2, len(response)) + response
        response_frame += struct.pack(">BBH", 0x72, ProtocolVersion.V2, 0)
        client._send_cotp_dt = AsyncMock()
        client._recv_cotp_dt = AsyncMock(side_effect=[event_frame, response_frame])

        assert await client._send_request(FunctionCode.GET_MULTI_VARIABLES, bytes(4)) == b"\x00\x01"
        assert client._recv_cotp_dt.await_count == 2

    @pytest.mark.asyncio
    async def test_too_many_async_system_events_raise_protocol_error_from_typeinfo_read(self) -> None:
        client = S7CommPlusAsyncClient()
        client._connected = True
        client._reader = MagicMock()
        client._writer = MagicMock()
        client._protocol_version = ProtocolVersion.V2

        confirmation = bytes.fromhex("00000000000002f60000000000000000")
        event_frame = encode_header(ProtocolVersion.SYSTEM_EVENT, len(confirmation)) + confirmation
        client._send_cotp_dt = AsyncMock()
        client._recv_cotp_dt = AsyncMock(return_value=event_frame)

        with pytest.raises(S7ProtocolError, match="Too many S7CommPlus SystemEvents"):
            await client._read_typeinfo_rid(0x8A0E0001)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("reassemble", [False, True])
    async def test_async_short_response_raises_connection_error(self, reassemble: bool) -> None:
        client = S7CommPlusAsyncClient()
        client._connected = True
        client._reader = MagicMock()
        client._writer = MagicMock()
        client._protocol_version = ProtocolVersion.V2
        response = b"short"
        response_frame = encode_header(ProtocolVersion.V2, len(response)) + response
        response_frame += struct.pack(">BBH", 0x72, ProtocolVersion.V2, 0)
        client._send_cotp_dt = AsyncMock()
        client._recv_cotp_dt = AsyncMock(return_value=response_frame)

        with pytest.raises(S7ConnectionError, match="Response too short"):
            await client._send_request(FunctionCode.GET_MULTI_VARIABLES, b"", reassemble=reassemble)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("reassemble", [False, True])
    async def test_async_sequence_mismatch_raises_protocol_error(self, reassemble: bool) -> None:
        client = S7CommPlusAsyncClient()
        client._connected = True
        client._reader = MagicMock()
        client._writer = MagicMock()
        client._protocol_version = ProtocolVersion.V2
        response = struct.pack(">BHHHHB", 0x32, 0, FunctionCode.GET_MULTI_VARIABLES, 0, 99, 0x34)
        response_frame = encode_header(ProtocolVersion.V2, len(response)) + response
        response_frame += struct.pack(">BBH", 0x72, ProtocolVersion.V2, 0)
        client._send_cotp_dt = AsyncMock()
        client._recv_cotp_dt = AsyncMock(return_value=response_frame)

        with pytest.raises(S7ProtocolError, match="Response sequence mismatch"):
            await client._send_request(FunctionCode.GET_MULTI_VARIABLES, b"", reassemble=reassemble)

    @pytest.mark.parametrize("reassemble", [False, True])
    def test_sync_function_mismatch_raises_protocol_error(self, reassemble: bool) -> None:
        conn = S7CommPlusConnection("127.0.0.1")
        conn._connected = True
        conn._protocol_version = ProtocolVersion.V2
        response = struct.pack(">BHHHHB", Opcode.RESPONSE, 0, FunctionCode.SET_MULTI_VARIABLES, 0, 0, 0x34)
        response_frame = encode_header(ProtocolVersion.V2, len(response)) + response
        response_frame += struct.pack(">BBH", 0x72, ProtocolVersion.V2, 0)
        conn._send_s7_data = MagicMock()
        conn._recv_s7_data = MagicMock(return_value=response_frame)

        with pytest.raises(S7ProtocolError, match="Response function mismatch"):
            conn.send_request(FunctionCode.GET_MULTI_VARIABLES, b"", reassemble=reassemble)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("reassemble", [False, True])
    async def test_async_function_mismatch_raises_protocol_error(self, reassemble: bool) -> None:
        client = S7CommPlusAsyncClient()
        client._connected = True
        client._reader = MagicMock()
        client._writer = MagicMock()
        client._protocol_version = ProtocolVersion.V2
        response = struct.pack(">BHHHHB", Opcode.RESPONSE, 0, FunctionCode.SET_MULTI_VARIABLES, 0, 0, 0x34)
        response_frame = encode_header(ProtocolVersion.V2, len(response)) + response
        response_frame += struct.pack(">BBH", 0x72, ProtocolVersion.V2, 0)
        client._send_cotp_dt = AsyncMock()
        client._recv_cotp_dt = AsyncMock(return_value=response_frame)

        with pytest.raises(S7ProtocolError, match="Response function mismatch"):
            await client._send_request(FunctionCode.GET_MULTI_VARIABLES, b"", reassemble=reassemble)

    @pytest.mark.parametrize("opcode", [Opcode.REQUEST, 0x7F])
    def test_sync_unexpected_opcode_raises_protocol_error(self, opcode: int) -> None:
        conn = S7CommPlusConnection("127.0.0.1")
        conn._connected = True
        conn._protocol_version = ProtocolVersion.V2
        response = struct.pack(">BHHHHB", opcode, 0, FunctionCode.GET_MULTI_VARIABLES, 0, 0, 0x34)
        response_frame = encode_header(ProtocolVersion.V2, len(response)) + response
        conn._send_s7_data = MagicMock()
        conn._recv_s7_data = MagicMock(return_value=response_frame)

        with pytest.raises(S7ProtocolError, match="Unexpected S7CommPlus opcode"):
            conn.send_request(FunctionCode.GET_MULTI_VARIABLES)

    @pytest.mark.asyncio
    async def test_async_unexpected_opcode_raises_protocol_error(self) -> None:
        client = S7CommPlusAsyncClient()
        client._connected = True
        client._reader = MagicMock()
        client._writer = MagicMock()
        client._protocol_version = ProtocolVersion.V2
        response = struct.pack(">BHHHHB", Opcode.REQUEST, 0, FunctionCode.GET_MULTI_VARIABLES, 0, 0, 0x34)
        response_frame = encode_header(ProtocolVersion.V2, len(response)) + response
        client._send_cotp_dt = AsyncMock()
        client._recv_cotp_dt = AsyncMock(return_value=response_frame)

        with pytest.raises(S7ProtocolError, match="Unexpected S7CommPlus opcode"):
            await client._send_request(FunctionCode.GET_MULTI_VARIABLES, b"")

    def test_sync_notification_before_response_is_queued(self) -> None:
        conn = S7CommPlusConnection("127.0.0.1")
        conn._connected = True
        conn._protocol_version = ProtocolVersion.V2
        notification = struct.pack(">BHHHHB", Opcode.NOTIFICATION, 0, 0, 0, 12, 0x34)
        notification_frame = encode_header(ProtocolVersion.V2, len(notification)) + notification
        response = struct.pack(">BHHHHB", Opcode.RESPONSE, 0, FunctionCode.GET_MULTI_VARIABLES, 0, 0, 0x34)
        response_frame = encode_header(ProtocolVersion.V2, len(response)) + response
        response_frame += struct.pack(">BBH", 0x72, ProtocolVersion.V2, 0)
        conn._send_s7_data = MagicMock()
        conn._recv_s7_data = MagicMock(side_effect=[notification_frame, response_frame])

        assert conn.send_request(FunctionCode.GET_MULTI_VARIABLES) == b""
        assert conn.receive_notification() == notification_frame
        assert conn._recv_s7_data.call_count == 2

    @pytest.mark.asyncio
    async def test_async_notification_before_response_is_queued(self) -> None:
        client = S7CommPlusAsyncClient()
        client._connected = True
        client._reader = MagicMock()
        client._writer = MagicMock()
        client._protocol_version = ProtocolVersion.V2
        notification = struct.pack(">BHHHHB", Opcode.NOTIFICATION, 0, 0, 0, 12, 0x34)
        notification_frame = encode_header(ProtocolVersion.V2, len(notification)) + notification
        response = struct.pack(">BHHHHB", Opcode.RESPONSE, 0, FunctionCode.GET_MULTI_VARIABLES, 0, 0, 0x34)
        response_frame = encode_header(ProtocolVersion.V2, len(response)) + response
        response_frame += struct.pack(">BBH", 0x72, ProtocolVersion.V2, 0)
        client._send_cotp_dt = AsyncMock()
        client._recv_cotp_dt = AsyncMock(side_effect=[notification_frame, response_frame])

        assert await client._send_request(FunctionCode.GET_MULTI_VARIABLES, b"") == b""
        assert list(client._notification_frames) == [notification_frame]

    def test_stale_sync_response_is_skipped_before_next_response(self) -> None:
        conn = S7CommPlusConnection("127.0.0.1")
        conn._connected = True
        conn._protocol_version = ProtocolVersion.V2
        response = struct.pack(">BHHHHB", Opcode.RESPONSE, 0, FunctionCode.GET_MULTI_VARIABLES, 0, 0, 0x34)
        response_frame = encode_header(ProtocolVersion.V2, len(response)) + response
        response_frame += struct.pack(">BBH", 0x72, ProtocolVersion.V2, 0)
        conn._send_s7_data = MagicMock()
        next_response = struct.pack(">BHHHHB", Opcode.RESPONSE, 0, FunctionCode.GET_MULTI_VARIABLES, 0, 1, 0x34)
        next_response_frame = encode_header(ProtocolVersion.V2, len(next_response)) + next_response
        next_response_frame += struct.pack(">BBH", 0x72, ProtocolVersion.V2, 0)
        conn._recv_s7_data = MagicMock(side_effect=[response_frame, response_frame, next_response_frame])

        assert conn.send_request(FunctionCode.GET_MULTI_VARIABLES) == b""
        assert conn.send_request(FunctionCode.GET_MULTI_VARIABLES) == b""
        assert conn._recv_s7_data.call_count == 3

    @pytest.mark.asyncio
    async def test_stale_async_response_is_skipped_before_next_response(self) -> None:
        client = S7CommPlusAsyncClient()
        client._connected = True
        client._reader = MagicMock()
        client._writer = MagicMock()
        client._protocol_version = ProtocolVersion.V2
        response = struct.pack(">BHHHHB", Opcode.RESPONSE, 0, FunctionCode.GET_MULTI_VARIABLES, 0, 0, 0x34)
        response_frame = encode_header(ProtocolVersion.V2, len(response)) + response
        client._send_cotp_dt = AsyncMock()
        next_response = struct.pack(">BHHHHB", Opcode.RESPONSE, 0, FunctionCode.GET_MULTI_VARIABLES, 0, 1, 0x34)
        next_response_frame = encode_header(ProtocolVersion.V2, len(next_response)) + next_response
        next_response_frame += struct.pack(">BBH", 0x72, ProtocolVersion.V2, 0)
        client._recv_cotp_dt = AsyncMock(side_effect=[response_frame, response_frame, next_response_frame])

        assert await client._send_request(FunctionCode.GET_MULTI_VARIABLES, b"") == b""
        assert await client._send_request(FunctionCode.GET_MULTI_VARIABLES, b"") == b""
        assert client._recv_cotp_dt.await_count == 3

    def test_sync_requests_are_serialized(self) -> None:
        conn = S7CommPlusConnection("127.0.0.1")
        first_entered = threading.Event()
        release_first = threading.Event()
        second_started = threading.Event()
        second_entered = threading.Event()
        call_count = 0
        count_lock = threading.Lock()

        def exchange(*_args: object) -> bytes:
            nonlocal call_count
            with count_lock:
                call_count += 1
                current = call_count
            if current == 1:
                first_entered.set()
                assert release_first.wait(1)
            else:
                second_entered.set()
            return b""

        conn._send_request = MagicMock(side_effect=exchange)
        first = threading.Thread(target=conn.send_request, args=(FunctionCode.GET_MULTI_VARIABLES,))

        def run_second() -> None:
            second_started.set()
            conn.send_request(FunctionCode.GET_MULTI_VARIABLES)

        second = threading.Thread(target=run_second)
        first.start()
        assert first_entered.wait(1)
        second.start()
        assert second_started.wait(1)
        assert not second_entered.wait(0.05)
        release_first.set()
        first.join(1)
        second.join(1)
        assert not first.is_alive()
        assert not second.is_alive()
        assert second_entered.is_set()

    @pytest.mark.parametrize("client_kind", ["sync", "async"])
    @pytest.mark.asyncio
    async def test_connection_close_while_waiting_is_connection_error(self, client_kind: str) -> None:
        if client_kind == "sync":
            conn = S7CommPlusConnection("127.0.0.1")
            conn._connected = True
            conn._protocol_version = ProtocolVersion.V2
            conn._send_s7_data = MagicMock()
            conn._recv_s7_data = MagicMock(return_value=b"")
            with pytest.raises(S7ConnectionError, match="Connection closed"):
                conn.send_request(FunctionCode.GET_MULTI_VARIABLES)
            return

        client = S7CommPlusAsyncClient()
        client._connected = True
        client._reader = MagicMock()
        client._writer = MagicMock()
        client._protocol_version = ProtocolVersion.V2
        client._send_cotp_dt = AsyncMock()
        client._recv_cotp_dt = AsyncMock(return_value=b"")
        with pytest.raises(S7ConnectionError, match="Connection closed"):
            await client._send_request(FunctionCode.GET_MULTI_VARIABLES, b"")


class TestAsyncReassembledPayloadErrors:
    @pytest.mark.asyncio
    async def test_closed_connection_raises_connection_error(self) -> None:
        client = S7CommPlusAsyncClient()
        client._recv_cotp_dt = AsyncMock(return_value=b"")

        with pytest.raises(S7ConnectionError, match="closed during"):
            await client._recv_reassembled_payload()

    @pytest.mark.asyncio
    async def test_bad_fragment_header_raises_connection_error(self) -> None:
        client = S7CommPlusAsyncClient()

        with pytest.raises(S7ConnectionError, match="fragment header"):
            await client._recv_reassembled_payload(b"\x99\x02\x00\x01x")

    @pytest.mark.asyncio
    async def test_fragment_limit_raises_connection_error(self) -> None:
        client = S7CommPlusAsyncClient()
        client._MAX_REASSEMBLED_FRAGMENTS = 1
        fragments = b"\x72\x02\x00\x01a\x72\x02\x00\x01b\x72\x02\x00\x00"

        with pytest.raises(S7ConnectionError, match="exceeds limits"):
            await client._recv_reassembled_payload(fragments)


class TestServerResponseIntegrityId:
    """Test V2 response IntegrityId selection and encoding."""

    @staticmethod
    def _request(function_code: int) -> bytes:
        request = struct.pack(
            ">BHHHHIB",
            Opcode.REQUEST,
            0,
            function_code,
            0,
            1,
            0x12345678,
            0x34,
        )
        return encode_header(ProtocolVersion.V2, len(request)) + request

    @pytest.mark.parametrize(
        ("function_code", "expected_integrity_id"),
        [
            (FunctionCode.GET_MULTI_VARIABLES, 128),
            (FunctionCode.EXPLORE, 128),
            (FunctionCode.GET_VAR_SUBSTREAMED, 128),
            (FunctionCode.SET_MULTI_VARIABLES, 16384),
            (FunctionCode.SET_VAR_SUBSTREAMED, 16384),
            (FunctionCode.DELETE_OBJECT, 16384),
        ],
    )
    def test_v2_response_appends_function_counter(self, function_code: int, expected_integrity_id: int) -> None:
        server = S7CommPlusServer(protocol_version=ProtocolVersion.V2)
        request = self._request(function_code)

        initial_response, initial_rst = server._process_request(request, 0x12345678)
        advanced_response, advanced_rst = server._process_request(
            request, 0x12345678, integrity_id_read=128, integrity_id_write=16384
        )

        assert initial_response is not None
        assert advanced_response is not None
        assert advanced_response == initial_response[:-1] + encode_uint32_vlq(expected_integrity_id)
        assert not initial_rst
        assert not advanced_rst

    def test_v1_response_keeps_legacy_integrity_field(self) -> None:
        server = S7CommPlusServer(protocol_version=ProtocolVersion.V1)
        request = self._request(FunctionCode.GET_MULTI_VARIABLES)

        initial_response, initial_rst = server._process_request(request, 0x12345678)
        advanced_response, advanced_rst = server._process_request(request, 0x12345678, integrity_id_read=128)

        assert advanced_response == initial_response
        assert not initial_rst
        assert not advanced_rst

    def test_v2_substreamed_response_has_one_integrity_id(self) -> None:
        server = S7CommPlusServer(protocol_version=ProtocolVersion.V2)
        request = self._request(FunctionCode.GET_VAR_SUBSTREAMED)

        response, rst = server._process_request(request, 0x12345678, integrity_id_read=128)

        assert response == server._handle_get_var_substreamed(1, 0x12345678, b"") + encode_uint32_vlq(128)
        assert not rst

    def test_init_ssl_response_has_no_integrity_id(self) -> None:
        server = S7CommPlusServer(protocol_version=ProtocolVersion.V2)
        request = bytearray(self._request(FunctionCode.INIT_SSL))
        request[13:17] = bytes(4)  # InitSSL runs before a session id exists.

        response, rst = server._process_request(bytes(request), 0, integrity_id_write=128)

        assert response == server._handle_init_ssl(1)
        assert not rst

    def test_in_session_error_response_uses_write_integrity_id(self) -> None:
        server = S7CommPlusServer(protocol_version=ProtocolVersion.V2)
        unsupported_function = 0xFFFF
        request = self._request(unsupported_function)

        response, rst = server._process_request(request, 0x12345678, integrity_id_write=128)

        assert response == server._build_error_response(1, 0x12345678, unsupported_function) + encode_uint32_vlq(128)
        assert not rst


class TestIntegrityIdVlqEncoding:
    """Test VLQ encoding used for IntegrityId values."""

    def test_encode_zero(self) -> None:
        assert encode_uint32_vlq(0) == b"\x00"

    def test_encode_small(self) -> None:
        encoded = encode_uint32_vlq(42)
        value, _ = decode_uint32_vlq(encoded)
        assert value == 42

    def test_encode_large(self) -> None:
        encoded = encode_uint32_vlq(0xFFFFFFFF)
        value, _ = decode_uint32_vlq(encoded)
        assert value == 0xFFFFFFFF

    def test_roundtrip_integrity_range(self) -> None:
        """Test encoding/decoding typical IntegrityId counter values."""
        for val in [0, 1, 127, 128, 255, 1000, 65535, 0x7FFFFFFF]:
            encoded = encode_uint32_vlq(val)
            decoded, consumed = decode_uint32_vlq(encoded)
            assert decoded == val
            assert consumed == len(encoded)


class TestLegitimationWireFormat:
    """Protocol fixtures matching the upstream S7CommPlus driver."""

    def test_build_get_var_substreamed_payload(self) -> None:
        payload = _build_get_var_substreamed_payload(0x01020304, LegitimationId.SERVER_SESSION_REQUEST)

        expected = struct.pack(">I", 0x01020304)
        expected += bytes([0x20, 0x04, 0x01])
        expected += encode_uint32_vlq(LegitimationId.SERVER_SESSION_REQUEST)
        expected += encode_object_qualifier(protocol_version=ProtocolVersion.V2)
        expected += struct.pack(">H", 1)
        expected += struct.pack(">I", 0)
        assert payload == expected

    def test_build_v1_session_key_challenge_payload(self) -> None:
        """Match the challenge request accepted by the S7-1200 in GH-710."""
        conn = S7CommPlusConnection("127.0.0.1")
        conn._sequence_number = 4
        conn._v1_session_key_family = 1

        payload = conn._build_get_var_substreamed(0x0000039B, LegitimationId.SERVER_SESSION_REQUEST)

        assert payload == bytes.fromhex("0000039b200401822f000004e88969001200000000896a001300896b00040000000401000000")

    def test_v1_session_key_challenge_splices_integrity_before_three_byte_fill(self) -> None:
        conn = S7CommPlusConnection("127.0.0.1")
        conn._session_id = 0x0000039B
        conn._session_challenge = bytes(range(20))
        conn._session_key = bytes(range(24))
        conn._v1_session_key_public_key = bytes(range(24))
        conn._v1_session_key_family = 1
        challenge = bytes(range(20))
        challenge_response = bytes([0x00, 0x00, 0x10, DataType.USINT, len(challenge)]) + challenge + bytes([0x00])
        conn.send_request = MagicMock(side_effect=[challenge_response, b"\x00"])

        with patch("s7commplus.v1_session_key.legitimation.solve_legitimate_challenge_real_plc", return_value=bytes(248)):
            conn._post_auth_legitimation()

        first_call = conn.send_request.call_args_list[0]
        assert first_call.args == (
            FunctionCode.GET_VAR_SUBSTREAMED,
            conn._build_get_var_substreamed(0x0000039B, LegitimationId.SERVER_SESSION_REQUEST),
        )
        assert first_call.kwargs == {"integrity_tail": 3}

    def test_parse_get_var_substreamed_usint_array(self) -> None:
        challenge = bytes(range(20))
        response = bytes([0x00, 0x00, 0x10, 0x02])
        response += encode_uint32_vlq(len(challenge)) + challenge
        response += encode_uint32_vlq(7)  # trailing IntegrityId

        assert _parse_get_var_substreamed_response(response) == challenge

    def test_parse_get_var_substreamed_blob(self) -> None:
        challenge = bytes(range(16))
        response = bytes([0x00, 0x00, 0x00, DataType.BLOB, 0x00])
        response += encode_uint32_vlq(len(challenge)) + challenge
        response += encode_uint32_vlq(3)

        assert _parse_get_var_substreamed_response(response) == challenge

    def test_parse_get_var_substreamed_error(self) -> None:
        with pytest.raises(S7ConnectionError, match="return_value=0x1234"):
            _parse_get_var_substreamed_response(encode_uint32_vlq(0x1234))

    def test_build_set_variable_payload(self) -> None:
        value = bytes([0x10, 0x02, 0x02, 0xAA, 0xBB])
        payload = _build_set_variable_payload(0x01020304, LegitimationId.SERVER_SESSION_RESPONSE, value)

        expected = struct.pack(">I", 0x01020304)
        expected += encode_uint32_vlq(1)
        expected += encode_uint32_vlq(LegitimationId.SERVER_SESSION_RESPONSE)
        expected += value
        expected += encode_object_qualifier()
        expected += bytes([0x00])
        expected += struct.pack(">I", 0)
        assert payload == expected

    def test_set_variable_response_rejects_nonzero_return(self) -> None:
        with pytest.raises(S7ConnectionError, match="return_value=0x8104"):
            _check_set_variable_response(encode_uint32_vlq(0x8104))

    def test_sync_challenge_uses_protocol_request_shape(self) -> None:
        challenge = bytes(range(20))
        response = bytes([0x00, 0x00, 0x10, 0x02, len(challenge)]) + challenge + bytes([0x00])
        conn = S7CommPlusConnection("127.0.0.1")
        conn._session_id = 0x01020304
        conn.send_request = MagicMock(return_value=response)

        assert conn._get_legitimation_challenge() == challenge
        conn.send_request.assert_called_once_with(
            FunctionCode.GET_VAR_SUBSTREAMED,
            _build_get_var_substreamed_payload(0x01020304, LegitimationId.SERVER_SESSION_REQUEST),
            integrity_tail=4,
        )

    @pytest.mark.asyncio
    async def test_async_challenge_uses_protocol_request_shape(self) -> None:
        challenge = bytes(range(20))
        response = bytes([0x00, 0x00, 0x10, 0x02, len(challenge)]) + challenge + bytes([0x00])
        client = S7CommPlusAsyncClient()
        client._session_id = 0x01020304
        client._send_request = AsyncMock(return_value=response)

        assert await client._get_legitimation_challenge() == challenge
        client._send_request.assert_awaited_once_with(
            FunctionCode.GET_VAR_SUBSTREAMED,
            _build_get_var_substreamed_payload(0x01020304, LegitimationId.SERVER_SESSION_REQUEST),
            integrity_tail=4,
        )

    @pytest.mark.conformance
    def test_challenge_request_frame(self) -> None:
        challenge = bytes.fromhex("7d8f8470d20590efc1d740416b4a073296bf463b")
        payload = bytes([0x00, 0x00, 0x10, DataType.USINT]) + encode_uint32_vlq(len(challenge)) + challenge + bytes([0x00])
        body = struct.pack(">BHHHHB", 0x32, 0, FunctionCode.GET_VAR_SUBSTREAMED, 0, 6, 0x34) + payload

        conn = S7CommPlusConnection("127.0.0.1")
        conn._connected = True
        conn._protocol_version = ProtocolVersion.V2
        conn._session_id = 0x70000CB7
        conn._sequence_number = 6
        conn._with_integrity_id = True
        conn._integrity_id_read = 3
        conn._send_s7_data = MagicMock()
        conn._recv_s7_data = MagicMock(
            return_value=encode_header(ProtocolVersion.V2, len(body)) + body + struct.pack(">BBH", 0x72, 0x02, 0)
        )

        assert conn._get_legitimation_challenge() == challenge
        conn._send_s7_data.assert_called_once_with(
            bytes.fromhex(
                "72020035"  # header, data length 0x35
                "310000058600000006"  # request, GetVarSubStreamed, seq 6
                "70000cb734"  # session id, transport flags
                "70000cb7"  # InObjectId
                "200401822f"  # address array header + id 303
                "000004e88969001200000000896a001300896b00040000"  # ObjectQualifier
                "0001"  # unknown
                "03"  # IntegrityId (read)
                "00000000"  # fill
                "72020000"  # trailer
            )
        )

    @pytest.mark.conformance
    def test_legitimation_request_frame(self) -> None:
        response = bytes.fromhex("f5cc5389f613b1f2283cf9229406e5b3b32c6e43")
        body = struct.pack(">BHHHHB", 0x32, 0, FunctionCode.SET_VARIABLE, 0, 7, 0x34) + encode_uint32_vlq(0)

        conn = S7CommPlusConnection("127.0.0.1")
        conn._connected = True
        conn._protocol_version = ProtocolVersion.V2
        conn._session_id = 0x70000CB7
        conn._sequence_number = 7
        conn._with_integrity_id = True
        conn._integrity_id_write = 1
        conn._send_s7_data = MagicMock()
        conn._recv_s7_data = MagicMock(
            return_value=encode_header(ProtocolVersion.V2, len(body)) + body + struct.pack(">BBH", 0x72, 0x02, 0)
        )

        conn._send_legitimation_legacy(response)

        conn._send_s7_data.assert_called_once_with(
            bytes.fromhex(
                "72020049"  # header, data length 0x49
                "31000004f200000007"  # request, SetVariable, seq 7
                "70000cb734"  # session id, transport flags
                "70000cb7"  # InObjectId
                "018230"  # always-1, address id 304
                "100214"  # USInt array of 20
            )
            + response
            + bytes.fromhex(
                "000004e88969001200000000896a001300896b00040000"  # ObjectQualifier
                "00"  # unknown
                "01"  # IntegrityId (write)
                "00000000"  # fill
                "72020000"  # trailer
            )
        )

    @pytest.mark.conformance
    def test_non_zero_return_value_is_accepted(self) -> None:
        """The PLC signals success with a non-zero status word. Response captured from an S7-1512."""
        _check_set_variable_response(bytes.fromhex("9381b0808099a68019"))

    @pytest.mark.conformance
    def test_refusal_is_invisible_in_the_return_value(self) -> None:
        """A refused password is indistinguishable from an accepted one here. Response captured from an S7-1512."""
        _check_set_variable_response(bytes.fromhex("9381b390809aca8016"))


class TestCreateSessionRequest:
    """The CreateObject request that opens an S7CommPlus session."""

    def test_sync_request_shape(self) -> None:
        conn = S7CommPlusConnection("127.0.0.1")
        conn._send_s7_data = MagicMock()
        # Frame header declaring a zero-length body: _create_session bails out on the
        # length check, by which point the request is already on the wire.
        conn._recv_s7_data = MagicMock(return_value=bytes.fromhex("72010000"))

        with pytest.raises(S7ConnectionError, match="CreateObject response too short"):
            conn._create_session()

        frame = conn._send_s7_data.call_args[0][0]
        request = struct.pack(
            ">BHHHHIB",
            Opcode.REQUEST,
            0x0000,
            FunctionCode.CREATE_OBJECT,
            0x0000,
            0,  # first sequence number on a fresh connection
            ObjectId.OBJECT_NULL_SERVER_SESSION,
            0x36,
        )
        request += struct.pack(">I", ObjectId.OBJECT_SERVER_SESSION_CONTAINER)
        expected = encode_header(ProtocolVersion.V1, len(frame) - 8) + request
        assert frame[: len(expected)] == expected
        assert frame[-4:] == struct.pack(">BBH", 0x72, ProtocolVersion.V1, 0x0000)

    @pytest.mark.asyncio
    async def test_async_request_shape(self) -> None:
        client = S7CommPlusAsyncClient()
        client._send_cotp_dt = AsyncMock()
        client._recv_cotp_dt = AsyncMock(return_value=bytes.fromhex("72010000"))

        with pytest.raises(S7ConnectionError, match="CreateObject response too short"):
            await client._create_session()

        client._send_cotp_dt.assert_awaited_once()
        assert client._send_cotp_dt.await_args is not None
        frame = client._send_cotp_dt.await_args[0][0]
        request = struct.pack(
            ">BHHHHIB",
            Opcode.REQUEST,
            0x0000,
            FunctionCode.CREATE_OBJECT,
            0x0000,
            0,
            ObjectId.OBJECT_NULL_SERVER_SESSION,
            0x36,
        )
        request += struct.pack(">I", ObjectId.OBJECT_SERVER_SESSION_CONTAINER)
        expected = encode_header(ProtocolVersion.V1, len(frame) - 8) + request
        assert frame[: len(expected)] == expected
        assert frame[-4:] == struct.pack(">BBH", 0x72, ProtocolVersion.V1, 0x0000)

    @pytest.mark.asyncio
    async def test_async_detects_session_key_attributes(self) -> None:
        server = S7CommPlusServer(
            public_key_fingerprint="01:BD426B091F08731A",
            session_challenge=bytes(range(20)),
        )
        application_response = server._handle_create_object(seq_num=0, request_data=b"")
        response = encode_header(ProtocolVersion.V1, len(application_response)) + application_response
        response += struct.pack(">BBH", 0x72, ProtocolVersion.V1, 0x0000)

        client = S7CommPlusAsyncClient()
        client._send_cotp_dt = AsyncMock()
        client._recv_cotp_dt = AsyncMock(return_value=response)

        await client._create_session()

        assert client._public_key_fingerprint == "01:BD426B091F08731A"
        assert client._session_challenge == bytes(range(20))
        assert client._server_session_version is not None


class TestInitSSLResponse:
    @pytest.mark.asyncio
    async def test_async_short_response_raises_connection_error(self) -> None:
        client = S7CommPlusAsyncClient()
        client._send_cotp_dt = AsyncMock()
        client._recv_cotp_dt = AsyncMock(return_value=bytes.fromhex("72010000"))

        with pytest.raises(S7ConnectionError, match="InitSSL response too short"):
            await client._init_ssl()

    @pytest.mark.asyncio
    async def test_async_ten_byte_response_is_accepted(self) -> None:
        client = S7CommPlusAsyncClient()
        client._send_cotp_dt = AsyncMock()
        response = bytes(10)
        client._recv_cotp_dt = AsyncMock(return_value=encode_header(ProtocolVersion.V1, len(response)) + response)

        await client._init_ssl()


class TestDeleteSessionRequest:
    """The DeleteObject request that closes an S7CommPlus session."""

    def test_sync_request_shape(self) -> None:
        conn = S7CommPlusConnection("127.0.0.1")
        conn._protocol_version = ProtocolVersion.V2
        conn._session_id = 0x70000001
        conn._send_s7_data = MagicMock()
        conn._recv_s7_data = MagicMock(side_effect=OSError("no reply"))

        conn._delete_session()

        request = struct.pack(
            ">BHHHHIB",
            Opcode.REQUEST,
            0x0000,
            FunctionCode.DELETE_OBJECT,
            0x0000,
            0,  # first sequence number on a fresh connection
            0x70000001,
            0x34,
        )
        request += struct.pack(">I", 0)
        expected = encode_header(ProtocolVersion.V2, len(request)) + request
        expected += struct.pack(">BBH", 0x72, ProtocolVersion.V2, 0x0000)
        conn._send_s7_data.assert_called_once_with(expected)

    @pytest.mark.asyncio
    async def test_async_request_shape(self) -> None:
        client = S7CommPlusAsyncClient()
        client._protocol_version = ProtocolVersion.V2
        client._session_id = 0x70000001
        client._send_cotp_dt = AsyncMock()
        client._recv_cotp_dt = AsyncMock(side_effect=OSError("no reply"))

        await client._delete_session()

        request = struct.pack(
            ">BHHHHIB",
            Opcode.REQUEST,
            0x0000,
            FunctionCode.DELETE_OBJECT,
            0x0000,
            0,
            0x70000001,
            0x34,
        )
        request += struct.pack(">I", 0)
        expected = encode_header(ProtocolVersion.V2, len(request)) + request
        expected += struct.pack(">BBH", 0x72, ProtocolVersion.V2, 0x0000)
        client._send_cotp_dt.assert_awaited_once_with(expected)


class TestProtectionLevel:
    """The effective protection level read that precedes legitimation."""

    # Captured from a password-protected S7-1512: UDInt(4), trailing IntegrityId 7.
    RESPONSE = bytes.fromhex("00000004040700000000")

    def test_parse_scalar_udint(self) -> None:
        assert _parse_protection_level_response(self.RESPONSE) == AccessLevel.NO_ACCESS

    def test_parse_rejects_nonzero_return(self) -> None:
        with pytest.raises(S7ConnectionError, match="return_value=4660"):
            _parse_protection_level_response(encode_uint32_vlq(0x1234))

    def test_parse_rejects_missing_pvalue(self) -> None:
        with pytest.raises(S7ConnectionError, match="missing PValue header"):
            _parse_protection_level_response(bytes([0x00]))

    def test_parse_rejects_truncated_pvalue_header(self) -> None:
        with pytest.raises(S7ConnectionError, match="missing PValue header"):
            _parse_protection_level_response(bytes([0x00, 0x00, 0x00]))

    def test_parse_rejects_non_udint_datatype(self) -> None:
        response = bytes([0x00, 0x00, 0x00, DataType.USINT, 0x04])
        with pytest.raises(S7ConnectionError, match="expected a scalar UDInt, got flags=0x00 datatype=0x02"):
            _parse_protection_level_response(response)

    def test_parse_rejects_udint_array(self) -> None:
        response = bytes([0x00, 0x00, 0x10, DataType.UDINT, 0x01, 0x04])
        with pytest.raises(S7ConnectionError, match="expected a scalar UDInt, got flags=0x10 datatype=0x04"):
            _parse_protection_level_response(response)

    def test_parse_rejects_truncated_value(self) -> None:
        response = bytes([0x00, 0x00, 0x00, DataType.UDINT, 0x84])
        with pytest.raises(S7ConnectionError, match="Malformed protection level response"):
            _parse_protection_level_response(response)

    def test_sync_read_uses_protocol_request_shape(self) -> None:
        conn = S7CommPlusConnection("127.0.0.1")
        conn._session_id = 0x01020304
        conn.send_request = MagicMock(return_value=self.RESPONSE)

        assert conn._get_effective_protection_level() == AccessLevel.NO_ACCESS
        conn.send_request.assert_called_once_with(
            FunctionCode.GET_VAR_SUBSTREAMED,
            _build_get_var_substreamed_payload(0x01020304, Ids.EFFECTIVE_PROTECTION_LEVEL),
            integrity_tail=4,
        )

    @pytest.mark.asyncio
    async def test_async_read_uses_protocol_request_shape(self) -> None:
        client = S7CommPlusAsyncClient()
        client._session_id = 0x01020304
        client._send_request = AsyncMock(return_value=self.RESPONSE)

        assert await client._get_effective_protection_level() == AccessLevel.NO_ACCESS
        client._send_request.assert_awaited_once_with(
            FunctionCode.GET_VAR_SUBSTREAMED,
            _build_get_var_substreamed_payload(0x01020304, Ids.EFFECTIVE_PROTECTION_LEVEL),
            integrity_tail=4,
        )


class TestSessionKeyTransportFlags:
    """After SessionKey auth, requests use V3 HMAC framing and transport flags 0x34."""

    def test_session_key_request_frame_structure(self) -> None:
        conn = S7CommPlusConnection("127.0.0.1")
        conn._connected = True
        conn._protocol_version = ProtocolVersion.V2
        conn._session_id = 0x70000001
        conn._session_key = bytes(32)
        conn._send_s7_data = MagicMock()
        conn._recv_s7_data = MagicMock(side_effect=OSError("no reply"))

        with pytest.raises(OSError, match="no reply"):
            conn.send_request(FunctionCode.GET_VARIABLE, bytes(4))

        frame = conn._send_s7_data.call_args[0][0]
        request = struct.pack(
            ">BHHHHIB",
            Opcode.REQUEST,
            0x0000,
            FunctionCode.GET_VARIABLE,
            0x0000,
            0,  # first sequence number on a fresh connection
            0x70000001,
            0x34,  # the session key forces 0x34 even for a function code outside FLAGS_34_FUNCTION_CODES
        )
        request += bytes(4)
        assert frame[:4] == encode_header(ProtocolVersion.V3, len(frame) - 8)
        assert frame[4] == 0x20  # hash-length marker before the 32-byte HMAC digest
        assert frame[37:-4] == request
        assert frame[-4:] == struct.pack(">BBH", 0x72, ProtocolVersion.V3, 0x0000)


class TestSessionKeySelection:
    def test_tls_v2_does_not_attempt_session_key_auth(self) -> None:
        conn = S7CommPlusConnection("127.0.0.1")
        conn._tls_active = True
        conn._protocol_version = ProtocolVersion.V2
        conn._public_key_fingerprint = "01:BD426B091F08731A"
        conn._session_challenge = bytes(range(20))

        assert conn._try_session_key_auth() is None
        assert conn._session_key is None


class TestLegacySessionKeyRefresh:
    @staticmethod
    def _authenticated_connection() -> S7CommPlusConnection:
        from s7commplus.v1_session_key.keys import KeyFamily

        conn = S7CommPlusConnection("127.0.0.1")
        conn._connected = True
        conn._session_ready = True
        conn._session_id = 0x70000FDC
        conn._session_key = b"o" * 24
        conn._v1_session_key_public_key = b"p" * 40
        conn._v1_session_key_family = KeyFamily.S7_1500
        return conn

    def test_renewal_installs_key_only_after_accepted_old_key_response(self) -> None:
        conn = self._authenticated_connection()
        challenge = bytes(range(20))
        challenge_response = bytes([0x00, 0x00, 0x10, DataType.USINT, len(challenge)]) + challenge
        old_key = conn._session_key
        new_key = b"n" * 24
        keys_during_exchange: list[bytes | None] = []

        def exchange(*_args: object) -> bytes:
            keys_during_exchange.append(conn._session_key)
            return challenge_response if len(keys_during_exchange) == 1 else b"\x00"

        conn._send_request = MagicMock(side_effect=exchange)
        with patch("s7commplus.v1_session_key.handshake.authenticate_real_plc", return_value=(b"b" * 180, new_key)):
            conn._renew_session_key_locked()

        assert keys_during_exchange == [old_key, old_key]
        assert conn._session_key == new_key
        renewal_call = conn._send_request.call_args_list[1]
        assert renewal_call.args[0] == FunctionCode.SET_VARIABLE
        assert encode_uint32_vlq(LegitimationId.SESSION_SETUP_LEGITIMATION) in renewal_call.args[1]

    def test_rejected_renewal_never_installs_generated_key(self) -> None:
        conn = self._authenticated_connection()
        challenge = bytes(range(20))
        challenge_response = bytes([0x00, 0x00, 0x10, DataType.USINT, len(challenge)]) + challenge
        old_key = conn._session_key
        conn._send_request = MagicMock(side_effect=[challenge_response, encode_uint32_vlq(0x8104)])

        with (
            patch("s7commplus.v1_session_key.handshake.authenticate_real_plc", return_value=(b"b" * 180, b"n" * 24)),
            pytest.raises(S7ConnectionError, match="return_value=0x8104"),
        ):
            conn._renew_session_key_locked()

        assert conn._session_key == old_key

    def test_short_interval_renews_while_requests_remain_usable(self) -> None:
        conn = self._authenticated_connection()
        conn._session_key_refresh_interval = 0.01
        renewed = threading.Event()
        conn._renew_session_key_locked = MagicMock(side_effect=renewed.set)
        conn._schedule_session_key_refresh()

        assert renewed.wait(1)
        conn._send_request = MagicMock(return_value=b"read result")
        assert conn.send_request(FunctionCode.GET_VARIABLE) == b"read result"

        next_timer = conn._session_key_refresh_timer
        conn.disconnect()
        if next_timer is not None:
            next_timer.join(1)
            assert not next_timer.is_alive()
        assert conn._session_key_refresh_timer is None

    def test_refresh_failure_is_terminal_and_surfaces_on_next_request(self) -> None:
        conn = self._authenticated_connection()
        conn._iso_conn.disconnect = MagicMock()
        conn._renew_session_key_locked = MagicMock(side_effect=S7ConnectionError("PLC rejected key"))

        conn._session_key_refresh_callback(conn._session_key_refresh_generation)

        assert not conn.connected
        assert conn._session_key is None
        with pytest.raises(S7ConnectionError, match="Legacy SessionKey renewal failed: PLC rejected key"):
            conn.send_request(FunctionCode.GET_VARIABLE)

    def test_refresh_interval_must_be_positive(self) -> None:
        conn = S7CommPlusConnection("127.0.0.1")
        with pytest.raises(ValueError, match="must be positive"):
            conn.connect(legacy_session_key_refresh_interval=0)


class TestSessionKeyDescriptors:
    def test_security_key_descriptor_uses_pending_generated_key(self) -> None:
        from s7commplus.v1_session_key.keys import KeyFamily, get_public_key
        from s7commplus.v1_session_key.utils import derive_key_id
        from s7commplus.vlq import encode_uint64_vlq

        conn = S7CommPlusConnection("127.0.0.1")
        conn._v1_session_key_public_key = get_public_key("01:BD426B091F08731A")
        conn._v1_session_key_family = KeyFamily.S7_1200
        generated_key = bytes(range(24))

        assert conn._session_key is None
        encoded = conn._encode_security_key_struct(bytes(180), generated_key)
        symmetric_id = int.from_bytes(derive_key_id(generated_key), "little")
        symmetric_descriptor = (
            encode_uint32_vlq(1804)
            + bytes([0x00, DataType.STRUCT])
            + struct.pack(">I", Ids.SECURITY_KEY_ID)
            + encode_uint32_vlq(1826)
            + bytes([0x00, DataType.ULINT])
            + encode_uint64_vlq(symmetric_id)
        )
        assert symmetric_descriptor in encoded

    def test_security_key_descriptor_rejects_missing_key_material(self) -> None:
        conn = S7CommPlusConnection("127.0.0.1")
        with pytest.raises(ValueError, match="public key material"):
            conn._encode_security_key_struct(bytes(180), bytes(24))

        conn._v1_session_key_public_key = bytes(40)
        with pytest.raises(ValueError, match="generated session key material"):
            conn._encode_security_key_struct(bytes(180), b"")


class TestAtomicSessionSetup:
    @pytest.mark.parametrize("negotiated_version", [ProtocolVersion.V1, ProtocolVersion.V2])
    def test_setup_request_preserves_existing_wire_layout(self, negotiated_version: ProtocolVersion) -> None:
        conn = S7CommPlusConnection("127.0.0.1")
        conn._protocol_version = negotiated_version
        conn._session_id = 7
        conn._server_session_version = bytes.fromhex("000401")
        conn._try_session_key_auth = MagicMock(return_value=None)
        conn._send_s7_data = MagicMock()
        response = struct.pack(">BHHHHB", Opcode.RESPONSE, 0, FunctionCode.SET_MULTI_VARIABLES, 0, 0, 0x34)
        conn._recv_s7_data = MagicMock(
            return_value=encode_header(ProtocolVersion.V2, len(response) + 1) + response + b"\x00" + bytes.fromhex("72020000")
        )

        assert conn._setup_session()
        qualifier = (
            "000004e88969001200000000896a001300896b000400000000"
            if negotiated_version == ProtocolVersion.V1
            else "000004e88969001200000000896a001300896b00040000"
        )
        request = bytes.fromhex("310000054200000000000000073400000007010182320100040100" + qualifier + "00000000")
        conn._send_s7_data.assert_called_once_with(
            encode_header(ProtocolVersion.V2, len(request)) + request + bytes.fromhex("72020000")
        )

    def test_fatal_system_event_during_setup_is_not_success(self) -> None:
        conn = S7CommPlusConnection("127.0.0.1")
        conn._protocol_version = ProtocolVersion.V1
        conn._session_id = 7
        conn._server_session_version = bytes.fromhex("000401")
        conn._try_session_key_auth = MagicMock(return_value=None)
        conn._send_s7_data = MagicMock()
        fatal = bytes(16) + bytes.fromhex("0000001700009d6c")
        fatal += struct.pack(">I", 40305) + bytes.fromhex("00000009") + (-1).to_bytes(8, "big", signed=True)
        conn._recv_s7_data = MagicMock(return_value=encode_header(ProtocolVersion.SYSTEM_EVENT, len(fatal)) + fatal)

        with pytest.raises(S7ProtocolError, match="Fatal S7CommPlus SystemEvent"):
            conn._setup_session()
        assert not conn._session_setup_ok

    def test_unrelated_response_cannot_complete_setup(self) -> None:
        conn = S7CommPlusConnection("127.0.0.1")
        conn._protocol_version = ProtocolVersion.V1
        conn._session_id = 7
        conn._server_session_version = bytes.fromhex("000401")
        conn._try_session_key_auth = MagicMock(return_value=None)
        conn._send_s7_data = MagicMock()
        response = struct.pack(">BHHHHB", Opcode.RESPONSE, 0, FunctionCode.GET_MULTI_VARIABLES, 0, 0, 0x34) + b"\x00"
        conn._recv_s7_data = MagicMock(return_value=encode_header(ProtocolVersion.V2, len(response)) + response)

        with pytest.raises(S7ProtocolError, match="Response function mismatch"):
            conn._setup_session()

    def test_rejected_setup_does_not_activate_generated_key(self) -> None:
        from s7commplus.v1_session_key.keys import KeyFamily, get_public_key

        conn = S7CommPlusConnection("127.0.0.1")
        conn._protocol_version = ProtocolVersion.V1
        conn._session_id = 7
        conn._server_session_version = bytes([0x00, DataType.UDINT, 0x01])
        conn._v1_session_key_public_key = get_public_key("01:BD426B091F08731A")
        conn._v1_session_key_family = KeyFamily.S7_1200
        generated_key = bytes(range(24))
        conn._try_session_key_auth = MagicMock(return_value=(bytes(180), generated_key))
        conn._send_s7_data = MagicMock()
        response = struct.pack(">BHHHHB", Opcode.RESPONSE, 0, FunctionCode.SET_MULTI_VARIABLES, 0, 0, 0)
        response += bytes([1])
        conn._recv_s7_data = MagicMock(
            return_value=encode_header(ProtocolVersion.V2, len(response))
            + response
            + struct.pack(">BBH", 0x72, ProtocolVersion.V2, 0)
        )

        assert not conn._setup_session()
        assert conn._session_key is None
        assert not conn._with_integrity_id

    def test_malformed_setup_response_does_not_activate_generated_key(self) -> None:
        from s7commplus.v1_session_key.keys import KeyFamily, get_public_key

        conn = S7CommPlusConnection("127.0.0.1")
        conn._protocol_version = ProtocolVersion.V1
        conn._session_id = 7
        conn._server_session_version = bytes([0x00, DataType.UDINT, 0x01])
        conn._v1_session_key_public_key = get_public_key("01:BD426B091F08731A")
        conn._v1_session_key_family = KeyFamily.S7_1200
        generated_key = bytes(range(24))
        conn._try_session_key_auth = MagicMock(return_value=(bytes(180), generated_key))
        conn._send_s7_data = MagicMock()
        conn._recv_s7_data = MagicMock(return_value=encode_header(ProtocolVersion.V2, 0))

        with pytest.raises(S7ConnectionError, match="response too short"):
            conn._setup_session()
        assert conn._session_key is None
        assert not conn._with_integrity_id

    def test_sync_rejected_setup_clears_pending_authentication_state(self) -> None:
        conn = S7CommPlusConnection("127.0.0.1")
        conn._iso_conn.connect = MagicMock()
        conn._iso_conn.disconnect = MagicMock()
        conn._init_ssl = MagicMock()

        def create_session() -> None:
            conn._protocol_version = ProtocolVersion.V1
            conn._session_id = 7
            conn._server_session_version = bytes([0x00, DataType.UDINT, 0x01])

        def reject_setup() -> bool:
            conn._session_key = bytes(24)
            conn._with_integrity_id = True
            return False

        conn._create_session = MagicMock(side_effect=create_session)
        conn._setup_session = MagicMock(side_effect=reject_setup)

        with pytest.raises(S7ConnectionError, match="session setup was rejected"):
            conn.connect()

        assert not conn.connected
        assert not conn.session_setup_ok
        assert conn._session_key is None
        assert not conn._with_integrity_id
        assert not conn._session_ready

    def test_sync_setup_exception_cleans_intermediate_state(self) -> None:
        conn = S7CommPlusConnection("127.0.0.1")
        conn._iso_conn.connect = MagicMock()
        conn._iso_conn.disconnect = MagicMock()
        conn._init_ssl = MagicMock()

        def create_session() -> None:
            conn._protocol_version = ProtocolVersion.V1
            conn._session_id = 7
            conn._server_session_version = bytes([0x00, DataType.UDINT, 0x01])

        conn._create_session = MagicMock(side_effect=create_session)
        conn._setup_session = MagicMock(side_effect=OSError("socket closed during setup"))

        with pytest.raises(OSError, match="socket closed during setup"):
            conn.connect()
        assert not conn.connected
        assert conn.session_id == 0
        assert not conn._session_ready

    @pytest.mark.asyncio
    async def test_async_rejected_setup_never_becomes_connected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = S7CommPlusAsyncClient()
        reader = MagicMock()
        writer = MagicMock()
        writer.wait_closed = AsyncMock()
        monkeypatch.setattr("s7commplus.async_client.asyncio.open_connection", AsyncMock(return_value=(reader, writer)))
        client._cotp_connect = AsyncMock()
        client._init_ssl = AsyncMock()

        async def create_session() -> None:
            client._protocol_version = ProtocolVersion.V1
            client._session_id = 7
            client._server_session_version = bytes([0x00, DataType.UDINT, 0x01])

        client._create_session = AsyncMock(side_effect=create_session)
        client._setup_session = AsyncMock(return_value=False)

        with pytest.raises(S7ConnectionError, match="session setup was rejected"):
            await client.connect("127.0.0.1")

        assert not client.connected
        assert not client.session_setup_ok
        assert not client._session_ready
        assert not client._transport_connected
        writer.close.assert_called_once()


class TestProtocolVersionV2:
    """Test V2 protocol version constant."""

    def test_v2_value(self) -> None:
        assert int(ProtocolVersion.V2) == 0x02

    def test_v2_greater_than_v1(self) -> None:
        assert ProtocolVersion.V2 > ProtocolVersion.V1

    def test_v2_less_than_v3(self) -> None:
        assert ProtocolVersion.V2 < ProtocolVersion.V3


try:
    import cryptography  # noqa: F401

    _has_cryptography = True
except ImportError:
    _has_cryptography = False


@pytest.mark.skipif(not _has_cryptography, reason="requires cryptography package")
class TestBuildNewResponse:
    """Test AES-256-CBC legitimation response building."""

    def test_new_response_returns_bytes(self) -> None:
        from s7commplus.legitimation import build_new_response

        result = build_new_response(
            password="test",
            challenge=b"\x00" * 16,
            oms_secret=b"\x00" * 32,
        )
        assert isinstance(result, bytes)

    def test_new_response_is_aes_block_aligned(self) -> None:
        from s7commplus.legitimation import build_new_response

        result = build_new_response(
            password="test",
            challenge=b"\x00" * 16,
            oms_secret=b"\x00" * 32,
        )
        # AES-CBC output is always a multiple of 16 bytes
        assert len(result) % 16 == 0

    def test_new_response_different_passwords_differ(self) -> None:
        from s7commplus.legitimation import build_new_response

        challenge = b"\xab" * 16
        oms = b"\xcd" * 32
        r1 = build_new_response("password1", challenge, oms)
        r2 = build_new_response("password2", challenge, oms)
        assert r1 != r2

    def test_new_response_different_secrets_differ(self) -> None:
        from s7commplus.legitimation import build_new_response

        challenge = b"\xab" * 16
        r1 = build_new_response("test", challenge, b"\x00" * 32)
        r2 = build_new_response("test", challenge, b"\x01" * 32)
        assert r1 != r2

    def test_new_response_with_username(self) -> None:
        from s7commplus.legitimation import build_new_response

        result = build_new_response(
            password="test",
            challenge=b"\x00" * 16,
            oms_secret=b"\x00" * 32,
            username="admin",
        )
        assert isinstance(result, bytes)
        assert len(result) % 16 == 0

    def test_new_response_decryptable(self) -> None:
        """Verify the response can be decrypted back to the original payload."""
        from cryptography.hazmat.primitives import padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        from s7commplus.legitimation import (
            _build_legitimation_payload,
            build_new_response,
            derive_legitimation_key,
        )

        challenge = b"\x12\x34\x56\x78" * 4  # 16-byte IV
        oms_secret = b"\xaa\xbb\xcc\xdd" * 8  # 32 bytes

        encrypted = build_new_response("mypassword", challenge, oms_secret)

        # Decrypt
        key = derive_legitimation_key(oms_secret)
        iv = challenge[:16]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded = decryptor.update(encrypted) + decryptor.finalize()

        # Remove PKCS7 padding
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded) + unpadder.finalize()

        # Should match the payload
        expected = _build_legitimation_payload("mypassword")
        assert plaintext == expected


class TestAuthenticate:
    """Test connection.authenticate() preconditions."""

    def test_authenticate_requires_connection(self) -> None:
        import pytest

        from s7commplus.error import S7ConnectionError

        conn = S7CommPlusConnection("127.0.0.1")
        with pytest.raises(S7ConnectionError, match="Not connected"):
            conn.authenticate("password")

    def test_authenticate_requires_tls(self) -> None:
        import pytest

        from s7commplus.error import S7ConnectionError

        conn = S7CommPlusConnection("127.0.0.1")
        conn._connected = True
        conn._tls_active = False
        with pytest.raises(S7ConnectionError, match="requires TLS"):
            conn.authenticate("password")


class TestCreateObjectStatusLogging:
    """A CreateObject status alone does not identify a TLS requirement."""

    def test_plain_connection_does_not_recommend_tls(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING, logger="s7commplus.connection"):
            _log_create_object_return_value(0x4000800000000011, tls_active=False)

        assert "continuing to parse the returned session data" in caplog.text
        assert "TLS" not in caplog.text

    def test_success_is_silent(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.DEBUG, logger="s7commplus.connection"):
            _log_create_object_return_value(0, tls_active=False)

        assert caplog.text == ""
