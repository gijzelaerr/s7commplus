"""Unit tests for S7CommPlus client payload builders, connection parsing, and error paths."""

import asyncio
import hashlib
import hmac
import struct
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest

from s7commplus.client import (
    S7CommPlusClient,
    _build_read_payload,
    _parse_read_response,
    _build_write_payload,
    _parse_write_response,
    _build_explore_request,
    _parse_cpu_state,
    _parse_explore_datablocks,
    _build_area_read_payload,
    _build_area_write_payload,
    _build_symbolic_read_payload,
    _build_symbolic_write_payload,
    _build_substreamed_write_payload,
)
from s7commplus.connection import S7CommPlusConnection, _strip_paom_string_in_session_version, _verify_v3_hmac
from s7commplus.codec import encode_header, encode_object_qualifier, encode_pvalue_blob
from s7commplus.codec import _pvalue_element_size as _element_size
from s7commplus.codec import skip_typed_value, parse_server_session_version
from s7commplus.protocol import (
    DataType,
    ElementID,
    FunctionCode,
    Ids,
    ObjectId,
    Opcode,
    ProtocolVersion,
    ServiceResult,
    block_language_name,
    service_result_code,
)
from s7commplus.vlq import (
    encode_uint32_vlq,
    encode_uint64_vlq,
    encode_int32_vlq,
    decode_uint32_vlq,
)


# -- Payload builder / parser tests --


class TestProtocolConstants:
    """Pin wire values of the protocol enums.

    These are on-the-wire facts; a change here is a protocol-visible change
    and must be justified in CHANGES.md.
    """

    def test_function_code_values(self) -> None:
        expected = {
            "ERROR": 0x04B1,
            "EXPLORE": 0x04BB,
            "CREATE_OBJECT": 0x04CA,
            "DELETE_OBJECT": 0x04D4,
            "SET_VARIABLE": 0x04F2,
            "GET_VARIABLE": 0x04FC,
            "ADD_LINK": 0x0506,
            "REMOVE_LINK": 0x051A,
            "GET_LINK": 0x0524,
            "NOTIFY": 0x052E,
            "SET_MULTI_VARIABLES": 0x0542,
            "GET_MULTI_VARIABLES": 0x054C,
            "BEGIN_SEQUENCE": 0x0556,
            "END_SEQUENCE": 0x0560,
            "INVOKE": 0x056B,
            "SET_VAR_SUBSTREAMED": 0x057C,
            "GET_VAR_SUBSTREAMED": 0x0586,
            "GET_VARIABLES_ADDRESS": 0x0590,
            "ABORT": 0x059A,
            "ERROR2": 0x05A9,
            "INIT_SSL": 0x05B3,
        }
        for name, value in expected.items():
            assert FunctionCode[name] == value, name

    def test_function_codes_are_unique(self) -> None:
        values = [int(code) for code in FunctionCode]
        assert len(values) == len(set(values))

    def test_element_id_values(self) -> None:
        expected = {
            "START_OF_OBJECT": 0xA1,
            "TERMINATING_OBJECT": 0xA2,
            "ATTRIBUTE": 0xA3,
            "RELATION": 0xA4,
            "ERROR": 0xA5,
            "INCLUDE_OBJECT": 0xA6,
            "START_OF_TAG_DESCRIPTION": 0xA7,
            "TERMINATING_TAG_DESCRIPTION": 0xA8,
            "LINK_NAMESPACE": 0xA9,
            "TYPE_MICRO_INFO": 0xAB,
            "TYPE_MICRO_NAMES": 0xAC,
        }
        for name, value in expected.items():
            assert ElementID[name] == value, name

    def test_element_id_aliases_point_at_the_type_list_tags(self) -> None:
        # The parser names 0xAB/0xAC VARTYPE/VARNAME list; the wire tags are
        # the type-micro list tags, and both spellings must stay in sync.
        assert ElementID.VARTYPE_LIST == ElementID.TYPE_MICRO_INFO == 0xAB
        assert ElementID.VARNAME_LIST == ElementID.TYPE_MICRO_NAMES == 0xAC

    def test_session_version_struct_elements(self) -> None:
        assert Ids.SESSION_VERSION_STRUCT == 314
        assert Ids.SESSION_VERSION_SYSTEM_OMS == 315
        assert Ids.SESSION_VERSION_PROJECT_OMS == 316
        assert Ids.SESSION_VERSION_SYSTEM_PAOM == 317
        assert Ids.SESSION_VERSION_PROJECT_PAOM == 318
        assert Ids.SESSION_VERSION_SYSTEM_PAOM_STRING == 319
        assert Ids.SESSION_VERSION_PROJECT_PAOM_STRING == 320

    def test_native_object_roots(self) -> None:
        assert Ids.NATIVE_THE_AS_ROOT_RID == 1
        assert Ids.NATIVE_THE_HW_CONFIGURATION_RID == 2
        assert Ids.NATIVE_THE_PLC_PROGRAM_RID == 3
        assert Ids.NATIVE_THE_CPU_RID == 48
        assert Ids.NATIVE_THE_CPU_EXEC_UNIT_RID == 52
        assert Ids.NATIVE_THE_WEB_SERVER_RID == 53
        assert Ids.NATIVE_THE_CPU_DISPLAY_RID == 54

    def test_server_session_attribute_ids(self) -> None:
        assert Ids.SERVER_SESSION_CLIENT_ID == 289
        assert Ids.SERVER_SESSION_TIMEOUT == 302
        assert Ids.SERVER_SESSION_ROLES == 305
        assert Ids.CLIENT_SESSION_PASSWORD == 309
        assert Ids.CLIENT_SESSION_LEGITIMATED == 310


class TestBuildReadPayload:
    def test_single_item(self) -> None:
        payload = _build_read_payload([(1, 0, 4)])
        assert isinstance(payload, bytes)
        assert len(payload) > 0

    def test_multi_item(self) -> None:
        payload = _build_read_payload([(1, 0, 4), (2, 10, 8)])
        assert isinstance(payload, bytes)
        # Multi-item payload should be larger than single
        single = _build_read_payload([(1, 0, 4)])
        assert len(payload) > len(single)


def _decode_first_item_lids(payload: bytes) -> tuple[int, int, list[int]]:
    """Decode the first ItemAddress from a read or write payload."""
    offset = 4
    _item_count, consumed = decode_uint32_vlq(payload, offset)
    offset += consumed
    _field_count, consumed = decode_uint32_vlq(payload, offset)
    offset += consumed
    _symbol_crc, consumed = decode_uint32_vlq(payload, offset)
    offset += consumed
    access_area, consumed = decode_uint32_vlq(payload, offset)
    offset += consumed
    num_lids, consumed = decode_uint32_vlq(payload, offset)
    offset += consumed
    access_sub_area, consumed = decode_uint32_vlq(payload, offset)
    offset += consumed
    lids: list[int] = []
    for _ in range(num_lids - 1):
        lid, consumed = decode_uint32_vlq(payload, offset)
        offset += consumed
        lids.append(lid)
    return access_area, access_sub_area, lids


@pytest.mark.parametrize(
    "payload",
    [
        _build_read_payload([(7, 12, 4)]),
        _build_write_payload([(7, 12, b"data", DataType.BLOB)]),
    ],
)
def test_db_byte_offset_uses_classic_blob_marker_and_zero_based_offset(payload: bytes) -> None:
    area, sub_area, lids = _decode_first_item_lids(payload)
    assert area == Ids.DB_ACCESS_AREA_BASE + 7
    assert sub_area == Ids.DB_VALUE_ACTUAL
    assert lids == [Ids.LID_OMS_STB_CLASSIC_BLOB, 12, 4]


@pytest.mark.parametrize(
    "payload",
    [
        _build_area_read_payload(Ids.NATIVE_THE_M_AREA_RID, 12, 4),
        _build_area_write_payload(Ids.NATIVE_THE_M_AREA_RID, 12, b"data"),
    ],
)
def test_area_byte_offset_uses_classic_blob_marker_and_zero_based_offset(payload: bytes) -> None:
    area, sub_area, lids = _decode_first_item_lids(payload)
    assert area == Ids.NATIVE_THE_M_AREA_RID
    assert sub_area == Ids.CONTROLLER_AREA_VALUE_ACTUAL
    assert lids == [Ids.LID_OMS_STB_CLASSIC_BLOB, 12, 4]


class TestParseCpuState:
    # Exact attribute sequence isolated by the hardware RUN/STOP capture in #878.
    RUN_ATTRIBUTES = bytes.fromhex("a3bf0000030001a3bf0100030007a3be5400030000")
    STOP_ATTRIBUTES = bytes.fromhex("a3bf0000030000a3bf0100030000a3be540003ffff")

    def test_run_capture(self) -> None:
        assert _parse_cpu_state(b"\x00\x00" + self.RUN_ATTRIBUTES + b"\xa2") == "RUN"

    def test_stop_capture(self) -> None:
        assert _parse_cpu_state(b"\x00\x00" + self.STOP_ATTRIBUTES + b"\xa2") == "STOP"

    @pytest.mark.parametrize(
        "response",
        [
            b"",
            bytes.fromhex("a3bf0000030000"),  # executing attribute only
            bytes.fromhex("a3bf0100030000"),  # operating-mode attribute only
            bytes.fromhex("a3bf0000030001a3bf0100030000"),  # attributes disagree
            bytes.fromhex("a3bf0000030000a3bf0100030002"),  # unknown mode
            bytes.fromhex("a3bf00000200a3bf0100030000"),  # wrong executing datatype
        ],
    )
    def test_unknown_without_two_consistent_typed_attributes(self, response: bytes) -> None:
        assert _parse_cpu_state(response) == "UNKNOWN"

    def test_conflicting_duplicate_is_unknown(self) -> None:
        response = self.RUN_ATTRIBUTES + bytes.fromhex("a3bf0000030000")
        assert _parse_cpu_state(response) == "UNKNOWN"


class TestParseReadResponse:
    @staticmethod
    def _build_response(
        return_value: int = 0,
        items: list[bytes] | None = None,
        errors: list[tuple[int, int]] | None = None,
    ) -> bytes:
        """Build a synthetic GetMultiVariables response."""
        result = bytearray()
        # ReturnValue (UInt64 VLQ)
        result += encode_uint64_vlq(return_value)

        # Value list
        if items:
            for i, item_data in enumerate(items, 1):
                result += encode_uint32_vlq(i)  # ItemNumber
                result += encode_pvalue_blob(item_data)  # PValue
        result += encode_uint32_vlq(0)  # Terminator

        # Error list
        if errors:
            for err_item_nr, err_value in errors:
                result += encode_uint32_vlq(err_item_nr)
                result += encode_uint64_vlq(err_value)
        result += encode_uint32_vlq(0)  # Terminator

        return bytes(result)

    def test_single_item_success(self) -> None:
        data = bytes([1, 2, 3, 4])
        response = self._build_response(items=[data])
        results = _parse_read_response(response)
        assert len(results) == 1
        assert results[0] == data

    def test_multi_item_success(self) -> None:
        data1 = bytes([0x0A, 0x0B])
        data2 = bytes([0x0C, 0x0D, 0x0E])
        response = self._build_response(items=[data1, data2])
        results = _parse_read_response(response)
        assert len(results) == 2
        assert results[0] == data1
        assert results[1] == data2

    def test_error_return_value(self) -> None:
        response = self._build_response(return_value=0x05A9)
        results = _parse_read_response(response)
        assert results == []

    def test_empty_response(self) -> None:
        response = self._build_response()
        results = _parse_read_response(response)
        assert results == []

    def test_with_error_items(self) -> None:
        data1 = bytes([1, 2, 3, 4])
        response = self._build_response(items=[data1], errors=[(2, 0xDEAD)])
        results = _parse_read_response(response)
        assert len(results) == 2
        assert results[0] == data1
        assert results[1] is None  # Error item

    def test_single_byte_scalar_bool_true(self) -> None:
        response = b"\x01\x00\x00\x04\x00\x00\x00\x00"
        results = _parse_read_response(response)
        assert results == [b"\x01"]

    def test_single_byte_scalar_bool_false(self) -> None:
        response = b"\x00\x00\x00\x04\x00\x00\x00\x00"
        results = _parse_read_response(response)
        assert results == [b"\x00"]

    def test_single_byte_scalar_usint(self) -> None:
        response = b"\x2a\x00\x00\x04\x00\x00\x00\x00"
        results = _parse_read_response(response)
        assert results == [b"\x2a"]


class TestParseWriteResponse:
    @staticmethod
    def _build_response(return_value: int = 0, errors: list[tuple[int, int]] | None = None) -> bytes:
        result = bytearray()
        result += encode_uint64_vlq(return_value)
        if errors:
            for err_item_nr, err_value in errors:
                result += encode_uint32_vlq(err_item_nr)
                result += encode_uint64_vlq(err_value)
        result += encode_uint32_vlq(0)  # Terminator
        return bytes(result)

    def test_success(self) -> None:
        response = self._build_response(return_value=0)
        _parse_write_response(response)  # Should not raise

    def test_error_return_value(self) -> None:
        response = self._build_response(return_value=0x05A9)
        with pytest.raises(RuntimeError, match="Write failed"):
            _parse_write_response(response)

    def test_error_items(self) -> None:
        response = self._build_response(return_value=0, errors=[(1, 0xDEAD)])
        with pytest.raises(RuntimeError, match="Write failed"):
            _parse_write_response(response)


class TestBuildWritePayload:
    def test_single_item(self) -> None:
        payload = _build_write_payload([(1, 0, bytes([1, 2, 3, 4]), DataType.BLOB)])
        assert isinstance(payload, bytes)
        assert len(payload) > 0

    def test_data_appears_in_payload(self) -> None:
        data = bytes([0xDE, 0xAD, 0xBE, 0xEF])
        payload = _build_write_payload([(1, 0, data, DataType.BLOB)])
        # The raw data should appear in the payload (inside the BLOB PValue)
        assert data in payload


# -- Client/server payload agreement --


class TestPayloadAgreement:
    """Verify client payloads can be parsed by the server's request parser."""

    def test_read_payload_roundtrip(self) -> None:
        """Build a read payload, then manually verify it has expected structure."""
        payload = _build_read_payload([(1, 0, 4)])
        offset = 0

        # LinkId (4 bytes fixed)
        link_id = struct.unpack_from(">I", payload, offset)[0]
        offset += 4
        assert link_id == 0

        # Item count (VLQ)
        item_count, consumed = decode_uint32_vlq(payload, offset)
        offset += consumed
        assert item_count == 1

        # Total field count (VLQ)
        total_fields, consumed = decode_uint32_vlq(payload, offset)
        offset += consumed
        assert total_fields == 7  # 4 base + ClassicBlob marker, offset, and size

    def test_write_read_consistency(self) -> None:
        """Build write and read payloads for same address, verify both compile."""
        read_payload = _build_read_payload([(1, 0, 4)])
        write_payload = _build_write_payload([(1, 0, bytes([1, 2, 3, 4]), DataType.BLOB)])
        assert isinstance(read_payload, bytes)
        assert isinstance(write_payload, bytes)


class TestIntegrityPlaceholder:
    """Verify payload builders leave IntegrityId insertion to the connection."""

    @staticmethod
    def _has_only_trailing_fill(payload: bytes) -> bool:
        oq = encode_object_qualifier()
        idx = bytes(payload).find(oq)
        assert idx >= 0, "ObjectQualifier not found in payload"
        return payload[idx + len(oq) :] == bytes(4)

    def test_read_payload_has_no_static_integrity_id(self) -> None:
        payload = _build_read_payload([(1, 0, 4)])
        assert self._has_only_trailing_fill(payload)

    def test_write_payload_has_no_static_integrity_id(self) -> None:
        payload = _build_write_payload([(1, 0, bytes([1, 2, 3, 4]), DataType.BLOB)])
        assert self._has_only_trailing_fill(payload)

    def test_area_read_payload_has_no_static_integrity_id(self) -> None:
        payload = _build_area_read_payload(82, 0, 4)
        assert self._has_only_trailing_fill(payload)

    def test_area_write_payload_has_no_static_integrity_id(self) -> None:
        payload = _build_area_write_payload(82, 0, b"\x00\x00\x00\x00")
        assert self._has_only_trailing_fill(payload)

    def test_symbolic_read_payload_has_no_static_integrity_id(self) -> None:
        payload = _build_symbolic_read_payload(0x8A0E0001, [1, 4])
        assert self._has_only_trailing_fill(payload)

    def test_symbolic_write_payload_has_no_static_integrity_id(self) -> None:
        payload = _build_symbolic_write_payload(0x8A0E0001, [1, 4], b"\x01")
        assert self._has_only_trailing_fill(payload)

    def test_write_payload_validates_type_but_encodes_classic_blob(self) -> None:
        data = struct.pack(">f", 2.0)
        payload = _build_write_payload([(1, 0, data, DataType.REAL)])
        assert encode_pvalue_blob(data) in payload

    @pytest.mark.parametrize(("with_integrity", "integrity_id"), [(False, 0), (True, 7)])
    def test_connection_conditionally_inserts_integrity_id(self, with_integrity: bool, integrity_id: int) -> None:
        payload = _build_read_payload([(1, 0, 4)])
        response = struct.pack(">BHHHHB", Opcode.RESPONSE, 0, FunctionCode.GET_MULTI_VARIABLES, 0, 0, 0x34)
        connection = S7CommPlusConnection("127.0.0.1")
        connection._connected = True
        connection._protocol_version = ProtocolVersion.V2
        connection._with_integrity_id = with_integrity
        connection._integrity_id_read = integrity_id
        connection._send_s7_data = MagicMock()
        connection._recv_s7_data = MagicMock(
            return_value=encode_header(ProtocolVersion.V2, len(response))
            + response
            + struct.pack(">BBH", 0x72, ProtocolVersion.V2, 0),
        )

        connection.send_request(FunctionCode.GET_MULTI_VARIABLES, payload)

        frame = connection._send_s7_data.call_args.args[0]
        sent_payload = frame[4 + 14 : -4]
        expected = payload[:-4] + (encode_uint32_vlq(integrity_id) if with_integrity else b"") + payload[-4:]
        assert sent_payload == expected


# -- Connection unit tests --


class TestConnectionElementSize:
    def test_single_byte(self) -> None:
        for dt in (DataType.BOOL, DataType.USINT, DataType.BYTE, DataType.SINT):
            assert _element_size(dt) == 1

    def test_two_byte(self) -> None:
        for dt in (DataType.UINT, DataType.WORD, DataType.INT):
            assert _element_size(dt) == 2

    def test_four_byte(self) -> None:
        for dt in (DataType.REAL, DataType.RID):
            assert _element_size(dt) == 4

    def test_eight_byte(self) -> None:
        for dt in (DataType.LREAL, DataType.TIMESTAMP):
            assert _element_size(dt) == 8

    def test_variable_length(self) -> None:
        for dt in (DataType.UDINT, DataType.BLOB, DataType.WSTRING, DataType.STRUCT):
            assert _element_size(dt) == 0


class TestSkipTypedValue:
    """Test codec.skip_typed_value with constructed byte buffers."""

    def test_null(self) -> None:
        assert skip_typed_value(b"", 0, DataType.NULL, 0x00) == 0

    def test_bool(self) -> None:
        data = bytes([0x01])
        assert skip_typed_value(data, 0, DataType.BOOL, 0x00) == 1

    def test_usint(self) -> None:
        data = bytes([42])
        assert skip_typed_value(data, 0, DataType.USINT, 0x00) == 1

    def test_byte(self) -> None:
        data = bytes([0xAB])
        assert skip_typed_value(data, 0, DataType.BYTE, 0x00) == 1

    def test_sint(self) -> None:
        data = bytes([0xD6])
        assert skip_typed_value(data, 0, DataType.SINT, 0x00) == 1

    def test_uint(self) -> None:
        data = struct.pack(">H", 1000)
        assert skip_typed_value(data, 0, DataType.UINT, 0x00) == 2

    def test_word(self) -> None:
        data = struct.pack(">H", 0xBEEF)
        assert skip_typed_value(data, 0, DataType.WORD, 0x00) == 2

    def test_int(self) -> None:
        data = struct.pack(">h", -1000)
        assert skip_typed_value(data, 0, DataType.INT, 0x00) == 2

    def test_udint(self) -> None:
        vlq = encode_uint32_vlq(100000)
        new_offset = skip_typed_value(vlq, 0, DataType.UDINT, 0x00)
        assert new_offset == len(vlq)

    def test_dword(self) -> None:
        # DWORD is fixed 4-byte (not VLQ).
        data = struct.pack(">I", 0xDEADBEEF)
        assert skip_typed_value(data, 0, DataType.DWORD, 0x00) == 4

    def test_aid(self) -> None:
        vlq = encode_uint32_vlq(306)
        new_offset = skip_typed_value(vlq, 0, DataType.AID, 0x00)
        assert new_offset == len(vlq)

    def test_dint(self) -> None:
        vlq = encode_int32_vlq(-100000)
        new_offset = skip_typed_value(vlq, 0, DataType.DINT, 0x00)
        assert new_offset == len(vlq)

    def test_ulint(self) -> None:
        vlq = encode_uint64_vlq(2**40)
        new_offset = skip_typed_value(vlq, 0, DataType.ULINT, 0x00)
        assert new_offset == len(vlq)

    def test_lword(self) -> None:
        # LWORD is fixed 8-byte (not VLQ).
        data = struct.pack(">Q", 0xCAFE)
        assert skip_typed_value(data, 0, DataType.LWORD, 0x00) == 8

    def test_lint(self) -> None:
        from s7commplus.vlq import encode_int64_vlq

        vlq = encode_int64_vlq(-(2**40))
        new_offset = skip_typed_value(vlq, 0, DataType.LINT, 0x00)
        assert new_offset == len(vlq)

    def test_real(self) -> None:
        data = struct.pack(">f", 3.14)
        assert skip_typed_value(data, 0, DataType.REAL, 0x00) == 4

    def test_lreal(self) -> None:
        data = struct.pack(">d", 2.718)
        assert skip_typed_value(data, 0, DataType.LREAL, 0x00) == 8

    def test_timestamp(self) -> None:
        data = struct.pack(">Q", 0x0001020304050607)
        assert skip_typed_value(data, 0, DataType.TIMESTAMP, 0x00) == 8

    def test_timespan(self) -> None:
        from s7commplus.vlq import encode_int64_vlq

        vlq = encode_int64_vlq(5000)
        # TIMESPAN uses uint64_vlq for skipping in _skip_typed_value
        new_offset = skip_typed_value(vlq, 0, DataType.TIMESPAN, 0x00)
        assert new_offset == len(vlq)

    def test_rid(self) -> None:
        data = struct.pack(">I", 0x12345678)
        assert skip_typed_value(data, 0, DataType.RID, 0x00) == 4

    def test_blob(self) -> None:
        blob_data = bytes([1, 2, 3, 4])
        blob_root_id = encode_uint32_vlq(0)
        vlq_len = encode_uint32_vlq(len(blob_data))
        data = blob_root_id + vlq_len + blob_data
        new_offset = skip_typed_value(data, 0, DataType.BLOB, 0x00)
        assert new_offset == len(data)

    def test_wstring(self) -> None:
        text = "hello".encode("utf-8")
        vlq_len = encode_uint32_vlq(len(text))
        data = vlq_len + text
        new_offset = skip_typed_value(data, 0, DataType.WSTRING, 0x00)
        assert new_offset == len(data)

    def test_struct(self) -> None:
        # Normal-mode struct: UInt32 struct-id, then members [VLQ key][flags+type+value],
        # terminated by a 0x00 list-terminator byte (member keys never start with 0x00).
        struct_id = struct.pack(">I", 0x0000002A)
        member1 = encode_uint32_vlq(1) + bytes([0x00, DataType.USINT, 0x0A])
        member2 = encode_uint32_vlq(2) + bytes([0x00, DataType.USINT, 0x14])
        data = struct_id + member1 + member2 + bytes([0x00])
        new_offset = skip_typed_value(data, 0, DataType.STRUCT, 0x00)
        assert new_offset == len(data)

    def test_unknown_type(self) -> None:
        # Unknown type should return same offset (can't skip)
        assert skip_typed_value(bytes([0xFF]), 0, 0xFF, 0x00) == 0

    # -- Array tests --

    def test_array_fixed_size(self) -> None:
        count_vlq = encode_uint32_vlq(3)
        elements = bytes([10, 20, 30])
        data = count_vlq + elements
        new_offset = skip_typed_value(data, 0, DataType.USINT, 0x10)
        assert new_offset == len(data)

    def test_array_variable_length(self) -> None:
        count_vlq = encode_uint32_vlq(2)
        elem1 = encode_uint32_vlq(100)
        elem2 = encode_uint32_vlq(200)
        data = count_vlq + elem1 + elem2
        new_offset = skip_typed_value(data, 0, DataType.UDINT, 0x10)
        assert new_offset == len(data)

    def test_array_empty_data(self) -> None:
        # Edge case: array flag but no data
        assert skip_typed_value(b"", 0, DataType.USINT, 0x10) == 0


class TestParseCreateObjectResponse:
    """Test parse_server_session_version with constructed payloads.

    Returns the raw typed value (flags + datatype + value) to echo back verbatim —
    real S7-1500 PLCs send ServerSessionVersion as a Struct — or None if absent.
    """

    def _build_create_response_with_session_version(self, version: int, datatype: int = DataType.UDINT) -> bytes:
        """Build a minimal CreateObject response containing ServerSessionVersion."""
        payload = bytearray()
        # Attribute tag
        payload += bytes([ElementID.ATTRIBUTE])
        # Attribute ID = ServerSessionVersion (306)
        payload += encode_uint32_vlq(ObjectId.SERVER_SESSION_VERSION)
        # Typed value: flags + datatype + VLQ value
        payload += bytes([0x00, datatype])
        payload += encode_uint32_vlq(version)
        return bytes(payload)

    def test_parse_udint_version(self) -> None:
        payload = self._build_create_response_with_session_version(3, DataType.UDINT)
        result = parse_server_session_version(payload)
        assert result == bytes([0x00, DataType.UDINT]) + encode_uint32_vlq(3)

    def test_parse_dword_version(self) -> None:
        payload = self._build_create_response_with_session_version(2, DataType.DWORD)
        result = parse_server_session_version(payload)
        assert result == bytes([0x00, DataType.DWORD]) + encode_uint32_vlq(2)

    def test_version_not_found(self) -> None:
        # Build payload with a different attribute, not ServerSessionVersion
        payload = bytearray()
        payload += bytes([ElementID.ATTRIBUTE])
        payload += encode_uint32_vlq(999)  # Some other attribute ID
        payload += bytes([0x00, DataType.USINT, 42])
        assert parse_server_session_version(bytes(payload)) is None

    def test_with_preceding_attributes(self) -> None:
        payload = bytearray()
        # First attribute: some random one with a UINT value
        payload += bytes([ElementID.ATTRIBUTE])
        payload += encode_uint32_vlq(100)  # Random attribute ID
        payload += bytes([0x00, DataType.UINT])
        payload += struct.pack(">H", 0x1234)
        # Second attribute: ServerSessionVersion
        payload += bytes([ElementID.ATTRIBUTE])
        payload += encode_uint32_vlq(ObjectId.SERVER_SESSION_VERSION)
        payload += bytes([0x00, DataType.UDINT])
        payload += encode_uint32_vlq(1)
        result = parse_server_session_version(bytes(payload))
        assert result == bytes([0x00, DataType.UDINT]) + encode_uint32_vlq(1)

    def test_with_start_of_object(self) -> None:
        payload = bytearray()
        # StartOfObject tag (needs RelationId + ClassId + ClassFlags + AttributeId)
        payload += bytes([ElementID.START_OF_OBJECT])
        payload += struct.pack(">I", 0)  # RelationId (4 bytes)
        payload += encode_uint32_vlq(100)  # ClassId
        payload += encode_uint32_vlq(0)  # ClassFlags
        payload += encode_uint32_vlq(0)  # AttributeId
        # TerminatingObject
        payload += bytes([ElementID.TERMINATING_OBJECT])
        # Now the attribute we want
        payload += bytes([ElementID.ATTRIBUTE])
        payload += encode_uint32_vlq(ObjectId.SERVER_SESSION_VERSION)
        payload += bytes([0x00, DataType.UDINT])
        payload += encode_uint32_vlq(3)
        result = parse_server_session_version(bytes(payload))
        assert result == bytes([0x00, DataType.UDINT]) + encode_uint32_vlq(3)

    def test_strip_paom_string(self) -> None:
        # Real ServerSessionVersion struct from an S7-1200 (FW v4.2). Element 319
        # carries the device PAOM string "1;6ES7 215-1BG40-0XB0 ;V4.2".
        captured = bytes.fromhex(
            "00170000013a"
            "823b00048400823c00048400823d00048480c200823e00048480c200"
            "823f00151b313b36455337203231352d31424734302d30584230203b56342e32"
            "8240001506323b3130383282410003000300"
        )
        stripped = _strip_paom_string_in_session_version(captured)
        # Element 319 should now be an empty WString (length-VLQ 0x00).
        assert b"\x82\x3f\x00\x15\x00\x82\x40" in stripped
        assert b"6ES7 215-1BG40-0XB0" not in stripped

    def test_strip_paom_string_idempotent_on_already_empty(self) -> None:
        # Already-stripped struct: no PAOM string content present.
        already_stripped = bytes.fromhex("00170000013a823f001500824000150000")
        assert _strip_paom_string_in_session_version(already_stripped) == already_stripped

    def test_strip_paom_string_no_match_returns_unchanged(self) -> None:
        # Struct without element 319 at all — helper should leave it alone.
        nopaom = bytes.fromhex("00170000013a823b0004840000")
        assert _strip_paom_string_in_session_version(nopaom) == nopaom

    def test_parse_public_key_checksum(self) -> None:
        from s7commplus.codec import parse_create_object_attributes

        payload = bytearray()
        payload += bytes([ElementID.ATTRIBUTE])
        payload += encode_uint32_vlq(233)  # ObjectVariableTypeName
        payload += bytes([0x00, DataType.WSTRING])
        text = "01:BD426B091F08731A"
        payload += encode_uint32_vlq(len(text))
        payload += text.encode("utf-8")
        attrs = parse_create_object_attributes(bytes(payload))
        assert attrs.public_key_fingerprint == "01:BD426B091F08731A"

    def test_parse_struct_version(self) -> None:
        from s7commplus.codec import parse_create_object_attributes

        payload = bytearray()
        payload += bytes([ElementID.ATTRIBUTE])
        payload += encode_uint32_vlq(ObjectId.SERVER_SESSION_VERSION)
        struct_value = bytes([0x00, DataType.STRUCT])
        struct_value += struct.pack(">I", 314)
        struct_value += encode_uint32_vlq(315) + bytes([0x00, DataType.UDINT]) + encode_uint32_vlq(512)
        struct_value += encode_uint32_vlq(319) + bytes([0x00, DataType.WSTRING]) + encode_uint32_vlq(0)
        struct_value += bytes([0x00])
        payload += struct_value
        attrs = parse_create_object_attributes(bytes(payload))
        assert attrs.server_session_version == struct_value


# -- Client error path tests --


class TestClientErrorPaths:
    def test_properties_not_connected(self) -> None:
        client = S7CommPlusClient()
        assert client.connected is False
        assert client.protocol_version == 0
        assert client.session_id == 0
        assert client.session_setup_ok is False

    def test_db_read_not_connected(self) -> None:
        client = S7CommPlusClient()
        with pytest.raises(RuntimeError, match="Not connected"):
            client.db_read(1, 0, 4)

    def test_db_write_not_connected(self) -> None:
        client = S7CommPlusClient()
        with pytest.raises(RuntimeError, match="Not connected"):
            client.db_write(1, 0, bytes([1, 2, 3, 4]))

    def test_db_read_multi_not_connected(self) -> None:
        client = S7CommPlusClient()
        with pytest.raises(RuntimeError, match="Not connected"):
            client.db_read_multi([(1, 0, 4)])

    def test_db_write_multi_not_connected(self) -> None:
        client = S7CommPlusClient()
        with pytest.raises(RuntimeError, match="Not connected"):
            client.db_write_multi([(1, 0, b"data", DataType.BLOB)])

    def test_write_multi_not_connected(self) -> None:
        client = S7CommPlusClient()
        with pytest.raises(RuntimeError, match="Not connected"):
            client.write_multi([(1, 0, b"data", DataType.BLOB)])

    def test_db_write_multi_uses_one_substreamed_request_per_item(self) -> None:
        client = S7CommPlusClient()
        connection = MagicMock()
        connection.requires_substreamed = True
        connection.session_id = 0x70000001
        client._connection = connection
        items = [(1, 0, b"first", DataType.BLOB), (2, 10, b"second", DataType.BLOB)]

        client.db_write_multi(items)

        connection.send_request.assert_has_calls(
            [
                call(
                    FunctionCode.SET_VAR_SUBSTREAMED,
                    _build_substreamed_write_payload(
                        connection.session_id,
                        Ids.DB_ACCESS_AREA_BASE + db_number,
                        Ids.DB_VALUE_ACTUAL,
                        [Ids.LID_OMS_STB_CLASSIC_BLOB, start, len(data)],
                        data,
                    ),
                )
                for db_number, start, data, _ in items
            ]
        )

    def test_read_symbolic_multi_not_connected(self) -> None:
        client = S7CommPlusClient()
        with pytest.raises(RuntimeError, match="Not connected"):
            client.read_symbolic_multi([(0x8A0E0001, [1, 4])])

    def test_explore_not_connected(self) -> None:
        client = S7CommPlusClient()
        with pytest.raises(RuntimeError, match="Not connected"):
            client.explore()

    def test_explore_xml_not_connected(self) -> None:
        client = S7CommPlusClient()
        with pytest.raises(RuntimeError, match="Not connected"):
            client.explore_xml()

    def test_context_manager_not_connected(self) -> None:
        """Test that context manager works without connection (disconnect is a no-op)."""
        with S7CommPlusClient() as client:
            assert client.connected is False
        # Should not raise


class TestExploreDatablocks:
    """Test the EXPLORE(thePLCProgram) request format and DB-list parser."""

    def test_build_explore_request_format(self) -> None:
        # ExploreId as a fixed UInt32, then the marker bytes, address count + ids,
        # and a 5-byte trailer (UInt32 fill + filler byte) for the IntegrityId splice.
        from s7commplus.protocol import Ids

        payload = _build_explore_request(Ids.NATIVE_THE_PLC_PROGRAM_RID, [233, 2521])
        assert payload[:4] == struct.pack(">I", Ids.NATIVE_THE_PLC_PROGRAM_RID)
        assert payload[4] == 0  # ExploreRequestId
        assert payload[5:9] == bytes([1, 1, 0, 0])  # recursive, unknown, parents, following
        assert payload.endswith(bytes(5))  # UInt32 fill + filler byte

    def test_parse_explore_datablocks(self) -> None:
        from s7commplus.protocol import Ids

        r = bytearray()
        r += encode_uint64_vlq(0)  # ReturnValue
        # A DataBlock object: ClassId DB_CLASS_RID, RelationId in the DB area.
        r += bytes([ElementID.START_OF_OBJECT])
        r += struct.pack(">I", Ids.DB_ACCESS_AREA_BASE | 42)
        r += encode_uint32_vlq(Ids.DB_CLASS_RID)
        r += encode_uint32_vlq(0)  # ClassFlags
        r += encode_uint32_vlq(0)  # AttributeId
        r += bytes([ElementID.ATTRIBUTE])
        r += encode_uint32_vlq(Ids.OBJECT_VARIABLE_TYPE_NAME)
        name = b"DataBlock_1"  # single-byte WString content, as a real S7-1500 sends
        r += bytes([0x00, DataType.WSTRING]) + encode_uint32_vlq(len(name)) + name
        r += bytes([ElementID.TERMINATING_OBJECT])
        # A non-DB object (different ClassId) must be ignored.
        r += bytes([ElementID.START_OF_OBJECT])
        r += struct.pack(">I", 0x00000003)
        r += encode_uint32_vlq(2520)  # PLCProgram class, not a DB
        r += encode_uint32_vlq(0)
        r += encode_uint32_vlq(0)
        r += bytes([ElementID.TERMINATING_OBJECT])

        dbs = _parse_explore_datablocks(bytes(r))
        assert len(dbs) == 1
        assert dbs[0]["number"] == 42
        assert dbs[0]["rid"] == Ids.DB_ACCESS_AREA_BASE | 42

    @staticmethod
    def _db_object(db_number: int, name: bytes = b"DataBlock_1", extra_attributes: bytes = b"") -> bytes:
        from s7commplus.protocol import Ids

        r = bytearray()
        r += bytes([ElementID.START_OF_OBJECT])
        r += struct.pack(">I", Ids.DB_ACCESS_AREA_BASE | db_number)
        r += encode_uint32_vlq(Ids.DB_CLASS_RID)
        r += encode_uint32_vlq(0)  # ClassFlags
        r += encode_uint32_vlq(0)  # AttributeId
        r += bytes([ElementID.ATTRIBUTE])
        r += encode_uint32_vlq(Ids.OBJECT_VARIABLE_TYPE_NAME)
        r += bytes([0x00, DataType.WSTRING]) + encode_uint32_vlq(len(name)) + name
        r += extra_attributes
        r += bytes([ElementID.TERMINATING_OBJECT])
        return bytes(r)

    def test_parse_explore_datablocks_defaults_without_block_metadata(self) -> None:
        r = encode_uint64_vlq(0) + self._db_object(7)
        dbs = _parse_explore_datablocks(bytes(r))
        assert dbs == [
            {
                "name": "DataBlock_1",
                "number": 7,
                "rid": Ids.DB_ACCESS_AREA_BASE | 7,
                "language": None,
                "knowhow_protected": False,
                "unlinked": False,
            }
        ]

    def test_parse_explore_datablocks_reports_knowhow_protection(self) -> None:
        # KnowhowProtected (0x9DC) is struct 0xD77; its presence marks the block.
        # Struct ids are fixed 4-byte values, member keys are VLQ.
        knowhow = (
            bytes([ElementID.ATTRIBUTE])
            + encode_uint32_vlq(Ids.BLOCK_KNOWHOW_PROTECTED)
            + bytes([0x00, DataType.STRUCT])
            + struct.pack(">I", Ids.KNOWHOW_PROTECTION_STRUCT)
            + encode_uint32_vlq(Ids.KNOWHOW_PROTECTION_MODE)
            + bytes([0x00, DataType.WORD])
            + struct.pack(">H", 1)
            + encode_uint32_vlq(0)  # struct terminator key
        )
        r = encode_uint64_vlq(0) + self._db_object(8, extra_attributes=knowhow)
        dbs = _parse_explore_datablocks(bytes(r))
        assert dbs[0]["knowhow_protected"] is True
        assert dbs[0]["language"] is None

    def test_parse_explore_datablocks_reports_language(self) -> None:
        from s7commplus.protocol import Ids

        language = (
            bytes([ElementID.ATTRIBUTE]) + encode_uint32_vlq(Ids.BLOCK_BLOCK_LANGUAGE) + bytes([0x00, DataType.USINT, 4])  # SCL
        )
        r = encode_uint64_vlq(0) + self._db_object(9, extra_attributes=language)
        dbs = _parse_explore_datablocks(bytes(r))
        assert dbs[0]["language"] == "SCL"
        assert dbs[0]["knowhow_protected"] is False

    def test_parse_explore_datablocks_reports_unknown_language(self) -> None:
        language = (
            bytes([ElementID.ATTRIBUTE]) + encode_uint32_vlq(Ids.BLOCK_BLOCK_LANGUAGE) + bytes([0x00, DataType.USINT, 0x7B])
        )
        r = encode_uint64_vlq(0) + self._db_object(10, extra_attributes=language)
        dbs = _parse_explore_datablocks(bytes(r))
        assert dbs[0]["language"] == "language 123"

    def test_parse_explore_datablocks_language_codes_at_and_above_128(self) -> None:
        # A USINT code of 0x80+ would look like a VLQ continuation if decoded
        # as VLQ; it must be read as the single byte it is. 201 is MOTION_DB,
        # 300 (above any single byte) arrives as a UINT.
        motion_db = (
            bytes([ElementID.ATTRIBUTE]) + encode_uint32_vlq(Ids.BLOCK_BLOCK_LANGUAGE) + bytes([0x00, DataType.USINT, 201])
        )
        dbs = _parse_explore_datablocks(encode_uint64_vlq(0) + self._db_object(12, extra_attributes=motion_db))
        assert dbs[0]["language"] == "MOTION_DB"

        as_uint = (
            bytes([ElementID.ATTRIBUTE])
            + encode_uint32_vlq(Ids.BLOCK_BLOCK_LANGUAGE)
            + bytes([0x00, DataType.UINT])
            + struct.pack(">H", 300)
        )
        dbs = _parse_explore_datablocks(encode_uint64_vlq(0) + self._db_object(13, extra_attributes=as_uint))
        assert dbs[0]["language"] == "GRAPH_ACTIONS"  # 300 is a defined code

        unknown_uint = (
            bytes([ElementID.ATTRIBUTE])
            + encode_uint32_vlq(Ids.BLOCK_BLOCK_LANGUAGE)
            + bytes([0x00, DataType.UINT])
            + struct.pack(">H", 1234)
        )
        dbs = _parse_explore_datablocks(encode_uint64_vlq(0) + self._db_object(14, extra_attributes=unknown_uint))
        assert dbs[0]["language"] == "language 1234"

    def test_parse_explore_datablocks_reports_unlinked(self) -> None:
        unlinked = bytes([ElementID.ATTRIBUTE]) + encode_uint32_vlq(Ids.BLOCK_UNLINKED) + bytes([0x00, DataType.BOOL, 1])
        r = encode_uint64_vlq(0) + self._db_object(11, extra_attributes=unlinked)
        dbs = _parse_explore_datablocks(bytes(r))
        assert dbs[0]["unlinked"] is True


class TestBlockLanguage:
    def test_known_codes(self) -> None:
        from s7commplus.protocol import BlockLanguage

        assert BlockLanguage.STL == 1
        assert BlockLanguage.LAD == 2
        assert BlockLanguage.FBD == 3
        assert BlockLanguage.SCL == 4
        assert BlockLanguage.DB == 5
        assert BlockLanguage.GRAPH == 6
        assert BlockLanguage.CPU_DB == 8
        assert BlockLanguage.C_FOR_S7 == 21
        assert BlockLanguage.MC7PLUS == 400

    def test_names(self) -> None:
        assert block_language_name(0) == "UNDEF"
        assert block_language_name(4) == "SCL"
        assert block_language_name(201) == "MOTION_DB"
        assert block_language_name(4242) == "language 4242"


class TestReassembledPayload:
    """Test S7CommPlusConnection._recv_reassembled_payload (multi-PDU fragment reassembly)."""

    @staticmethod
    def _frag(data: bytes) -> bytes:
        return bytes([0x72, 0x02, (len(data) >> 8) & 0xFF, len(data) & 0xFF]) + data

    _TRAILER = bytes([0x72, 0x02, 0x00, 0x00])

    def _conn_yielding(self, chunks: list[bytes]) -> S7CommPlusConnection:
        conn = S7CommPlusConnection("127.0.0.1", 102)
        it = iter(chunks)

        def fake_recv() -> bytes:
            return next(it, b"")

        conn._recv_s7_data = fake_recv  # type: ignore[method-assign]
        return conn

    def test_single_fragment(self) -> None:
        conn = self._conn_yielding([self._frag(b"abc") + self._TRAILER])
        assert conn._recv_reassembled_payload() == b"abc"

    def test_multiple_fragments_split_across_reads(self) -> None:
        conn = self._conn_yielding([self._frag(b"abc"), self._frag(b"de"), self._TRAILER])
        assert conn._recv_reassembled_payload() == b"abcde"

    _SYSTEM_EVENT = bytes([0x72, ProtocolVersion.SYSTEM_EVENT, 0x00, 0x10]) + bytes(16)

    @pytest.mark.parametrize("split", [1, 3, 7, 1024])
    def test_system_event_between_fragments_is_skipped(self, split: int) -> None:
        stream = self._frag(b"abc") + self._SYSTEM_EVENT + self._frag(b"de") + self._SYSTEM_EVENT + self._TRAILER
        conn = self._conn_yielding([stream[i : i + split] for i in range(0, len(stream), split)])
        assert conn._recv_reassembled_payload() == b"abcde"

    def test_too_many_system_events_during_reassembly_raises(self) -> None:
        from s7commplus.connection import _MAX_SYSTEM_EVENTS_PER_RESPONSE
        from s7commplus.error import S7ProtocolError

        conn = self._conn_yielding([self._frag(b"abc")] + [self._SYSTEM_EVENT] * (_MAX_SYSTEM_EVENTS_PER_RESPONSE + 1))
        with pytest.raises(S7ProtocolError, match="SystemEvents"):
            conn._recv_reassembled_payload()

    def test_v3_session_key_hmac_is_stripped_from_each_fragment(self) -> None:
        conn = self._conn_yielding([])
        conn._session_key = bytes(24)
        digest_state = hmac.new(conn._session_key, digestmod=hashlib.sha256)

        def v3_frag(data: bytes) -> bytes:
            digest_state.update(data)
            digest = digest_state.digest()
            protected = bytes([len(digest)]) + digest + data
            return bytes([0x72, ProtocolVersion.V3, 0, len(protected)]) + protected

        initial = v3_frag(b"abc") + v3_frag(b"de") + bytes([0x72, ProtocolVersion.V3, 0, 0])
        assert conn._recv_reassembled_payload(initial) == b"abcde"

    def test_bad_fragment_header_raises(self) -> None:
        from s7commplus.error import S7ConnectionError

        conn = self._conn_yielding([bytes([0x99, 0x02, 0x00, 0x01]) + b"x"])
        with pytest.raises(S7ConnectionError, match="fragment header"):
            conn._recv_reassembled_payload()

    def test_closed_connection_raises(self) -> None:
        from s7commplus.error import S7ConnectionError

        conn = self._conn_yielding([])  # immediate EOF
        with pytest.raises(S7ConnectionError, match="closed during"):
            conn._recv_reassembled_payload()

    def test_fragment_count_cap(self) -> None:
        from s7commplus.error import S7ConnectionError

        chunks = [self._frag(b"a"), self._frag(b"b"), self._frag(b"c"), self._TRAILER]
        conn = self._conn_yielding(chunks)
        conn._MAX_REASSEMBLED_FRAGMENTS = 2
        with pytest.raises(S7ConnectionError, match="exceeds limits"):
            conn._recv_reassembled_payload()


class TestV3ResponseIntegrity:
    KEY = bytes(range(24))

    @classmethod
    def _protected(cls, data: bytes, key: bytes | None = None) -> bytes:
        digest = hmac.new(key or cls.KEY, data, hashlib.sha256).digest()
        return bytes([len(digest)]) + digest + data

    def test_valid_digest_uses_constant_time_comparison(self) -> None:
        protected = self._protected(b"authenticated response")
        with patch("s7commplus.connection.hmac.compare_digest", wraps=hmac.compare_digest) as compare:
            assert _verify_v3_hmac(protected, self.KEY) == b"authenticated response"
        compare.assert_called_once()

    @pytest.mark.parametrize("mutation", ["wrong-key", "payload", "digest"])
    def test_changed_digest_covered_data_is_rejected(self, mutation: str) -> None:
        from s7commplus.error import S7IntegrityError

        signing_key = bytes(reversed(self.KEY)) if mutation == "wrong-key" else None
        protected = self._protected(b"authenticated response", signing_key)
        if mutation == "payload":
            protected = protected[:-1] + bytes([protected[-1] ^ 1])
        elif mutation == "digest":
            protected = protected[:1] + bytes([protected[1] ^ 1]) + protected[2:]
        with pytest.raises(S7IntegrityError, match="integrity check failed"):
            _verify_v3_hmac(protected, self.KEY)

    @pytest.mark.parametrize(
        "protected, message",
        [(b"", "Empty authenticated"), (b"\x1f" + bytes(31), "digest length"), (b"\x20" + bytes(12), "Truncated")],
    )
    def test_invalid_or_truncated_digest_is_rejected(self, protected: bytes, message: str) -> None:
        from s7commplus.error import S7IntegrityError

        with pytest.raises(S7IntegrityError, match=message):
            _verify_v3_hmac(protected, self.KEY)

    def test_failure_invalidates_connection(self) -> None:
        from s7commplus.error import S7IntegrityError

        conn = S7CommPlusConnection("127.0.0.1")
        conn._connected = True
        conn._session_ready = True
        conn._session_id = 123
        conn._session_key = self.KEY
        conn._iso_conn.disconnect = MagicMock()
        response = struct.pack(">BHHHHB", Opcode.RESPONSE, 0, FunctionCode.GET_MULTI_VARIABLES, 0, 0, 0x34)
        protected = bytearray(self._protected(response))
        protected[1] ^= 1
        frame = encode_header(ProtocolVersion.V3, len(protected)) + protected
        conn._recv_s7_data = MagicMock(return_value=bytes(frame))
        conn._send_s7_data = MagicMock()

        with pytest.raises(S7IntegrityError, match="integrity check failed"):
            conn.send_request(FunctionCode.GET_MULTI_VARIABLES)
        assert not conn.connected
        assert conn._session_key is None
        conn._iso_conn.disconnect.assert_called_once_with()

    def test_authenticated_response_rejects_frame_version_downgrade(self) -> None:
        from s7commplus.error import S7IntegrityError

        conn = S7CommPlusConnection("127.0.0.1")
        conn._connected = True
        conn._session_ready = True
        conn._session_id = 123
        conn._session_key = self.KEY
        conn._iso_conn.disconnect = MagicMock()
        response = struct.pack(">BHHHHB", Opcode.RESPONSE, 0, FunctionCode.GET_MULTI_VARIABLES, 0, 0, 0x34)
        frame = encode_header(ProtocolVersion.V2, len(response)) + response
        conn._recv_s7_data = MagicMock(return_value=frame)
        conn._send_s7_data = MagicMock()

        with pytest.raises(S7IntegrityError, match="unauthenticated frame version"):
            conn.send_request(FunctionCode.GET_MULTI_VARIABLES)
        assert not conn.connected


class TestLegitimationRejection:
    # Legitimation response of an S7-1215C (FW V4.2) with no password, reported on PR #44.
    _REJECTED = bytes.fromhex("c1c691908086e7fffe0500000000")

    def test_rejection_hidden_by_integrity_id_strip_is_detected(self) -> None:
        from s7commplus.connection import _check_v1_legitimation_response, _strip_response_integrity_id
        from s7commplus.error import S7ConnectionError

        stripped = _strip_response_integrity_id(FunctionCode.SET_VAR_SUBSTREAMED, self._REJECTED, True, False)
        _check_v1_legitimation_response(stripped)  # the stripped reading alone looks like success
        with pytest.raises(S7ConnectionError, match="rejected"):
            _check_v1_legitimation_response(stripped, self._REJECTED)

    def test_success_with_leading_integrity_id_is_accepted(self) -> None:
        from s7commplus.connection import _check_v1_legitimation_response

        raw = bytes([0x05, 0x00, 0x00, 0x00])  # IntegrityId 5, return value 0
        _check_v1_legitimation_response(raw[1:], raw)

    def test_async_client_checks_raw_response(self) -> None:
        from s7commplus.async_client import S7CommPlusAsyncClient

        client = S7CommPlusAsyncClient()
        assert client._response_payload(FunctionCode.SET_VAR_SUBSTREAMED, self._REJECTED) is not None
        assert client._last_raw_response_payload == self._REJECTED


class TestServiceResultCodes:
    """The legitimation outcomes a PLC can answer with besides plain zero."""

    @pytest.mark.parametrize(
        ("code", "expected"),
        [
            (0, ServiceResult.OK),
            (-2, ServiceResult.INVALID_VALUE_TYPE),
            (-118, ServiceResult.SERVICE_SESSION_DELEGITIMATED_LEGACY),
            (17, ServiceResult.SESSION_PRE_LEGITIMIZED),
            (22, ServiceResult.SERVICE_SESSION_DELEGITIMATED),
            (25, ServiceResult.SERVICE_LEGITIMATED_FOR_LEVEL2),
            (33, ServiceResult.SERVICE_LEGITIMATED_FOR_LEVEL1),
        ],
    )
    def test_enum_values(self, code: int, expected: ServiceResult) -> None:
        assert ServiceResult(code) is expected

    @pytest.mark.parametrize(
        ("return_value", "expected_code"),
        [
            (0, 0),  # plain success
            (-118, -118),  # legacy bare negative
            (0x8318890001B3FFFE, -2),  # composite from issue #70: sign-extended low word
            (0x8318890001B3FF9A, -102),  # arbitrary negative low word
            (17, 17),  # positive informational stays itself
            (25, 25),
            (0x100, 256),  # low word without the sign bit is the value itself
        ],
    )
    def test_service_result_code_extracts_the_low_word(self, return_value: int, expected_code: int) -> None:
        assert service_result_code(return_value) == expected_code


class TestLegitimationOutcomes:
    """Positive legitimation outcomes must be accepted; wrong password must raise."""

    @staticmethod
    def _payload(return_value: int) -> bytes:
        return encode_uint64_vlq(return_value if return_value >= 0 else return_value + (1 << 64)) + b"\x00" * 4

    @pytest.mark.parametrize(
        "code",
        [
            ServiceResult.OK,
            ServiceResult.SESSION_PRE_LEGITIMIZED,
            ServiceResult.SERVICE_LEGITIMATED_FOR_LEVEL1,
            ServiceResult.SERVICE_LEGITIMATED_FOR_LEVEL2,
            ServiceResult.SERVICE_LEGITIMATED_FOR_LEVEL3,
        ],
    )
    def test_accepted_outcomes(self, code: ServiceResult) -> None:
        from s7commplus.connection import _check_v1_legitimation_response

        _check_v1_legitimation_response(self._payload(int(code)))

    @pytest.mark.parametrize(
        "code",
        [
            ServiceResult.SERVICE_SESSION_DELEGITIMATED,
            ServiceResult.SERVICE_SESSION_DELEGITIMATED_LEGACY,
        ],
    )
    def test_wrong_password_raises_authentication_error(self, code: ServiceResult) -> None:
        from s7commplus.connection import _check_v1_legitimation_response
        from s7commplus.error import S7AuthenticationError

        with pytest.raises(S7AuthenticationError, match="wrong password"):
            _check_v1_legitimation_response(self._payload(int(code)))

    def test_composite_rejection_raises_with_decoded_code(self) -> None:
        """The composite value from issue #70 decodes to code -2, a generic rejection."""
        from s7commplus.connection import _check_v1_legitimation_response
        from s7commplus.error import S7ConnectionError

        composite = 0x8318890001B3FFFE
        raw = encode_uint64_vlq(composite) + b"\x00" * 4
        with pytest.raises(S7ConnectionError, match="rejected"):
            _check_v1_legitimation_response(b"", raw)

    def test_composite_wrong_password_code_raises_authentication_error(self) -> None:
        """A composite whose low word is the delegitimated code is a wrong-password answer."""
        from s7commplus.connection import _check_v1_legitimation_response
        from s7commplus.error import S7AuthenticationError

        # Same shape as the issue-70 value, but the low word is 22 (delegitimated).
        composite = 0x8318890001B3FF9A - 0x8318890001B3FF9A % 0x10000 - 0x1_0000 + 22
        raw = encode_uint64_vlq(composite) + b"\x00" * 4
        with pytest.raises(S7AuthenticationError, match="wrong password"):
            _check_v1_legitimation_response(b"", raw)

    def test_other_negative_failure_raises_connection_error(self) -> None:
        from s7commplus.connection import _check_v1_legitimation_response
        from s7commplus.error import S7ConnectionError

        with pytest.raises(S7ConnectionError, match="rejected"):
            _check_v1_legitimation_response(self._payload(-3))

    @staticmethod
    def _integrity_id_first(integrity_id: int, return_value: int) -> tuple[bytes, bytes]:
        """(payload, raw_payload) where the raw response starts with an IntegrityId."""
        payload = encode_uint64_vlq(return_value if return_value >= 0 else return_value + (1 << 64))
        raw = encode_uint32_vlq(integrity_id) + payload
        return payload, raw

    @pytest.mark.parametrize("integrity_id", [0, 17, 22, 25])
    def test_rejection_raises_even_when_an_integrity_id_precedes_it(self, integrity_id: int) -> None:
        """The negative return value is a rejection regardless of a leading IntegrityId."""
        from s7commplus.connection import _check_v1_legitimation_response
        from s7commplus.error import S7ConnectionError

        rejection = 0x8318890001B3FFFE
        payload = encode_uint64_vlq(rejection)
        raw = encode_uint32_vlq(integrity_id) + payload
        with pytest.raises(S7ConnectionError, match="rejected"):
            _check_v1_legitimation_response(payload, raw)

    @pytest.mark.parametrize("integrity_id", [0, 17, 22, 25, 26, 33, 1000])
    def test_success_with_leading_integrity_id_is_accepted(self, integrity_id: int) -> None:
        """A positive IntegrityId ahead of return value 0 must not raise.

        In particular an IntegrityId of 22 (the delegitimated code) is just a
        counter and must not be mistaken for a wrong-password answer.
        """
        from s7commplus.connection import _check_v1_legitimation_response

        payload, raw = self._integrity_id_first(integrity_id, 0)
        _check_v1_legitimation_response(payload, raw)

    def test_level_outcome_from_the_return_value_position_is_accepted(self) -> None:
        from s7commplus.connection import _check_v1_legitimation_response

        payload, raw = self._integrity_id_first(5, int(ServiceResult.SERVICE_LEGITIMATED_FOR_LEVEL1))
        _check_v1_legitimation_response(payload, raw)

    @pytest.mark.parametrize("integrity_id", [0, 17, 22, 25, 26, 33, 1000])
    def test_empty_payload_with_a_leading_integrity_id_is_accepted(self, integrity_id: int) -> None:
        """An empty payload means no return-value reading exists.

        The raw reading starts with an IntegrityId, which must not be
        interpreted as a code: there is no payload reading to trust, so
        nothing raises.
        """
        from s7commplus.connection import _check_v1_legitimation_response

        _raw_payload, _ = self._integrity_id_first(integrity_id, 0)
        _check_v1_legitimation_response(b"", _raw_payload)


class TestPlcsimResponseLayout:
    """PLCSIM family 03 puts the response IntegrityId after the body for set ops."""

    @staticmethod
    def _connection(family: object) -> object:
        from s7commplus.connection import S7CommPlusConnection

        conn = S7CommPlusConnection("127.0.0.1")
        conn._session_key = b"k" * 24
        conn._protocol_version = ProtocolVersion.V1
        conn._v1_session_key_family = family
        return conn

    def test_plcsim_set_response_keeps_the_body(self) -> None:
        from s7commplus.v1_session_key.keys import KeyFamily

        # return_value(00), empty error list(00), trailing IntegrityId(05), fill.
        payload = bytes.fromhex("00 00 05 00 00 00 00")
        conn = self._connection(KeyFamily.PLCSIM)
        assert conn.legacy_s7_1500
        assert conn._response_payload(FunctionCode.SET_MULTI_VARIABLES, payload) == payload

    def test_other_family_set_response_strips_the_leading_id(self) -> None:
        from s7commplus.v1_session_key.keys import KeyFamily

        payload = bytes.fromhex("05 00 00 00 00")  # leading IntegrityId 5, return_value 0, fill
        conn = self._connection(KeyFamily.S7_1500)
        assert conn._response_payload(FunctionCode.SET_MULTI_VARIABLES, payload) == payload[1:]


class TestWriteDeleteQualifierVersion:
    """write_symbolic and the subscription delete use the V2 ObjectQualifier on PLCSIM only.

    A real S7-1200/1500 V1 SessionKey session keeps the negotiated V1 layout of
    these two requests, as before #66; every other data path already sends V2.
    """

    _WRITE_ARGS = (0x8A0E0001, [1], b"\x00\x2a", 0)

    @staticmethod
    def _expected_write(version: int) -> bytes:
        from s7commplus.client import _build_symbolic_write_payload

        area, lids, data, crc = TestWriteDeleteQualifierVersion._WRITE_ARGS
        return _build_symbolic_write_payload(area, lids, data, crc, protocol_version=version, datatype=DataType.INT)

    @staticmethod
    def _expected_delete(version: int) -> bytes:
        from s7commplus.subscription import build_delete_subscription_request

        return build_delete_subscription_request(0x70000F90, version)

    @pytest.mark.parametrize(("family", "version"), [("PLCSIM", 2), ("S7_1200", 1), ("S7_1500", 1)])
    def test_sync_client(self, family: str, version: int) -> None:
        from s7commplus.client import S7CommPlusClient
        from s7commplus.v1_session_key.keys import KeyFamily

        conn = TestPlcsimResponseLayout._connection(KeyFamily[family])
        conn._subscription_container_id = 0x70000F90
        conn.send_request = MagicMock(return_value=b"\x00\x00")  # return value 0, no item errors
        client = S7CommPlusClient()
        client._connection = conn
        assert conn.write_delete_qualifier_version == version

        area, lids, data, crc = self._WRITE_ARGS
        client.write_symbolic(area, lids, data, crc, datatype=DataType.INT)
        client.delete_subscription(0x70000F91)
        (_, write_payload), _ = conn.send_request.call_args_list[0]
        (_, delete_payload), _ = conn.send_request.call_args_list[1]
        assert write_payload == self._expected_write(version) != self._expected_write(3 - version)
        assert delete_payload == self._expected_delete(version) != self._expected_delete(3 - version)

    @pytest.mark.parametrize(("family", "version"), [("PLCSIM", 2), ("S7_1200", 1), ("S7_1500", 1)])
    def test_async_client(self, family: str, version: int) -> None:
        from s7commplus.async_client import S7CommPlusAsyncClient
        from s7commplus.v1_session_key.keys import KeyFamily

        client = S7CommPlusAsyncClient()
        client._connected = True
        client._session_key = b"k" * 24
        client._protocol_version = ProtocolVersion.V1
        client._v1_session_key_family = KeyFamily[family]
        client._subscription_container_id = 0x70000F90
        client._send_request = AsyncMock(return_value=b"\x00\x00")  # type: ignore[method-assign]
        assert client.write_delete_qualifier_version == version

        area, lids, data, crc = self._WRITE_ARGS

        async def run() -> None:
            await client.write_symbolic(area, lids, data, crc, datatype=DataType.INT)
            await client.delete_subscription(0x70000F91)

        asyncio.run(run())
        (_, write_payload), _ = client._send_request.call_args_list[0]
        (_, delete_payload), _ = client._send_request.call_args_list[1]
        assert write_payload == self._expected_write(version) != self._expected_write(3 - version)
        assert delete_payload == self._expected_delete(version) != self._expected_delete(3 - version)


class TestS71200Subscriptions:
    """A CPU 1215C FW V4.2 accepts a subscription only without the session activation.

    Seen on that CPU with a read-only probe: after the address-323 activation the
    PLC resets the connection on the subscription's CreateObject (reads keep
    working); without it the CreateObject is answered, return value first.
    """

    # return_value 0, one object id (0x70000F91), then the IntegrityId (5) and fill.
    _CREATE_RESPONSE = bytes([0x00, 0x01]) + bytes.fromhex("8780809f11") + bytes([0x05]) + bytes(4)

    @pytest.mark.parametrize(
        ("family", "activated"),
        [("PLCSIM", False), ("S7_1200", False), ("S7_1500", True), (None, True)],
    )
    def test_session_activation_by_family(self, family: object, activated: bool) -> None:
        from s7commplus.connection import _sends_session_activation
        from s7commplus.v1_session_key.keys import KeyFamily

        assert _sends_session_activation(None if family is None else KeyFamily[str(family)]) is activated

    @pytest.mark.parametrize(
        ("family", "function_code", "follows"),
        [
            ("S7_1200", FunctionCode.CREATE_OBJECT, True),
            ("S7_1200", FunctionCode.SET_MULTI_VARIABLES, False),
            ("S7_1200", FunctionCode.DELETE_OBJECT, False),
            ("S7_1500", FunctionCode.CREATE_OBJECT, False),
            ("PLCSIM", FunctionCode.CREATE_OBJECT, True),
            ("PLCSIM", FunctionCode.SET_MULTI_VARIABLES, True),
        ],
    )
    def test_integrity_id_position_by_family(self, family: str, function_code: int, follows: bool) -> None:
        from s7commplus.connection import _integrity_id_follows_body
        from s7commplus.v1_session_key.keys import KeyFamily

        assert _integrity_id_follows_body(KeyFamily[family], function_code) is follows

    def test_create_object_response_keeps_its_return_value(self) -> None:
        from s7commplus.codec import parse_create_object_session_id
        from s7commplus.v1_session_key.keys import KeyFamily

        conn = TestPlcsimResponseLayout._connection(KeyFamily.S7_1200)
        payload = conn._response_payload(FunctionCode.CREATE_OBJECT, self._CREATE_RESPONSE)
        assert payload == self._CREATE_RESPONSE
        object_ids, _, return_value = parse_create_object_session_id(payload)
        assert (object_ids, return_value) == ([0x70000F91], 0)

    def test_s7_1500_create_object_response_still_strips_the_leading_id(self) -> None:
        from s7commplus.v1_session_key.keys import KeyFamily

        payload = bytes([0x05]) + self._CREATE_RESPONSE[:-5]  # leading IntegrityId 5
        conn = TestPlcsimResponseLayout._connection(KeyFamily.S7_1500)
        assert conn._response_payload(FunctionCode.CREATE_OBJECT, payload) == payload[1:]

    def test_async_create_object_response_keeps_its_return_value(self) -> None:
        from s7commplus.async_client import S7CommPlusAsyncClient
        from s7commplus.codec import parse_create_object_session_id
        from s7commplus.v1_session_key.keys import KeyFamily

        client = S7CommPlusAsyncClient()
        client._session_key = b"k" * 24
        client._protocol_version = ProtocolVersion.V1
        client._v1_session_key_family = KeyFamily.S7_1200
        assert client.legacy_s7_1500
        payload = client._response_payload(FunctionCode.CREATE_OBJECT, self._CREATE_RESPONSE)
        assert parse_create_object_session_id(payload)[0] == [0x70000F91]
        client._v1_session_key_family = KeyFamily.S7_1500
        leading = bytes([0x05]) + self._CREATE_RESPONSE[:-5]
        assert client._response_payload(FunctionCode.CREATE_OBJECT, leading) == leading[1:]
