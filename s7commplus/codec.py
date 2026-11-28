"""
S7CommPlus data encoding and decoding.

Provides serialization for the S7CommPlus wire format including:
- Fixed-width integers (big-endian)
- VLQ-encoded integers
- Floating point values
- Strings (UTF-8 encoded WStrings)
- Blobs (raw byte arrays)
- S7CommPlus frame header

Reference: thomas-v2/S7CommPlusDriver/Core/S7p.cs
"""

import struct
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Optional

from .error import S7ReturnValueError
from .protocol import PROTOCOL_ID, ArrayKind, DataType, ElementID, Ids, ObjectId, ProtocolVersion, ReturnValue, ServiceResult
from .vlq import (
    decode_int32_vlq,
    decode_int64_vlq,
    decode_uint32_vlq,
    decode_uint64_vlq,
    encode_int32_vlq,
    encode_int64_vlq,
    encode_uint32_vlq,
    encode_uint64_vlq,
)

# ServerSession.Role (attribute 299): the roles the session may take. The
# bit below was observed set on PLCs running a secured (SessionKey-protected)
# session in TIA Portal captures; the meaning is inferred from those captures
# and not verified against a live PLC. Ids.cs defines no ServerSession.Role
# and no role bits.
SERVER_SESSION_ROLE_ID = 299
SERVER_SESSION_ROLE_SECURED_BIT = 0x20000000
# ServerSession.Roles (305): the mask of every role the session may take, as
# opposed to the single Role the secured-session detection reads.
SERVER_SESSION_ROLES_ID = 305


def encode_header(version: int, data_length: int) -> bytes:
    """Encode an S7CommPlus frame header.

    Header format (4 bytes)::

        [0]   Protocol ID: 0x72
        [1]   Protocol version
        [2-3] Data length (big-endian uint16)

    Args:
        version: Protocol version byte
        data_length: Length of data following the header

    Returns:
        4-byte header
    """
    return struct.pack(">BBH", PROTOCOL_ID, version, data_length)


def decode_header(data: bytes, offset: int = 0) -> tuple[int, int, int]:
    """Decode an S7CommPlus frame header.

    Args:
        data: Buffer containing the header
        offset: Starting position

    Returns:
        Tuple of (protocol_version, data_length, bytes_consumed)

    Raises:
        ValueError: If protocol ID is not 0x72
    """
    if len(data) - offset < 4:
        raise ValueError("Not enough data for S7CommPlus header")

    proto_id, version, length = struct.unpack_from(">BBH", data, offset)

    if proto_id != PROTOCOL_ID:
        raise ValueError(f"Invalid protocol ID: {proto_id:#04x}, expected {PROTOCOL_ID:#04x}")

    return version, length, 4


def encode_request_header(
    function_code: int,
    sequence_number: int,
    session_id: int = 0,
    transport_flags: int = 0x36,
) -> bytes:
    """Encode an S7CommPlus request header (after the frame header).

    Request header format::

        [0]     Opcode: 0x31 (Request)
        [1-2]   Reserved: 0x0000
        [3-4]   Function code (big-endian uint16)
        [5-6]   Reserved: 0x0000
        [7-8]   Sequence number (big-endian uint16)
        [9-12]  Session ID (big-endian uint32)
        [13]    Transport flags

    Args:
        function_code: S7CommPlus function code
        sequence_number: Request sequence number
        session_id: Session identifier (0 for initial connection)
        transport_flags: Transport flags byte

    Returns:
        14-byte request header
    """
    from .protocol import Opcode

    return struct.pack(
        ">BHHHHIB",
        Opcode.REQUEST,
        0x0000,  # Reserved
        function_code,
        0x0000,  # Reserved
        sequence_number,
        session_id,
        transport_flags,
    )


def decode_response_header(data: bytes, offset: int = 0) -> dict[str, Any]:
    """Decode an S7CommPlus response header.

    Args:
        data: Buffer containing the response
        offset: Starting position

    Returns:
        Dictionary with opcode, function_code, sequence_number, session_id,
        transport_flags, and bytes_consumed
    """
    if len(data) - offset < 14:
        raise ValueError("Not enough data for S7CommPlus response header")

    opcode, reserved1, function_code, reserved2, seq_num, session_id, transport_flags = struct.unpack_from(
        ">BHHHHIB", data, offset
    )

    return {
        "opcode": opcode,
        "function_code": function_code,
        "sequence_number": seq_num,
        "session_id": session_id,
        "transport_flags": transport_flags,
        "bytes_consumed": 14,
    }


def parse_or_raise_for_return_value(response: bytes, operation: str) -> int:
    """Raise if a response's leading ReturnValue is truncated or non-zero.

    The error message names the decoded code, generic category and source (see `ReturnValue`).

    Args:
        response: Raw response payload, starting with the ReturnValue.
        operation: Operation named in the error message, e.g. "EXPLORE of 0x00000003".

    Returns:
        Offset of the first byte after the ReturnValue.

    Raises:
        ValueError: If the ReturnValue is truncated.
        S7ReturnValueError: If the ReturnValue is non-zero.
    """
    try:
        return_value, offset = decode_uint64_vlq(response, 0)
    except ValueError as error:
        raise ValueError(f"{operation}: truncated ReturnValue") from error
    if return_value != 0:
        result = ReturnValue.from_int(return_value)
        message = f"{operation} failed: PLC returned 0x{result.raw:016X} ({result})"
        if result.failed and not result.source and result.code == ServiceResult.SERVICE_ACCESS_DENIED:
            # A protected PLC answers this before a login, e.g. to the browse a named read starts with.
            message += ". The session's access level does not allow it; log in with a password that grants this access (connect(password=...), or authenticate() on a TLS session)"
        raise S7ReturnValueError(message, return_value, response)
    return offset


# -- Fixed-width encoding (big-endian) --


def encode_uint8(value: int) -> bytes:
    return struct.pack(">B", value)


def decode_uint8(data: bytes, offset: int = 0) -> tuple[int, int]:
    return struct.unpack_from(">B", data, offset)[0], 1


def encode_uint16(value: int) -> bytes:
    return struct.pack(">H", value)


def decode_uint16(data: bytes, offset: int = 0) -> tuple[int, int]:
    return struct.unpack_from(">H", data, offset)[0], 2


def encode_uint32(value: int) -> bytes:
    return struct.pack(">I", value)


def decode_uint32(data: bytes, offset: int = 0) -> tuple[int, int]:
    return struct.unpack_from(">I", data, offset)[0], 4


def encode_uint64(value: int) -> bytes:
    return struct.pack(">Q", value)


def decode_uint64(data: bytes, offset: int = 0) -> tuple[int, int]:
    return struct.unpack_from(">Q", data, offset)[0], 8


def encode_int16(value: int) -> bytes:
    return struct.pack(">h", value)


def decode_int16(data: bytes, offset: int = 0) -> tuple[int, int]:
    return struct.unpack_from(">h", data, offset)[0], 2


def encode_int32(value: int) -> bytes:
    return struct.pack(">i", value)


def decode_int32(data: bytes, offset: int = 0) -> tuple[int, int]:
    return struct.unpack_from(">i", data, offset)[0], 4


def encode_int64(value: int) -> bytes:
    return struct.pack(">q", value)


def decode_int64(data: bytes, offset: int = 0) -> tuple[int, int]:
    return struct.unpack_from(">q", data, offset)[0], 8


def encode_float32(value: float) -> bytes:
    return struct.pack(">f", value)


def decode_float32(data: bytes, offset: int = 0) -> tuple[float, int]:
    return struct.unpack_from(">f", data, offset)[0], 4


def encode_float64(value: float) -> bytes:
    return struct.pack(">d", value)


def decode_float64(data: bytes, offset: int = 0) -> tuple[float, int]:
    return struct.unpack_from(">d", data, offset)[0], 8


# -- String encoding --


def encode_wstring(value: str) -> bytes:
    """Encode a string as UTF-8 (S7CommPlus WString wire format)."""
    return value.encode("utf-8")


def decode_wstring(data: bytes, offset: int, length: int) -> tuple[str, int]:
    """Decode a UTF-8 string.

    Args:
        data: Buffer
        offset: Start position
        length: Number of bytes to decode

    Returns:
        Tuple of (decoded_string, bytes_consumed)
    """
    return data[offset : offset + length].decode("utf-8"), length


# -- Typed value encoding --


def encode_typed_value(datatype: int, value: Any) -> bytes:
    """Encode a value with its type tag.

    This prepends the DataType byte before the encoded value, which is how
    attribute values are serialized in the S7CommPlus object model.

    Args:
        datatype: DataType enum value
        value: Value to encode

    Returns:
        Type-tagged encoded value
    """
    tag = struct.pack(">B", datatype)

    if datatype == DataType.NULL:
        return tag
    elif datatype == DataType.BOOL:
        return tag + struct.pack(">B", 1 if value else 0)
    elif datatype == DataType.USINT or datatype == DataType.BYTE:
        return tag + struct.pack(">B", value)
    elif datatype == DataType.UINT or datatype == DataType.WORD:
        return tag + struct.pack(">H", value)
    elif datatype == DataType.UDINT:
        return tag + encode_uint32_vlq(value)
    elif datatype == DataType.DWORD:
        return tag + struct.pack(">I", value)  # fixed 4-byte, not VLQ
    elif datatype == DataType.ULINT:
        return tag + encode_uint64_vlq(value)
    elif datatype == DataType.LWORD:
        return tag + struct.pack(">Q", value)  # fixed 8-byte, not VLQ
    elif datatype == DataType.SINT:
        return tag + struct.pack(">b", value)
    elif datatype == DataType.INT:
        return tag + struct.pack(">h", value)
    elif datatype == DataType.DINT:
        return tag + encode_int32_vlq(value)
    elif datatype == DataType.LINT:
        return tag + encode_int64_vlq(value)
    elif datatype == DataType.REAL:
        return tag + struct.pack(">f", value)
    elif datatype == DataType.LREAL:
        return tag + struct.pack(">d", value)
    elif datatype == DataType.TIMESTAMP:
        return tag + struct.pack(">Q", value)
    elif datatype == DataType.TIMESPAN:
        return tag + encode_int64_vlq(value)
    elif datatype == DataType.RID:
        return tag + struct.pack(">I", value)
    elif datatype == DataType.AID:
        return tag + encode_uint32_vlq(value)
    elif datatype == DataType.WSTRING:
        encoded: bytes = value.encode("utf-8")
        return tag + encode_uint32_vlq(len(encoded)) + encoded
    elif datatype == DataType.BLOB:
        return bytes(tag + encode_uint32_vlq(0) + encode_uint32_vlq(len(value)) + value)  # BlobRootId, length, data
    else:
        raise ValueError(f"Unsupported DataType for encoding: {datatype:#04x}")


# -- S7CommPlus request/response payload helpers --


def encode_object_qualifier(key_qualifier: int = 0, protocol_version: int = ProtocolVersion.V2) -> bytes:
    """Encode the S7CommPlus ObjectQualifier structure.

    This fixed structure is appended to GetMultiVariables and
    SetMultiVariables requests.

    Args:
        key_qualifier: Sequence number for KEY_QUALIFIER field. TIA Portal
            sets this to the current S7CommPlus sequence number.
        protocol_version: Initial protocol version negotiated with the PLC.
            V1-initial sessions use a fixed-width uint32; V2 sessions use a
            VLQ followed by a terminator byte.

    Reference: thomas-v2/S7CommPlusDriver/Core/S7p.cs EncodeObjectQualifier
    """
    result = bytearray()
    result += struct.pack(">I", Ids.OBJECT_QUALIFIER)
    # ParentRID = RID(0)
    result += encode_uint32_vlq(Ids.PARENT_RID)
    result += bytes([0x00, DataType.RID]) + struct.pack(">I", 0)
    # CompositionAID = AID(0)
    result += encode_uint32_vlq(Ids.COMPOSITION_AID)
    result += bytes([0x00, DataType.AID]) + encode_uint32_vlq(0)
    # KeyQualifier = UDInt(key_qualifier)
    result += encode_uint32_vlq(Ids.KEY_QUALIFIER)
    result += bytes([0x00, DataType.UDINT])
    if protocol_version == ProtocolVersion.V1:
        result += struct.pack(">I", key_qualifier)
    else:
        result += encode_uint32_vlq(key_qualifier)
        result += bytes([0x00])
    return bytes(result)


def encode_item_address(
    access_area: int,
    access_sub_area: int,
    lids: list[int] | None = None,
    symbol_crc: int = 0,
) -> tuple[bytes, int]:
    """Encode an S7CommPlus ItemAddress for variable access.

    Args:
        access_area: Access area ID (e.g., 0x8A0E0001 for DB1)
        access_sub_area: Sub-area ID (e.g., Ids.DB_VALUE_ACTUAL)
        lids: Additional LID values for sub-addressing
        symbol_crc: Symbol CRC (0 for no CRC check)

    Returns:
        Tuple of (encoded_bytes, field_count)

    Reference: thomas-v2/S7CommPlusDriver/ClientApi/ItemAddress.cs
    """
    if lids is None:
        lids = []
    result = bytearray()
    result += encode_uint32_vlq(symbol_crc)
    result += encode_uint32_vlq(access_area)
    result += encode_uint32_vlq(len(lids) + 1)  # +1 for AccessSubArea
    result += encode_uint32_vlq(access_sub_area)
    for lid in lids:
        result += encode_uint32_vlq(lid)
    field_count = 4 + len(lids)  # SymbolCrc + AccessArea + NumLIDs + AccessSubArea + LIDs
    return bytes(result), field_count


def encode_pvalue_blob(data: bytes) -> bytes:
    """Encode raw bytes as a BLOB PValue.

    PValue format: [flags:1][datatype:1][blob_root_id:VLQ][length:VLQ][data]
    """
    result = bytearray()
    result += bytes([0x00, DataType.BLOB])
    result += encode_uint32_vlq(0)  # BlobRootId (unused for plain byte blobs)
    result += encode_uint32_vlq(len(data))
    result += data
    return bytes(result)


@dataclass(frozen=True)
class PValueArray:
    """A write type sent as an array PValue of ``element``.

    PLCs take some types this way: a STRING as a USINT array of
    ``[max length, length, characters...]``, a WSTRING as a UINT array of the
    same shape, and a DATE_AND_TIME as its eight BCD bytes (see
    ``catalog._WRITE_FORMS``).
    """

    element: DataType


def encode_pvalue_array(element: DataType, data: bytes) -> bytes:
    """Encode raw big-endian elements as an array PValue of fixed-size ``element``."""
    size = _pvalue_element_size(element)
    if size == 0:
        raise ValueError(f"{DataType(element).name} arrays are not supported for writing")
    if len(data) % size:
        raise ValueError(f"{DataType(element).name} array data must be a multiple of {size} bytes, got {len(data)}")
    return bytes((0x10, element)) + encode_uint32_vlq(len(data) // size) + data


def encode_pvalue_typed(datatype: DataType, data: bytes) -> bytes:
    """Encode already-serialized value bytes with an explicit PValue type.

    Raw DB offsets do not carry enough metadata to infer the PLC datatype.
    Callers writing anything other than a byte-array/BLOB must therefore
    provide the type reported by the PLC's symbol information.
    """
    datatype = DataType(datatype)
    fixed_sizes = {
        DataType.BOOL: 1,
        DataType.USINT: 1,
        DataType.BYTE: 1,
        DataType.SINT: 1,
        DataType.UINT: 2,
        DataType.WORD: 2,
        DataType.INT: 2,
        DataType.UDINT: 4,
        DataType.DWORD: 4,
        DataType.DINT: 4,
        DataType.REAL: 4,
        DataType.ULINT: 8,
        DataType.LWORD: 8,
        DataType.LINT: 8,
        DataType.LREAL: 8,
        DataType.TIMESTAMP: 8,
        DataType.TIMESPAN: 8,
        DataType.RID: 4,
        DataType.AID: 4,
    }
    expected_size = fixed_sizes.get(datatype)
    if expected_size is not None and len(data) != expected_size:
        raise ValueError(f"{datatype.name} requires {expected_size} encoded bytes, got {len(data)}")
    if datatype == DataType.NULL and data:
        raise ValueError("NULL requires an empty value")

    result = bytearray((0x00, datatype))
    if datatype == DataType.BLOB:
        result += encode_uint32_vlq(0)  # BlobRootId
        result += encode_uint32_vlq(len(data))
    elif datatype in (DataType.WSTRING, DataType.S7STRING):
        result += encode_uint32_vlq(len(data))
    if datatype in (DataType.UDINT, DataType.AID):
        result += encode_uint32_vlq(int.from_bytes(data, "big"))
    elif datatype == DataType.ULINT:
        result += encode_uint64_vlq(int.from_bytes(data, "big"))
    elif datatype == DataType.DINT:
        result += encode_int32_vlq(int.from_bytes(data, "big", signed=True))
    elif datatype in (DataType.LINT, DataType.TIMESPAN):
        result += encode_int64_vlq(int.from_bytes(data, "big", signed=True))
    else:
        result += data
    return bytes(result)


def _pack_decoded(fmt: str, value: int) -> bytes:
    """Pack a value decoded from a VLQ, refusing one too large for ``fmt``.

    A VLQ can carry more bits than the fixed-width type it stands for, so a
    malformed PValue would otherwise surface as ``struct.error``.
    """
    try:
        return struct.pack(fmt, value)
    except struct.error as exc:
        raise ValueError(f"PValue value {value} does not fit {fmt}") from exc


def _is_packed_struct(struct_id: int) -> bool:
    """Whether a struct id marks a packed struct, whose members travel as one opaque blob."""
    return 0x90000000 < struct_id < 0x9FFFFFFF or 0x02000000 < struct_id < 0x02FFFFFF


def decode_blob_element(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """Decode a BLOB value after its PValue header.

    Root ids 0 and 1 are plain BLOBs. Root id 2 or more is a type-safe BLOB, whose 8-byte
    modification time and flags come before the length. No captured reply has used root id 1,
    so its layout is unconfirmed.

    Args:
        data: Response buffer
        offset: Position of the BLOB root id

    Returns:
        Tuple of (root_id, blob, bytes_consumed)

    Raises:
        ValueError: If the BLOB has unknown flags or is cut short.
    """
    root_id, consumed = decode_uint32_vlq(data, offset)
    if root_id > 1:
        if offset + consumed + 8 > len(data):
            raise ValueError("Truncated type-safe BLOB header")
        consumed += 8
        blob_flags, c = decode_uint32_vlq(data, offset + consumed)
        consumed += c
        if blob_flags not in (0x02, 0x03):
            # only 0x02 has been captured; 0x03 with the same layout is unverified
            raise ValueError(f"Unsupported type-safe BLOB flags: {blob_flags:#x}")
    length, c = decode_uint32_vlq(data, offset + consumed)
    consumed += c
    if offset + consumed + length > len(data):
        raise ValueError("Not enough data for a BLOB")
    return root_id, bytes(data[offset + consumed : offset + consumed + length]), consumed + length


def decode_pvalue_sparse_array(data: bytes, offset: int) -> tuple[list[tuple[int, bytes]], int]:
    """Decode a sparse array of BLOBs or WStrings into its elements.

    The elements are (key, element) pairs up to a key of 0. The ``LineComm`` attribute of a program
    EXPLORE and alarm texts send BLOB elements, and an object's comment sends WString elements; no
    other datatype has been seen in a sparse array. Keys come in no particular order. A repeated key
    has never been seen, so it is treated as a malformed reply. Every captured BLOB element had root
    id 0; an element with a type-safe root id is read with the type-safe header, which is unverified
    inside a sparse array.

    Args:
        data: Response buffer
        offset: Position of the PValue

    Returns:
        Tuple of ([(key, element data), ...] in the order sent, bytes_consumed)

    Raises:
        ValueError: If the PValue is not a sparse array of BLOBs or WStrings, repeats a key, or is cut short.
    """
    if offset + 2 > len(data) or ArrayKind.from_flags(data[offset]) is not ArrayKind.SPARSE:
        raise ValueError("Not a sparse array PValue")
    decoded = _decode_sparse_elements(data, offset + 2, data[offset + 1])
    if decoded is None:
        raise ValueError(f"Unsupported sparse array PValue datatype: {data[offset + 1]:#04x}")
    elements, consumed = decoded
    return elements, consumed + 2


def _decode_sparse_elements(data: bytes, offset: int, datatype: int) -> Optional[tuple[list[tuple[int, bytes]], int]]:
    """The (key, element) pairs of a sparse array, from just after its PValue header to its closing key.

    Returns None for a datatype not seen in a sparse array.
    """
    if datatype not in (DataType.BLOB, DataType.WSTRING):
        return None
    elements: list[tuple[int, bytes]] = []
    seen_keys: set[int] = set()
    consumed = 0
    while True:
        key, c = decode_uint32_vlq(data, offset + consumed)
        consumed += c
        if key == 0:
            return elements, consumed
        # keys are not expected in any order, only once each
        if key in seen_keys:
            raise ValueError(f"Repeated sparse array key {key}")
        seen_keys.add(key)
        if datatype == DataType.BLOB:
            _, element, c = decode_blob_element(data, offset + consumed)
            consumed += c
        else:
            length, c = decode_uint32_vlq(data, offset + consumed)
            consumed += c
            if offset + consumed + length > len(data):
                raise ValueError("Not enough data for a WString")
            element = bytes(data[offset + consumed : offset + consumed + length])
            consumed += length
        elements.append((key, element))


def decode_pvalue_to_bytes(data: bytes, offset: int) -> tuple[bytes, int]:
    """Decode a PValue from S7CommPlus response to raw bytes.

    Supports scalar types and BLOBs. Returns the raw big-endian bytes
    of the value regardless of type. A sparse array of BLOBs or WStrings returns its
    elements' data joined in order, without their keys; ``decode_pvalue_sparse_array``
    keeps them. A sparse array of any other datatype is not decoded.

    Args:
        data: Response buffer
        offset: Position of the PValue

    Returns:
        Tuple of (raw_bytes, bytes_consumed)

    Raises:
        ValueError: If the header, a length or other VLQ field, or a sparse array is cut short, or the
            PValue is a sparse array of a datatype other than BLOB or WString. A fixed-size value that is cut short
            is returned short.
    """
    if offset + 2 > len(data):
        raise ValueError("Not enough data for PValue header")

    kind = ArrayKind.from_flags(data[offset])
    datatype = data[offset + 1]
    consumed = 2

    if kind is ArrayKind.SPARSE:
        elements, consumed = decode_pvalue_sparse_array(data, offset)
        return b"".join(element for _, element in elements), consumed

    if kind in (ArrayKind.FIXED, ArrayKind.DYNAMIC):
        # Array: read count then elements
        count, c = decode_uint32_vlq(data, offset + consumed)
        consumed += c
        if datatype == DataType.BLOB:
            blobs = bytearray()
            for _ in range(count):
                _root_id, blob, c = decode_blob_element(data, offset + consumed)
                blobs += blob
                consumed += c
            return bytes(blobs), consumed
        elem_size = _pvalue_element_size(datatype)
        if elem_size > 0:
            raw = data[offset + consumed : offset + consumed + count * elem_size]
            consumed += count * elem_size
            return bytes(raw), consumed
        else:
            # Variable-length elements (VLQ encoded)
            result = bytearray()
            decode, encode = _vlq_element_codec(datatype)
            for _ in range(count):
                val, c = decode(data, offset + consumed)
                consumed += c
                result += encode(val)
            return bytes(result), consumed

    # Scalar types
    if datatype == DataType.NULL:
        return b"", consumed
    elif datatype == DataType.BOOL:
        return data[offset + consumed : offset + consumed + 1], consumed + 1
    elif datatype in (DataType.USINT, DataType.BYTE, DataType.SINT):
        return data[offset + consumed : offset + consumed + 1], consumed + 1
    elif datatype in (DataType.UINT, DataType.WORD, DataType.INT):
        return data[offset + consumed : offset + consumed + 2], consumed + 2
    elif datatype == DataType.UDINT:
        val, c = decode_uint32_vlq(data, offset + consumed)
        consumed += c
        return _pack_decoded(">I", val), consumed
    elif datatype == DataType.DWORD:
        # ValueDWord is a fixed 4-byte big-endian value, not VLQ.
        return data[offset + consumed : offset + consumed + 4], consumed + 4
    elif datatype in (DataType.DINT,):
        # Signed VLQ
        val, c = decode_int32_vlq(data, offset + consumed)
        consumed += c
        return _pack_decoded(">i", val), consumed
    elif datatype == DataType.REAL:
        return data[offset + consumed : offset + consumed + 4], consumed + 4
    elif datatype == DataType.LREAL:
        return data[offset + consumed : offset + consumed + 8], consumed + 8
    elif datatype == DataType.ULINT:
        val, c = decode_uint64_vlq(data, offset + consumed)
        consumed += c
        return _pack_decoded(">Q", val), consumed
    elif datatype == DataType.LWORD:
        # ValueLWord is a fixed 8-byte big-endian value, not VLQ.
        return data[offset + consumed : offset + consumed + 8], consumed + 8
    elif datatype in (DataType.LINT,):
        val, c = decode_int64_vlq(data, offset + consumed)
        consumed += c
        return _pack_decoded(">q", val), consumed
    elif datatype == DataType.TIMESTAMP:
        return data[offset + consumed : offset + consumed + 8], consumed + 8
    elif datatype == DataType.TIMESPAN:
        val, c = decode_int64_vlq(data, offset + consumed)
        consumed += c
        return _pack_decoded(">q", val), consumed
    elif datatype == DataType.RID:
        return data[offset + consumed : offset + consumed + 4], consumed + 4
    elif datatype == DataType.AID:
        val, c = decode_uint32_vlq(data, offset + consumed)
        consumed += c
        return _pack_decoded(">I", val), consumed
    elif datatype == DataType.BLOB:
        _root_id, blob, c = decode_blob_element(data, offset + consumed)
        return blob, consumed + c
    elif datatype in (DataType.WSTRING, DataType.S7STRING):
        length, c = decode_uint32_vlq(data, offset + consumed)
        consumed += c
        raw = data[offset + consumed : offset + consumed + length]
        consumed += length
        return bytes(raw), consumed
    elif datatype == DataType.STRUCT:
        # Struct value. Mirrors ValueStruct.Deserialize in the C# reference driver
        # (thomas-v2/S7CommPlusDriver, Core/PValue.cs).
        #
        # The leading struct id is a fixed UInt32 (not VLQ). Two transmission forms:
        #
        #  * Packed struct — for system datatypes (DTL, optimized-DB structs, ...) whose
        #    members are sent as one opaque blob. Detected by the id falling in the ranges
        #    0x90000000..0x9fffffff or 0x02000000..0x02ffffff. Layout: UInt64 interface
        #    timestamp, VLQ transport flags, VLQ element count (a second count follows when
        #    the Count2Present flag, bit 10, is set), then `count` raw bytes. We return those
        #    raw bytes verbatim — the caller interprets them using the struct's member layout.
        #
        #  * Normal struct — members as [VLQ key][PValue], terminated by a key of 0.
        struct_id = int.from_bytes(data[offset + consumed : offset + consumed + 4], "big")
        consumed += 4

        if _is_packed_struct(struct_id):
            consumed += 8  # PackedStructInterfaceTimestamp (UInt64, fixed)
            transport_flags, c = decode_uint32_vlq(data, offset + consumed)
            consumed += c
            count, c = decode_uint32_vlq(data, offset + consumed)
            consumed += c
            if transport_flags & 0x400:  # Count2Present: a second count follows (a sender sets 0x400 only when it writes it)
                count, c = decode_uint32_vlq(data, offset + consumed)
                consumed += c
            raw = data[offset + consumed : offset + consumed + count]
            consumed += count
            return bytes(raw), consumed

        # Normal struct: concatenate member values, stopping at the 0 key terminator.
        result = bytearray()
        key, c = decode_uint32_vlq(data, offset + consumed)
        consumed += c
        while key > 0:
            val_bytes, c = decode_pvalue_to_bytes(data, offset + consumed)
            consumed += c
            result += val_bytes
            key, c = decode_uint32_vlq(data, offset + consumed)
            consumed += c
        return bytes(result), consumed
    else:
        raise ValueError(f"Unsupported PValue datatype: {datatype:#04x}")


def _pvalue_element_size(datatype: int) -> int:
    """Return the fixed byte size for a PValue array element, or 0 for variable-length.

    DWORD and LWORD elements are fixed-size, like their scalars. A CPU 1214C FW V4.2
    sent an ``Array[0..99] of DWord`` as ``10 0c 64`` followed by 100 four-byte
    elements (``de ad be ef ...``), which the VLQ reader cannot parse (#160). No
    LWORD array has been captured; it is assumed to follow its 8-byte scalar.
    """
    if datatype in (DataType.BOOL, DataType.USINT, DataType.BYTE, DataType.SINT):
        return 1
    elif datatype in (DataType.UINT, DataType.WORD, DataType.INT):
        return 2
    elif datatype in (DataType.REAL, DataType.DWORD):
        return 4
    elif datatype in (DataType.LREAL, DataType.TIMESTAMP, DataType.LWORD):
        return 8
    elif datatype in (DataType.RID,):
        return 4
    else:
        return 0  # Variable-length (VLQ encoded)


def _vlq_element_codec(datatype: int) -> tuple[Callable[[bytes, int], tuple[int, int]], Callable[[int], bytes]]:
    """Return the (decoder, encoder) for a variable-length array element of this type."""
    if datatype == DataType.ULINT:
        return decode_uint64_vlq, encode_uint64_vlq
    if datatype in (DataType.LINT, DataType.TIMESPAN):
        return decode_int64_vlq, encode_int64_vlq
    if datatype == DataType.DINT:
        return decode_int32_vlq, encode_int32_vlq
    return decode_uint32_vlq, encode_uint32_vlq


# -- PObject-tree parsing shared by the sync (S7CommPlusConnection) and async clients --


def skip_typed_value(data: bytes, offset: int, datatype: int, flags: int) -> int:
    """Skip over a typed value in the PObject tree (best-effort). Returns the new offset."""
    try:
        kind = ArrayKind.from_flags(flags)
    except ValueError:
        return offset  # like an unknown type: the value's layout is not known

    if kind is ArrayKind.SPARSE:
        decoded = _decode_sparse_elements(data, offset, datatype)
        if decoded is None:
            return offset  # like an unknown type: a datatype never seen in a sparse array
        return offset + decoded[1]

    if kind in (ArrayKind.FIXED, ArrayKind.DYNAMIC):
        if offset >= len(data):
            return offset
        count, consumed = decode_uint32_vlq(data, offset)
        offset += consumed
        if datatype == DataType.BLOB:
            for _ in range(count):
                _, _, consumed = decode_blob_element(data, offset)
                offset += consumed
            return offset
        elem_size = _pvalue_element_size(datatype)
        if elem_size > 0:
            offset += count * elem_size
        else:
            # Variable-length: skip each VLQ element.
            decode, _encode = _vlq_element_codec(datatype)
            for _ in range(count):
                if offset >= len(data):
                    break
                _, consumed = decode(data, offset)
                offset += consumed
        return offset

    if datatype == DataType.NULL:
        return offset
    elif datatype in (DataType.BOOL, DataType.USINT, DataType.BYTE, DataType.SINT):
        return offset + 1
    elif datatype in (DataType.UINT, DataType.WORD, DataType.INT):
        return offset + 2
    elif datatype in (DataType.UDINT, DataType.AID):
        _, consumed = decode_uint32_vlq(data, offset)
        return offset + consumed
    elif datatype == DataType.DINT:
        _, consumed = decode_int32_vlq(data, offset)
        return offset + consumed
    elif datatype == DataType.DWORD:
        return offset + 4  # fixed 4-byte, not VLQ
    elif datatype in (DataType.ULINT, DataType.LINT):
        _, consumed = decode_uint64_vlq(data, offset)
        return offset + consumed
    elif datatype == DataType.LWORD:
        return offset + 8  # fixed 8-byte, not VLQ
    elif datatype == DataType.REAL:
        return offset + 4
    elif datatype == DataType.LREAL:
        return offset + 8
    elif datatype == DataType.TIMESTAMP:
        return offset + 8
    elif datatype == DataType.TIMESPAN:
        _, consumed = decode_uint64_vlq(data, offset)  # int64 VLQ
        return offset + consumed
    elif datatype == DataType.RID:
        return offset + 4
    elif datatype == DataType.BLOB:
        _, _, consumed = decode_blob_element(data, offset)
        return offset + consumed
    elif datatype in (DataType.WSTRING, DataType.S7STRING):
        length, consumed = decode_uint32_vlq(data, offset)
        return offset + consumed + length
    elif datatype == DataType.STRUCT:
        struct_id = int.from_bytes(data[offset : offset + 4], "big")
        offset += 4  # struct id (UInt32, not VLQ)
        if _is_packed_struct(struct_id):
            # Same layout as in decode_pvalue_to_bytes.
            offset += 8  # PackedStructInterfaceTimestamp (UInt64, fixed)
            transport_flags, consumed = decode_uint32_vlq(data, offset)
            offset += consumed
            count, consumed = decode_uint32_vlq(data, offset)
            offset += consumed
            if transport_flags & 0x400:  # Count2Present: a second count follows (a sender sets 0x400 only when it writes it)
                count, consumed = decode_uint32_vlq(data, offset)
                offset += consumed
            return offset + count
        # Normal-mode struct: UInt32 struct-id, then members [VLQ key][typed value],
        # terminated by a 0x00 list-terminator byte (keys always start with high bit set).
        while offset < len(data):
            if data[offset] == 0x00:
                offset += 1
                break
            _key, consumed = decode_uint32_vlq(data, offset)
            offset += consumed
            if offset + 2 > len(data):
                break
            sub_flags = data[offset]
            sub_type = data[offset + 1]
            offset += 2
            offset = skip_typed_value(data, offset, sub_type, sub_flags)
        return offset
    else:
        # Unknown type, cannot skip reliably. Callers stop walking here. When
        # this fires on real traffic, capture the frame: a new datatype shows
        # up first as a gap in this function.
        return offset


def parse_create_object_session_id(body: bytes) -> tuple[list[int], int, int]:
    """Parse a CreateObject response body (after the 10-byte response header).

    Body layout: ReturnValue (UInt64 VLQ) + ObjectIdCount (1 byte) + ObjectIds (UInt32 VLQ
    each). The usable session id is ``ObjectIds[0]`` (not the header SessionId field).

    Returns ``(object_ids, offset, return_value)`` where ``offset`` points just past the ObjectIds.
    """
    return_value, consumed = decode_uint64_vlq(body, 0)
    boff = consumed
    obj_count = body[boff] if boff < len(body) else 0
    boff += 1
    object_ids: list[int] = []
    for _ in range(obj_count):
        oid, c = decode_uint32_vlq(body, boff)
        boff += c
        object_ids.append(oid)
    return object_ids, boff, return_value


class CreateObjectAttributes:
    """Attributes parsed from a CreateObject response PObject tree."""

    __slots__ = (
        "server_session_version",
        "public_key_fingerprint",
        "session_challenge",
        "server_session_role",
        "server_session_roles",
    )

    def __init__(self) -> None:
        self.server_session_version: Optional[bytes] = None
        self.public_key_fingerprint: Optional[str] = None
        self.session_challenge: Optional[bytes] = None
        self.server_session_role: Optional[int] = None
        self.server_session_roles: Optional[int] = None


def parse_create_object_attributes(payload: bytes) -> CreateObjectAttributes:
    """Scan a CreateObject response payload for session-setup attributes.

    Extracts up to three attributes from the PObject tree:

    - ``306`` (ServerSessionVersion) — raw typed value echoed back in session setup.
    - ``233`` (ObjectVariableTypeName) — ``"FF:HHHHHHHHHHHHHHHH"`` public key
      fingerprint on V1-initial PLCs with SessionKey auth.
    - ``303`` (ServerSessionRequest) — 20-byte session challenge (USINT array)
      on V1-initial PLCs.

    Returns a :class:`CreateObjectAttributes` with whichever attributes were found.
    """
    from .protocol import DataType

    result = CreateObjectAttributes()
    offset = 0
    while offset < len(payload):
        tag = payload[offset]

        if tag == ElementID.ATTRIBUTE:
            offset += 1
            if offset >= len(payload):
                break
            attr_id, consumed = decode_uint32_vlq(payload, offset)
            offset += consumed

            if offset + 2 > len(payload):
                break
            flags = payload[offset]
            datatype = payload[offset + 1]

            if attr_id == ObjectId.SERVER_SESSION_VERSION:
                value_start = offset
                end = skip_typed_value(payload, offset + 2, datatype, flags)
                result.server_session_version = bytes(payload[value_start:end])
                offset = end

            elif attr_id == Ids.OBJECT_VARIABLE_TYPE_NAME and datatype == DataType.WSTRING:
                offset += 2
                length, consumed = decode_uint32_vlq(payload, offset)
                offset += consumed
                raw = bytes(payload[offset : offset + length])
                offset += length
                try:
                    text = raw.decode("utf-8")
                    if len(text) == 19 and text[2] == ":":
                        result.public_key_fingerprint = text
                except (UnicodeDecodeError, ValueError):
                    pass

            elif attr_id == 303 and result.session_challenge is None:
                is_array = bool(flags & 0x10)
                offset += 2
                if is_array and datatype == DataType.USINT:
                    count, consumed = decode_uint32_vlq(payload, offset)
                    offset += consumed
                    result.session_challenge = bytes(payload[offset : offset + count])
                    offset += count
                else:
                    offset = skip_typed_value(payload, offset, datatype, flags)

            elif attr_id in (SERVER_SESSION_ROLE_ID, SERVER_SESSION_ROLES_ID) and datatype == DataType.UDINT and not flags & 0x10:
                offset += 2
                try:
                    value, consumed = decode_uint32_vlq(payload, offset)
                except ValueError:
                    # Truncated value: leave the role unset and let the outer
                    # loop's bounds checks terminate the scan.
                    break
                offset += consumed
                if attr_id == SERVER_SESSION_ROLE_ID:
                    result.server_session_role = value
                else:
                    result.server_session_roles = value

            else:
                offset = skip_typed_value(payload, offset + 2, datatype, flags)

        elif tag == ElementID.START_OF_OBJECT:
            offset += 1
            if offset + 4 > len(payload):
                break
            offset += 4
            for _ in range(3):
                _, consumed = decode_uint32_vlq(payload, offset)
                offset += consumed

        elif tag == ElementID.TERMINATING_OBJECT:
            offset += 1
        elif tag == 0x00:
            offset += 1
        else:
            offset += 1

    return result


def parse_server_session_version(payload: bytes) -> Optional[bytes]:
    """Scan a CreateObject response payload for the ServerSessionVersion attribute (306).

    Returns the raw typed value (flags + datatype + data) to echo back during session
    setup, or ``None`` if the attribute is not present.

    .. deprecated:: Use :func:`parse_create_object_attributes` for new code.
    """
    return parse_create_object_attributes(payload).server_session_version
