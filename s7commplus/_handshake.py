"""The messages of connecting and legitimating, without I/O.

Builders and parsers for the handshake steps both clients run after the
COTP connection (CreateObject, SessionSetup and the V1 SessionKey blob it
carries), and for password legitimation and the session-variable requests
it uses. They moved here from the connection module, which re-exports them.
"""

from __future__ import annotations

import logging
import struct
from typing import Callable, Optional

from .codec import decode_header, encode_header, encode_object_qualifier
from .error import S7AuthenticationError, S7ConnectionError
from .legitimation import iter_struct_elements
from .protocol import DataType, FunctionCode, Ids, LegitimationId, ObjectId, Opcode, ProtocolVersion, ServiceResult
from .v1_session_key.keys import KeyFamily
from .vlq import decode_uint32_vlq, decode_uint64_vlq, encode_uint32_vlq, encode_uint64_vlq

# Logged under the connection module's name, as before the move.
logger = logging.getLogger("s7commplus.connection")

# ServerSessionVersion elements 315-318. Echoing the PlcSim values back makes
# PLCSIM Advanced FW 2.8 accept the session and serve reads, but it then rejects
# the post-auth legitimation blob (the challenge/key derivation ends up wrong).
# The real-PLC (S7-1500) values are accepted for the setup *and* for the
# legitimation. Source: the S7-1500 session-setup capture in HarpoS7 (MIT),
# `HarpoS7.PoC/Packets/SetMultiVarsRequest.cs` (`S71500Data`, lines 40-42 at
# bonk-dev/HarpoS7@19411a7: 315/316 = 84 00, 317/318 = 84 81 82 40); verified
# live against PLCSIM Advanced V8 (#66).
_PLCSIM_SERVER_SESSION_VERSION_REWRITES: dict[int, bytes] = {
    315: bytes([0x84, 0x00]),
    316: bytes([0x84, 0x00]),
    317: bytes([0x84, 0x81, 0x82, 0x40]),
    318: bytes([0x84, 0x81, 0x82, 0x40]),
}


class SessionKeyAuthenticationDependencyError(S7ConnectionError):
    """Optional dependencies required for SessionKey authentication are absent."""


def _log_create_object_return_value(return_value: int, tls_active: bool) -> None:
    """Log a non-zero CreateObject status without guessing at TLS requirements."""
    if return_value == 0:
        return
    if tls_active:
        # Some firmware (e.g. S7-1200 FW V4.1) returns a non-zero value on a
        # usable TLS session, so keep this informational.
        logger.debug(
            "CreateObject returned non-zero 0x%X on an active TLS session; continuing to parse the returned session data",
            return_value,
        )
        return
    logger.warning(
        "CreateObject returned non-zero 0x%X; continuing to parse the returned session data",
        return_value,
    )


def _strip_paom_string_in_session_version(struct_bytes: bytes) -> bytes:
    """Replace element 319 in a captured ServerSessionVersion struct with an empty WString.

    The element is the device "PAOM string" (e.g. ``1;6ES7 215-1BG40-0XB0 ;V4.2``)
    that the PLC sends in its CreateObject response. Real PLCs reject the V2
    SetMultiVariables echo if we write that identity back verbatim — TIA
    Portal strips this element to empty before echoing, and the V1-initial
    S7-1200 drops the connection without it.

    The input is a captured raw typed value: ``[flags][0x17 STRUCT][4-byte ID]
    [...elements...][0x00 terminator]``. Element 319 is encoded as VLQ key
    ``0x82 0x3f`` followed by ``[flags][0x15 WSTRING][len VLQ][utf-8 bytes]``.
    """
    needle = bytes([0x82, 0x3F, 0x00, 0x15])
    idx = struct_bytes.find(needle)
    if idx < 0:
        return struct_bytes
    after_dtype = idx + len(needle)
    length, consumed = decode_uint32_vlq(struct_bytes, after_dtype)
    return struct_bytes[:after_dtype] + bytes([0x00]) + struct_bytes[after_dtype + consumed + length :]


def _patch_plcsim_server_session_version(struct_bytes: bytes) -> bytes:
    """Rewrite ServerSessionVersion elements 315-318 to the real-PLC values.

    PLCSIM Advanced rejects the post-auth legitimation when the setup echo carries
    the emulator's own 315-318 values; the S7-1500 values are needed for both the
    setup and the legitimation.

    The struct is walked at element boundaries (`iter_struct_elements`), so only
    real elements with those keys are rewritten — never lookalike bytes inside
    another element's value. The first element the walk cannot size (or the
    terminator) ends the rewrite and everything from there is copied verbatim.
    """
    out = bytearray()
    cursor = 0
    for element in iter_struct_elements(struct_bytes):
        replacement = _PLCSIM_SERVER_SESSION_VERSION_REWRITES.get(element.key)
        if replacement is None:
            continue
        out += struct_bytes[cursor : element.value_start]
        out += replacement
        cursor = element.end
    out += struct_bytes[cursor:]
    return bytes(out)


def _generate_session_key_blob(challenge: bytes, fingerprint: str) -> Optional[tuple[bytes, bytes, bytes, KeyFamily]]:
    """Build the SecurityKey blob for ``fingerprint``'s public key.

    Returns ``(blob, session_key, public_key, family)``, or ``None`` when the
    key is unknown or the blob cannot be built.
    """
    try:
        from .v1_session_key.keys import get_public_key, parse_fingerprint

        family, _key_id = parse_fingerprint(fingerprint)
        public_key = get_public_key(fingerprint)
        if public_key is None:
            logger.info(f"SessionKey auth: no matching public key for {fingerprint}")
            return None

        from .v1_session_key.handshake import authenticate_session_key

        blob, session_key = authenticate_session_key(challenge, public_key, family)
        logger.info(f"SessionKey auth blob generated with key {fingerprint} ({len(blob)} bytes)")
        return blob, session_key, public_key, family

    except ImportError as e:
        raise SessionKeyAuthenticationDependencyError(
            "Cannot load S7CommPlus SessionKey authentication dependencies. "
            "Install them with python -m pip install 's7commplus' "
            "(or python -m pip install -e '.[s7commplus]' for a source checkout). "
            f"Original error: {e}"
        ) from e
    except Exception as e:
        logger.warning(f"SessionKey auth failed: {e}")
        return None


def _encode_security_key_struct(public_key: bytes, family: KeyFamily, blob: bytes, session_key: bytes) -> bytes:
    """Encode the SecurityKey PObject struct (Struct 1800) wrapping the auth blob.

    Matches the wire format from TIA Portal / HarpoS7 PoC:
    Struct(1800) containing key descriptors for the public and symmetric
    keys, plus the encrypted blob.
    """
    from .v1_session_key.blob_metadata import get_public_key_flags, get_symmetric_key_flags
    from .v1_session_key.utils import derive_key_id

    if not public_key:
        raise ValueError("SessionKey authentication requires public key material")
    if not session_key:
        raise ValueError("SessionKey authentication requires generated session key material")

    public_key_id = derive_key_id(public_key)
    symmetric_key_id = derive_key_id(session_key)
    sym_flags = get_symmetric_key_flags(family)
    pub_flags = get_public_key_flags(family)

    # Inside a Struct, attributes are VLQ(absolute_id) + flags + type + value.
    # No 0xA3 tag prefix — that's only for PObject tree attributes.
    # Struct(1800): 1801=Version 1802=SecurityLevel 1803=PublicKey
    #               1804=SymmetricKey 1805=EncryptedKey
    # Struct(1825): 1826=KeyId 1827=KeyFlags 1828=InternalFlags

    def _udint_val(v: int) -> bytes:
        return bytes([0x00, DataType.UDINT]) + encode_uint32_vlq(v)

    def _usint_val(v: int) -> bytes:
        return bytes([0x00, DataType.USINT]) + bytes([v & 0xFF])

    def _ulint_val(v: int) -> bytes:
        return bytes([0x00, DataType.ULINT]) + encode_uint64_vlq(v)

    def _blob_val(data: bytes) -> bytes:
        return bytes([0x00, DataType.BLOB, 0x00]) + encode_uint32_vlq(len(data)) + data

    def _struct_begin(struct_id: int) -> bytes:
        return bytes([0x00, DataType.STRUCT]) + struct.pack(">I", struct_id)

    _STRUCT_END = bytes([0x00])

    def _key_descriptor(key_id: bytes, flags: int) -> bytes:
        key_id_int = int.from_bytes(key_id, byteorder="little", signed=False)
        out = _struct_begin(Ids.SECURITY_KEY_ID)
        out += encode_uint32_vlq(1826) + _ulint_val(key_id_int)  # KeyId
        out += encode_uint32_vlq(1827) + _udint_val(flags)  # KeyFlags
        out += encode_uint32_vlq(1828) + _udint_val(0)  # InternalFlags
        out += _STRUCT_END
        return out

    result = _struct_begin(Ids.STRUCT_SECURITY_KEY)
    result += encode_uint32_vlq(1801) + _udint_val(0)  # Version
    result += encode_uint32_vlq(1802) + _usint_val(0)  # SecurityLevel
    result += encode_uint32_vlq(1803) + _key_descriptor(public_key_id, pub_flags)  # PublicKey
    result += encode_uint32_vlq(1804) + _key_descriptor(symmetric_key_id, sym_flags | 0x10000)  # SymmetricKey
    result += encode_uint32_vlq(1805) + _blob_val(blob)  # EncryptedKey
    result += _STRUCT_END

    return result


def _build_session_setup_frame(
    session_id: int,
    sequence_number: int,
    server_session_version: bytes,
    protocol_version: int,
    security_key: Optional[bytes] = None,
) -> bytes:
    """Build the complete setup frame echoing ServerSessionVersion, optionally with the SecurityKey.

    Always uses V2 framing, transport flags 0x34, and no IntegrityId. On
    V1-initial PLCs the SecurityKey struct goes to address 1830 as a second
    item.
    """
    request = struct.pack(
        ">BHHHHIB",
        Opcode.REQUEST,
        0x0000,
        FunctionCode.SET_MULTI_VARIABLES,
        0x0000,
        sequence_number,
        session_id,
        0x34,
    )

    payload = bytearray()
    payload += struct.pack(">I", session_id)  # InObjectId

    if security_key is not None:
        payload += encode_uint32_vlq(2)  # ItemCount
        payload += encode_uint32_vlq(2)  # AddressCount
        payload += encode_uint32_vlq(LegitimationId.SESSION_SETUP_LEGITIMATION)  # 1830
        payload += encode_uint32_vlq(ObjectId.SERVER_SESSION_VERSION)  # 306
        payload += encode_uint32_vlq(1)  # ItemNumber for SecurityKey
        payload += security_key
        payload += encode_uint32_vlq(2)  # ItemNumber for ServerSessionVersion
    else:
        payload += encode_uint32_vlq(1)  # ItemCount
        payload += encode_uint32_vlq(1)  # AddressCount
        payload += encode_uint32_vlq(ObjectId.SERVER_SESSION_VERSION)  # 306
        payload += encode_uint32_vlq(1)  # ItemNumber

    # PValue: echo the ServerSessionVersion typed value verbatim (it may be a Struct).
    # Strip the PAOM device string (element 319) which V1-initial PLCs reject.
    payload += _strip_paom_string_in_session_version(server_session_version)

    payload += bytes([0x00])  # Fill byte
    payload += encode_object_qualifier(protocol_version=protocol_version)
    payload += struct.pack(">I", 0)  # Trailing padding

    request += bytes(payload)

    # Outer S7+ frame is always V2 for the setup write, even if the PLC
    # negotiated V1 on the initial CreateObject.
    frame = encode_header(ProtocolVersion.V2, len(request)) + request
    frame += struct.pack(">BBH", 0x72, ProtocolVersion.V2, 0x0000)
    return frame


def _session_setup_accepted(response_frame: bytes) -> bool:
    """Whether the PLC's response to the setup frame reports success."""
    version, data_length, consumed = decode_header(response_frame)
    response = response_frame[consumed : consumed + data_length]

    if len(response) < 10:
        raise S7ConnectionError("SetupSession response too short")

    resp_func = struct.unpack_from(">H", response, 3)[0]
    logger.debug(f"SetupSession response: function=0x{resp_func:04X}")

    # Parse return value from payload (data responses use a 10-byte header)
    resp_payload = response[10:]
    if len(resp_payload) >= 1:
        return_value, _ = decode_uint64_vlq(resp_payload, 0)
        if return_value != 0:
            logger.warning(f"SetupSession: PLC returned error {return_value}")
            return False
        return True
    return False


# --- Legitimation and other session requests ---

_LEGITIMATION_ACCEPTED = frozenset(
    {
        ServiceResult.OK,
        ServiceResult.SESSION_PRE_LEGITIMIZED,
        ServiceResult.SERVICE_LEGITIMATED_FOR_LEVEL1,
        ServiceResult.SERVICE_LEGITIMATED_FOR_LEVEL2,
        ServiceResult.SERVICE_LEGITIMATED_FOR_LEVEL3,
    }
)
_LEGITIMATION_REJECTED = frozenset(
    {
        ServiceResult.SERVICE_SESSION_DELEGITIMATED,
        ServiceResult.SERVICE_SESSION_DELEGITIMATED_LEGACY,
    }
)


def _build_get_var_substreamed_payload(
    in_object_id: int,
    address: int,
    key_qualifier: int = 0,
    sequence_field: int = 1,
    protocol_version: int = ProtocolVersion.V2,
) -> bytes:
    """Build the request set used by ``GetVarSubStreamedRequest``.

    The IntegrityId is inserted by :meth:`send_request` immediately before
    the final four-byte fill field.
    """
    payload = struct.pack(">I", in_object_id)
    payload += bytes([0x20, DataType.UDINT, 0x01])  # one-element address array
    payload += encode_uint32_vlq(address)
    payload += encode_object_qualifier(key_qualifier=key_qualifier, protocol_version=protocol_version)
    payload += struct.pack(">H", sequence_field)
    payload += struct.pack(">I", 0)  # fill
    return payload


def _response_pvalue_offset(payload: bytes, offset: int, supported: Callable[[int, int], bool]) -> int:
    """Locate a PValue directly after ReturnValue or after a zero marker."""
    if offset + 2 <= len(payload) and supported(payload[offset], payload[offset + 1]):
        return offset
    if payload[offset : offset + 1] == b"\x00":
        offset += 1
    if offset + 2 > len(payload):
        raise ValueError("missing PValue header")
    return offset


def _parse_get_var_substreamed_response(payload: bytes) -> bytes:
    """Extract the typed value from a GetVarSubStreamed response payload."""
    try:
        return_value, consumed = decode_uint64_vlq(payload, 0)
        if return_value != 0:
            raise S7ConnectionError(f"GetVarSubStreamed failed: return_value=0x{return_value:X}")

        offset = _response_pvalue_offset(
            payload,
            consumed,
            lambda flags, datatype: datatype == DataType.BLOB or (datatype == DataType.USINT and bool(flags & 0x10)),
        )
        flags = payload[offset]
        datatype = payload[offset + 1]
        offset += 2

        if datatype == DataType.BLOB:
            _blob_root_id, consumed = decode_uint32_vlq(payload, offset)
            offset += consumed
        elif datatype != DataType.USINT or not (flags & 0x10):
            raise ValueError(f"unsupported PValue flags=0x{flags:02X} datatype=0x{datatype:02X}")

        length, consumed = decode_uint32_vlq(payload, offset)
        offset += consumed
        end = offset + length
        if end > len(payload):
            raise ValueError(f"declared value length {length} exceeds response payload")
        return bytes(payload[offset:end])
    except S7ConnectionError:
        raise
    except (IndexError, ValueError) as exc:
        raise S7ConnectionError(f"Malformed GetVarSubStreamed response: {exc}") from exc


def _parse_protection_level_response(payload: bytes) -> int:
    """Extract the scalar UDInt value from a GetVarSubStreamed response payload."""
    try:
        return_value, offset = decode_uint64_vlq(payload, 0)
        if return_value != 0:
            raise S7ConnectionError(f"GetVarSubStreamed for the protection level failed: return_value={return_value}")

        offset = _response_pvalue_offset(
            payload,
            offset,
            lambda flags, datatype: datatype == DataType.UDINT and not flags & 0x10,
        )
        flags = payload[offset]
        datatype = payload[offset + 1]
        offset += 2

        if datatype != DataType.UDINT or flags & 0x10:
            raise ValueError(f"expected a scalar UDInt, got flags=0x{flags:02X} datatype=0x{datatype:02X}")

        value, _ = decode_uint32_vlq(payload, offset)
        return value
    except S7ConnectionError:
        raise
    except (IndexError, ValueError) as exc:
        raise S7ConnectionError(f"Malformed protection level response: {exc}") from exc


def _build_set_variable_payload(in_object_id: int, address: int, value: bytes) -> bytes:
    """Build a SetVariable request set around an already encoded PValue."""
    payload = struct.pack(">I", in_object_id)
    payload += encode_uint32_vlq(1)
    payload += encode_uint32_vlq(address)
    payload += value
    payload += encode_object_qualifier()
    # Byte after the ObjectQualifier in this plain SetVariable. Real PLCs
    # accept it (this legitimation path is field proven). Independent capture
    # analysis notes TIA's own SetMultiVariables carries no extra byte between
    # the KeyQualifier value and the 4 byte fill; the PLC parser tolerates
    # both shapes.
    payload += bytes([0x00])
    payload += struct.pack(">I", 0)  # fill; IntegrityId is inserted before it
    return payload


def _build_set_operating_state_payload(in_object_id: int, state: int) -> bytes:
    """Build the SetVariable body that writes CPUexecUnit.OperatingStateREQ (0x877).

    Reuses the plain SetVariable layout (:func:`_build_set_variable_payload`),
    targeting the CPUexecUnit object. The operating-state request value is
    carried as a USINT PValue, the same ``[flags][USINT][VLQ value]`` shape TIA
    Portal uses for the address-323 session activation.

    .. warning::

        The request layout, the USINT datatype of ``OperatingStateREQ`` and the
        :class:`~s7commplus.protocol.OperatingStateRequest` values are **not
        verified against a real PLC**; see
        https://github.com/gijzelaerr/s7commplus/issues/8.

    Args:
        in_object_id: RID of the CPUexecUnit object (``Ids.NATIVE_THE_CPU_EXEC_UNIT_RID``).
        state: Target operating state (an ``OperatingStateRequest`` value).

    Returns:
        Encoded SetVariable payload, ready for ``send_request(integrity_tail=4)``.
    """
    value = bytes([0x00, DataType.USINT]) + encode_uint32_vlq(state)
    return _build_set_variable_payload(in_object_id, Ids.CPU_EXEC_UNIT_OPERATING_STATE_REQ, value)


def _check_set_variable_response(payload: bytes, function: Optional[int] = None) -> None:
    """Raise when a SetVariable response reports a refused write.

    ``function`` is the response's function code. A generic ERROR frame is
    always a refusal, whatever its payload decodes to: its first value is the
    error function code, which has no sign bit.

    Reference: thomas-v2/S7CommPlusDriver/Legitimation/Legitimation.cs
    """
    if function == FunctionCode.ERROR:
        raise S7ConnectionError("SetVariable answered with the generic error function")
    if not payload:
        raise S7ConnectionError("SetVariable response is empty")
    try:
        return_value, _ = decode_uint64_vlq(payload, 0)
    except ValueError as exc:
        raise S7ConnectionError(f"Malformed SetVariable response: {exc}") from exc
    # The low 16 bits of the status word are a signed error code; the reference
    # driver casts them with (Int16) and rejects negatives, i.e. the sign bit.
    if return_value & 0x8000:
        raise S7ConnectionError(f"Legitimation rejected by PLC: return_value=0x{return_value:X}")


def _v1_integrity_tail(family: KeyFamily) -> int:
    """Trailing fill bytes of V1 SessionKey substreamed requests: 3 on the S7-1200, 4 on the S7-1500."""
    return 3 if family == KeyFamily.S7_1200 else 4


def _build_v1_get_var_substreamed_payload(
    family: KeyFamily, in_object_id: int, address: int, sequence_number: int, seq_field: int = 1
) -> bytes:
    """Build the family-specific GET_VAR_SUBSTREAMED layout captured on V1 SessionKey sessions.

    S7-1200 captures use the request's sequence number as a fixed-width
    ObjectQualifier, a VLQ request field, and a three-byte fill. S7-1500
    captures use a zero-valued VLQ qualifier, a two-byte request field, and a
    four-byte fill. The IntegrityId is inserted before that fill.
    """
    if family == KeyFamily.S7_1200:
        oq = encode_object_qualifier(key_qualifier=sequence_number, protocol_version=ProtocolVersion.V1)
        payload = struct.pack(">I", in_object_id)
        payload += bytes([0x20, DataType.UDINT])
        payload += encode_uint32_vlq(1)  # field count
        payload += encode_uint32_vlq(address)
        payload += oq
        payload += encode_uint32_vlq(seq_field)
        payload += bytes(3)  # fill
        return payload
    return _build_get_var_substreamed_payload(in_object_id, address, sequence_field=seq_field)


def _v1_legitimation_integrity_tail(family: KeyFamily) -> int:
    """Trailing fill bytes of the legitimation ``SET_VAR_SUBSTREAMED`` request.

    PLCSIM's layout leaves four bytes for the IntegrityId; the real-PLC layouts
    are unchanged from before (three), matching master.
    """
    return 4 if family == KeyFamily.PLCSIM else 3


def _build_v1_legitimation_payload(session_id: int, sequence_number: int, legitimation_blob: bytes, family: KeyFamily) -> bytes:
    """SET_VAR_SUBSTREAMED writing the solved legitimation blob to address 1846.

    Two layouts, chosen by key family. PLCSIM (family 03) needs the item intro
    without an item-number byte, an object qualifier with key qualifier 1, and a
    four-byte trailing fill (captured from HarpoS7). The real-PLC families keep
    the pre-existing layout byte-for-byte: an item-number byte after the
    qualifier, the sequence number as the key qualifier, and a ``VLQ(seq)`` plus
    three-byte fill — none of them has been seen with the PLCSIM layout, and the
    change must not silently alter their requests.
    """
    if family == KeyFamily.PLCSIM:
        oq = encode_object_qualifier(key_qualifier=1, protocol_version=ProtocolVersion.V1)
        payload = struct.pack(">I", session_id)
        payload += bytes([0x20, 0x04, 0x01])
        payload += encode_uint32_vlq(LegitimationId.LEGITIMATE)  # 1846
        payload += oq
        payload += bytes([0x00, DataType.BLOB, 0x00])
        payload += encode_uint32_vlq(len(legitimation_blob))
        payload += legitimation_blob
        payload += struct.pack(">I", 0)  # trailing fill (the IntegrityId is spliced before it)
        return payload

    oq = encode_object_qualifier(key_qualifier=sequence_number, protocol_version=ProtocolVersion.V1)
    payload = struct.pack(">I", session_id)
    payload += bytes([0x20, 0x04])
    payload += encode_uint32_vlq(1)  # ItemNumber
    payload += encode_uint32_vlq(LegitimationId.LEGITIMATE)  # 1846
    payload += oq
    payload += encode_uint32_vlq(1)  # ItemNumber for the value
    payload += bytes([0x00, DataType.BLOB, 0x00])
    payload += encode_uint32_vlq(len(legitimation_blob))
    payload += legitimation_blob
    payload += encode_uint32_vlq(sequence_number)
    payload += bytes(3)  # trailing fill (the IntegrityId is spliced before it)
    return payload


def _check_v1_legitimation_response(payload: bytes, raw_payload: Optional[bytes] = None) -> None:
    """Raise when the PLC rejects the legitimation blob.

    ``payload`` has had a leading IntegrityId stripped, but this PLC family may
    send the return value first, so the stripped bytes can start inside it.
    ``raw_payload`` is the response before stripping.

    Two readings are checked, in two passes:

    1. Any reading decoding to a negative value is a rejection — an
       IntegrityId never decodes as negative, so a negative is always the
       return value. This is the check ``master`` performs.
    2. Positive codes are only trusted from ``payload``, the return-value
       position: ``raw_payload`` may start with an IntegrityId, which is a
       positive number that could masquerade as any code. In that position
       the delegitimated code means the wrong password, and the level
       outcomes (already legitimized, legitimated to a level) mean success.
       When ``payload`` is empty or does not decode, there is no
       return-value reading at all, so no positive code is interpreted.
    """
    payload_reading: Optional[tuple[int, int]] = None  # (signed_value, raw_value) from payload
    for candidate in (raw_payload, payload):
        if not candidate:
            continue
        try:
            return_value, _ = decode_uint64_vlq(candidate, 0)
        except ValueError:
            continue
        signed = return_value if return_value < (1 << 63) else return_value - (1 << 64)
        if candidate is payload:
            payload_reading = (signed, return_value)
        if signed < 0:
            # Pass 1: a negative reading is always the return value, in either
            # reading position, and always a rejection.
            low = signed & 0xFFFF
            if (low - 0x10000 if low & 0x8000 else low) in _LEGITIMATION_REJECTED:
                raise S7AuthenticationError(
                    f"Post-auth legitimation rejected by PLC (wrong password): return_value=0x{return_value:X}"
                )
            raise S7ConnectionError(f"Post-auth legitimation rejected by PLC: return_value=0x{return_value:X}")

    if payload_reading is None:
        return

    # Pass 2: positive codes, only from the return-value reading of payload —
    # never from raw_payload, whose first value may be an IntegrityId.
    signed, return_value = payload_reading
    if signed in _LEGITIMATION_REJECTED:
        raise S7AuthenticationError(f"Post-auth legitimation rejected by PLC (wrong password): return_value=0x{return_value:X}")
    if signed in _LEGITIMATION_ACCEPTED:
        logger.debug("Legitimation response accepted (return_value=%d)", signed)


def _build_session_activate_payload(session_id: int, sequence_number: int) -> bytes:
    """SET_VARIABLE writing USINT(5) to address 323, which activates a V1 SessionKey session.

    TIA Portal sends this immediately after the SetupSession key exchange
    succeeds, before any data reads or legitimation. The payload matches frame
    17 of TIAPortalWatchDB7.pcapng from GH-710: the ObjectQualifier's
    KEY_QUALIFIER carries the request's sequence number as a 4-byte uint32, and
    the trailing section is 3 zero bytes (the IntegrityId is spliced before
    them).
    """
    oq = encode_object_qualifier(key_qualifier=sequence_number, protocol_version=ProtocolVersion.V1)

    payload = struct.pack(">I", session_id)
    payload += encode_uint32_vlq(1)  # AddressCount
    payload += encode_uint32_vlq(323)  # address
    payload += bytes([0x00, DataType.USINT])
    payload += encode_uint32_vlq(5)
    payload += oq
    payload += bytes(3)  # trailing zeros (IntegrityId spliced before these)
    return payload


def _renews_session_key(family: Optional[KeyFamily]) -> bool:
    """Whether a legacy session of this key family renews its SessionKey on a timer.

    Only a CPU 1214C FW V4.2 (key family 01) is known to accept the SecurityKey
    write to address 1830 on an established session (#169). S7-1500 CPUs (key
    family 00: 1512C-1 PN FW V2.5, 1517-3 PN/DP FW V2.9 and V3.0) refuse it with
    a fatal SystemEvent, request parsing error, and the connection is lost; a
    1517-3 FW V3.0 did so for six request layouts (#184). PLCSIM Advanced FW V2.8 (key family 03) resets
    the connection, with the SET_VARIABLE layout and with the session-setup
    SET_MULTI_VARIABLES one (#83). On those two a renewal would end the session
    it is meant to extend, so none is sent; the CPU ends the session when the
    key expires, after one hour on the 1517-3.
    """
    return family == KeyFamily.S7_1200
