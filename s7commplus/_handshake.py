"""The CreateObject and SessionSetup messages of connecting, without I/O.

Builders and parsers for the two handshake steps both clients run after the
COTP connection, and the V1 SessionKey blob that SessionSetup carries. They
moved here from the connection module, which re-exports them.
"""

from __future__ import annotations

import logging
import struct
from typing import Optional

from .codec import decode_header, encode_header, encode_object_qualifier
from .error import S7ConnectionError
from .legitimation import iter_struct_elements
from .protocol import DataType, FunctionCode, Ids, LegitimationId, ObjectId, Opcode, ProtocolVersion
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
