"""The request path both clients share: session state and framing, without I/O.

`S7CommPlusConnection` (synchronous) and `S7CommPlusAsyncClient` used to
carry their own copy of this code, and the copies drifted. Both now inherit
`SessionCore`: it numbers requests, splices in the IntegrityId, frames and
signs a request, and checks and unwraps its reply. Each client only does the
I/O around it: sending the frame, receiving the reply (reassembling a reply
split over several PDUs) and closing a session whose integrity check failed.

`SessionCore` reads and writes the session state as attributes of the
client, under the names both clients already used, so code and tests that
set that state directly keep working.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import struct
from typing import NamedTuple, Optional

from ._handshake import (
    _build_session_setup_frame,
    _encode_security_key_struct,
    _generate_session_key_blob,
    _log_create_object_return_value,
    _patch_plcsim_server_session_version,
    _session_setup_accepted,
)
from .codec import SERVER_SESSION_ROLE_SECURED_BIT, decode_header, encode_header, parse_create_object_attributes
from .error import S7ConnectionError, S7IntegrityError, S7ProtocolError
from .protocol import (
    FLAGS_34_FUNCTION_CODES,
    READ_FUNCTION_CODES,
    DataType,
    ElementID,
    FunctionCode,
    ObjectId,
    Opcode,
    ProtocolVersion,
)
from .v1_session_key.keys import KeyFamily
from .vlq import decode_uint32_vlq, decode_uint64_vlq, encode_uint32_vlq

# The request path logged under the connection module's name before it moved
# here; logging configuration and tests select it by that name.
logger = logging.getLogger("s7commplus.connection")


class _HexDump:
    """Formats bytes as spaced hex only when a log record is actually emitted."""

    __slots__ = ("_data",)

    def __init__(self, data: bytes) -> None:
        self._data = data

    def __str__(self) -> str:
        return self._data.hex(" ")


def _response_continues(frame: bytes) -> bool:
    """Whether a response PDU is not followed by its closing trailer, so more fragments follow.

    A PLC splits a response larger than its frame size (a GetMultiVariables of
    long strings, an Explore) over several PDUs and sends the ``0x72 <ver> 0x0000``
    trailer only after the last one. Reading just the first would truncate the
    result and leave the rest in the stream for the next request. Only the four
    bytes after the data that equal that trailer mark a complete response; anything
    else (no bytes, a partial trailer, the next fragment's header) is left to the
    reassembly path, which validates it.
    """
    try:
        version, data_length, consumed = decode_header(frame)
    except ValueError:
        return False
    end = consumed + data_length
    return bytes(frame[end : end + 4]) != struct.pack(">BBH", 0x72, version, 0x0000)


def _validate_response_header(response: bytes, expected_function: int, expected_sequence: int) -> int:
    """Validate that application data is the response to one outstanding request; return its function code."""
    if len(response) < 10:
        raise S7ConnectionError("Response too short")
    opcode = response[0]
    function = struct.unpack_from(">H", response, 3)[0]
    sequence = struct.unpack_from(">H", response, 7)[0]
    if opcode not in (Opcode.RESPONSE, Opcode.RESPONSE2):
        raise S7ProtocolError(f"Unexpected response opcode 0x{opcode:02X}")
    # A PLC may answer any failed request with the protocol's generic ERROR
    # function while retaining the request sequence number.
    if function not in (expected_function, FunctionCode.ERROR):
        raise S7ProtocolError(
            f"Response function mismatch: expected function=0x{expected_function:04X}, got function=0x{function:04X}"
        )
    if sequence != expected_sequence:
        raise S7ProtocolError(
            f"Response sequence mismatch: expected seq={expected_sequence}, got seq={sequence} for function=0x{function:04X}"
        )
    return int(function)


def _verify_v3_hmac(protected: bytes, verifier: bytes | hmac.HMAC) -> bytes:
    """Verify and remove the V3 HMAC prefix from application data."""
    if not protected:
        raise S7IntegrityError("Empty authenticated V3 frame")
    digest_length = protected[0]
    if digest_length != hashlib.sha256().digest_size:
        raise S7IntegrityError(f"Invalid V3 HMAC digest length: {digest_length}")
    if len(protected) < 1 + digest_length:
        raise S7IntegrityError("Truncated V3 HMAC digest")
    received_digest = protected[1 : 1 + digest_length]
    application_data = protected[1 + digest_length :]
    if isinstance(verifier, bytes):
        expected_digest = hmac.new(verifier[:24], application_data, hashlib.sha256).digest()
    else:
        verifier.update(application_data)
        expected_digest = verifier.digest()
    if not hmac.compare_digest(received_digest, expected_digest):
        raise S7IntegrityError("S7CommPlus response integrity check failed")
    return bytes(application_data)


def _frame_request(request: bytes, protocol_version: int, session_key: Optional[bytes]) -> bytes:
    """Wrap a request in its S7CommPlus frame.

    After SessionKey authentication every request uses V3 framing, with the
    HMAC-SHA256 of the request under the session key prepended.
    """
    if session_key is not None:
        digest = hmac.new(session_key[:24], request, hashlib.sha256).digest()
        frame_data = bytes([0x20]) + digest + request
        frame = encode_header(ProtocolVersion.V3, len(frame_data)) + frame_data
        return frame + struct.pack(">BBH", 0x72, ProtocolVersion.V3, 0x0000)
    frame = encode_header(protocol_version, len(request)) + request
    return frame + struct.pack(">BBH", 0x72, protocol_version, 0x0000)


def _v1_session_key_profile(override: Optional[bool], session_key: Optional[bytes], protocol_version: int) -> bool:
    """Whether the non-TLS V1 SessionKey request profile applies.

    Both PLCs validated on hardware (S7-1500 FW 2.6, S7-1200 FW V4.2) need it,
    so it is the default for every V1 SessionKey session; ``override=False``
    selects the classic layout instead. V2/V3 sessions never use it.
    """
    if session_key is None or protocol_version != ProtocolVersion.V1:
        return False
    return override is not False


def _integrity_id_follows_body(family: Optional[KeyFamily], function_code: int) -> bool:
    """Whether a V1 SessionKey response carries its IntegrityId after the body, not before it.

    PLCSIM Advanced does so for the set-side operations (SET/CREATE/DELETE_OBJECT).
    A CPU 1215C FW V4.2 starts its CreateObject response with the return value
    as well, and a CPU 1214C FW V4.2 its SetMultiVariables response (#136); other
    responses keep the existing handling, which is all that has been exercised
    on these CPUs.
    """
    if family == KeyFamily.PLCSIM:
        return True
    return family == KeyFamily.S7_1200 and function_code in (FunctionCode.CREATE_OBJECT, FunctionCode.SET_MULTI_VARIABLES)


def _strip_response_integrity_id(function_code: int, payload: bytes, session_key_active: bool, legacy_s7_1500: bool) -> bytes:
    """Remove the IntegrityId that leads SessionKey response payloads.

    The legacy S7-1500 profile keeps GET_MULTI_VARIABLES and EXPLORE payloads
    whole, because there the IntegrityId follows the body. A leading value too
    large for an IntegrityId is the return value of a PLC that sends it first,
    as a rejected S7-1215C legitimation does, so that payload stays whole too.
    """
    if legacy_s7_1500 and function_code in (FunctionCode.GET_MULTI_VARIABLES, FunctionCode.EXPLORE):
        return payload
    if session_key_active and len(payload) > 1:
        try:
            resp_iid, consumed = decode_uint32_vlq(payload, 0)
        except ValueError:
            logger.debug("  Response starts with a value that is not an IntegrityId; keeping it whole")
            return payload
        logger.debug("  Response IntegrityId: %d (%d bytes)", resp_iid, consumed)
        return payload[consumed:]
    return payload


class _PendingRequest(NamedTuple):
    """A request that `SessionCore._encode_request` framed, for sending and for checking its reply."""

    function_code: int
    sequence: int
    frame: bytes
    #: Which IntegrityId counter the request used: True for the read counter,
    #: False for the write counter, None when it carried no IntegrityId.
    reads: Optional[bool]


class SessionCore:
    """Session state and the request path over it, shared by the sync and async clients.

    Subclasses initialise the attributes below and call the methods from
    their own send-and-receive code; nothing here does I/O.
    """

    _session_id: int
    _sequence_number: int
    _protocol_version: int
    _session_key: Optional[bytes]
    _with_integrity_id: bool
    _integrity_id_read: int
    _integrity_id_write: int
    _legacy_s7_1500: Optional[bool]
    _v1_session_key_family: KeyFamily
    _last_raw_response_payload: Optional[bytes]
    _last_response_function: Optional[int]
    _tls_active: bool
    _subscription_container_id: int
    _server_session_version: Optional[bytes]
    _public_key_fingerprint: Optional[str]
    _public_key_checksum: Optional[bytes]
    _session_challenge: Optional[bytes]
    _server_session_role: Optional[int]
    _server_session_roles: Optional[int]
    _session_key_fingerprint_override: Optional[str]
    _v1_session_key_public_key: bytes

    @property
    def legacy_s7_1500(self) -> bool:
        """Whether the V1 SessionKey profile is active (automatic unless overridden)."""
        return _v1_session_key_profile(self._legacy_s7_1500, self._session_key, self._protocol_version)

    def _next_sequence_number(self) -> int:
        """Get next sequence number and increment."""
        seq = self._sequence_number
        self._sequence_number = (self._sequence_number + 1) & 0xFFFF
        return seq

    def _uses_integrity_id(self) -> bool:
        """Whether requests carry an IntegrityId: tracking is on, on a V2+ or SessionKey session.

        Tracking is switched on only for V2 sessions and once a SessionKey is
        accepted, so the version check changes nothing on a real session; it
        keeps a V1 session without a SessionKey from ever sending one.
        """
        return self._with_integrity_id and (self._protocol_version >= ProtocolVersion.V2 or self._session_key is not None)

    def _encode_request(self, function_code: int, payload: bytes, integrity_tail: int) -> _PendingRequest:
        """Number and frame one request; call `_request_sent` once its frame is sent.

        For V2+ with IntegrityId tracking enabled, the IntegrityId is spliced into
        the request payload just before its trailing fill bytes. Read vs write
        counters are selected based on the function code.

        Args:
            function_code: S7CommPlus function code
            payload: Request payload (after the 14-byte request header)
            integrity_tail: number of trailing payload bytes the V2 IntegrityId is
                inserted *before* — 4 for GetMultiVariables/SetMultiVariables (a
                trailing UInt32), 5 for Explore (a trailing UInt32 + filler byte).
        """
        seq_num = self._next_sequence_number()

        # Build request header (14 bytes)
        request_header = struct.pack(
            ">BHHHHIB",
            Opcode.REQUEST,
            0x0000,  # Reserved
            function_code,
            0x0000,  # Reserved
            seq_num,
            self._session_id,
            # Transport flags: 0x34 after SessionKey auth (matches TIA Portal),
            # and for the function codes the reference sends with 0x34.
            0x34 if self._session_key is not None or function_code in FLAGS_34_FUNCTION_CODES else 0x36,
        )

        reads: Optional[bool] = None
        integrity_id_bytes = b""
        if self._uses_integrity_id():
            reads = function_code in READ_FUNCTION_CODES
            integrity_id = self._integrity_id_read if reads else self._integrity_id_write
            integrity_id_bytes = encode_uint32_vlq(integrity_id)
            logger.debug(f"  IntegrityId: {'read' if reads else 'write'}={integrity_id}")

        # The IntegrityId is spliced in just before the payload's trailing fill bytes
        # (integrity_tail of them), not right after the header.
        if integrity_id_bytes and len(payload) >= integrity_tail:
            request = request_header + payload[:-integrity_tail] + integrity_id_bytes + payload[-integrity_tail:]
        else:
            request = request_header + integrity_id_bytes + payload

        logger.debug(f"=== SEND REQUEST === function_code=0x{function_code:04X} seq={seq_num} session=0x{self._session_id:08X}")
        logger.debug("  Request header (14 bytes): %s", _HexDump(request_header))
        if integrity_id_bytes:
            logger.debug("  IntegrityId (%d bytes): %s", len(integrity_id_bytes), _HexDump(integrity_id_bytes))
        logger.debug("  Request payload (%d bytes): %s", len(payload), _HexDump(payload))

        # After SessionKey auth, all data ops use V3 framing with HMAC
        frame = _frame_request(request, self._protocol_version, self._session_key)
        logger.debug("  Full frame (%d bytes): %s", len(frame), _HexDump(frame))
        return _PendingRequest(function_code, seq_num, frame, reads)

    def _request_sent(self, pending: _PendingRequest) -> None:
        """Advance the IntegrityId counter that ``pending`` used."""
        if pending.reads is True:
            self._integrity_id_read = (self._integrity_id_read + 1) & 0xFFFFFFFF
        elif pending.reads is False:
            self._integrity_id_write = (self._integrity_id_write + 1) & 0xFFFFFFFF

    def _decode_reassembled(self, pending: _PendingRequest, data: bytes) -> bytes:
        """Check a reply reassembled from several PDUs and return its payload."""
        if len(data) < 10:
            raise S7ConnectionError("Response too short")
        self._last_response_function = _validate_response_header(data, pending.function_code, pending.sequence)
        logger.debug(f"  Reassembled response ({len(data)} bytes), payload {len(data) - 10} bytes")
        return self._response_payload(pending.function_code, bytes(data[10:]))

    def _decode_response(self, pending: _PendingRequest, response_frame: bytes) -> bytes:
        """Check the one-PDU reply to ``pending`` and return its payload.

        Raises:
            S7IntegrityError: The reply of an authenticated session is not a V3
                frame, or its HMAC is wrong. The caller must then close the
                session: its stream can no longer be trusted.
        """
        logger.debug("=== RECV RESPONSE === raw frame (%d bytes): %s", len(response_frame), _HexDump(response_frame))

        # Parse frame header, use data_length to exclude trailer
        version, data_length, consumed = decode_header(response_frame)
        logger.debug(f"  Frame header: version=V{version}, data_length={data_length}, header_size={consumed}")

        if self._session_key is not None and version != ProtocolVersion.V3:
            raise S7IntegrityError(f"Authenticated response used unauthenticated frame version V{version}; reconnect")

        response = response_frame[consumed : consumed + data_length]

        # V3 responses have a hash-length byte + HMAC prefix before the payload.
        if version == ProtocolVersion.V3:
            if self._session_key is None:
                raise S7ConnectionError("V3 response received without a session key")
            response = _verify_v3_hmac(response, self._session_key)
            logger.debug("  V3 HMAC verified")

        logger.debug("  Response data (%d bytes): %s", len(response), _HexDump(response))

        self._last_response_function = _validate_response_header(response, pending.function_code, pending.sequence)

        # RESPONSE header is 10 bytes (opcode+res+func+res+seqnr+transport) — responses have
        # NO SessionId field (requests do, making their header 14 bytes). For V2+ the
        # IntegrityId travels at the END of the payload and is ignored by the parsers;
        # after SessionKey auth it leads the payload and is removed by _response_payload.
        logger.debug(
            "  Response header: opcode=0x%02X function=0x%04X seq=%d transport=0x%02X",
            response[0],
            struct.unpack_from(">H", response, 3)[0],
            struct.unpack_from(">H", response, 7)[0],
            response[9],
        )
        resp_payload = self._response_payload(pending.function_code, response[10:])
        logger.debug("  Response payload (%d bytes): %s", len(resp_payload), _HexDump(resp_payload))

        trailer = response_frame[consumed + data_length :]
        if trailer:
            logger.debug("  Trailer (%d bytes): %s", len(trailer), _HexDump(trailer))
        return resp_payload

    def _response_payload(self, function_code: int, payload: bytes) -> bytes:
        """Preserve legacy return values where IntegrityId follows the body."""
        self._last_raw_response_payload = payload
        if self.legacy_s7_1500 and _integrity_id_follows_body(self._v1_session_key_family, function_code):
            return payload
        return _strip_response_integrity_id(function_code, payload, self._session_key is not None, self.legacy_s7_1500)

    # --- Connecting: CreateObject and SessionSetup ---

    def _encode_create_object(self) -> _PendingRequest:
        """Frame the CreateObject request that opens an S7CommPlus session.

        Builds a NullServerSession CreateObject request matching the
        structure expected by S7-1200/1500 PLCs:

        Reference: thomas-v2/S7CommPlusDriver CreateObjectRequest.SetNullServerSessionData()
        """
        seq_num = self._next_sequence_number()

        # Build CreateObject request header
        request = struct.pack(
            ">BHHHHIB",
            Opcode.REQUEST,
            0x0000,
            FunctionCode.CREATE_OBJECT,
            0x0000,
            seq_num,
            ObjectId.OBJECT_NULL_SERVER_SESSION,  # SessionId = 288 for initial setup
            0x36,  # Transport flags
        )

        # RequestId: ObjectServerSessionContainer (285)
        request += struct.pack(">I", ObjectId.OBJECT_SERVER_SESSION_CONTAINER)

        # RequestValue: ValueUDInt(0) = DatatypeFlags(0x00) + Datatype.UDInt(0x04) + VLQ(0)
        request += bytes([0x00, DataType.UDINT]) + encode_uint32_vlq(0)

        # u32 zero between RequestValue and the request object. Confirmed
        # against a golden TIA session CreateObject frame from independent
        # capture analysis: RequestId 285, ValueUDInt(0), then this u32
        # padding, all constant 0.
        request += struct.pack(">I", 0)

        # RequestObject: PObject for NullServerSession
        # StartOfObject
        request += bytes([ElementID.START_OF_OBJECT])
        # RelationId: GetNewRIDOnServer (211)
        request += struct.pack(">I", ObjectId.GET_NEW_RID_ON_SERVER)
        # ClassId: ClassServerSession (287), VLQ encoded
        request += encode_uint32_vlq(ObjectId.CLASS_SERVER_SESSION)
        # ClassFlags: 0
        request += encode_uint32_vlq(0)
        # AttributeId: None (0)
        request += encode_uint32_vlq(0)

        # ServerSession attributes: full TIA-Portal-style identification.
        # V1-initial S7-1200 firmware (e.g. FW v4.2.x) only returns
        # ServerSessionVersion in its CreateObject response when the client
        # introduces itself with this fuller attribute set; minimal requests
        # (ClientRID only) get an incomplete session. See GH-712.
        def _wstring_attr(attr_id: int, s: str) -> bytes:
            data = s.encode("utf-8")
            return (
                bytes([ElementID.ATTRIBUTE])
                + encode_uint32_vlq(attr_id)
                + bytes([0x00, DataType.WSTRING])
                + encode_uint32_vlq(len(data))
                + data
            )

        client_id = "s7commplus"
        request += _wstring_attr(233, client_id)  # ObjectVariableTypeName / class name
        request += _wstring_attr(289, f"1:::6.0::{client_id}")  # network interface info
        request += _wstring_attr(296, client_id)  # project name
        request += _wstring_attr(297, "")
        request += _wstring_attr(298, client_id)  # hostname
        # 299: UDInt(1)
        request += bytes([ElementID.ATTRIBUTE]) + encode_uint32_vlq(299)
        request += bytes([0x00, DataType.UDINT]) + encode_uint32_vlq(1)
        # 300: ServerSessionClientRID
        request += bytes([ElementID.ATTRIBUTE])
        request += encode_uint32_vlq(ObjectId.SERVER_SESSION_CLIENT_RID)
        request += bytes([0x00, DataType.RID]) + struct.pack(">I", 0x80C3C901)
        request += _wstring_attr(301, "")

        # Nested object: ClassSubscriptions, with required class-name attribute
        request += bytes([ElementID.START_OF_OBJECT])
        request += struct.pack(">I", ObjectId.GET_NEW_RID_ON_SERVER)
        request += encode_uint32_vlq(ObjectId.CLASS_SUBSCRIPTIONS)
        request += encode_uint32_vlq(0)  # ClassFlags
        request += encode_uint32_vlq(0)  # AttributeId
        request += _wstring_attr(233, "SubscriptionContainer")
        request += bytes([ElementID.TERMINATING_OBJECT])

        # End outer object
        request += bytes([ElementID.TERMINATING_OBJECT])

        # Trailing padding
        request += struct.pack(">I", 0)

        # Wrap in S7CommPlus frame header + trailer
        frame = encode_header(ProtocolVersion.V1, len(request)) + request
        # S7CommPlus trailer (end-of-frame marker)
        frame += struct.pack(">BBH", 0x72, ProtocolVersion.V1, 0x0000)
        logger.debug("=== CreateObject === sending (%d bytes): %s", len(frame), _HexDump(frame))
        return _PendingRequest(FunctionCode.CREATE_OBJECT, seq_num, frame, None)

    def _apply_create_object_reply(self, response_frame: bytes) -> None:
        """Take the session id, protocol version and session attributes from the CreateObject reply."""
        logger.debug("=== CreateObject === received (%d bytes): %s", len(response_frame), _HexDump(response_frame))

        # Parse S7CommPlus frame header
        version, data_length, consumed = decode_header(response_frame)
        response = response_frame[consumed:]

        logger.debug(f"CreateObject response: version=V{version}, data_length={data_length}")
        logger.debug("CreateObject response body (%d bytes): %s", len(response), _HexDump(response))

        if len(response) < 10:
            raise S7ConnectionError("CreateObject response too short")

        # Response header is 10 bytes: opcode(1)+reserved(2)+func(2)+reserved(2)+seq(2)+transport(1).
        # Responses do NOT carry a SessionId field (unlike requests which are 14 bytes).
        resp_opcode = response[0]
        resp_func = struct.unpack_from(">H", response, 3)[0]
        resp_seq = struct.unpack_from(">H", response, 7)[0]
        resp_transport = response[9]

        offset = 10
        return_value, consumed = decode_uint64_vlq(response, offset)
        offset += consumed
        if offset >= len(response):
            raise S7ConnectionError("CreateObject response truncated before ObjectIdCount")
        object_id_count = response[offset]
        offset += 1
        object_ids: list[int] = []
        for _ in range(object_id_count):
            obj_id, consumed = decode_uint32_vlq(response, offset)
            offset += consumed
            object_ids.append(obj_id)

        if not object_ids:
            raise S7ConnectionError("CreateObject response has no session ObjectId")

        # First ObjectId is the session; the second is its subscription container.
        self._session_id = object_ids[0]
        self._subscription_container_id = object_ids[1] if len(object_ids) > 1 else 0
        self._protocol_version = version

        logger.debug(
            f"CreateObject response header: opcode=0x{resp_opcode:02X} function=0x{resp_func:04X} "
            f"seq={resp_seq} transport=0x{resp_transport:02X}"
        )
        logger.debug(f"CreateObject response: return_value={return_value} object_ids={[hex(i) for i in object_ids]}")
        logger.debug(f"Session created: id=0x{self._session_id:08X} ({self._session_id}), version=V{version}")

        _log_create_object_return_value(return_value, self._tls_active)

        # Parse remaining payload (the ResponseObject tree) for session attributes
        attrs = parse_create_object_attributes(response[offset:])
        self._server_session_version = attrs.server_session_version
        if self._server_session_version is not None:
            logger.info(f"ServerSessionVersion captured ({len(self._server_session_version)} bytes)")
        else:
            logger.debug("ServerSessionVersion not found in CreateObject response")
        if attrs.public_key_fingerprint is not None:
            self._public_key_fingerprint = attrs.public_key_fingerprint
            self._public_key_checksum = bytes.fromhex(attrs.public_key_fingerprint[3:])
            logger.info(f"Public key fingerprint captured: {attrs.public_key_fingerprint}")
        if attrs.session_challenge is not None:
            self._session_challenge = attrs.session_challenge
            logger.info(f"Session challenge captured ({len(attrs.session_challenge)} bytes)")
        if attrs.server_session_role is not None:
            self._server_session_role = attrs.server_session_role
            self._server_session_roles = attrs.server_session_roles
            if attrs.server_session_role & SERVER_SESSION_ROLE_SECURED_BIT:
                logger.info(
                    "ServerSession.Role bit 0x20000000 is set; observed on secured "
                    "(SessionKey-protected) PLCs in TIA Portal captures, so SessionKey "
                    "authentication is likely required"
                )

    def _try_session_key_auth(self) -> Optional[tuple[bytes, bytes]]:
        """Attempt to generate the SecurityKey authentication blob.

        Returns (blob, session_key) if we have the challenge and a matching
        public key, or None if any prerequisite is missing.
        """
        if self._tls_active or self._protocol_version != ProtocolVersion.V1:
            logger.debug("SessionKey auth: skipped for TLS/non-V1 session")
            return None

        if self._session_challenge is None:
            logger.debug("SessionKey auth: no challenge captured from CreateObject")
            return None

        if self._public_key_fingerprint is None:
            logger.debug("SessionKey auth: no public key fingerprint captured")
            return None

        fingerprint = self._session_key_fingerprint_override or self._public_key_fingerprint
        result = _generate_session_key_blob(self._session_challenge, fingerprint)
        if result is None:
            return None
        blob, session_key, self._v1_session_key_public_key, self._v1_session_key_family = result
        return blob, session_key

    def _encode_security_key_struct(self, blob: bytes, session_key: bytes) -> bytes:
        """Encode the SecurityKey struct for this connection's public key and family."""
        return _encode_security_key_struct(self._v1_session_key_public_key, self._v1_session_key_family, blob, session_key)

    def _encode_session_setup(self) -> Optional[tuple[_PendingRequest, Optional[tuple[bytes, bytes]]]]:
        """Frame the SetMultiVariables that echoes ServerSessionVersion back to the PLC.

        Always uses V2 framing, transport flags 0x34, and no IntegrityId.

        On V1-initial PLCs (FW < 4.5), this also includes the SecurityKey
        blob at address 1830, carrying a seed encrypted with an ECDH against
        the PLC's public key and the challenge encrypted under keys derived
        from that seed (see ``v1_session_key.real_plc.authenticator``).

        Returns:
            The request and the ``(blob, session_key)`` it carries, if any;
            ``None`` when the PLC sent no ServerSessionVersion to echo.
        """
        if self._server_session_version is None:
            return None

        auth_result = self._try_session_key_auth()
        security_key = None if auth_result is None else self._encode_security_key_struct(*auth_result)

        server_session_version = self._server_session_version
        if self._v1_session_key_family == KeyFamily.PLCSIM:
            # PLCSIM needs the real-PLC 315-318 values for the post-auth
            # legitimation to be accepted (see the helper).
            server_session_version = _patch_plcsim_server_session_version(server_session_version)

        seq_num = self._next_sequence_number()
        frame = _build_session_setup_frame(
            self._session_id,
            seq_num,
            server_session_version,
            self._protocol_version,
            security_key,
        )
        logger.debug("=== SetupSession === sending (%d bytes): %s", len(frame), _HexDump(frame))
        return _PendingRequest(FunctionCode.SET_MULTI_VARIABLES, seq_num, frame, None), auth_result

    def _apply_session_setup_reply(
        self, pending: _PendingRequest, auth_result: Optional[tuple[bytes, bytes]], response_frame: bytes
    ) -> bool:
        """Check the SessionSetup reply; on success, switch to the SessionKey in ``auth_result``, if any.

        Returns:
            True if session setup succeeded (return_value == 0).
        """
        logger.debug("=== SetupSession === received (%d bytes): %s", len(response_frame), _HexDump(response_frame))
        version, data_length, consumed = decode_header(response_frame)
        response = response_frame[consumed : consumed + data_length]
        if len(response) < 10:
            raise S7ConnectionError("SetupSession response too short")
        _validate_response_header(response, FunctionCode.SET_MULTI_VARIABLES, pending.sequence)
        if not _session_setup_accepted(response_frame):
            return False

        if auth_result is not None:
            self._session_key = auth_result[1]
            self._with_integrity_id = True
            self._integrity_id_read = 0
            self._integrity_id_write = 0
            logger.info("SecurityKey accepted by PLC, IntegrityId tracking enabled")
        logger.info("Session setup completed successfully")
        return True
