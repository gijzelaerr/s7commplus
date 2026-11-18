"""
S7CommPlus connection management.

Establishes an ISO-on-TCP connection to S7-1200/1500 PLCs using the
S7CommPlus protocol, with support for all protocol versions:

- V1: Early S7-1200 (FW >= V4.0). Simple session handshake.
- V2: Adds integrity checking and session authentication.
- V3: Adds public-key-based key exchange.
- V3 + TLS: TIA Portal V17+. TLS 1.2 with per-device certificates.

The wire protocol (VLQ encoding, data types, function codes, object model) is
the same across all versions -- only the session authentication layer differs.

Connection sequence (all versions)::

    1. TCP connect to port 102
    2. COTP Connection Request / Confirm
       - Local TSAP: 0x0600
       - Remote TSAP: "SIMATIC-ROOT-HMI" (16-byte ASCII string)
    3. InitSSL request / response (unencrypted)
    4. TLS activation (for V3/TLS PLCs)
    5. S7CommPlus CreateObject request (NullServer session setup)
       - SessionId = ObjectNullServerSession (288)
       - Proper PObject tree with ServerSession class
    6. PLC responds with CreateObject response containing:
       - Protocol version (V1/V2/V3)
       - Session ID
       - Server session challenge (V2/V3)

Version-specific authentication after step 6::

    V1: No further authentication needed
    V2: Session key derivation and integrity checking
    V3 (no TLS): Public-key key exchange
    V3 (TLS): TLS 1.3 handshake is already done in step 4

Reference: thomas-v2/S7CommPlusDriver (C#, LGPL-3.0)
"""

import contextlib
import logging
import math
import ssl
import struct
import threading
import time
from collections import deque
from collections.abc import Mapping
from types import TracebackType
from typing import Any, Optional, Type

# The framing helpers moved to _session_core; the names stay importable from here.
from ._tls import (
    _OMS_EXPORTER_LABEL as _OMS_EXPORTER_LABEL,
    _OMS_EXPORTER_LENGTH as _OMS_EXPORTER_LENGTH,
    _S7_CIPHERS as _S7_CIPHERS,
    _S7_PREFERRED_GROUPS as _S7_PREFERRED_GROUPS,
    _derive_oms_secret as _derive_oms_secret,
    _hkdf_expand_label as _hkdf_expand_label,
    _set_s7_groups as _set_s7_groups,
    _tls13_exporter as _tls13_exporter,
    _tls_key_log as _tls_key_log,
    _verify_pinned_certificate as _verify_pinned_certificate,
)
from ._handshake import (
    _build_session_activate_payload as _build_session_activate_payload,
    _renews_session_key as _renews_session_key,
    _LEGITIMATION_ACCEPTED as _LEGITIMATION_ACCEPTED,
    _LEGITIMATION_REJECTED as _LEGITIMATION_REJECTED,
    _build_get_var_substreamed_payload as _build_get_var_substreamed_payload,
    _build_set_variable_payload as _build_set_variable_payload,
    _build_v1_get_var_substreamed_payload as _build_v1_get_var_substreamed_payload,
    _build_v1_legitimation_payload as _build_v1_legitimation_payload,
    _check_set_variable_response as _check_set_variable_response,
    _check_v1_legitimation_response as _check_v1_legitimation_response,
    _parse_get_var_substreamed_response as _parse_get_var_substreamed_response,
    _parse_protection_level_response as _parse_protection_level_response,
    _response_pvalue_offset as _response_pvalue_offset,
    _v1_integrity_tail as _v1_integrity_tail,
    _v1_legitimation_integrity_tail as _v1_legitimation_integrity_tail,
    SessionKeyAuthenticationDependencyError as SessionKeyAuthenticationDependencyError,
    _PLCSIM_SERVER_SESSION_VERSION_REWRITES as _PLCSIM_SERVER_SESSION_VERSION_REWRITES,
    _build_session_setup_frame as _build_session_setup_frame,
    _encode_security_key_struct as _encode_security_key_struct,
    _generate_session_key_blob as _generate_session_key_blob,
    _log_create_object_return_value as _log_create_object_return_value,
    _patch_plcsim_server_session_version as _patch_plcsim_server_session_version,
    _session_setup_accepted as _session_setup_accepted,
    _strip_paom_string_in_session_version as _strip_paom_string_in_session_version,
)
from ._session_core import (
    _Incoming as _Incoming,
    _ReplyWait as _ReplyWait,
    _SYSTEM_EVENT_RETURN_VALUE_ID as _SYSTEM_EVENT_RETURN_VALUE_ID,
    _MAX_STALE_RESPONSES_PER_REQUEST as _MAX_STALE_RESPONSES_PER_REQUEST,
    _MAX_SYSTEM_EVENTS_PER_RESPONSE as _MAX_SYSTEM_EVENTS_PER_RESPONSE,
    _check_system_event as _check_system_event,
    _incoming_frame_opcode as _incoming_frame_opcode,
    _incoming_response_sequence as _incoming_response_sequence,
    _is_stale_response_sequence as _is_stale_response_sequence,
    _system_event_return_value as _system_event_return_value,
    SessionCore as SessionCore,
    _HexDump as _HexDump,
    _frame_request as _frame_request,
    _integrity_id_follows_body as _integrity_id_follows_body,
    _response_continues as _response_continues,
    _strip_response_integrity_id as _strip_response_integrity_id,
    _v1_session_key_profile as _v1_session_key_profile,
    _validate_response_header as _validate_response_header,
    _verify_v3_hmac as _verify_v3_hmac,
)
from .transport import ISOTCPConnection
from .v1_session_key.keys import KeyFamily

from .codec import (
    SERVER_SESSION_ROLE_SECURED_BIT,
)
from .error import (
    S7CertificateError,
    S7ConnectionError,
    S7Error,
    S7IntegrityError,
    S7ProtocolError,
    S7TimeoutError,
    S7TlsHandshakeError,
)
from .legitimation import (
    extract_session_oms_version,
    oms_session_version_name,
)
from .protocol import (
    S7COMMPLUS_LOCAL_TSAP,
    remote_tsap_for_connection_type,
    DataType,
    FunctionCode,
    Ids,
    LegitimationType,
    Opcode,
    ProtocolVersion,
)
from .vlq import encode_uint32_vlq

logger = logging.getLogger(__name__)


class FamilyOnlyFingerprintError(S7ConnectionError):
    """A legacy PLC advertised only a public-key family identifier."""

    def __init__(self, family: int) -> None:
        self.family = family
        super().__init__(
            f"PLC advertised public-key family {family:02X} without a key id; "
            "connect through Client with allow_legacy_key_fallback enabled to probe known same-family keys"
        )


class SessionKeyCandidateRejectedError(S7ConnectionError):
    """The PLC rejected setup with one explicitly selected family key."""


_MAX_QUEUED_NOTIFICATION_FRAMES = 1000
_DEFAULT_LEGACY_SESSION_KEY_REFRESH_INTERVAL = 25 * 60.0
# Default seconds to wait for the reply to an EXPLORE, and for each further
# part of it. A CPU 1215C (FW V4.2, 6802 variables) took 5.9 to 7.0 s in total
# for the type-info EXPLORE of browse(), against at most 0.52 s for a
# GetMultiVariables.
_DEFAULT_EXPLORE_TIMEOUT = 30.0


def _check_timeout(name: str, value: Optional[float], *, optional: bool = True) -> None:
    """Reject a timeout that is not a positive, finite number of seconds (``None`` passes if ``optional``)."""
    if value is None and optional:
        return
    if value is None or not (math.isfinite(value) and value > 0):
        raise ValueError(f"{name} must be a positive, finite number of seconds{' or None' if optional else ''}")


# --- V1 SessionKey helpers, shared by S7CommPlusConnection and the async client. ---


def _resolve_session_key_fingerprint(public_key_fingerprint: Optional[str], override: Optional[str]) -> Optional[str]:
    """Return the key candidate to try, given the fingerprint the PLC advertised.

    A complete PLC fingerprint wins over any candidate, so the result is then
    ``None``. A family-only id needs a same-family candidate.

    Raises:
        FamilyOnlyFingerprintError: For a family-only id without a candidate.
        S7ConnectionError: For a candidate from another family.
    """
    if public_key_fingerprint is None:
        return override
    if ":" in public_key_fingerprint:
        return None

    from .v1_session_key.keys import parse_family_identifier, parse_fingerprint

    try:
        family = parse_family_identifier(public_key_fingerprint)
    except ValueError as exc:
        raise S7ConnectionError(str(exc)) from exc
    if override is None:
        raise FamilyOnlyFingerprintError(family)
    override_family, _ = parse_fingerprint(override)
    if override_family != family:
        raise S7ConnectionError(f"SessionKey candidate {override} does not belong to PLC family {family.value:02X}")
    return override


def _build_subscription_credit_frame(
    subscription_id: int,
    credit_limit: int,
    sequence: int,
    session_id: int,
    integrity_id: Optional[int],
    protocol_version: int,
    session_key: Optional[bytes],
) -> bytes:
    """Frame the fire-and-forget SetVariable that replenishes a subscription's credits.

    Shared by both clients, so a SessionKey session gets the same V3 framing and
    HMAC from either. ``integrity_id`` is the write counter, or ``None`` on a
    session without IntegrityIds.
    """
    if not 1 <= credit_limit <= 255:
        raise ValueError("credit_limit must be between 1 and 255")
    value = bytes([0x00, DataType.INT]) + struct.pack(">h", credit_limit)
    payload = _build_set_variable_payload(subscription_id, Ids.SUBSCRIPTION_CREDIT_LIMIT, value)
    header = struct.pack(">BHHHHIB", Opcode.REQUEST, 0, FunctionCode.SET_VARIABLE, 0, sequence, session_id, 0x74)
    integrity = encode_uint32_vlq(integrity_id) if integrity_id is not None else b""
    request = header + payload[:-4] + integrity + payload[-4:]
    return _frame_request(request, protocol_version, session_key)


def _write_delete_qualifier_version(family: Optional[KeyFamily], protocol_version: int, object_qualifier_version: int) -> int:
    """ObjectQualifier layout version of ``write_symbolic`` and the subscription deletes.

    PLCSIM Advanced V8 (key family 03) and the S7-1200 (key family 01) need the
    layout of the session's other data requests there too, V2 on a V1 SessionKey
    session. PLCSIM was found in #66. A CPU 1214C FW V4.2 resets the connection on
    a V1 delete and accepts a V2 one (#136). The data and the alarm subscription
    delete are the same DeleteObject of the session's subscription container, and
    the CPU refused the V1 alarm delete with a fatal SystemEvent as well (#136);
    ``write_symbolic`` is the same SetMultiVariables request as ``write_tags``,
    which that CPU accepts with V2. The S7-1500 keeps the negotiated protocol
    version, which these requests have always used and which hasn't been checked
    on hardware.
    """
    if family in (KeyFamily.PLCSIM, KeyFamily.S7_1200):
        return object_qualifier_version
    return protocol_version


def _alarm_texts_and_domain_filter(family: Optional[KeyFamily]) -> bool:
    """Whether an alarm subscription may send the domain filter and the text attributes.

    A CPU 1214C FW V4.2 (key family 01, no TLS) refuses an alarm subscription
    carrying ``AlarmDomainFilter`` (7731) and ``SendTexts``/``TextLanguages``
    (8173/8181) with ``INVALID_AID``, and accepts it without them (#173). Every
    other PLC keeps the S7-1500 reference layout.
    """
    return family != KeyFamily.S7_1200


def _request_frame_overhead(with_integrity_id: bool, session_key_active: bool) -> int:
    """Bytes a request frame adds to its payload, for sizing requests.

    The 4-byte frame header and 4-byte trailer, the 14-byte request header, the
    IntegrityId at its longest (a 5-byte VLQ) when the session sends one, and
    the V3 HMAC (a length byte and a 32-byte digest) after SessionKey
    authentication. TLS records, COTP and TPKT wrap the frame and are not
    counted.
    """
    return 4 + 14 + (5 if with_integrity_id else 0) + (1 + 32 if session_key_active else 0) + 4


def _sends_session_activation(family: Optional[KeyFamily]) -> bool:
    """Whether a V1 SessionKey session is activated with the address-323 SetVariable.

    PLCSIM Advanced V8 (#66) and a CPU 1215C FW V4.2 both reset the connection
    on the next CreateObject (a subscription) when the activation was sent,
    while reads keep working; without it they accept the subscription. S7-1500
    sessions keep the activation: whether they need it is not verified.
    """
    return family not in (KeyFamily.PLCSIM, KeyFamily.S7_1200)


def _parse_certificate_fingerprint(fingerprint: str) -> bytes:
    """Parse a SHA-256 TLS certificate fingerprint into its 32 raw bytes.

    Accepts hex with optional ``:``, ``-`` or whitespace separators (the format
    TIA Portal shows), and the whole line ``openssl x509 -fingerprint -sha256``
    prints (``sha256 Fingerprint=AA:BB:...``), so it is the value to pass as
    ``tls_cert_fingerprint`` on ``connect()``.

    Raises:
        ValueError: If the fingerprint is not exactly 32 bytes of hex.
    """
    value = fingerprint.rsplit("=", 1)[-1]
    cleaned = "".join(value.split()).replace(":", "").replace("-", "")
    if len(cleaned) != 64:
        raise ValueError("certificate fingerprint must be 64 hex characters (a SHA-256 digest)")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError("certificate fingerprint is not valid hex") from exc


def _check_certificate_pin(tls_cert_fingerprint: Optional[str], use_tls: bool) -> Optional[bytes]:
    """Parse a ``connect()`` pin and refuse it on a plaintext connection.

    Both clients call this before any network I/O, so a malformed pin, or a pin
    without TLS, fails the same way and before anything is sent.

    Raises:
        ValueError: If the pin is malformed, or given without ``use_tls``.
    """
    if tls_cert_fingerprint is None:
        return None
    expected = _parse_certificate_fingerprint(tls_cert_fingerprint)
    if not use_tls:
        raise ValueError("tls_cert_fingerprint requires use_tls=True: a pinned certificate must never be used in the clear")
    return expected


def _resolve_use_tls(use_tls: "bool | str") -> tuple[bool, bool]:
    """Split ``connect(use_tls=...)`` into (try TLS first, automatic mode).

    Accepts ``True``, ``False`` or ``"auto"``. Any other string is refused: a
    truthy ``"false"`` or ``"off"`` must not quietly turn TLS on.
    """
    if isinstance(use_tls, str):
        if use_tls != "auto":
            raise ValueError(f"use_tls must be True, False or 'auto', not {use_tls!r}")
        return True, True
    return bool(use_tls), False


def _plaintext_fallback_refusal(params: Mapping[str, Any]) -> Optional[str]:
    """Why ``use_tls="auto"`` must not continue without TLS, or None when it may.

    Any TLS setting the caller supplied, or a password, means the caller
    expects TLS, so a failed handshake is an error rather than a reason to
    talk to the PLC in the clear.
    """
    if params.get("tls_cert_fingerprint") is not None:
        return "a certificate is pinned (tls_cert_fingerprint)"
    if params.get("tls_ca") is not None:
        return "a CA certificate is configured (tls_ca)"
    if params.get("tls_cert") is not None or params.get("tls_key") is not None:
        return "a client certificate is configured (tls_cert/tls_key)"
    if params.get("password") is not None:
        return "a password is given"
    return None


def _check_plaintext_fallback(params: Mapping[str, Any], exc: S7TlsHandshakeError) -> None:
    """Allow ``use_tls="auto"`` to retry without TLS after ``exc``, or raise why not."""
    reason = _plaintext_fallback_refusal(params)
    if reason is not None:
        raise S7TlsHandshakeError(f"{exc}; use_tls='auto' does not fall back to plaintext because {reason}") from exc
    logger.warning(
        "TLS handshake with %s:%s did not complete (%s); continuing without TLS (use_tls='auto')",
        params.get("host"),
        params.get("port"),
        exc,
    )


class S7CommPlusConnection(SessionCore):
    """S7CommPlus connection with multi-version support.

    Wraps an ISOTCPConnection and adds:
    - S7CommPlus session establishment (CreateObject)
    - Protocol version detection from PLC response
    - Version-appropriate authentication (V1/V2/V3/TLS)
    - Frame send/receive (TLS-encrypted when using V17+ firmware)

    Sessions are V1 (optionally with the SessionKey handshake), V2 or V3,
    with password legitimation where the PLC asks for it.
    """

    def __init__(
        self,
        host: str,
        port: int = 102,
        *,
        legacy_s7_1500: bool | None = None,
        connection_type: int | str | None = None,
    ):
        self._legacy_s7_1500 = legacy_s7_1500
        self._last_raw_response_payload: Optional[bytes] = None
        self._last_response_function: Optional[int] = None
        self.host = host
        self.port = port

        self._iso_conn = ISOTCPConnection(
            host=host,
            port=port,
            local_tsap=S7COMMPLUS_LOCAL_TSAP,
            remote_tsap=remote_tsap_for_connection_type(connection_type),
        )

        self._ssl_context: Optional[ssl.SSLContext] = None
        self._ssl_object: Optional[ssl.SSLObject] = None
        self._incoming_bio: Optional[ssl.MemoryBIO] = None
        self._outgoing_bio: Optional[ssl.MemoryBIO] = None
        self._session_id: int = 0
        self._subscription_container_id: int = 0
        self._sequence_number: int = 0
        self._protocol_version: int = 0  # Detected from PLC response
        self._tls_active: bool = False
        self._session_ready = False
        self._connected = False
        # ServerSessionVersion is captured as its raw typed value (flags+datatype+data)
        # so it can be echoed back verbatim — real S7-1500 PLCs send it as a Struct.
        self._server_session_version: Optional[bytes] = None
        self._session_oms_version: Optional[tuple[int, Optional[int]]] = None
        self._session_oms_version_cache_key: Optional[bytes] = None
        self._session_setup_ok: bool = False
        # PLC-provided 8-byte public-key checksum (parsed from the
        # ObjectVariableTypeName "01:HEX" attribute in the CreateObject
        # response, e.g. "01:1A73081F096B42BD"). Used to look up the
        # matching Siemens public key for the SessionKey handshake.
        self._public_key_checksum: Optional[bytes] = None
        self._public_key_fingerprint: Optional[str] = None
        # ServerSession.Role from the CreateObject response; the
        # 0x20000000 bit marks a PLC that runs a secured session.
        self._server_session_role: Optional[int] = None
        self._server_session_roles: Optional[int] = None

        # 20-byte session challenge from CreateObject response, used
        # to generate the SecurityKeyEncryptedKey blob (pre-TLS auth).
        self._session_challenge: Optional[bytes] = None

        # Session key derived from the SessionKey handshake, used for
        # HMAC packet integrity after authentication.
        self._session_key: Optional[bytes] = None
        self._v1_session_key_public_key: bytes = b""
        self._v1_session_key_family = KeyFamily.S7_1500
        self._session_key_fingerprint_override: Optional[str] = None
        self._session_key_refresh_interval: Optional[float] = _DEFAULT_LEGACY_SESSION_KEY_REFRESH_INTERVAL
        self._session_key_refresh_timer: Optional[threading.Timer] = None
        self._session_key_refresh_generation = 0
        self._session_key_refresh_error: Optional[Exception] = None

        # V2+ IntegrityId tracking
        self._integrity_id_read: int = 0
        self._integrity_id_write: int = 0
        self._with_integrity_id: bool = False

        # TLS OMS exporter secret (for legitimation key derivation)
        self._oms_secret: Optional[bytes] = None

        # Pinned TLS certificate: the expected SHA-256 (set by connect) and the
        # one the PLC actually presented (captured during the handshake).
        self._tls_cert_fingerprint: Optional[bytes] = None
        self._peer_certificate_fingerprint: Optional[bytes] = None

        # Password for post-auth legitimation (V1-initial PLCs)
        self._connect_password: str = ""
        # Bound in seconds for one reply once the handshake is done, and the
        # time.monotonic() deadline of the handshake while connect() runs it.
        self._request_timeout = 5.0
        self._handshake_deadline: Optional[float] = None
        # The same bound for the reply to an EXPLORE, which can be large.
        self._explore_timeout = _DEFAULT_EXPLORE_TIMEOUT
        # Default wait in seconds for an unsolicited notification; None uses
        # the request timeout.
        self._notification_timeout: Optional[float] = None
        self._notification_frames: deque[bytes] = deque(maxlen=_MAX_QUEUED_NOTIFICATION_FRAMES)
        self._notification_frame_overflows = 0
        # Reentrant because integrity failures disconnect from inside a
        # serialized request. Disconnect itself also takes this lock so a
        # renewal cannot race transport teardown.
        self._request_lock = threading.RLock()

        # Effective protection level, read once the session is up
        self._protection_level: Optional[int] = None

    @property
    def connected(self) -> bool:
        return self._connected

    @property
    def protocol_version(self) -> int:
        """Protocol version negotiated with the PLC."""
        return self._protocol_version

    @property
    def session_id(self) -> int:
        """Session ID assigned by the PLC."""
        return self._session_id

    @property
    def subscription_container_id(self) -> int:
        """Object ID assigned to the session's subscription container."""
        return self._subscription_container_id

    @property
    def tls_active(self) -> bool:
        """Whether TLS encryption is active on this connection."""
        return self._tls_active

    @property
    def secured_session(self) -> bool:
        """Whether the PLC advertised a secured session requiring SessionKey auth.

        Read from the ServerSession.Role attribute of the CreateObject
        response (bit 0x20000000, observed set on secured PLCs in TIA Portal
        captures; not verified against a live PLC). ``False`` when the PLC did
        not report a role, which includes every PLC that does not implement
        the attribute.
        """
        return bool(self._server_session_role and self._server_session_role & SERVER_SESSION_ROLE_SECURED_BIT)

    @property
    def server_session_roles(self) -> Optional[int]:
        """The ServerSession.Roles mask (attribute 305), or ``None``.

        The mask of every role the session may take, as opposed to the single
        `Role` that `secured_session` reads. The individual bit meanings are
        not decoded; ``None`` when the PLC did not send the attribute.
        """
        return self._server_session_roles

    @property
    def integrity_id_read(self) -> int:
        """Current read IntegrityId counter (V2+)."""
        return self._integrity_id_read

    @property
    def integrity_id_write(self) -> int:
        """Current write IntegrityId counter (V2+)."""
        return self._integrity_id_write

    @property
    def session_setup_ok(self) -> bool:
        """Whether the session setup (ServerSessionVersion echo) succeeded."""
        return self._session_setup_ok

    @property
    def object_qualifier_version(self) -> int:
        """Protocol version whose ObjectQualifier layout data requests use.

        The opt-in non-TLS profile sends the V2 layout although the session
        negotiated V1; its PLCs reset the connection on the V1 layout.
        """
        return ProtocolVersion.V2 if self.legacy_s7_1500 else self._protocol_version

    @property
    def write_delete_qualifier_version(self) -> int:
        """ObjectQualifier layout version of ``write_symbolic`` and the subscription deletes.

        See ``_write_delete_qualifier_version``: PLCSIM and the S7-1200 use
        :attr:`object_qualifier_version`, the S7-1500 the negotiated protocol version.
        """
        return _write_delete_qualifier_version(self._v1_session_key_family, self._protocol_version, self.object_qualifier_version)

    @property
    def alarm_texts_and_domain_filter(self) -> bool:
        """Whether an alarm subscription may send the domain filter and texts; see ``_alarm_texts_and_domain_filter``."""
        return _alarm_texts_and_domain_filter(self._v1_session_key_family)

    @property
    def requires_substreamed(self) -> bool:
        """Whether data operations must use substreamed function codes.

        V1+SessionKey PLCs use GET_VAR_SUBSTREAMED for session-level ops
        (legitimation challenge/response) but accept GET_MULTI_VARIABLES
        for DB data reads — same as the thomas-v2 S7CommPlusDriver.
        V3+HMAC framing is controlled separately by session_key presence.
        """
        return False

    @property
    def oms_secret(self) -> Optional[bytes]:
        """OMS exporter secret from TLS session (for legitimation)."""
        return self._oms_secret

    @property
    def protection_level(self) -> Optional[int]:
        """Effective protection level reported by the PLC (see `AccessLevel`)."""
        return self._protection_level

    @property
    def session_oms_version(self) -> Optional[tuple[int, Optional[int]]]:
        """(SystemOMS, ProjectOMS) negotiated for the session, or ``None``.

        SystemOMS is the OMS session version (64..448, V1..V7) that gates
        which optional request fields the PLC understands. ProjectOMS is the
        version of the loaded project, where an explicit 0 means the
        controller has no project loaded; ``None`` means the PLC did not send
        element 316 at all. ``None`` for the whole tuple when the PLC sent no
        readable versions.
        """
        if self._server_session_version is None:
            return None
        if self._session_oms_version_cache_key is self._server_session_version:
            return self._session_oms_version
        versions = extract_session_oms_version(self._server_session_version)
        self._session_oms_version = versions
        self._session_oms_version_cache_key = self._server_session_version
        return versions

    def connect(
        self,
        timeout: float = 5.0,
        use_tls: bool = False,
        tls_cert: Optional[str] = None,
        tls_key: Optional[str] = None,
        tls_ca: Optional[str] = None,
        password: str = "",
        legacy_session_key_refresh_interval: Optional[float] = _DEFAULT_LEGACY_SESSION_KEY_REFRESH_INTERVAL,
        *,
        tls_cert_fingerprint: Optional[str] = None,
        request_timeout: Optional[float] = None,
        explore_timeout: Optional[float] = _DEFAULT_EXPLORE_TIMEOUT,
        notification_timeout: Optional[float] = None,
        _session_key_fingerprint: Optional[str] = None,
    ) -> None:
        """Establish S7CommPlus connection.

        The connection sequence:
        1. COTP connection (same as legacy S7comm)
        2. InitSSL handshake
        3. TLS activation (if use_tls=True, required for V2)
        4. CreateObject to establish S7CommPlus session
        5. Session setup (echo ServerSessionVersion)
        6. Enable IntegrityId tracking (V2+)

        Args:
            timeout: Connection timeout in seconds, bounding the TCP connect and
                steps 1-4 together.
            use_tls: Whether to activate TLS after InitSSL.
            tls_cert: Path to client TLS certificate (PEM)
            tls_key: Path to client private key (PEM)
            tls_ca: Path to CA certificate for PLC verification (PEM)
            tls_cert_fingerprint: Expected SHA-256 fingerprint of the PLC's TLS
                certificate, as hex (``:``/``-``/spaces allowed). The connection
                is refused unless the certificate the PLC presents matches it.
                Unlike ``tls_ca`` this pins the exact certificate, which is what
                a self-signed PLC certificate offers. Keyword-only; requires
                ``use_tls=True``.
            legacy_session_key_refresh_interval: Seconds between legacy
                SessionKey renewals. Defaults to 25 minutes; pass ``None`` to
                disable automatic renewal. Only an S7-1200 (key family 01)
                renews; an S7-1500 or PLCSIM session without TLS refuses the
                renewal, so none is sent and the PLC ends the session when
                the key expires (after one hour on a CPU 1517-3).
            request_timeout: Seconds to wait for the reply to each request
                after step 4 (and for each further part of a multi-part
                reply), or ``None`` to use ``timeout``. A reply that does not
                arrive in time raises ``S7TimeoutError`` and closes the session.
            explore_timeout: The same bound for the reply to an EXPLORE, whose
                answer can be large; 30 s by default, or ``None`` to use the
                request timeout.
            notification_timeout: Default wait in seconds of
                :meth:`receive_notification`, or ``None`` to use the request
                timeout.
        """
        if self._legacy_s7_1500 and use_tls:
            raise ValueError("legacy_s7_1500 requires use_tls=False")
        if legacy_session_key_refresh_interval is not None and legacy_session_key_refresh_interval <= 0:
            raise ValueError("legacy_session_key_refresh_interval must be positive or None")
        _check_timeout("timeout", timeout, optional=False)
        _check_timeout("request_timeout", request_timeout)
        _check_timeout("explore_timeout", explore_timeout)
        _check_timeout("notification_timeout", notification_timeout)
        self._session_key_refresh_interval = legacy_session_key_refresh_interval
        self._session_key_refresh_error = None
        self._connect_password = password
        self._session_key_fingerprint_override = _session_key_fingerprint
        self._tls_cert_fingerprint = _check_certificate_pin(tls_cert_fingerprint, use_tls)
        self._peer_certificate_fingerprint = None
        self._request_timeout = timeout if request_timeout is None else request_timeout
        self._explore_timeout = self._request_timeout if explore_timeout is None else explore_timeout
        self._notification_timeout = notification_timeout
        try:
            # Steps 1-4 share one deadline: the connect timeout bounds the
            # TCP connect and the whole handshake, as in the async client.
            self._handshake_deadline = time.monotonic() + timeout

            # Step 1: COTP connection (same TSAP for all S7CommPlus versions)
            self._iso_conn.connect(timeout)

            # Step 2: InitSSL handshake (required before CreateObject)
            self._init_ssl()

            # Step 3: TLS activation (between InitSSL and CreateObject)
            if use_tls:
                self._activate_tls(tls_cert=tls_cert, tls_key=tls_key, tls_ca=tls_ca)

            # Step 4: CreateObject (S7CommPlus session setup)
            # CreateObject always uses V1 framing
            self._create_session()

            # From here on every exchange is a request bounded by the request timeout.
            self._handshake_deadline = None
            self._iso_conn.set_request_timeout(self._request_timeout)

            self._session_key_fingerprint_override = _resolve_session_key_fingerprint(
                self._public_key_fingerprint, self._session_key_fingerprint_override
            )

            # After CreateObject (V1), data PDUs over TLS use ProtocolVersion V2 (matches C# driver)
            if self._tls_active:
                self._protocol_version = ProtocolVersion.V2

            # Step 5: Session setup - echo ServerSessionVersion back to PLC.
            # Transport establishment and CreateObject alone do not make the
            # public client usable.
            if self._server_session_version is None:
                raise S7ConnectionError(
                    "PLC did not provide a usable ServerSessionVersion attribute; S7CommPlus session setup cannot continue"
                )
            try:
                self._session_setup_ok = self._setup_session()
            except SessionKeyAuthenticationDependencyError:
                raise
            except Exception as exc:
                if self._session_key_fingerprint_override is not None:
                    raise SessionKeyCandidateRejectedError(
                        f"Session failed while trying SessionKey candidate {self._session_key_fingerprint_override}"
                    ) from exc
                raise
            if not self._session_setup_ok:
                if self._session_key_fingerprint_override is not None:
                    raise SessionKeyCandidateRejectedError(
                        f"PLC rejected SessionKey candidate {self._session_key_fingerprint_override}"
                    )
                raise S7ConnectionError("S7CommPlus session setup was rejected by the PLC")
            self._session_ready = True

            # Step 6: Version-specific post-setup
            if self._protocol_version >= ProtocolVersion.V3:
                if not use_tls:
                    logger.warning(
                        "PLC reports V3 protocol but TLS is not enabled. Connection may not work without use_tls=True."
                    )
            elif self._protocol_version == ProtocolVersion.V2:
                if not self._tls_active:
                    raise S7ConnectionError("PLC reports V2 protocol but TLS is not active. V2 requires TLS. Use use_tls=True.")
                # Enable IntegrityId tracking for V2+
                self._with_integrity_id = True
                self._integrity_id_read = 0
                self._integrity_id_write = 0
                logger.info("V2 IntegrityId tracking enabled")

            if self._session_key is not None and self._session_setup_ok:
                if _sends_session_activation(self._v1_session_key_family):
                    self._session_activate()
                else:
                    logger.info("Skipping the address-323 session activation for %s", self._v1_session_key_family)
                if self._connect_password:
                    self._post_auth_legitimation(password=self._connect_password)
                else:
                    logger.info("No PLC password supplied; skipping post-auth legitimation")
                self._skip_integrity_ids_after_legitimation()

            # Only a session that completed setup answers attribute reads; the
            # V1-initial band falls back to legacy PUT/GET and never gets here.
            if self._session_setup_ok:
                self._protection_level = self._get_effective_protection_level()
                if self._protection_level is not None:
                    logger.info(f"PLC reports protection level: {self._protection_level}")
                oms_versions = self.session_oms_version
                if oms_versions is not None:
                    system_oms, project_oms = oms_versions
                    logger.info(
                        f"OMS session version: system={oms_session_version_name(system_oms)}"
                        f" ({system_oms}), project={project_oms}"
                    )
                    if project_oms == 0:  # an explicit 0, not an absent element
                        logger.warning(
                            "Controller reports ProjectOMS 0: no project is loaded, so browsing and "
                            "symbolic access will find nothing"
                        )

            self._connected = True
            self._schedule_session_key_refresh()

            logger.info(
                f"S7CommPlus connected to {self.host}:{self.port}, "
                f"version=V{self._protocol_version}, session={self._session_id}, "
                f"tls={self._tls_active}"
            )

        except Exception:
            self._handshake_deadline = None
            self.disconnect()
            raise

    def authenticate(self, password: str, username: str = "") -> None:
        """Perform PLC password authentication (legitimation).

        Must be called after connect() and before data operations on
        password-protected PLCs. Requires TLS to be active (V2+).

        The method auto-detects legacy vs new legitimation based on
        the PLC's firmware version (stored in ServerSessionVersion).

        Args:
            password: PLC password
            username: Username for the new-mode exchange (leave empty for legacy)

        Raises:
            S7ConnectionError: If not connected, TLS is not active, the firmware
                does not support legitimation, or the password was refused
        """
        if not self._connected:
            raise S7ConnectionError("Not connected")
        plan = self._plan_legitimation(password)
        if plan is None:
            return
        mode, level_before = plan
        reply = self._legitimation_reply(mode, self._get_legitimation_challenge(), password, username)
        if mode is LegitimationType.LEGACY:
            self._send_legitimation_legacy(reply)
        else:
            self._send_legitimation_new(reply)
        self._legitimation_sent(mode)
        # Renewing the protection level is what verifies the outcome.
        self._protection_level = self._get_effective_protection_level()
        self._check_legitimation_outcome(level_before)

    def _get_effective_protection_level(self) -> Optional[int]:
        """Read the session's effective protection level (see `AccessLevel`), None if request failed."""
        try:
            reply = self.send_request(FunctionCode.GET_VAR_SUBSTREAMED, self._protection_level_payload(), integrity_tail=4)
            return _parse_protection_level_response(reply)
        except S7ConnectionError as exc:
            logger.warning(f"PLC did not report a protection level: {exc}")
            return None

    def _get_legitimation_challenge(self) -> bytes:
        """Request legitimation challenge from PLC.

        Sends GetVarSubStreamed with address ServerSessionRequest (303).

        Returns:
            Challenge bytes from PLC (typically 20 bytes)
        """
        reply = self.send_request(FunctionCode.GET_VAR_SUBSTREAMED, self._legitimation_challenge_payload(), integrity_tail=4)
        return _parse_get_var_substreamed_response(reply)

    def _send_legitimation_new(self, encrypted_response: bytes) -> None:
        """Send new-style legitimation response (AES-256-CBC encrypted).

        Uses SetVariable with address Legitimate (1846).
        """
        reply = self.send_request(FunctionCode.SET_VARIABLE, self._new_legitimation_payload(encrypted_response), integrity_tail=4)
        _check_set_variable_response(reply, self._last_response_function)

    def _send_legitimation_legacy(self, response: bytes) -> None:
        """Send legacy legitimation response (SHA-1 XOR).

        Uses SetVariable with address ServerSessionResponse (304).
        """
        reply = self.send_request(FunctionCode.SET_VARIABLE, self._legacy_legitimation_payload(response), integrity_tail=4)
        _check_set_variable_response(reply, self._last_response_function)

    def collect_explore_frames(self, first_payload: bytes) -> bytes:
        """Collect unauthenticated multi-fragment EXPLORE continuation frames.

        On V3 PLCs (FW >= V4.5) a large EXPLORE response (e.g. RID 0x8A11FFFF)
        spans multiple TPKT frames.  The first frame is the normal response
        (already stripped of its 10-byte header by send_request).  Continuation
        frames carry no response header. Authenticated callers must use
        ``send_request(..., reassemble=True)`` because this legacy helper no
        longer has the first frame bytes needed to verify cumulative digests.

        Termination: a ``frag_len == 0`` frame is the standard S7CommPlus
        end-of-stream trailer. As a fallback, a measurably shorter frame body is
        treated as the last fragment (5-byte tolerance).

        Collection is capped by ``_MAX_REASSEMBLED_FRAGMENTS`` and
        ``_MAX_REASSEMBLED_BYTES`` to prevent unbounded allocation on malformed
        or adversarial responses.

        Args:
            first_payload: First EXPLORE response payload, already returned by
                send_request() (10-byte response header already stripped).

        Returns:
            All fragment payloads concatenated (first_payload + continuations).
        """
        if self._session_key is not None:
            raise S7ProtocolError(
                "Authenticated Explore continuations require send_request(..., reassemble=True) so cumulative digests "
                "can be verified"
            )

        # The first frame body (already header-stripped) was originally
        # len(first_payload) + 10 bytes on the wire (10-byte response header).
        # Continuation frames of the same "full" size will be that long after
        # HMAC strip; a shorter body signals the last fragment.
        reference_size = len(first_payload) + 10
        all_data = first_payload
        fragment_count = 0
        while True:
            if len(all_data) > self._MAX_REASSEMBLED_BYTES or fragment_count >= self._MAX_REASSEMBLED_FRAGMENTS:
                raise S7ConnectionError(
                    f"collect_explore_frames: response too large ({len(all_data)} bytes, {fragment_count} fragments)"
                )
            try:
                raw = self._recv_s7_data(self._explore_timeout)
                if not raw:
                    break
                # Strip the 4-byte S7CommPlus fragment header (0x72 ver len:2)
                if len(raw) < 4 or raw[0] != 0x72:
                    break
                frag_len = (raw[2] << 8) | raw[3]
                if frag_len == 0:
                    break  # standard S7CommPlus end-of-stream trailer
                body = raw[4 : 4 + frag_len]
                if not body:
                    break
                all_data += body
                fragment_count += 1
                if len(body) < reference_size - 5:
                    break  # fallback: shorter-than-full frame signals last fragment
            except Exception:
                break
        return all_data

    def disconnect(self) -> None:
        """Disconnect from PLC."""
        self._stop_session_key_refresh()
        with self._request_lock:
            self._session_key_refresh_error = None
            self._disconnect()

    def _disconnect(self) -> None:
        """Clear connection state without changing a stored refresh failure."""
        if self._session_ready and self._session_id:
            try:
                self._delete_session()
            except Exception:
                pass

        self._connected = False
        self._session_ready = False
        self._session_setup_ok = False
        self._tls_active = False
        self._ssl_object = None
        self._incoming_bio = None
        self._outgoing_bio = None
        self._oms_secret = None
        self._session_id = 0
        self._subscription_container_id = 0
        self._sequence_number = 0
        self._protocol_version = 0
        self._server_session_version = None
        self._session_oms_version = None
        self._session_oms_version_cache_key = None
        self._public_key_checksum = None
        self._public_key_fingerprint = None
        self._server_session_role = None
        self._server_session_roles = None
        self._session_challenge = None
        self._session_key = None
        self._v1_session_key_public_key = b""
        self._v1_session_key_family = KeyFamily.S7_1500
        self._with_integrity_id = False
        self._integrity_id_read = 0
        self._integrity_id_write = 0
        self._protection_level = None
        self._notification_frames.clear()
        self._notification_frame_overflows = 0
        self._iso_conn.disconnect()

    def _invalidate_integrity_failure(self) -> None:
        """Discard authenticated state without writing to an untrusted stream."""
        self._session_ready = False
        self.disconnect()

    def _stop_session_key_refresh(self) -> None:
        """Cancel pending legacy SessionKey renewal activity."""
        self._session_key_refresh_generation += 1
        timer = self._session_key_refresh_timer
        self._session_key_refresh_timer = None
        if timer is not None:
            timer.cancel()

    def _schedule_session_key_refresh(self) -> None:
        """Schedule one renewal for an authenticated legacy session."""
        interval = self._renewal_interval()
        if interval is None:
            return
        generation = self._session_key_refresh_generation
        timer = threading.Timer(interval, self._session_key_refresh_callback, args=(generation,))
        timer.daemon = True
        self._session_key_refresh_timer = timer
        timer.start()

    def _session_key_refresh_callback(self, generation: int) -> None:
        """Renew under the request lock, or make a failed renewal terminal."""
        try:
            with self._request_lock:
                if generation != self._session_key_refresh_generation or not self._connected:
                    return
                self._session_key_refresh_timer = None
                self._renew_session_key_locked()
                if generation == self._session_key_refresh_generation:
                    self._schedule_session_key_refresh()
        except Exception as exc:
            failure = S7ConnectionError(f"Legacy SessionKey renewal failed: {exc}")
            logger.error("%s", failure)
            self._session_key_refresh_error = failure
            self._stop_session_key_refresh()
            self._session_ready = False
            self._session_id = 0
            self._disconnect()

    def _renew_session_key_locked(self) -> None:
        """Perform the challenge/SecurityKey exchange while the old key is active."""
        challenge_reply = self._send_request(FunctionCode.GET_VAR_SUBSTREAMED, self._renewal_challenge_payload(), 4, False)
        payload, new_session_key = self._renewal_request(challenge_reply)
        self._renewed(self._send_request(FunctionCode.SET_VARIABLE, payload, 4, False), new_session_key)

    def send_request(self, function_code: int, payload: bytes = b"", integrity_tail: int = 4, reassemble: bool = False) -> bytes:
        """Serialize one request/response exchange on the connection."""
        with self._request_lock:
            return self._send_request(function_code, payload, integrity_tail, reassemble)

    def send_subscription_credit(self, subscription_id: int, credit_limit: int) -> None:
        """Replenish finite notification credits without waiting for a reply."""
        if not 1 <= credit_limit <= 255:
            raise ValueError("credit_limit must be between 1 and 255")
        with self._request_lock:
            if not (self._connected or self._session_ready):
                raise S7ConnectionError("Not connected")
            frame = _build_subscription_credit_frame(
                subscription_id,
                credit_limit,
                self._next_sequence_number(),
                self._session_id,
                self._integrity_id_write if self._with_integrity_id else None,
                self._protocol_version,
                self._session_key,
            )
            self._send_s7_data(frame)
            if self._with_integrity_id:
                self._integrity_id_write = (self._integrity_id_write + 1) & 0xFFFFFFFF

    def _send_request(self, function_code: int, payload: bytes, integrity_tail: int, reassemble: bool) -> bytes:
        """Send an S7CommPlus request and receive the response.

        For V2+ with IntegrityId tracking enabled, the IntegrityId is spliced into
        the request payload just before its trailing fill bytes. Read vs write
        counters are selected based on the function code.

        Args:
            function_code: S7CommPlus function code
            payload: Request payload (after the 14-byte request header)
            integrity_tail: number of trailing payload bytes the V2 IntegrityId is
                inserted *before* — 4 for GetMultiVariables/SetMultiVariables (a
                trailing UInt32), 5 for Explore (a trailing UInt32 + filler byte).
            reassemble: when True, concatenate a multi-fragment response (e.g. Explore)
                before returning its payload.

        Returns:
            Response payload (after the 10-byte response header)
        """
        if self._session_key_refresh_error is not None:
            raise self._session_key_refresh_error
        if not (self._connected or self._session_ready):
            raise S7ConnectionError("Not connected")

        pending = self._encode_request(function_code, payload, integrity_tail)
        self._send_s7_data(pending.frame)
        self._request_sent(pending)

        reply_timeout = self._reply_timeout(function_code)
        response_frame = self._recv_response_frame(pending.sequence, reply_timeout)

        # Large responses (e.g. Explore) are split across several S7CommPlus PDUs;
        # any response whose first PDU has no trailer is reassembled the same way.
        if reassemble or _response_continues(response_frame):
            data = self._recv_reassembled_payload(response_frame, reply_timeout)
            return self._decode_reassembled(pending, data)
        try:
            return self._decode_response(pending, response_frame)
        except S7IntegrityError:
            self._invalidate_integrity_failure()
            raise

    def _verified_incoming_data(self, frame: bytes) -> bytes:
        """Return application data after authenticating the complete frame."""
        try:
            return self._authenticated_data(frame)
        except S7IntegrityError:
            self._invalidate_integrity_failure()
            raise

    def _recv_response_frame(self, expected_sequence: Optional[int] = None, timeout: Optional[float] = None) -> bytes:
        """Receive the next response, queueing notifications and consuming non-fatal SystemEvents.

        ``timeout`` bounds the wait in seconds (``None``: :meth:`_receive_timeout`);
        the frames skipped on the way count against it.
        """
        wait = _ReplyWait()
        deadline = time.monotonic() + (self._receive_timeout() if timeout is None else timeout)
        while True:
            response_frame = self._recv_s7_data(deadline - time.monotonic())
            try:
                step = self._sort_incoming(response_frame, expected_sequence, wait)
            except S7IntegrityError:
                self._invalidate_integrity_failure()
                raise
            if step is _Incoming.REPLY:
                return response_frame
            if step is _Incoming.DRAIN:
                self._recv_reassembled_payload(response_frame)

    def receive_notification(self, timeout: Optional[float] = None) -> bytes:
        """Receive one unsolicited S7CommPlus notification frame.

        Notifications observed while waiting for a request response are queued,
        so callers do not lose updates when protocol traffic interleaves. The
        wait for the next frame runs outside the request lock, so other
        threads, the SessionKey renewal timer among them, can send requests
        meanwhile; the frame itself is read under the lock.

        Args:
            timeout: Seconds to wait for the frame, or ``None`` for the
                ``notification_timeout`` passed to :meth:`connect`, else the
                request timeout.

        Raises:
            S7TimeoutError: The wait ran out. When no byte of a frame had
                arrived the session stays usable; a frame cut off part-way
                closes it.
        """
        _check_timeout("timeout", timeout)
        deadline = time.monotonic() + self._notification_wait(timeout)
        while True:
            with self._request_lock:
                if not self._connected:
                    raise S7ConnectionError("Not connected")
                left = deadline - time.monotonic()
                if self._notification_frames:
                    frame: Optional[bytes] = self._notification_frames.popleft()
                elif left > 0 and self._incoming_frame_ready():
                    frame = self._recv_s7_data(left, idle_ok=True)
                else:
                    frame = None
                if frame is not None:
                    data = self._verified_incoming_data(frame)
                    if not data or data[0] != Opcode.NOTIFICATION:
                        raise S7ConnectionError("Expected an S7CommPlus notification")
                    return frame
            if left <= 0:
                # Nothing of a next frame was read, so the session stays usable.
                raise S7TimeoutError("Receive timeout")
            # Wait without the lock; a request that takes the lock meanwhile
            # reads its own reply and queues any notification it meets. A
            # socket closed by another thread meanwhile is caught on the next
            # pass, under the lock.
            with contextlib.suppress(OSError, ValueError):
                self._iso_conn.data_available(left)

    def _incoming_frame_ready(self) -> bool:
        """Whether the next frame can be read now: decrypted TLS data is buffered or the socket is readable.

        A transport that is no longer connected counts as ready, so that the
        read raises its connection error at once instead of the wait running out.
        """
        if not self._iso_conn.connected:
            return True
        if self._tls_active and self._ssl_object is not None and self._ssl_object.pending():
            return True
        return self._iso_conn.data_available(0.0)

    def _recv_reassembled_payload(self, initial_data: bytes = b"", timeout: Optional[float] = None) -> bytes:
        """Receive a possibly-fragmented S7CommPlus response, returning its data section.

        A large response is split into several S7CommPlus PDUs. Each fragment is
        ``0x72 <ver> <len:2> <data:len>`` with no trailer; only the final fragment is
        followed by the ``0x72 <ver> 0x0000`` trailer. We concatenate the data parts
        of every fragment until the trailer is seen. Works for single-PDU responses
        too (one fragment immediately followed by the trailer). ``timeout`` bounds
        the wait for each further part in seconds (``None``: :meth:`_receive_timeout`).
        """
        reassembly = self._reassemble(initial_data)
        try:
            next(reassembly)
            while True:
                chunk = self._recv_s7_data(timeout)
                if not chunk:
                    raise S7ConnectionError("Connection closed during response reassembly")
                reassembly.send(chunk)
        except StopIteration as done:
            data: bytes = done.value
            return data
        except S7IntegrityError:
            self._invalidate_integrity_failure()
            raise

    def _init_ssl(self) -> None:
        """Send InitSSL request to prepare the connection.

        This is the first S7CommPlus message sent after COTP connect.
        The PLC responds with an InitSSL response. For PLCs that support
        TLS, the caller should then activate TLS before sending CreateObject.
        For V1 PLCs without TLS, the response may indicate that TLS is
        not supported, but the connection can continue without it.

        Reference: thomas-v2/S7CommPlusDriver InitSslRequest
        """
        pending = self._encode_init_ssl()
        self._send_s7_data(pending.frame)
        self._check_init_ssl_reply(self._recv_s7_data())

    def _create_session(self) -> None:
        """Send CreateObject request to establish an S7CommPlus session.

        Builds a NullServerSession CreateObject request matching the
        structure expected by S7-1200/1500 PLCs:

        Reference: thomas-v2/S7CommPlusDriver CreateObjectRequest.SetNullServerSessionData()
        """
        pending = self._encode_create_object()
        self._send_s7_data(pending.frame)
        self._apply_create_object_reply(self._recv_s7_data())

    def _setup_session(self) -> bool:
        """Send V2 SetMultiVariables to echo ServerSessionVersion back to the PLC.

        Always uses V2 framing, transport flags 0x34, and no IntegrityId.

        On V1-initial PLCs (FW < 4.5), this also includes the SecurityKey
        blob at address 1830, carrying a seed encrypted with an ECDH against
        the PLC's public key and the challenge encrypted under keys derived
        from that seed (see ``v1_session_key.real_plc.authenticator``).

        Returns:
            True if session setup succeeded (return_value == 0).
        """
        setup = self._encode_session_setup()
        if setup is None:
            return False
        pending, auth_result = setup
        self._send_s7_data(pending.frame)
        # Session setup can receive a SystemEvent before the reply. Route it
        # through the same dispatcher as ordinary requests so a fatal event
        # cannot be mistaken for a successful SetMultiVariables response.
        return self._apply_session_setup_reply(pending, auth_result, self._recv_response_frame(pending.sequence))

    def _build_get_var_substreamed(self, in_object_id: int, address: int, seq_field: int = 1) -> bytes:
        """Build the family-specific GET_VAR_SUBSTREAMED layout for the next request."""
        return _build_v1_get_var_substreamed_payload(
            self._v1_session_key_family, in_object_id, address, self._sequence_number, seq_field
        )

    def _session_activate(self) -> None:
        """Activate the V3 session after the SecurityKey handshake (see ``_build_session_activate_payload``)."""
        with self._request_lock:  # the payload carries the next sequence number
            self.send_request(FunctionCode.SET_VARIABLE, self._session_activate_payload(), integrity_tail=3)
        self._session_activated()

    def _post_auth_legitimation(self, password: str = "") -> None:
        """Perform the post-SessionKey legitimation handshake.

        V1-initial PLCs require this exchange after the SessionKey blob
        is accepted before they'll allow elevated access (e.g. writes).

        Matches HarpoS7 PoC legitimation sequence:
        1. GET_VAR_SUBSTREAMED: read 20-byte challenge from address 303
        2. Solve the challenge cryptographically (real-PLC or PlcSim scheme)
        3. SET_VAR_SUBSTREAMED: write the solved blob to address 1846
        """
        # Step 1: Read legitimation challenge from session, address 303
        logger.debug("Post-auth legitimation: reading challenge from address 303")
        with self._request_lock:  # the payload carries the next sequence number
            payload, tail = self._post_auth_challenge_request()
            challenge_reply = self.send_request(FunctionCode.GET_VAR_SUBSTREAMED, payload, integrity_tail=tail)
        blob = self._solve_post_auth_challenge(challenge_reply, password)
        logger.debug("Post-auth legitimation: writing solved blob to address 1846")
        with self._request_lock:
            payload, tail = self._post_auth_blob_request(blob)
            response = self.send_request(FunctionCode.SET_VAR_SUBSTREAMED, payload, integrity_tail=tail)
        _check_v1_legitimation_response(response, self._last_raw_response_payload)
        logger.info("Post-auth legitimation completed")

    def _delete_session(self) -> None:
        """Send DeleteObject to close the session."""
        self._send_s7_data(self._encode_delete_session())
        # Best-effort receive
        try:
            self._recv_s7_data()
        except Exception:
            pass

    def _send_s7_data(self, data: bytes) -> None:
        """Send an S7CommPlus frame, routing through TLS when active."""
        if self._tls_active:
            self._ssl_object.write(data)  # type: ignore[union-attr]
            self._tls_flush_outgoing()
        else:
            self._iso_conn.send_data(data)

    def _notification_wait(self, timeout: Optional[float]) -> float:
        """Seconds a notification wait may take: per call, else notification_timeout, else the request timeout."""
        if timeout is not None:
            return timeout
        if self._notification_timeout is not None:
            return self._notification_timeout
        return self._request_timeout

    def _reply_timeout(self, function_code: int) -> float:
        """Seconds each wait for the reply to ``function_code`` may take: the EXPLORE timeout, else the request timeout."""
        return self._explore_timeout if function_code == FunctionCode.EXPLORE else self._request_timeout

    def _receive_timeout(self) -> float:
        """Seconds the next frame may take: what is left of the handshake, else the request timeout."""
        if self._handshake_deadline is not None:
            return self._handshake_deadline - time.monotonic()
        return self._request_timeout

    def _recv_s7_data(self, timeout: Optional[float] = None, *, idle_ok: bool = False) -> bytes:
        """Receive an S7CommPlus frame, routing through TLS when active.

        Args:
            timeout: Seconds the whole frame may take, or ``None`` for
                :meth:`_receive_timeout`.
            idle_ok: Whether this is a wait for an unsolicited frame. Running
                out of time before any byte of it arrived then leaves the
                session usable. Any other timeout closes the session, whose
                stream position is then unknown.
        """
        wait = self._receive_timeout() if timeout is None else timeout
        try:
            if self._tls_active:
                # A TLS record can span several COTP frames; only the first
                # read of the frame may run out cleanly.
                deadline = time.monotonic() + wait
                first_read = True
                while True:
                    try:
                        return self._ssl_object.read(65536)  # type: ignore[union-attr]
                    except ssl.SSLWantReadError:
                        self._tls_read_incoming(deadline - time.monotonic(), idle_ok=idle_ok and first_read)
                        first_read = False
            return self._iso_conn.receive_data(wait, idle_ok=idle_ok)
        except S7TimeoutError:
            if not self._iso_conn.connected:
                self._close_after_timeout()
            raise

    def _close_after_timeout(self) -> None:
        """Close a session whose stream position is unknown, without a DeleteSession exchange."""
        self._session_ready = False
        self._stop_session_key_refresh()
        with self._request_lock:
            self._disconnect()

    def _tls_flush_outgoing(self) -> None:
        """Send all pending TLS records through COTP framing."""
        data = self._outgoing_bio.read()  # type: ignore[union-attr]
        if data:
            self._iso_conn.send_data(data)

    def _tls_read_incoming(self, timeout: Optional[float] = None, *, idle_ok: bool = False) -> None:
        """Read a COTP frame and feed its payload to the TLS BIO (``timeout`` as in :meth:`_recv_s7_data`)."""
        data = self._iso_conn.receive_data(self._receive_timeout() if timeout is None else timeout, idle_ok=idle_ok)
        self._incoming_bio.write(data)  # type: ignore[union-attr]

    def _activate_tls(
        self,
        tls_cert: Optional[str] = None,
        tls_key: Optional[str] = None,
        tls_ca: Optional[str] = None,
    ) -> None:
        """Activate TLS tunneled inside COTP data frames.

        The S7CommPlus protocol transports TLS records as the payload
        of COTP DT frames — TPKT and COTP headers stay unencrypted on
        the wire. This differs from a standard ``ssl.wrap_socket`` call
        which would encrypt everything (including TPKT/COTP), which
        Siemens PLCs reject.

        Uses ``ssl.MemoryBIO`` + ``ssl.SSLObject`` to encrypt/decrypt
        without wrapping the TCP socket, keeping TPKT/COTP framing
        intact via ``ISOTCPConnection.send_data/receive_data``.

        Called after InitSSL and before CreateObject.

        Args:
            tls_cert: Path to client TLS certificate (PEM)
            tls_key: Path to client private key (PEM)
            tls_ca: Path to PLC CA certificate (PEM)
        """
        ctx = self._setup_ssl_context(cert_path=tls_cert, key_path=tls_key, ca_path=tls_ca)
        with _tls_key_log(ctx) as keylog_path:
            self._start_tls_session(ctx, self.host)
            # TLS handshake: records tunnel through COTP frames
            try:
                self._do_tls_handshake()
            except ssl.SSLCertVerificationError as exc:
                raise S7CertificateError(f"PLC TLS certificate failed verification: {exc.verify_message}") from exc
            except (ssl.SSLError, OSError, S7Error) as exc:
                raise S7TlsHandshakeError(f"TLS handshake with the PLC did not complete: {exc}") from exc
            self._tls_session_established(keylog_path)

    def _do_tls_handshake(self) -> None:
        """Perform TLS handshake, tunneling records through COTP."""
        while True:
            try:
                self._ssl_object.do_handshake()  # type: ignore[union-attr]
                break
            except ssl.SSLWantReadError:
                self._tls_flush_outgoing()
                self._tls_read_incoming()
            except ssl.SSLWantWriteError:
                # Rare with MemoryBIO, but the SSLObject can ask to write before reading.
                self._tls_flush_outgoing()
        self._tls_flush_outgoing()

    def __enter__(self) -> "S7CommPlusConnection":
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        self.disconnect()
