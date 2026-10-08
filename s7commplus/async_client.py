"""Async S7CommPlus client for S7-1200/1500 PLCs.

Reference: thomas-v2/S7CommPlusDriver (C#, LGPL-3.0)
"""

import asyncio
import hashlib
import hmac
import logging
import ssl
import struct
from collections import deque
from collections.abc import AsyncIterator, Mapping, Sequence
from typing import Any, Awaitable, Callable, Optional, TypeVar

from .error import S7ConnectionError, S7IntegrityError, S7ProtocolError, S7TimeoutError

from . import typeinfo
from .blob_decompressor import find_and_decompress
from .client import (
    _LEGACY_KEY_CACHE,
    DBWriteItem,
    SymbolicReadItem,
    SymbolicWriteItem,
    _build_area_read_payload,
    _build_area_write_payload,
    _build_explore_payload_v3,
    _build_explore_request,
    _build_invoke_payload,
    _build_multi_symbolic_write_payload,
    _build_multi_symbolic_read_payload,
    _build_read_payload,
    _build_symbolic_read_payload,
    _build_symbolic_write_payload,
    _build_write_payload,
    _parse_explore_datablocks,
    _parse_cpu_state,
    _parse_read_response,
    _parse_write_response,
    _parse_write_response_errors,
)
from .catalog import SymbolCatalog, SymbolicTag, TagResult
from .codec import (
    SERVER_SESSION_ROLE_SECURED_BIT,
    decode_header,
    encode_header,
    encode_object_qualifier,
    encode_pvalue_blob,
    encode_typed_value,
    parse_create_object_attributes,
    parse_create_object_session_id,
)
from .connection import (
    _DEFAULT_LEGACY_SESSION_KEY_REFRESH_INTERVAL,
    _MAX_QUEUED_NOTIFICATION_FRAMES,
    _MAX_STALE_RESPONSES_PER_REQUEST,
    _MAX_SYSTEM_EVENTS_PER_RESPONSE,
    _S7_CIPHERS,
    FamilyOnlyFingerprintError,
    SessionKeyAuthenticationDependencyError,
    SessionKeyCandidateRejectedError,
    _build_get_var_substreamed_payload,
    _build_session_activate_payload,
    _build_session_setup_frame,
    _build_set_variable_payload,
    _build_v1_get_var_substreamed_payload,
    _build_v1_legitimation_payload,
    _check_set_variable_response,
    _check_system_event,
    _check_timeout,
    _check_v1_legitimation_response,
    _encode_security_key_struct,
    _frame_request,
    _generate_session_key_blob,
    _incoming_frame_opcode,
    _incoming_response_sequence,
    _is_stale_response_sequence,
    _log_create_object_return_value,
    _parse_get_var_substreamed_response,
    _parse_protection_level_response,
    _resolve_session_key_fingerprint,
    _session_setup_accepted,
    _skip_plcsim_legitimation,
    _set_s7_groups,
    _strip_response_integrity_id,
    _v1_session_key_profile,
    _v1_integrity_tail,
    _validate_response_header,
    _verify_v3_hmac,
)
from .subscription import (
    SubscriptionDiagnostics,
    SubscriptionItem,
    SubscriptionNotification,
    SubscriptionRegistry,
    SubscriptionRestoreResult,
    build_delete_subscription_request,
    build_subscription_request,
    notification_subscription_id,
    parse_subscription_notification,
)
from .alarm import (
    Alarm,
    AlarmNotification,
    LanguageId,
    build_alarm_explore_request,
    build_alarm_subscription_request,
    build_delete_alarm_subscription_request,
    parse_alarm_explore_response,
    parse_alarm_notification,
)
from .legitimation import (
    build_legacy_response,
    build_new_response,
    decide_legitimation_mode,
    derive_legitimation_key,
    extract_session_oms_version,
    extract_session_version_string,
    oms_session_version_name,
)
from .protocol import (
    FLAGS_34_FUNCTION_CODES,
    READ_FUNCTION_CODES,
    S7COMMPLUS_LOCAL_TSAP,
    AccessLevel,
    DataType,
    ElementID,
    FunctionCode,
    Ids,
    LegitimationId,
    LegitimationType,
    ObjectId,
    Opcode,
    remote_tsap_for_connection_type,
    ProtocolVersion,
)
from .transport import _configure_tcp_socket
from .v1_session_key.keys import KeyFamily
from .vlq import decode_uint32_vlq, decode_uint64_vlq, encode_uint32_vlq

logger = logging.getLogger(__name__)

_T = TypeVar("_T")

# COTP constants
_COTP_CR = 0xE0
_COTP_CC = 0xD0
_COTP_DT = 0xF0


class AsyncSubscriptionQueue:
    """Bounded queue-like view over one client's routed notifications."""

    def __init__(self, client: "S7CommPlusAsyncClient", subscription_id: int) -> None:
        self._client = client
        self._subscription_id = subscription_id

    async def get(self, timeout: Optional[float] = None) -> SubscriptionNotification:
        return await self._client.receive_subscription_notification(self._subscription_id, timeout=timeout)

    def get_nowait(self) -> SubscriptionNotification:
        notification = self._client._subscriptions.pop(self._subscription_id)
        if notification is None:
            raise asyncio.QueueEmpty
        return notification

    def qsize(self) -> int:
        return self._client.subscription_diagnostics(self._subscription_id).queued_notifications


class S7CommPlusAsyncClient:
    """Async S7CommPlus client for S7-1200/1500 PLCs.

    Use ``from s7commplus import AsyncClient`` to instantiate.
    """

    def __init__(self) -> None:
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._session_id: int = 0
        self._subscription_container_id: int = 0
        self._sequence_number: int = 0
        self._protocol_version: int = 0
        self._transport_connected = False
        self._request_timeout = 5.0
        # True while part of a message (a frame, or a reply still missing
        # fragments) has been read: a wait cut short then closes the session.
        self._rx_partial = False
        self._session_ready = False
        self._connected = False
        self._lock = asyncio.Lock()
        self._notification_frames: deque[bytes] = deque(maxlen=_MAX_QUEUED_NOTIFICATION_FRAMES)
        self._notification_frame_overflows = 0
        self._connect_params: Optional[dict[str, Any]] = None
        self._symbol_catalog: Optional[SymbolCatalog] = None
        self._subscription_change_counter = 1
        self._subscription_relation_id = 0x7FFFC001
        self._subscriptions = SubscriptionRegistry()
        self._alarm_subscription_ids: set[int] = set()
        self._alarm_notification_frames: deque[bytes] = deque(maxlen=100)

        # V2+ IntegrityId tracking
        self._integrity_id_read: int = 0
        self._integrity_id_write: int = 0
        self._with_integrity_id: bool = False

        # TLS state — TLS records are tunneled inside COTP DT frames via MemoryBIO
        # (TPKT/COTP headers stay unencrypted), mirroring the sync S7CommPlusConnection.
        self._tls_active: bool = False
        self._ssl_object: Optional[ssl.SSLObject] = None
        self._incoming_bio: Optional[ssl.MemoryBIO] = None
        self._outgoing_bio: Optional[ssl.MemoryBIO] = None
        self._oms_secret: Optional[bytes] = None
        # ServerSessionVersion is captured as its raw typed value (flags+datatype+data)
        # so it can be echoed back verbatim — real S7-1500 PLCs send it as a Struct.
        self._server_session_version: Optional[bytes] = None
        self._session_oms_version: Optional[tuple[int, Optional[int]]] = None
        self._session_oms_version_cache_key: Optional[bytes] = None
        self._session_setup_ok: bool = False
        # Effective protection level, read once the session is up
        self._protection_level: Optional[int] = None

        # V1 SessionKey state (non-TLS V1 sessions only), as in S7CommPlusConnection.
        self._legacy_s7_1500: bool | None = None
        self._last_raw_response_payload: bytes | None = None
        self._public_key_fingerprint: Optional[str] = None
        self._session_challenge: Optional[bytes] = None
        # ServerSession.Role from the CreateObject response; the
        # 0x20000000 bit marks a PLC that runs a secured session.
        self._server_session_role: Optional[int] = None
        self._server_session_roles: Optional[int] = None
        self._session_key: Optional[bytes] = None
        self._v1_session_key_public_key: bytes = b""
        self._v1_session_key_family = KeyFamily.S7_1500
        self._session_key_fingerprint_override: Optional[str] = None
        self._session_key_refresh_interval: Optional[float] = _DEFAULT_LEGACY_SESSION_KEY_REFRESH_INTERVAL
        self._session_key_refresh_task: Optional[asyncio.Task[None]] = None
        self._session_key_refresh_error: Optional[Exception] = None

    @property
    def connected(self) -> bool:
        return self._connected

    @property
    def protocol_version(self) -> int:
        return self._protocol_version

    @property
    def session_id(self) -> int:
        return self._session_id

    @property
    def subscription_container_id(self) -> int:
        """Object ID assigned to the session's subscription container."""
        return self._subscription_container_id

    @property
    def session_setup_ok(self) -> bool:
        """Whether the S7CommPlus session setup succeeded for data operations."""
        return self._session_setup_ok

    @property
    def tls_active(self) -> bool:
        """Whether TLS is active on the connection."""
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
    def oms_secret(self) -> Optional[bytes]:
        """OMS exporter secret from TLS session (None if TLS not active)."""
        return self._oms_secret

    @property
    def protection_level(self) -> Optional[int]:
        """Effective protection level reported by the PLC (see `AccessLevel`)."""
        return self._protection_level

    @property
    def session_oms_version(self) -> Optional[tuple[int, Optional[int]]]:
        """(SystemOMS, ProjectOMS) negotiated for the session, or ``None``.

        SystemOMS is the OMS session version (64..448, V1..V7); ProjectOMS is
        the loaded project's version, where an explicit 0 means the controller
        has no project loaded and ``None`` means the element was not sent.
        ``None`` for the whole tuple before connect or when unreadable.
        """
        if self._server_session_version is None:
            return None
        if self._session_oms_version_cache_key is self._server_session_version:
            return self._session_oms_version
        versions = extract_session_oms_version(self._server_session_version)
        self._session_oms_version = versions
        self._session_oms_version_cache_key = self._server_session_version
        return versions

    @property
    def legacy_s7_1500(self) -> bool:
        """Whether the V1 SessionKey profile is active (automatic unless overridden)."""
        return _v1_session_key_profile(self._legacy_s7_1500, self._session_key, self._protocol_version)

    @property
    def object_qualifier_version(self) -> int:
        """Protocol version whose ObjectQualifier layout data requests use.

        The opt-in non-TLS profile sends the V2 layout although the session
        negotiated V1; its PLCs reset the connection on the V1 layout.
        """
        return ProtocolVersion.V2 if self.legacy_s7_1500 else self._protocol_version

    async def connect(
        self,
        host: str,
        port: int = 102,
        rack: int = 0,
        slot: int = 1,
        *,
        use_tls: bool = False,
        tls_cert: Optional[str] = None,
        tls_key: Optional[str] = None,
        tls_ca: Optional[str] = None,
        password: Optional[str] = None,
        allow_legacy_key_fallback: bool = True,
        legacy_session_key_refresh_interval: Optional[float] = _DEFAULT_LEGACY_SESSION_KEY_REFRESH_INTERVAL,
        timeout: float = 5.0,
        request_timeout: Optional[float] = None,
        legacy_s7_1500: bool | None = None,
        connection_type: int | str | None = None,
    ) -> None:
        """Connect to an S7-1200/1500 PLC using S7CommPlus.

        Args:
            host: PLC IP address or hostname
            port: TCP port (default 102)
            rack: PLC rack number (unused, kept for API symmetry)
            slot: PLC slot number (unused, kept for API symmetry)
            use_tls: Whether to activate TLS after InitSSL.
            tls_cert: Path to client TLS certificate (PEM)
            tls_key: Path to client private key (PEM)
            tls_ca: Path to CA certificate for PLC verification (PEM)
            password: PLC password. V1 SessionKey sessions use it for the
                post-handshake legitimation; TLS sessions pass it to
                :meth:`authenticate` after connecting.
            allow_legacy_key_fallback: Try known same-family public keys on
                fresh sessions when a legacy PLC omits its key id.
            legacy_session_key_refresh_interval: Seconds between legacy
                SessionKey renewals, or ``None`` to disable them.
            timeout: Seconds for the TCP connect and the COTP, InitSSL, TLS
                and CreateObject handshake together.
            request_timeout: Seconds to wait for each reply once the handshake
                is done (and for each further part of a multi-part reply, and
                for a send the PLC does not accept), or ``None`` to use
                ``timeout``. Running out raises ``S7TimeoutError`` and closes
                the session, as its state is then unknown; ``connected`` turns
                ``False``.
            legacy_s7_1500: Override the non-TLS V1 SessionKey profile (structured
                browse, V2 object qualifier, trailing IntegrityId, chained fragment
                HMAC). ``None`` (default) selects it automatically for every V1
                SessionKey session, as the S7-1500 FW 2.6 (issue #12) and S7-1200
                FW V4.2 controllers need it; ``False`` forces the classic layout and
                ``True`` is only an explicit spelling of the automatic choice.
            connection_type: COTP identity to connect as: ``"hmi"`` (default,
                the HMI/SCADA data-client role), ``"es"`` (engineering station,
                TIA-Portal style) or ``"pg"`` (programming device). The TSAP
                strings name the client role; whether a given firmware serves
                engineering-style operations differently per role is not
                verified against a PLC, so try ``"es"`` if the default is
                refused.
        """
        if legacy_s7_1500 and use_tls:
            raise ValueError("legacy_s7_1500 requires use_tls=False")
        if legacy_session_key_refresh_interval is not None and legacy_session_key_refresh_interval <= 0:
            raise ValueError("legacy_session_key_refresh_interval must be positive or None")
        remote_tsap_for_connection_type(connection_type)  # validate early
        _check_timeout("timeout", timeout, optional=False)
        _check_timeout("request_timeout", request_timeout)
        self._symbol_catalog = None
        self._connect_params = {
            "host": host,
            "port": port,
            "rack": rack,
            "slot": slot,
            "use_tls": use_tls,
            "tls_cert": tls_cert,
            "tls_key": tls_key,
            "tls_ca": tls_ca,
            "password": password,
            "allow_legacy_key_fallback": allow_legacy_key_fallback,
            "legacy_session_key_refresh_interval": legacy_session_key_refresh_interval,
            "timeout": timeout,
            "request_timeout": request_timeout,
            "legacy_s7_1500": legacy_s7_1500,
            "connection_type": connection_type,
        }
        self._host = host
        try:
            await self._open_connection()
        except Exception:
            self._connect_params = None
            raise

    async def _open_connection(self) -> None:
        """Open the connection, trying bundled same-family keys when the PLC withholds its key id."""
        assert self._connect_params is not None
        p = self._connect_params
        cache_key = (p["host"], p["port"])
        cached = _LEGACY_KEY_CACHE.get(cache_key) if p["allow_legacy_key_fallback"] else None
        if cached is not None:
            try:
                await self._open_connection_once(cached)
                return
            except SessionKeyCandidateRejectedError:
                logger.info("Cached SessionKey candidate %s was rejected; trying remaining family keys", cached)
                _LEGACY_KEY_CACHE.pop(cache_key, None)
                from .v1_session_key.keys import parse_fingerprint

                family, _ = parse_fingerprint(cached)
                await self._probe_family_keys(family, excluded={cached})
                return

        try:
            await self._open_connection_once()
        except FamilyOnlyFingerprintError as exc:
            if not p["allow_legacy_key_fallback"]:
                raise S7ConnectionError(
                    f"PLC advertised family-only key id {exc.family:02X}, but legacy key fallback is disabled"
                ) from exc
            await self._probe_family_keys(exc.family)

    async def _probe_family_keys(self, family: int, excluded: set[str] | None = None) -> None:
        """Try each same-family key on a new connection and cache the winner."""
        assert self._connect_params is not None
        from .v1_session_key.keys import fingerprints_for_family

        excluded = excluded or set()
        candidates = [fingerprint for fingerprint in fingerprints_for_family(family) if fingerprint not in excluded]
        if not candidates:
            raise S7ConnectionError(f"No bundled SessionKey candidates for public-key family {family:02X}")

        for attempt, fingerprint in enumerate(candidates, 1):
            logger.info("Trying SessionKey candidate %s (%d/%d) on a fresh session", fingerprint, attempt, len(candidates))
            try:
                await self._open_connection_once(fingerprint)
            except SessionKeyCandidateRejectedError:
                continue
            _LEGACY_KEY_CACHE[(self._connect_params["host"], self._connect_params["port"])] = fingerprint
            logger.info("Confirmed and cached SessionKey candidate %s", fingerprint)
            return
        raise S7ConnectionError(
            f"PLC rejected all {len(candidates)} bundled SessionKey candidates for public-key family {family:02X}"
        )

    async def _open_connection_once(self, fingerprint: Optional[str] = None) -> None:
        """Open exactly one transport and session, optionally with one SessionKey candidate."""
        assert self._connect_params is not None
        p = self._connect_params
        use_tls = p["use_tls"]
        self._legacy_s7_1500 = p["legacy_s7_1500"]
        self._session_key_refresh_interval = p["legacy_session_key_refresh_interval"]
        self._session_key_refresh_error = None
        self._session_key_fingerprint_override = fingerprint
        self._request_timeout = p["timeout"] if p["request_timeout"] is None else p["request_timeout"]

        # TCP connect and steps 1-4 share one deadline: the connect timeout
        # bounds the TCP connect and the whole handshake, as in the sync client.
        loop = asyncio.get_running_loop()
        deadline = loop.time() + p["timeout"]
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(p["host"], p["port"]), timeout=p["timeout"])
        except asyncio.TimeoutError as exc:
            raise S7ConnectionError(f"TCP connection to {p['host']}:{p['port']} timed out after {p['timeout']}s") from exc
        self._reader, self._writer = reader, writer
        sock = writer.get_extra_info("socket")
        if sock is not None:
            try:
                _configure_tcp_socket(sock)
            except OSError:
                pass
        self._transport_connected = True
        self._rx_partial = False

        try:
            try:
                await asyncio.wait_for(self._handshake(p), timeout=deadline - loop.time())
            except asyncio.TimeoutError as exc:
                raise S7TimeoutError(
                    f"Connection handshake with {p['host']}:{p['port']} timed out after {p['timeout']}s"
                ) from exc
            self._session_key_fingerprint_override = _resolve_session_key_fingerprint(
                self._public_key_fingerprint, self._session_key_fingerprint_override
            )

            # After CreateObject (which always uses V1 framing), data PDUs over TLS
            # use ProtocolVersion V2 on a real S7-1500 (matches the C# reference driver).
            if self._tls_active:
                self._protocol_version = ProtocolVersion.V2

            # Step 5: Session setup. A transport and CreateObject response do
            # not make the public client usable until the PLC accepts setup.
            if self._server_session_version is None:
                raise S7ConnectionError(
                    "PLC did not provide a usable ServerSessionVersion attribute; S7CommPlus session setup cannot continue"
                )
            try:
                self._session_setup_ok = await self._setup_session()
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

            # Step 6: Version-specific validation
            if self._protocol_version >= ProtocolVersion.V3:
                if not use_tls:
                    logger.warning(
                        "PLC reports V3 protocol but TLS is not enabled. Connection may not work without use_tls=True."
                    )
            elif self._protocol_version == ProtocolVersion.V2:
                if not self._tls_active:
                    raise S7ConnectionError("PLC reports V2 protocol but TLS is not active. V2 requires TLS. Use use_tls=True.")
                self._with_integrity_id = True
                self._integrity_id_read = 0
                self._integrity_id_write = 0
                logger.info("V2 IntegrityId tracking enabled")

            if self._session_key is not None:
                await self._session_activate()
                if p["password"]:
                    await self._post_auth_legitimation(p["password"])
                else:
                    logger.info("No PLC password supplied; skipping post-auth legitimation")
                self._skip_integrity_ids_after_legitimation()

            self._protection_level = await self._get_effective_protection_level()
            if self._protection_level is not None:
                logger.info(f"PLC reports protection level: {self._protection_level}")
            oms_versions = self.session_oms_version
            if oms_versions is not None:
                system_oms, project_oms = oms_versions
                logger.info(
                    f"OMS session version: system={oms_session_version_name(system_oms)} ({system_oms}), project={project_oms}"
                )
                if project_oms == 0:
                    logger.warning(
                        "Controller reports ProjectOMS 0: no project is loaded, so browsing and symbolic access will find nothing"
                    )

            self._connected = True
            self._schedule_session_key_refresh()

            logger.info(
                f"Async S7CommPlus connected to {p['host']}:{p['port']}, "
                f"version=V{self._protocol_version}, session={self._session_id}, "
                f"tls={self._tls_active}"
            )

        except Exception:
            await self._close()
            raise

        if p["password"] is not None and self._tls_active:
            logger.info("Performing PLC legitimation (password authentication)")
            await self.authenticate(p["password"])

    async def _handshake(self, p: dict[str, Any]) -> None:
        """COTP, InitSSL, optional TLS and CreateObject: everything before session setup."""
        # Step 1: COTP handshake with the TSAP for the selected client role
        await self._cotp_connect(S7COMMPLUS_LOCAL_TSAP, remote_tsap_for_connection_type(p["connection_type"]))

        # Step 2: InitSSL handshake
        await self._init_ssl()

        # Step 3: TLS activation (between InitSSL and CreateObject)
        if p["use_tls"]:
            await self._activate_tls(tls_cert=p["tls_cert"], tls_key=p["tls_key"], tls_ca=p["tls_ca"])

        # Step 4: S7CommPlus session setup (CreateObject)
        await self._create_session()

    async def authenticate(self, password: str, username: str = "") -> None:
        """Perform PLC password authentication (legitimation).

        Args:
            password: PLC password
            username: Username for the new-mode exchange (leave empty for legacy)

        Raises:
            S7ConnectionError: If not connected, TLS is not active, the firmware
                does not support legitimation, or the password was refused
        """
        from .error import S7ConnectionError

        if not self._connected:
            raise S7ConnectionError("Not connected")

        if not self._tls_active:
            raise S7ConnectionError("Legitimation requires TLS. Connect with use_tls=True.")

        level_before = self._protection_level
        if level_before is None:
            raise S7ConnectionError("PLC does not report a protection level, so legitimation cannot be verified")

        if level_before <= AccessLevel.FULL_ACCESS:
            logger.info("PLC already grants full access, legitimation is not required")
            return
        if not password:
            logger.warning(f"PLC restricts access (level {level_before}) but no password was provided")
            return

        # Step 1: Auto-detect legacy vs new from the firmware version
        mode = self._decide_legitimation_mode()
        if mode is None:
            raise S7ConnectionError("PLC firmware version does not support legitimation")
        logger.info(f"Using {mode.name.lower()} legitimation")

        # Step 2: Get challenge from PLC via GetVarSubStreamed
        challenge = await self._get_legitimation_challenge()
        logger.info(f"Received legitimation challenge ({len(challenge)} bytes)")

        if mode is LegitimationType.LEGACY:
            # A legacy challenge is XORed with a SHA-1 password hash, so it is that long.
            if len(challenge) != 20:
                raise S7ConnectionError(f"Unexpected legacy challenge length: {len(challenge)}")
            await self._send_legitimation_legacy(build_legacy_response(password, challenge))
        else:
            if self._oms_secret is None:
                raise S7ConnectionError(
                    "New legitimation requires the TLS OMS exporter secret, which could not be derived from this TLS session."
                )
            await self._send_legitimation_new(build_new_response(password, challenge, self._oms_secret, username))
            # The PLC rolls the key after every attempt; mirror it so a second
            # legitimation on the same session encrypts with the same key.
            self._oms_secret = derive_legitimation_key(self._oms_secret)

        # Step 3: Renew protection level, which is what verifies the outcome
        self._protection_level = await self._get_effective_protection_level()
        if self._protection_level is None:
            raise S7ConnectionError("Legitimation outcome is unverifiable: the PLC stopped reporting its protection level")
        if self._protection_level >= level_before:
            raise S7ConnectionError(
                f"Legitimation failed, protection level unchanged at {self._protection_level}: the password was refused"
            )
        logger.info(f"PLC legitimation completed, protection level {level_before} -> {self._protection_level}")

    def _decide_legitimation_mode(self) -> Optional[LegitimationType]:
        """Return the legitimation exchange the PLC firmware expects, None if unsupported."""
        if self._server_session_version is None:
            return None
        version_string = extract_session_version_string(self._server_session_version)
        if version_string is None:
            logger.warning("ServerSessionVersion carries no device string, cannot pick a legitimation mode")
            return None
        logger.debug(f"PLC device string: {version_string}")
        return decide_legitimation_mode(version_string)

    async def _activate_tls(
        self,
        tls_cert: Optional[str] = None,
        tls_key: Optional[str] = None,
        tls_ca: Optional[str] = None,
    ) -> None:
        """Activate TLS over the COTP connection."""
        if self._writer is None:
            from .error import S7ConnectionError

            raise S7ConnectionError("Cannot activate TLS: not connected")

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        ctx.set_ciphers(_S7_CIPHERS)
        _set_s7_groups(ctx)
        ctx.options |= ssl.OP_NO_TICKET
        ctx.options |= 0x00080000  # SSL_OP_NO_ENCRYPT_THEN_MAC
        ctx.options |= 0x00000001  # SSL_OP_NO_EXTENDED_MASTER_SECRET (OpenSSL 3.0+)

        if tls_cert and tls_key:
            ctx.load_cert_chain(tls_cert, tls_key)

        if tls_ca:
            ctx.load_verify_locations(tls_ca)
        else:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        # BIO-based TLS: encrypt/decrypt in memory so the TLS records can be tunneled
        # through COTP DT frames (TPKT/COTP stay unencrypted) — `start_tls` would instead
        # wrap the whole TCP stream, encrypting TPKT/COTP too, which the PLC rejects.
        self._incoming_bio = ssl.MemoryBIO()
        self._outgoing_bio = ssl.MemoryBIO()
        self._ssl_object = ctx.wrap_bio(
            self._incoming_bio,
            self._outgoing_bio,
            server_side=False,
            server_hostname=self._host if ctx.check_hostname else None,
        )

        await self._do_tls_handshake()
        self._tls_active = True

        try:
            exporter = getattr(self._ssl_object, "export_keying_material")
            self._oms_secret = bytes(exporter("EXPERIMENTAL_OMS", 32, None))
            logger.debug("OMS exporter secret extracted from TLS session")
        except (AttributeError, ssl.SSLError) as e:
            logger.warning(f"Could not extract OMS exporter secret: {e}")
            self._oms_secret = None

        logger.info("TLS activated (tunneled inside COTP frames)")

    async def _do_tls_handshake(self) -> None:
        """Perform the TLS handshake, tunneling records through COTP DT frames."""
        assert self._ssl_object is not None
        while True:
            try:
                self._ssl_object.do_handshake()
                break
            except ssl.SSLWantReadError:
                await self._tls_flush_outgoing()
                await self._tls_read_incoming()
            except ssl.SSLWantWriteError:
                # Rare with MemoryBIO, but the SSLObject can ask to write before reading.
                await self._tls_flush_outgoing()
        await self._tls_flush_outgoing()

    async def _tls_flush_outgoing(self) -> None:
        """Send all pending outgoing TLS bytes as COTP DT frames."""
        assert self._outgoing_bio is not None
        data = self._outgoing_bio.read()
        if data:
            await self._send_cotp_raw(data)

    async def _tls_read_incoming(self) -> None:
        """Read one COTP DT frame and feed its payload to the TLS BIO."""
        assert self._incoming_bio is not None
        data = await self._recv_cotp_raw()
        self._incoming_bio.write(data)

    async def _get_effective_protection_level(self) -> Optional[int]:
        """Read the session's effective protection level (see `AccessLevel`), None if request failed."""
        from .error import S7ConnectionError

        payload = _build_get_var_substreamed_payload(self._session_id, Ids.EFFECTIVE_PROTECTION_LEVEL)
        try:
            resp = await self._send_request(FunctionCode.GET_VAR_SUBSTREAMED, payload, integrity_tail=4)
            level = _parse_protection_level_response(resp)
        except S7ConnectionError as exc:
            logger.warning(f"PLC did not report a protection level: {exc}")
            return None
        return level

    async def _get_legitimation_challenge(self) -> bytes:
        """Request legitimation challenge from PLC."""
        from .protocol import LegitimationId

        payload = _build_get_var_substreamed_payload(self._session_id, LegitimationId.SERVER_SESSION_REQUEST)
        resp_payload = await self._send_request(FunctionCode.GET_VAR_SUBSTREAMED, payload, integrity_tail=4)
        return _parse_get_var_substreamed_response(resp_payload)

    async def _send_legitimation_new(self, encrypted_response: bytes) -> None:
        """Send new-style legitimation response (AES-256-CBC encrypted)."""
        from .protocol import LegitimationId

        value = bytes([0x00, DataType.BLOB, 0x00])
        value += encode_uint32_vlq(len(encrypted_response))
        value += encrypted_response
        payload = _build_set_variable_payload(self._session_id, LegitimationId.LEGITIMATE, value)
        resp_payload = await self._send_request(FunctionCode.SET_VARIABLE, payload, integrity_tail=4)
        _check_set_variable_response(resp_payload)

    async def _send_legitimation_legacy(self, response: bytes) -> None:
        """Send legacy legitimation response (SHA-1 XOR)."""
        from .protocol import LegitimationId

        value = bytes([0x10, DataType.USINT])
        value += encode_uint32_vlq(len(response))
        value += response
        payload = _build_set_variable_payload(self._session_id, LegitimationId.SERVER_SESSION_RESPONSE, value)
        resp_payload = await self._send_request(FunctionCode.SET_VARIABLE, payload, integrity_tail=4)
        _check_set_variable_response(resp_payload)

    async def disconnect(self) -> None:
        """Disconnect from PLC."""
        await self._close()
        self._session_key_refresh_error = None
        self._connect_params = None

    async def _close(self) -> None:
        """Tear down the session and transport, keeping the connect parameters and any renewal failure."""
        self._stop_session_key_refresh()
        self._subscriptions.clear()
        self._alarm_subscription_ids.clear()
        self._alarm_notification_frames.clear()
        if self._session_ready and self._session_id:
            try:
                await self._delete_session()
            except Exception:
                pass

        writer = self._reset_session()
        if writer is not None:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    def _connection_lost(self, reason: str) -> None:
        """Drop a session whose stream position is unknown (a timeout, or a read cancelled part-way).

        The socket is aborted without a DeleteSession exchange, so no unread
        rest of a reply can be taken for the next message, and the next request
        raises ``S7ConnectionError("Not connected")``. The connect parameters
        and the subscription and alarm bookkeeping are kept, as after a
        connection the PLC dropped, so a reconnect can restore them.
        """
        logger.warning("Closing the session: %s", reason)
        self._stop_session_key_refresh()
        writer = self._reset_session()
        if writer is not None:
            writer.transport.abort()

    def _reset_session(self) -> Optional[asyncio.StreamWriter]:
        """Clear the session state and detach the transport, returning the writer still to close.

        The subscription and alarm bookkeeping is left to the caller.
        """
        self._connected = False
        self._session_ready = False
        self._transport_connected = False
        self._session_id = 0
        self._subscription_container_id = 0
        self._sequence_number = 0
        self._protocol_version = 0
        self._with_integrity_id = False
        self._integrity_id_read = 0
        self._integrity_id_write = 0
        self._tls_active = False
        self._ssl_object = None
        self._incoming_bio = None
        self._outgoing_bio = None
        self._oms_secret = None
        self._symbol_catalog = None
        self._server_session_version = None
        self._session_oms_version = None
        self._session_oms_version_cache_key = None
        self._session_setup_ok = False
        self._protection_level = None
        self._public_key_fingerprint = None
        self._session_challenge = None
        self._server_session_role = None
        self._server_session_roles = None
        self._session_key = None
        self._v1_session_key_public_key = b""
        self._v1_session_key_family = KeyFamily.S7_1500
        self._notification_frames.clear()
        self._notification_frame_overflows = 0
        self._rx_partial = False

        writer = self._writer
        self._writer = None
        self._reader = None
        return writer

    async def _invalidate_integrity_failure(self) -> None:
        """Discard authenticated state without writing to an untrusted stream."""
        self._session_ready = False
        await self._close()

    # -- V1 SessionKey renewal --

    def _stop_session_key_refresh(self) -> None:
        """Cancel the renewal task, unless it is the task doing the stopping."""
        task = self._session_key_refresh_task
        self._session_key_refresh_task = None
        if task is not None and task is not asyncio.current_task():
            task.cancel()

    def _schedule_session_key_refresh(self) -> None:
        """Start renewing an authenticated legacy session's key periodically."""
        interval = self._session_key_refresh_interval
        if interval is None or self._session_key is None or not self._connected:
            return
        self._session_key_refresh_task = asyncio.get_running_loop().create_task(self._session_key_refresh_loop(interval))

    async def _session_key_refresh_loop(self, interval: float) -> None:
        """Renew under the request lock every ``interval`` seconds; a failed renewal is terminal."""
        try:
            while True:
                await asyncio.sleep(interval)
                async with self._lock:
                    if not self._connected:
                        return
                    await self._renew_session_key_locked()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            failure = S7ConnectionError(f"Legacy SessionKey renewal failed: {exc}")
            logger.error("%s", failure)
            self._session_key_refresh_error = failure
            self._session_ready = False
            self._session_id = 0
            await self._close()

    async def _renew_session_key_locked(self) -> None:
        """Perform the challenge/SecurityKey exchange while the old key is active."""
        if self._session_key is None or not self._v1_session_key_public_key:
            raise S7ConnectionError("Legacy SessionKey renewal prerequisites are unavailable")

        from .v1_session_key.handshake import authenticate_session_key

        integrity_tail = _v1_integrity_tail(self._v1_session_key_family)
        challenge_payload = _build_v1_get_var_substreamed_payload(
            self._v1_session_key_family, self._session_id, LegitimationId.SERVER_SESSION_REQUEST, self._sequence_number
        )
        challenge_response = await self._send_request_locked(FunctionCode.GET_VAR_SUBSTREAMED, challenge_payload, integrity_tail)
        challenge = _parse_get_var_substreamed_response(challenge_response)
        if len(challenge) != 20:
            raise S7ConnectionError(f"SessionKey renewal returned an unexpected {len(challenge)}-byte challenge")
        blob, new_session_key = authenticate_session_key(challenge, self._v1_session_key_public_key, self._v1_session_key_family)
        security_key = _encode_security_key_struct(
            self._v1_session_key_public_key, self._v1_session_key_family, blob, new_session_key
        )
        renewal_payload = _build_set_variable_payload(self._session_id, LegitimationId.SESSION_SETUP_LEGITIMATION, security_key)
        _check_set_variable_response(await self._send_request_locked(FunctionCode.SET_VARIABLE, renewal_payload, 4))
        self._session_key = new_session_key
        logger.info("Legacy SessionKey renewed successfully")

    async def _reconnect(self) -> None:
        """Tear down and re-establish the connection with the same parameters."""
        if self._connect_params is None:
            raise S7ConnectionError("Not connected")
        params = self._connect_params.copy()
        await self.disconnect()
        await self.connect(**params)

    async def _with_reconnect(self, op: Callable[[], Awaitable[_T]]) -> _T:
        """Run ``op``; if the PLC dropped the socket, reconnect once and retry."""
        try:
            return await op()
        except S7ConnectionError as exc:
            logger.info("Connection dropped by PLC (%s); reconnecting and retrying", exc)
            await self._reconnect()
            return await op()

    async def db_read(self, db_number: int, start: int, size: int) -> bytes:
        """Read raw bytes from a data block."""
        payload = _build_read_payload([(db_number, start, size)], self.object_qualifier_version)
        response = await self._send_request(FunctionCode.GET_MULTI_VARIABLES, payload)

        results = _parse_read_response(response)
        if not results:
            raise RuntimeError("Read returned no data")
        if results[0] is None:
            raise RuntimeError("Read failed: PLC returned error for item")
        return results[0]

    async def db_write(self, db_number: int, start: int, data: bytes, datatype: DataType = DataType.BLOB) -> None:
        """Write raw bytes to a data block with an optional explicit PValue datatype."""
        await self.db_write_multi([(db_number, start, data, datatype)])

    async def db_write_multi(self, items: list[DBWriteItem]) -> None:
        """Write (db_number, start_offset, data, datatype) tuples matching the PLC target types."""
        payload = _build_write_payload(items, self.object_qualifier_version)
        response = await self._send_request(FunctionCode.SET_MULTI_VARIABLES, payload)
        _parse_write_response(response)

    async def write_multi(self, items: list[DBWriteItem]) -> None:
        """Alias for :meth:`db_write_multi`."""
        await self.db_write_multi(items)

    async def db_read_multi(self, items: list[tuple[int, int, int]]) -> list[bytes]:
        """Read multiple data block regions in a single request."""
        payload = _build_read_payload(items, self.object_qualifier_version)
        response = await self._send_request(FunctionCode.GET_MULTI_VARIABLES, payload)
        parsed = _parse_read_response(response)
        return [r if r is not None else b"" for r in parsed]

    async def read_area(self, area_rid: int, start: int, size: int) -> bytes:
        """Read raw bytes from a controller memory area (M, I, Q, counters, timers)."""
        payload = _build_area_read_payload(area_rid, start, size, self.object_qualifier_version)
        response = await self._send_request(FunctionCode.GET_MULTI_VARIABLES, payload)
        results = _parse_read_response(response)
        if not results or results[0] is None:
            raise RuntimeError("Area read failed")
        return results[0]

    async def write_area(self, area_rid: int, start: int, data: bytes, *, datatype: DataType = DataType.BLOB) -> None:
        """Write a controller memory area, specifying the target datatype for scalar writes."""
        payload = _build_area_write_payload(area_rid, start, data, self.object_qualifier_version, datatype=datatype)
        response = await self._send_request(FunctionCode.SET_MULTI_VARIABLES, payload)
        _parse_write_response(response)

    async def explore(self, explore_id: int = 0, attributes: Sequence[int] | None = None) -> bytes:
        """Browse the PLC object tree.

        Args:
            explore_id: RID of the object to explore. 0 explores the PLC program (`Ids.NATIVE_THE_PLC_PROGRAM_RID`).
            attributes: Attribute IDs to request. None or empty returns every attribute. Ignored on V1 SessionKey
                sessions, whose EXPLORE format carries no attribute list.

        Returns:
            Raw response payload. Read the compressed XML documents in it with `s7commplus.iter_preset_streams`.
        """
        if self._session_key is not None:
            payload = _build_explore_payload_v3(explore_id if explore_id else 0x38)
        else:
            payload = _build_explore_request(explore_id or Ids.NATIVE_THE_PLC_PROGRAM_RID, list(attributes or []))
        return await self._send_request(FunctionCode.EXPLORE, payload, integrity_tail=5, reassemble=True)

    async def explore_xml(self, explore_id: int = 0, attributes: Sequence[int] | None = None) -> str | None:
        """EXPLORE a PLC object and decompress the XML metadata from the response.

        S7-1200/1500 PLCs (FW V4.5+) compress XML metadata — tag definitions,
        interface descriptions, line comments, etc. — using zlib with Siemens
        preset dictionaries. This method sends an EXPLORE request and
        decompresses the first zlib stream found in the response.

        .. warning:: This method is **experimental** and may change.

        Args:
            explore_id: RID of the object to explore. 0 explores the PLC program.
            attributes: Attribute IDs to request. None or empty returns every attribute.

        Returns:
            Decompressed XML as a UTF-8 string, or ``None`` if the response
            contains no recognisable zlib stream.
        """
        raw = await self.explore(explore_id, attributes)
        return find_and_decompress(raw)

    async def set_plc_operating_state(self, state: int) -> None:
        """Set the PLC operating state (start/stop)."""
        payload = _build_invoke_payload(state)
        await self._send_request(FunctionCode.INVOKE, payload)

    async def get_cpu_state(self) -> str:
        """Get PLC CPU operating state via S7CommPlus.

        .. warning:: This method is **experimental** and may change.

        Returns:
            One of ``"RUN"``, ``"STOP"``, or ``"UNKNOWN"``.
        """
        payload = _build_explore_request(Ids.NATIVE_THE_CPU_EXEC_UNIT_RID, [])
        response = await self._send_request(FunctionCode.EXPLORE, payload, integrity_tail=5, reassemble=True)
        return _parse_cpu_state(response)

    async def upload_block(self, block_type: int, block_number: int) -> bytes:
        """Upload (read) a program block from the PLC.

        .. warning:: This method is **experimental** and may change.

        Args:
            block_type: Block type (e.g. 0x08 for DB, 0x0C for FC).
            block_number: Block number.

        Returns:
            Raw block data.
        """
        payload = bytearray()
        payload += struct.pack(">I", self._session_id)
        payload += encode_uint32_vlq(1)  # item count
        payload += encode_uint32_vlq(1)  # field count
        payload += encode_uint32_vlq(block_type)
        payload += encode_uint32_vlq(block_number)
        payload += struct.pack(">I", 0)

        response = await self._send_request(FunctionCode.GET_VAR_SUBSTREAMED, bytes(payload))
        # Skip return code VLQ
        offset = 0
        _, consumed = decode_uint32_vlq(response, offset)
        offset += consumed
        return response[offset:]

    async def download_block(self, block_type: int, block_number: int, data: bytes) -> None:
        """Download (write) a program block to the PLC.

        .. warning:: This method is **experimental** and may change.

        Args:
            block_type: Block type.
            block_number: Block number.
            data: Raw block data to write.
        """
        payload = bytearray()
        payload += struct.pack(">I", self._session_id)
        payload += encode_uint32_vlq(1)
        payload += encode_uint32_vlq(block_type)
        payload += encode_uint32_vlq(block_number)
        payload += encode_pvalue_blob(data)
        payload += struct.pack(">I", 0)

        await self._send_request(FunctionCode.SET_VAR_SUBSTREAMED, bytes(payload))

    async def create_subscription(
        self,
        items: Sequence[SubscriptionItem | SymbolicTag | str],
        cycle_ms: int = 100,
        credit_limit: int = 10,
        credit_step: int = 5,
        queue_size: int = 100,
    ) -> int:
        """Create a data change subscription.

        .. warning:: This method is **experimental** and may change.

        Args:
            items: Symbolic access sequences, catalog tags, or explicit items.
            cycle_ms: Sampling cycle in milliseconds.
            credit_limit: Initial notification credit limit, or -1 for unlimited.
            credit_step: Credits added before a finite limit expires.
            queue_size: Maximum buffered notifications for this subscription.

        Returns:
            Subscription object ID assigned by the PLC.
        """
        if self._subscription_container_id == 0:
            raise RuntimeError("PLC did not provide a subscription container object")
        if not 0 <= credit_step <= 255:
            raise ValueError("credit_step must be between 0 and 255")
        normalized = [
            SubscriptionItem.from_access_sequence(item)
            if isinstance(item, str)
            else SubscriptionItem.from_tag(item)
            if isinstance(item, SymbolicTag)
            else item
            for item in items
        ]
        change_counter = self._subscription_change_counter
        payload, integrity_tail = build_subscription_request(
            self._subscription_container_id,
            normalized,
            cycle_ms=cycle_ms,
            credit_limit=credit_limit,
            change_counter=change_counter,
            relation_id=self._subscription_relation_id,
        )
        response = await self._send_request(FunctionCode.CREATE_OBJECT, payload, integrity_tail=integrity_tail)
        object_ids, _, return_value = parse_create_object_session_id(response)
        if return_value != 0 or not object_ids:
            raise RuntimeError(f"Subscription creation failed: PLC returned 0x{return_value:X}")
        subscription_id = object_ids[0]
        self._subscriptions.register(
            subscription_id,
            normalized,
            change_counter=change_counter,
            credit_limit=credit_limit,
            credit_step=credit_step,
            queue_size=queue_size,
            cycle_ms=cycle_ms,
        )
        self._subscription_change_counter = self._subscription_change_counter % 0xFF + 1
        self._subscription_relation_id = (self._subscription_relation_id + 1) & 0xFFFFFFFF
        logger.info(f"Subscription created, id={subscription_id:#x}")
        return subscription_id

    async def receive_subscription_notification(
        self, subscription_id: int | None = None, timeout: Optional[float] = None
    ) -> SubscriptionNotification:
        """Wait for one routed data notification."""
        if subscription_id is not None:
            queued = self._subscriptions.pop(subscription_id)
            if queued is not None:
                return queued
        while True:
            async with self._lock:
                if not self._connected:
                    raise RuntimeError("Not connected")
                if self._notification_frames:
                    frame = self._notification_frames.popleft()
                else:
                    frame = await self._recv_notification_frame(timeout)
                await self._verified_incoming_data(frame)
            frame_subscription_id = notification_subscription_id(frame)
            if frame_subscription_id in self._alarm_subscription_ids:
                self._alarm_notification_frames.append(frame)
                continue
            notification = parse_subscription_notification(frame)
            matched, credit_update = self._subscriptions.route(notification)
            if not matched:
                continue
            if credit_update is not None:
                await self._send_subscription_credit(notification.subscription_id, credit_update)
            target_id = notification.subscription_id if subscription_id is None else subscription_id
            queued = self._subscriptions.pop(target_id)
            if queued is not None:
                return queued

    async def iter_subscription_notifications(
        self, subscription_id: int, limit: int | None = None
    ) -> AsyncIterator[SubscriptionNotification]:
        """Yield routed notifications, optionally stopping after ``limit``."""
        delivered = 0
        while limit is None or delivered < limit:
            yield await self.receive_subscription_notification(subscription_id)
            delivered += 1

    def subscription_diagnostics(self, subscription_id: int) -> SubscriptionDiagnostics:
        diagnostics = self._subscriptions.diagnostics(subscription_id)
        return SubscriptionDiagnostics(
            diagnostics.subscription_id,
            diagnostics.queued_notifications,
            diagnostics.dropped_notifications,
            diagnostics.missed_sequence_updates,
            self._notification_frame_overflows,
        )

    def subscription_queue(self, subscription_id: int) -> AsyncSubscriptionQueue:
        """Return a queue view for one active subscription."""
        self._subscriptions.diagnostics(subscription_id)
        return AsyncSubscriptionQueue(self, subscription_id)

    async def resubscribe(self) -> SubscriptionRestoreResult:
        """Recreate the data subscriptions lost with the previous session.

        Call it after reconnecting. Every subscription that was live when the
        session ended is created again with its items, cycle, credits, queue size
        and callbacks; the PLC assigns new IDs, which ``restored`` maps from the old
        ones. Queues and iterators are keyed by ID, so
        fetch them again for the new IDs. A subscription the PLC rejects (for example a renamed tag) lands in
        ``failed`` without stopping the others and stays pending for a retry.
        Notifications from the gap are not replayed. Alarm subscriptions are not
        restored.

        .. warning:: This method is **experimental** and may change.
        """
        restored: dict[int, int] = {}
        failed: dict[int, Exception] = {}
        for spec in self._subscriptions.pending_restore:
            try:
                new_id = await self.create_subscription(
                    spec.items,
                    cycle_ms=spec.cycle_ms,
                    credit_limit=spec.credit_limit,
                    credit_step=spec.credit_step,
                    queue_size=spec.queue_size,
                )
            except Exception as exc:
                logger.warning(f"Could not restore subscription {spec.subscription_id:#x}: {exc}")
                failed[spec.subscription_id] = exc
                continue
            for callback in spec.callbacks:
                self._subscriptions.add_callback(new_id, callback)
            self._subscriptions.mark_restored(spec.subscription_id)
            restored[spec.subscription_id] = new_id
        return SubscriptionRestoreResult(restored, failed)

    def forget_lost_subscriptions(self) -> None:
        """Stop remembering the subscriptions lost with the previous session."""
        self._subscriptions.forget_pending_restore()

    async def delete_subscription(self, subscription_id: int) -> None:
        """Delete a data change subscription.

        .. warning:: This method is **experimental** and may change.

        Args:
            subscription_id: ID returned by :meth:`create_subscription`.
        """
        if self._subscription_container_id == 0:
            raise RuntimeError("PLC did not provide a subscription container object")
        payload = build_delete_subscription_request(self._subscription_container_id, self._protocol_version)
        await self._send_request(FunctionCode.DELETE_OBJECT, payload)
        for active_id in self._subscriptions.subscription_ids:
            self._subscriptions.unregister(active_id)
        self._alarm_subscription_ids.clear()
        self._alarm_notification_frames.clear()
        self._notification_frames.clear()
        logger.info(f"Subscription {subscription_id:#x} deleted")

    async def create_alarm_subscription(
        self,
        language_ids: Optional[list[LanguageId | int]] = None,
        domains: Optional[list[int]] = None,
        credit_limit: int = 10,
    ) -> int:
        """Subscribe to PLC alarm events and return the subscription ID."""
        if self._subscription_container_id == 0:
            raise RuntimeError("PLC did not provide a subscription container object")
        payload = build_alarm_subscription_request(self._subscription_container_id, language_ids, domains, credit_limit)
        response = await self._send_request(FunctionCode.CREATE_OBJECT, payload, integrity_tail=len(payload) - 11)
        object_ids, _, return_value = parse_create_object_session_id(response)
        if return_value != 0 or not object_ids:
            raise RuntimeError(f"Alarm subscription failed: PLC returned {return_value:#x}")
        subscription_id = object_ids[0]
        self._alarm_subscription_ids.add(subscription_id)
        return subscription_id

    async def delete_alarm_subscription(self, subscription_id: int) -> None:
        """Delete an alarm subscription created by this client."""
        if self._subscription_container_id == 0:
            raise RuntimeError("PLC did not provide a subscription container object")
        payload = build_delete_alarm_subscription_request(self._subscription_container_id, self._protocol_version)
        await self._send_request(FunctionCode.DELETE_OBJECT, payload)
        for active_id in self._subscriptions.subscription_ids:
            self._subscriptions.unregister(active_id)
        self._alarm_subscription_ids.clear()
        self._alarm_notification_frames.clear()
        self._notification_frames.clear()
        logger.info(f"Alarm subscription {subscription_id:#x} deleted")

    async def receive_alarm_notification(
        self, language_ids: Optional[list[LanguageId | int]] = None, timeout: Optional[float] = None
    ) -> AlarmNotification:
        """Wait for one alarm notification, optionally with a timeout in seconds.

        Data notifications encountered first are routed to their bounded queues.
        """
        while True:
            if self._alarm_notification_frames:
                frame = self._alarm_notification_frames.popleft()
            else:
                async with self._lock:
                    if not self._connected:
                        raise RuntimeError("Not connected")
                    if self._notification_frames:
                        frame = self._notification_frames.popleft()
                    else:
                        frame = await self._recv_notification_frame(timeout)
                    await self._verified_incoming_data(frame)
            frame_subscription_id = notification_subscription_id(frame)
            if self._subscriptions.contains(frame_subscription_id):
                notification = parse_subscription_notification(frame)
                matched, credit_update = self._subscriptions.route(notification)
                if matched and credit_update is not None:
                    await self._send_subscription_credit(frame_subscription_id, credit_update)
                continue
            return parse_alarm_notification(frame, language_ids)

    async def _recv_notification_frame(self, timeout: Optional[float]) -> bytes:
        """Receive one unsolicited frame within ``timeout`` seconds (``None``: no limit).

        A wait that runs out before any byte of the frame was read keeps the
        session; one cut off part-way closes it. Either raises
        ``asyncio.TimeoutError``.
        """
        try:
            return await self._receive_bounded(
                self._recv_cotp_dt(), timeout, f"No notification from the PLC within {timeout}s", idle_ok=True
            )
        except S7TimeoutError as exc:
            raise asyncio.TimeoutError(str(exc)) from exc

    async def read_alarms(self, language_ids: Optional[list[LanguageId | int]] = None) -> list[Alarm]:
        """Return a snapshot of the PLC's active alarms without consuming notifications."""
        response = await self._send_request(
            FunctionCode.EXPLORE, build_alarm_explore_request(), integrity_tail=5, reassemble=True
        )
        return parse_alarm_explore_response(response, language_ids)

    async def read_symbolic(self, access_area: int, lids: list[int], symbol_crc: int = 0) -> bytes:
        """Read a variable using S7CommPlus symbolic (LID-based) access.

        .. warning:: This method is **experimental** and may change.
        """
        payload = _build_symbolic_read_payload(access_area, lids, symbol_crc, self.object_qualifier_version)
        response = await self._send_request(FunctionCode.GET_MULTI_VARIABLES, payload)
        results = _parse_read_response(response)
        if not results or results[0] is None:
            raise RuntimeError("Symbolic read failed")
        return results[0]

    async def read_symbolic_multi(self, items: Sequence[SymbolicReadItem]) -> list[Optional[bytes]]:
        """Read multiple variables using S7CommPlus symbolic (LID-based) access.

        .. warning:: This method is **experimental** and may change.

        Args:
            items: `(access_area, lids)` tuples, or three-tuples adding a
                symbol CRC.

        Returns:
            One entry per requested item, in request order.

        Raises:
            RuntimeError: If the PLC does not answer every requested item.
        """
        if not items:
            return []
        payload = _build_multi_symbolic_read_payload(items, self.object_qualifier_version)
        response = await self._send_request(FunctionCode.GET_MULTI_VARIABLES, payload)
        results = _parse_read_response(response, expected_count=len(items))
        if len(results) != len(items):
            raise RuntimeError(f"Symbolic multi-read failed: PLC returned {len(results)} of {len(items)} items")
        return results

    async def write_symbolic(
        self, access_area: int, lids: list[int], data: bytes, symbol_crc: int = 0, *, datatype: DataType = DataType.BLOB
    ) -> None:
        """Write a variable using S7CommPlus symbolic (LID-based) access.

        .. warning:: This method is **experimental** and may change.

        Set ``datatype`` to the target PLC datatype reported by browse().
        The legacy BLOB default is not a generic replacement for scalar types.
        """
        payload = _build_symbolic_write_payload(access_area, lids, data, symbol_crc, self._protocol_version, datatype=datatype)
        response = await self._send_request(FunctionCode.SET_MULTI_VARIABLES, payload)
        _parse_write_response(response)

    async def refresh_tag_catalog(self) -> SymbolCatalog:
        """Browse the PLC and replace the cached symbolic tag catalog."""
        self._symbol_catalog = SymbolCatalog.from_browse(await self.browse())
        return self._symbol_catalog

    def invalidate_tag_catalog(self) -> None:
        """Discard cached browse metadata after a PLC layout change."""
        self._symbol_catalog = None

    async def resolve_tag(self, name: str) -> SymbolicTag:
        """Resolve a browsed tag name to its typed symbolic descriptor."""
        catalog = self._symbol_catalog or await self.refresh_tag_catalog()
        return catalog.resolve(name)

    async def read_tag(self, name: str) -> bytes:
        """Read one symbolic tag by name."""
        result = (await self.read_tags([name]))[0]
        if result.error is not None:
            raise result.error
        assert result.value is not None
        return result.value

    async def read_tags(self, names: Sequence[str]) -> list[TagResult]:
        """Read names in one request and return a success/error for every item."""
        if not names:
            return []
        tags = [await self.resolve_tag(name) for name in names]
        values = await self.read_symbolic_multi([(tag.access_area, list(tag.lids), 0) for tag in tags])
        results = [
            TagResult(tag=tag, value=value)
            if value is not None
            else TagResult(tag=tag, error=RuntimeError(f"Symbolic read failed for {tag.name!r}"))
            for tag, value in zip(tags, values)
        ]
        return results

    async def write_tag(self, name: str, data: bytes) -> None:
        """Write one symbolic tag by name using its resolved PValue datatype."""
        result = (await self.write_tags({name: data}))[0]
        if result.error is not None:
            raise result.error

    async def write_tags(self, values: Mapping[str, bytes]) -> list[TagResult]:
        """Write names once and return per-item results without automatic retry."""
        if not self._connected:
            raise RuntimeError("Not connected")
        if not values:
            return []
        tags = [await self.resolve_tag(name) for name in values]
        unsupported = [tag.name for tag in tags if tag.datatype is None]
        if unsupported:
            raise ValueError(f"No S7CommPlus wire datatype mapping for: {', '.join(unsupported)}")
        items: list[SymbolicWriteItem] = [
            (tag.access_area, list(tag.lids), data, 0, tag.datatype)
            for tag, data in zip(tags, values.values())
            if tag.datatype is not None
        ]
        payload = _build_multi_symbolic_write_payload(items, self.object_qualifier_version)
        response = await self._send_request(FunctionCode.SET_MULTI_VARIABLES, payload)
        try:
            errors = _parse_write_response_errors(response, expected_count=len(tags))
        except RuntimeError as error:
            return [TagResult(tag=tag, error=error) for tag in tags]
        return [
            TagResult(tag=tag, error=RuntimeError(f"Symbolic write failed for {tag.name!r}: PLC error {errors[index]}"))
            if index in errors
            else TagResult(tag=tag)
            for index, tag in enumerate(tags, 1)
        ]

    async def list_datablocks(self) -> list[dict[str, Any]]:
        """List all datablocks on the PLC via EXPLORE.

        .. warning:: This method is **experimental** and may change.
        """
        if self._session_key is not None and not self.legacy_s7_1500:
            # V1-initial PLCs: explore the DB wildcard address (0x8A11FFFF)
            # matching TIA Portal's browse pattern
            payload = _build_explore_payload_v3(0x8A11FFFF)
        else:
            payload = _build_explore_request(
                Ids.NATIVE_THE_PLC_PROGRAM_RID, [Ids.OBJECT_VARIABLE_TYPE_NAME, Ids.BLOCK_BLOCK_NUMBER]
            )
        response = await self._send_request(FunctionCode.EXPLORE, payload, integrity_tail=5, reassemble=True)
        return _parse_explore_datablocks(response)

    async def browse(self) -> list[dict[str, Any]]:
        """Browse the full per-tag symbol tree via EXPLORE + the type-info container.

        .. warning:: This method is **experimental** and may change.

        Returns a flat list of variable dicts with keys ``name``, ``access_sequence``
        (the dot-separated hex path whose first component is the access area and
        remaining components are LIDs for :meth:`read_symbolic`), ``data_type``,
        and the optimized/non-optimized byte+bit offsets. Steps: enumerate DBs, resolve
        each DB's type-info RID via a LID=1 read, explore the OMS type-info container,
        then recombine into the symbol tree.

        Returns:
            List of variable info dicts.
        """
        # Phase A: enumerate data blocks. Phase B/C: resolve each DB's type-info RID
        # (a LID=1 read — needed for instance DBs whose TI is not their own RID) and seed
        # a root node per DB.
        root_nodes: list[typeinfo.Node] = []
        for db_info in await self.list_datablocks():
            if db_info.get("number", 0) <= 0 or db_info.get("rid", 0) == 0:
                continue
            ti_rid = await self._with_reconnect(lambda: self._read_typeinfo_rid(db_info["rid"]))
            if ti_rid == 0:
                continue  # load-memory-only DB, skip
            root_nodes.append(
                typeinfo.Node(
                    node_type=typeinfo.NodeType.ROOT, name=db_info["name"], access_id=db_info["rid"], relation_id=ti_rid
                )
            )

        # Add the native process areas with their known synthetic type-info ids.
        for name, access_rid, ti_rid in (
            ("IArea", Ids.NATIVE_THE_I_AREA_RID, 0x90010000),
            ("QArea", Ids.NATIVE_THE_Q_AREA_RID, 0x90020000),
            ("MArea", Ids.NATIVE_THE_M_AREA_RID, 0x90030000),
            ("S7Timers", Ids.NATIVE_THE_S7_TIMERS_RID, 0x90050000),
            ("S7Counters", Ids.NATIVE_THE_S7_COUNTERS_RID, 0x90060000),
        ):
            root_nodes.append(
                typeinfo.Node(node_type=typeinfo.NodeType.ROOT, name=name, access_id=access_rid, relation_id=ti_rid)
            )

        # Phase D: explore the OMS type-info container (a large, multi-fragment PDU).
        type_objects = await self._with_reconnect(self._explore_type_info_container)

        # Phase E: recombine type-info with the DB/area nodes and flatten.
        typeinfo.build_tree(root_nodes, type_objects)
        variables: list[dict[str, Any]] = []
        for v in typeinfo.build_flat_list(root_nodes):
            try:
                data_type = typeinfo.Softdatatype(v.softdatatype).name
            except ValueError:
                data_type = str(v.softdatatype)
            variables.append(
                {
                    "name": v.name,
                    "access_sequence": v.access_sequence,
                    "data_type": data_type,
                    "opt_address": v.opt_address,
                    "opt_bitoffset": v.opt_bitoffset,
                    "nonopt_address": v.nonopt_address,
                    "nonopt_bitoffset": v.nonopt_bitoffset,
                    "symbol_crc": v.symbol_crc,
                    "array_dimensions": v.array_dimensions,
                    "string_length": v.string_length,
                }
            )
        return variables

    async def _read_typeinfo_rid(self, db_rid: int) -> int:
        """Read LID=1 of a DB to get its type-info RID (0 if the DB has no readable value)."""
        try:
            raw = await self.read_symbolic(db_rid, [1], 0)
        except (S7ConnectionError, S7ProtocolError):
            raise
        except Exception:
            return 0
        return struct.unpack(">I", raw[:4])[0] if len(raw) >= 4 else 0

    async def _explore_type_info_container(self) -> list["typeinfo.PObject"]:
        """EXPLORE the OMS type-info container and return its per-type objects."""
        payload = _build_explore_request(Ids.OBJECT_OMS_TYPE_INFO_CONTAINER, [])
        response = await self._send_request(FunctionCode.EXPLORE, payload, integrity_tail=5, reassemble=True)
        return typeinfo.extract_type_info_objects(response)

    # -- Internal methods --

    # Sanity caps for fragment reassembly — generous vs. any real PLC EXPLORE response,
    # but bounded so a malformed/adversarial stream can't drive unbounded allocation.
    _MAX_REASSEMBLED_BYTES = 16 * 1024 * 1024
    _MAX_REASSEMBLED_FRAGMENTS = 4096

    async def _send_subscription_credit(self, subscription_id: int, credit_limit: int) -> None:
        """Send a fire-and-forget update before finite credits expire."""
        if not 1 <= credit_limit <= 255:
            raise ValueError("credit_limit must be between 1 and 255")
        value = bytes([0x00, DataType.INT]) + struct.pack(">h", credit_limit)
        payload = _build_set_variable_payload(subscription_id, Ids.SUBSCRIPTION_CREDIT_LIMIT, value)
        async with self._lock:
            if not self._connected or self._writer is None or self._reader is None:
                raise S7ConnectionError("Not connected")
            sequence = self._next_sequence_number()
            header = struct.pack(">BHHHHIB", Opcode.REQUEST, 0, FunctionCode.SET_VARIABLE, 0, sequence, self._session_id, 0x74)
            integrity = encode_uint32_vlq(self._integrity_id_write) if self._with_integrity_id else b""
            request = header + payload[:-4] + integrity + payload[-4:]
            frame = encode_header(self._protocol_version, len(request)) + request
            frame += struct.pack(">BBH", 0x72, self._protocol_version, 0)
            await self._send_cotp_dt(frame)
            if self._with_integrity_id:
                self._integrity_id_write = (self._integrity_id_write + 1) & 0xFFFFFFFF

    async def _send_request(
        self,
        function_code: int,
        payload: bytes,
        integrity_tail: int = 4,
        reassemble: bool = False,
    ) -> bytes:
        """Send an S7CommPlus request and receive the response.

        Args:
            function_code: S7CommPlus function code.
            payload: Request payload (after the 14-byte request header).
            integrity_tail: number of trailing payload bytes the V2 IntegrityId is
                inserted *before* — 4 for GetMultiVariables/SetMultiVariables (a
                trailing UInt32), 5 for Explore (a trailing UInt32 + filler byte).
            reassemble: when True, concatenate a multi-fragment response (e.g. Explore)
                before returning its payload.

        Returns:
            Response payload (after the 10-byte response header).
        """
        async with self._lock:
            return await self._send_request_locked(function_code, payload, integrity_tail, reassemble)

    async def _send_request_locked(
        self,
        function_code: int,
        payload: bytes,
        integrity_tail: int = 4,
        reassemble: bool = False,
    ) -> bytes:
        """:meth:`_send_request` for a caller that already holds the request lock."""
        if self._session_key_refresh_error is not None:
            raise self._session_key_refresh_error
        if not (self._connected or self._transport_connected) or self._writer is None or self._reader is None:
            raise S7ConnectionError("Not connected")

        seq_num = self._next_sequence_number()

        request_header = struct.pack(
            ">BHHHHIB",
            Opcode.REQUEST,
            0x0000,
            function_code,
            0x0000,
            seq_num,
            self._session_id,
            # Transport flags: 0x34 after SessionKey auth (matches TIA Portal),
            # and for the function codes the reference sends with 0x34.
            0x34 if self._session_key is not None or function_code in FLAGS_34_FUNCTION_CODES else 0x36,
        )

        with_integrity_id = self._with_integrity_id and (
            self._protocol_version >= ProtocolVersion.V2 or self._session_key is not None
        )
        integrity_id_bytes = b""
        if with_integrity_id:
            is_read = function_code in READ_FUNCTION_CODES
            integrity_id = self._integrity_id_read if is_read else self._integrity_id_write
            integrity_id_bytes = encode_uint32_vlq(integrity_id)

        # The IntegrityId is spliced in just before the payload's trailing fill bytes
        # (integrity_tail of them), not right after the header.
        if integrity_id_bytes and len(payload) >= integrity_tail:
            request = request_header + payload[:-integrity_tail] + integrity_id_bytes + payload[-integrity_tail:]
        else:
            request = request_header + integrity_id_bytes + payload

        # After SessionKey auth, all data ops use V3 framing with HMAC
        await self._send_cotp_dt(_frame_request(request, self._protocol_version, self._session_key))

        if with_integrity_id:
            if function_code in READ_FUNCTION_CODES:
                self._integrity_id_read = (self._integrity_id_read + 1) & 0xFFFFFFFF
            else:
                self._integrity_id_write = (self._integrity_id_write + 1) & 0xFFFFFFFF

        response_data = await self._receive_bounded(
            self._recv_response_frame(seq_num),
            self._request_timeout,
            f"No reply from the PLC within {self._request_timeout}s",
        )

        # Large responses (e.g. Explore) are split across several S7CommPlus PDUs.
        if reassemble:
            data = await self._recv_reassembled_payload(response_data)
            if len(data) < 10:
                raise S7ConnectionError("Response too short")
            _validate_response_header(data, function_code, seq_num)
            return self._response_payload(function_code, bytes(data[10:]))

        version, data_length, consumed = decode_header(response_data)
        if self._session_key is not None and version != ProtocolVersion.V3:
            await self._invalidate_integrity_failure()
            raise S7IntegrityError(f"Authenticated response used unauthenticated frame version V{version}; reconnect")
        response = response_data[consumed : consumed + data_length]
        if self._session_key is not None:
            try:
                response = _verify_v3_hmac(response, self._session_key)
            except S7IntegrityError:
                await self._invalidate_integrity_failure()
                raise

        _validate_response_header(response, function_code, seq_num)

        # RESPONSE header is 10 bytes (opcode+res+func+res+seqnr+transport) — responses
        # carry no SessionId field (requests do, hence their 14-byte header). For V2+ the
        # IntegrityId travels at the END of the payload and is ignored by the parsers;
        # after SessionKey auth it leads the payload and is removed here.
        return self._response_payload(function_code, response[10:])

    def _response_payload(self, function_code: int, payload: bytes) -> bytes:
        """Preserve legacy return values where IntegrityId follows the body."""
        self._last_raw_response_payload = payload
        return _strip_response_integrity_id(function_code, payload, self._session_key is not None, self.legacy_s7_1500)

    async def _verified_incoming_data(self, frame: bytes) -> bytes:
        """Return application data after authenticating the complete frame."""
        version, data_length, consumed = decode_header(frame)
        data = bytes(frame[consumed : consumed + data_length])
        if self._session_key is None:
            return data
        if version != ProtocolVersion.V3:
            await self._invalidate_integrity_failure()
            raise S7IntegrityError(f"Authenticated response used unauthenticated frame version V{version}; reconnect")
        try:
            return _verify_v3_hmac(data, self._session_key)
        except S7IntegrityError:
            await self._invalidate_integrity_failure()
            raise

    async def _receive_bounded(
        self, receive: Awaitable[_T], timeout: Optional[float], message: str, *, idle_ok: bool = False
    ) -> _T:
        """Await one receive for at most ``timeout`` seconds (``None``: no limit).

        A reply that does not arrive in time leaves the session in an unknown
        state, so the session is closed (see :meth:`_connection_lost`) before
        ``S7TimeoutError`` (with ``message``) is raised. A wait for an
        unsolicited frame (``idle_ok``) that runs out before any byte of the
        frame was read is clean and keeps the session. Running out of time, or
        being cancelled, part-way through a frame or a multi-part reply always
        closes it: the unread rest would otherwise be taken for the next
        message.
        """
        try:
            if timeout is None:
                return await receive
            return await asyncio.wait_for(receive, timeout)
        except asyncio.TimeoutError as exc:
            if not idle_ok or self._rx_partial:
                self._connection_lost(message)
            raise S7TimeoutError(message) from exc
        except asyncio.CancelledError:
            if self._rx_partial:
                self._connection_lost("a read was cancelled part-way through a frame")
            raise

    async def _recv_response_frame(self, expected_sequence: Optional[int] = None) -> bytes:
        """Receive the next response, queueing unsolicited application frames."""
        system_events = 0
        stale_responses = 0
        while True:
            response_data = await self._recv_cotp_dt()
            if not response_data:
                raise S7ConnectionError("Connection closed while waiting for an S7CommPlus response")
            version, data_length, consumed = decode_header(response_data)
            if version == ProtocolVersion.SYSTEM_EVENT:
                _check_system_event(bytes(response_data[consumed : consumed + data_length]))
                system_events += 1
                if system_events > _MAX_SYSTEM_EVENTS_PER_RESPONSE:
                    raise S7ProtocolError("Too many S7CommPlus SystemEvents while waiting for a response")
                continue
            if self._session_key is not None:
                await self._verified_incoming_data(response_data)
            if data_length < 10:
                return response_data
            opcode = _incoming_frame_opcode(response_data)
            if opcode == Opcode.NOTIFICATION:
                if len(self._notification_frames) == self._notification_frames.maxlen:
                    self._notification_frame_overflows += 1
                self._notification_frames.append(response_data)
                continue
            if opcode not in (Opcode.RESPONSE, Opcode.RESPONSE2):
                raise S7ProtocolError(f"Unexpected S7CommPlus opcode 0x{opcode:02X} while waiting for a response")
            if expected_sequence is not None:
                sequence = _incoming_response_sequence(response_data)
                if _is_stale_response_sequence(sequence, expected_sequence):
                    stale_responses += 1
                    logger.warning(
                        "Ignoring stale S7CommPlus response sequence %d while waiting for sequence %d",
                        sequence,
                        expected_sequence,
                    )
                    if stale_responses > _MAX_STALE_RESPONSES_PER_REQUEST:
                        raise S7ProtocolError(
                            f"Too many stale S7CommPlus responses while waiting for sequence {expected_sequence}"
                        )
                    continue
            return response_data

    async def _recv_reassembled_payload(self, initial_data: bytes = b"") -> bytes:
        """Receive a possibly-fragmented S7CommPlus response, returning its data section.

        A large response is split into several S7CommPlus PDUs. Each fragment is
        ``0x72 <ver> <len:2> <data:len>`` with no trailer; only the final fragment is
        followed by the ``0x72 <ver> 0x0000`` trailer. We concatenate the data parts
        of every fragment until the trailer is seen. Works for single-PDU responses
        too (one fragment immediately followed by the trailer). After SessionKey
        auth every fragment must be V3, and its HMAC covers the fragments so far.
        """
        buf = bytearray(initial_data)
        # Until the trailer is read the stream sits inside this reply.
        self._rx_partial = True

        async def ensure(n: int) -> None:
            while len(buf) < n:
                chunk = await self._receive_bounded(
                    self._recv_cotp_dt(),
                    self._request_timeout,
                    f"The PLC's multi-part reply stopped for {self._request_timeout}s",
                )
                self._rx_partial = True
                if not chunk:
                    raise S7ConnectionError("Connection closed during response reassembly")
                buf.extend(chunk)

        from ._fragment_hmac import FragmentHMACVerifier

        session_key = self._session_key
        legacy_verifier = FragmentHMACVerifier(session_key) if self.legacy_s7_1500 and session_key else None
        digest_state = hmac.new(session_key[:24], digestmod=hashlib.sha256) if session_key is not None else None
        data = bytearray()
        fragments = 0
        system_events = 0
        expected_version: int | None = None
        while True:
            await ensure(4)
            if buf[0] != 0x72:
                raise S7ConnectionError("Expected S7CommPlus fragment header (0x72)")
            fragment_version = buf[1]
            if fragment_version == ProtocolVersion.SYSTEM_EVENT:
                # See S7CommPlusConnection._recv_reassembled_payload.
                event_len = (buf[2] << 8) | buf[3]
                await ensure(4 + event_len)
                event = bytes(buf[4 : 4 + event_len])
                del buf[: 4 + event_len]
                _check_system_event(event)
                system_events += 1
                if system_events > _MAX_SYSTEM_EVENTS_PER_RESPONSE:
                    raise S7ProtocolError("Too many S7CommPlus SystemEvents during response reassembly")
                continue
            if session_key is not None and fragment_version != ProtocolVersion.V3:
                await self._invalidate_integrity_failure()
                raise S7IntegrityError(
                    f"Authenticated response used unauthenticated frame version V{fragment_version}; reconnect"
                )
            if expected_version is None:
                expected_version = fragment_version
            elif fragment_version != expected_version:
                if session_key is not None:
                    await self._invalidate_integrity_failure()
                    raise S7IntegrityError(
                        f"Authenticated S7CommPlus response changed fragment version from {expected_version} "
                        f"to {fragment_version}; reconnect"
                    )
                raise S7ConnectionError(
                    f"S7CommPlus response changed fragment version from {expected_version} to {fragment_version}"
                )
            frag_len = (buf[2] << 8) | buf[3]
            del buf[:4]
            if frag_len == 0:
                break  # standalone trailer (defensive)
            await ensure(frag_len)
            fragment_data = bytes(buf[:frag_len])
            del buf[:frag_len]
            if digest_state is not None:
                try:
                    fragment_data = (
                        legacy_verifier.verify(fragment_data)
                        if legacy_verifier is not None
                        else _verify_v3_hmac(fragment_data, digest_state)
                    )
                except S7IntegrityError:
                    await self._invalidate_integrity_failure()
                    raise
            data.extend(fragment_data)
            fragments += 1
            if fragments > self._MAX_REASSEMBLED_FRAGMENTS or len(data) > self._MAX_REASSEMBLED_BYTES:
                raise S7ConnectionError(f"Reassembled response exceeds limits ({len(data)} bytes, {fragments} fragments)")
            # The next 4 bytes are either the trailer (0x72 ver 0x0000) or the next
            # fragment's header (0x72 ver len>0).
            await ensure(4)
            if buf[0] == 0x72 and buf[2] == 0 and buf[3] == 0:
                del buf[:4]  # consume trailer — last fragment
                break
        self._rx_partial = False
        return bytes(data)

    async def _cotp_connect(self, local_tsap: int, remote_tsap: bytes) -> None:
        """Perform COTP Connection Request / Confirm handshake."""
        if self._writer is None or self._reader is None:
            raise S7ConnectionError("Not connected")

        base_pdu = struct.pack(">BBHHB", 6, _COTP_CR, 0x0000, 0x0001, 0x00)
        calling_tsap = struct.pack(">BBH", 0xC1, 2, local_tsap)
        called_tsap = struct.pack(">BB", 0xC2, len(remote_tsap)) + remote_tsap
        pdu_size_param = struct.pack(">BBB", 0xC0, 1, 0x0A)

        params = calling_tsap + called_tsap + pdu_size_param
        cr_pdu = struct.pack(">B", 6 + len(params)) + base_pdu[1:] + params

        tpkt = struct.pack(">BBH", 3, 0, 4 + len(cr_pdu)) + cr_pdu
        self._writer.write(tpkt)
        await self._writer.drain()

        tpkt_header = await self._reader.readexactly(4)
        _, _, length = struct.unpack(">BBH", tpkt_header)
        payload = await self._reader.readexactly(length - 4)

        if len(payload) < 7:
            raise S7ConnectionError(f"COTP CC response too short: {len(payload)} bytes")
        if payload[1] != _COTP_CC:
            raise S7ConnectionError(f"Expected COTP CC, got {payload[1]:#04x}")

    async def _init_ssl(self) -> None:
        """Send InitSSL request (required before CreateObject)."""
        seq_num = self._next_sequence_number()

        request = struct.pack(
            ">BHHHHIB",
            Opcode.REQUEST,
            0x0000,
            FunctionCode.INIT_SSL,
            0x0000,
            seq_num,
            0x00000000,
            0x30,
        )
        request += struct.pack(">I", 0)

        frame = encode_header(ProtocolVersion.V1, len(request)) + request
        frame += struct.pack(">BBH", 0x72, ProtocolVersion.V1, 0x0000)
        await self._send_cotp_dt(frame)

        response_data = await self._recv_cotp_dt()
        version, data_length, consumed = decode_header(response_data)
        response = response_data[consumed : consumed + data_length]

        if len(response) < 10:
            raise S7ConnectionError("InitSSL response too short")

        logger.debug(f"InitSSL response received, version=V{version}")

    async def _create_session(self) -> None:
        """Send CreateObject to establish S7CommPlus session."""
        seq_num = self._next_sequence_number()

        request = struct.pack(
            ">BHHHHIB",
            Opcode.REQUEST,
            0x0000,
            FunctionCode.CREATE_OBJECT,
            0x0000,
            seq_num,
            ObjectId.OBJECT_NULL_SERVER_SESSION,
            0x36,
        )

        request += struct.pack(">I", ObjectId.OBJECT_SERVER_SESSION_CONTAINER)
        request += bytes([0x00, DataType.UDINT]) + encode_uint32_vlq(0)
        request += struct.pack(">I", 0)

        request += bytes([ElementID.START_OF_OBJECT])
        request += struct.pack(">I", ObjectId.GET_NEW_RID_ON_SERVER)
        request += encode_uint32_vlq(ObjectId.CLASS_SERVER_SESSION)
        request += encode_uint32_vlq(0)
        request += encode_uint32_vlq(0)

        request += bytes([ElementID.ATTRIBUTE])
        request += encode_uint32_vlq(ObjectId.SERVER_SESSION_CLIENT_RID)
        request += bytes([0x00]) + encode_typed_value(DataType.RID, 0x80C3C901)

        request += bytes([ElementID.START_OF_OBJECT])
        request += struct.pack(">I", ObjectId.GET_NEW_RID_ON_SERVER)
        request += encode_uint32_vlq(ObjectId.CLASS_SUBSCRIPTIONS)
        request += encode_uint32_vlq(0)
        request += encode_uint32_vlq(0)
        request += bytes([ElementID.TERMINATING_OBJECT])

        request += bytes([ElementID.TERMINATING_OBJECT])
        request += struct.pack(">I", 0)

        frame = encode_header(ProtocolVersion.V1, len(request)) + request
        frame += struct.pack(">BBH", 0x72, ProtocolVersion.V1, 0x0000)
        await self._send_cotp_dt(frame)

        response_data = await self._recv_cotp_dt()
        version, data_length, consumed = decode_header(response_data)
        response = response_data[consumed : consumed + data_length]

        if len(response) < 10:
            raise S7ConnectionError("CreateObject response too short")

        # Response header is 10 bytes (opcode+reserved+func+reserved+seq+transport).
        # Responses do NOT carry a SessionId field (unlike requests which are 14 bytes).
        body = response[10:]
        object_ids, obj_end, return_value = parse_create_object_session_id(body)
        if object_ids:
            self._session_id = object_ids[0]
            self._subscription_container_id = object_ids[1] if len(object_ids) > 1 else 0
        else:
            self._session_id = struct.unpack_from(">I", response, 9)[0]
            self._subscription_container_id = 0
        self._protocol_version = version

        _log_create_object_return_value(return_value, self._tls_active)

        attrs = parse_create_object_attributes(response[10 + obj_end :])
        self._server_session_version = attrs.server_session_version
        if self._server_session_version is not None:
            logger.info(f"ServerSessionVersion captured: {len(self._server_session_version)} bytes")
        else:
            logger.debug("ServerSessionVersion not found in CreateObject response")
        if attrs.public_key_fingerprint is not None:
            self._public_key_fingerprint = attrs.public_key_fingerprint
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
        """Generate the SecurityKey blob for a V1 session without TLS, or return None (see the sync connection)."""
        if self._tls_active or self._protocol_version != ProtocolVersion.V1:
            return None
        if self._session_challenge is None or self._public_key_fingerprint is None:
            return None
        fingerprint = self._session_key_fingerprint_override or self._public_key_fingerprint
        result = _generate_session_key_blob(self._session_challenge, fingerprint)
        if result is None:
            return None
        blob, session_key, self._v1_session_key_public_key, self._v1_session_key_family = result
        return blob, session_key

    async def _setup_session(self) -> bool:
        """Echo ServerSessionVersion back to the PLC via SetMultiVariables.

        On V1-initial PLCs this also carries the SecurityKey blob, in the same
        V2-framed request the synchronous connection sends.
        """
        if self._server_session_version is None:
            return False

        auth_result = self._try_session_key_auth()
        if auth_result is not None:
            blob, session_key = auth_result
            security_key = _encode_security_key_struct(
                self._v1_session_key_public_key, self._v1_session_key_family, blob, session_key
            )
            frame = _build_session_setup_frame(
                self._session_id,
                self._next_sequence_number(),
                self._server_session_version,
                self._protocol_version,
                security_key,
            )
            async with self._lock:
                await self._send_cotp_dt(frame)
                reply = await self._receive_bounded(
                    self._recv_cotp_dt(),
                    self._request_timeout,
                    f"No session setup reply from the PLC within {self._request_timeout}s",
                )
                accepted = _session_setup_accepted(reply)
            if accepted:
                self._session_key = session_key
                self._with_integrity_id = True
                self._integrity_id_read = 0
                self._integrity_id_write = 0
                logger.info("SecurityKey accepted by PLC, IntegrityId tracking enabled")
            return accepted

        payload = bytearray()
        payload += struct.pack(">I", self._session_id)
        payload += encode_uint32_vlq(1)
        payload += encode_uint32_vlq(1)
        payload += encode_uint32_vlq(ObjectId.SERVER_SESSION_VERSION)
        payload += encode_uint32_vlq(1)
        # PValue: echo the ServerSessionVersion typed value verbatim (it may be a Struct)
        payload += self._server_session_version
        payload += bytes([0x00])
        payload += encode_object_qualifier(protocol_version=self._protocol_version)
        payload += struct.pack(">I", 0)

        resp_payload = await self._send_request(FunctionCode.SET_MULTI_VARIABLES, bytes(payload))
        if len(resp_payload) >= 1:
            return_value, _ = decode_uint64_vlq(resp_payload, 0)
            if return_value != 0:
                logger.warning(f"SetupSession: PLC returned error {return_value}")
                return False
            logger.info("Session setup completed successfully")
            return True
        return False

    def _skip_integrity_ids_after_legitimation(self) -> None:
        """Skip one IntegrityId on both counters after the S7-1200 legitimation.

        An S7-1215C on FW V4.2 resets the connection when the first data
        request after legitimation carries the next id of either counter, and
        accepts it one id later. The handshake itself must start at id 0: the
        same PLC rejects a session activation sent with id 1. S7-1500 FW 2.6
        does not need the skip.
        """
        if self.legacy_s7_1500 and self._v1_session_key_family == KeyFamily.S7_1200:
            self._integrity_id_read = (self._integrity_id_read + 1) & 0xFFFFFFFF
            self._integrity_id_write = (self._integrity_id_write + 1) & 0xFFFFFFFF

    async def _session_activate(self) -> None:
        """Activate the V3 session after the SecurityKey handshake (SET_VARIABLE addr 323 = USINT(5))."""
        async with self._lock:
            payload = _build_session_activate_payload(self._session_id, self._sequence_number)
            await self._send_request_locked(FunctionCode.SET_VARIABLE, payload, integrity_tail=3)
        logger.info("Session activation completed")

    async def _post_auth_legitimation(self, password: str = "") -> None:
        """Solve the V1 legitimation challenge after the SessionKey handshake (see the sync connection)."""
        if self._v1_session_key_family == KeyFamily.PLCSIM:
            _skip_plcsim_legitimation(password)
            return
        async with self._lock:
            payload = _build_v1_get_var_substreamed_payload(
                self._v1_session_key_family, self._session_id, LegitimationId.SERVER_SESSION_REQUEST, self._sequence_number
            )
            challenge_resp = await self._send_request_locked(
                FunctionCode.GET_VAR_SUBSTREAMED, payload, integrity_tail=_v1_integrity_tail(self._v1_session_key_family)
            )

        # Never substitute the earlier CreateObject challenge when this read
        # fails: it belongs to a different authentication exchange.
        challenge = _parse_get_var_substreamed_response(challenge_resp)
        if len(challenge) != 20:
            raise S7ConnectionError("Post-auth legitimation failed: expected a 20-byte challenge")

        from .v1_session_key.legitimation import solve_legitimate_challenge_real_plc

        session_key = self._session_key
        if session_key is None:
            raise S7ConnectionError("Post-auth legitimation failed: no session key")
        blob = solve_legitimate_challenge_real_plc(
            challenge, self._v1_session_key_public_key, self._v1_session_key_family, session_key, password
        )

        async with self._lock:
            payload = _build_v1_legitimation_payload(self._session_id, self._sequence_number, blob)
            response = await self._send_request_locked(FunctionCode.SET_VAR_SUBSTREAMED, payload, integrity_tail=3)
        _check_v1_legitimation_response(response, self._last_raw_response_payload)
        logger.info("Post-auth legitimation completed")

    async def _delete_session(self) -> None:
        """Send DeleteObject to close the session."""
        seq_num = self._next_sequence_number()

        request = struct.pack(
            ">BHHHHIB",
            Opcode.REQUEST,
            0x0000,
            FunctionCode.DELETE_OBJECT,
            0x0000,
            seq_num,
            self._session_id,
            0x34,
        )
        request += struct.pack(">I", 0)

        frame = encode_header(self._protocol_version, len(request)) + request
        frame += struct.pack(">BBH", 0x72, self._protocol_version, 0x0000)
        await self._send_cotp_dt(frame)

        try:
            await asyncio.wait_for(self._recv_cotp_dt(), timeout=1.0)
        except Exception:
            pass

    async def _send_cotp_dt(self, data: bytes) -> None:
        """Send an S7CommPlus frame, routing through TLS (tunneled in COTP) when active."""
        if self._tls_active:
            assert self._ssl_object is not None
            self._ssl_object.write(data)
            await self._tls_flush_outgoing()
        else:
            await self._send_cotp_raw(data)

    async def _recv_cotp_dt(self) -> bytes:
        """Receive an S7CommPlus frame, decrypting from the TLS tunnel when active."""
        if self._tls_active:
            assert self._ssl_object is not None
            while True:
                try:
                    frame = self._ssl_object.read(65536)
                except ssl.SSLWantReadError:
                    await self._tls_read_incoming()
                    continue
                self._rx_partial = False
                return frame
        frame = await self._recv_cotp_raw()
        self._rx_partial = False
        return frame

    async def _send_cotp_raw(self, data: bytes) -> None:
        """Send raw bytes wrapped in COTP DT + TPKT (no TLS)."""
        if self._writer is None:
            raise S7ConnectionError("Not connected")

        cotp_dt = struct.pack(">BBB", 2, _COTP_DT, 0x80) + data
        tpkt = struct.pack(">BBH", 3, 0, 4 + len(cotp_dt)) + cotp_dt
        self._writer.write(tpkt)
        try:
            await asyncio.wait_for(self._writer.drain(), self._request_timeout)
        except asyncio.TimeoutError as exc:
            # The frame is still queued, so the session cannot be resumed.
            message = f"The PLC accepted no data for {self._request_timeout}s"
            self._connection_lost(message)
            raise S7TimeoutError(message) from exc

    async def _recv_cotp_raw(self) -> bytes:
        """Receive one TPKT + COTP DT frame and return the payload (no TLS)."""
        if self._reader is None:
            raise S7ConnectionError("Not connected")

        # readexactly() consumes nothing until all its bytes are buffered, so a
        # cancelled header read loses nothing; after it, part of a frame is read.
        tpkt_header = await self._reader.readexactly(4)
        self._rx_partial = True
        _, _, length = struct.unpack(">BBH", tpkt_header)
        payload = await self._reader.readexactly(length - 4)

        if len(payload) < 3:
            raise S7ConnectionError(f"COTP DT response too short: {len(payload)} bytes")
        if payload[1] != _COTP_DT:
            raise S7ConnectionError(f"Expected COTP DT, got {payload[1]:#04x}")

        return payload[3:]

    def _next_sequence_number(self) -> int:
        seq = self._sequence_number
        self._sequence_number = (self._sequence_number + 1) & 0xFFFF
        return seq

    async def __aenter__(self) -> "S7CommPlusAsyncClient":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.disconnect()
