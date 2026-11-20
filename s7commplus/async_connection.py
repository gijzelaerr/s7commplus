"""Transport and session of the async S7CommPlus client.

``S7CommPlusAsyncConnection`` is the asyncio counterpart of
``s7commplus.connection.S7CommPlusConnection``: the TPKT/COTP stream, TLS,
the handshake, SessionKey renewal and the request path, around the shared
``SessionCore``. ``S7CommPlusAsyncClient`` holds one and keeps reconnects,
subscriptions, the tag catalog and the operations.

Reference: thomas-v2/S7CommPlusDriver (C#, LGPL-3.0)
"""

import asyncio
import contextlib
import logging
import ssl
import struct
import time
from collections import deque
from typing import Any, Awaitable, Callable, Optional, TypeVar

from .error import (
    S7CertificateError,
    S7ConnectionError,
    S7NotConnectedError,
    S7Error,
    S7IntegrityError,
    S7TimeoutError,
    S7TlsHandshakeError,
)

from ._session_core import SessionCore
from ._session_core import _Incoming, _ReplyWait
from .codec import (
    SERVER_SESSION_ROLE_SECURED_BIT,
)
from .connection import (
    _DEFAULT_EXPLORE_TIMEOUT,
    _DEFAULT_LEGACY_SESSION_KEY_REFRESH_INTERVAL,
    _MAX_QUEUED_NOTIFICATION_FRAMES,
    SessionKeyAuthenticationDependencyError,
    SessionKeyCandidateRejectedError,
    _alarm_texts_and_domain_filter,
    _check_set_variable_response,
    _check_v1_legitimation_response,
    _build_subscription_credit_frame,
    _check_certificate_pin,
    _parse_get_var_substreamed_response,
    _parse_protection_level_response,
    _resolve_session_key_fingerprint,
    _sends_session_activation,
    _tls_key_log,
    _write_delete_qualifier_version,
    _response_continues,
)
from .legitimation import (
    extract_session_oms_version,
    oms_session_version_name,
)
from .protocol import (
    S7COMMPLUS_LOCAL_TSAP,
    FunctionCode,
    LegitimationType,
    remote_tsap_for_connection_type,
    ProtocolVersion,
)
from .transport import _configure_tcp_socket
from .v1_session_key.keys import KeyFamily

logger = logging.getLogger(__name__)

_T = TypeVar("_T")

# COTP constants
_COTP_CR = 0xE0
_COTP_CC = 0xD0
_COTP_DT = 0xF0


def _nothing() -> None:
    return None


def _never() -> bool:
    return False


class S7CommPlusAsyncConnection(SessionCore):
    """One asyncio transport and S7CommPlus session, reused across reconnects."""

    def __init__(
        self,
        *,
        on_close: Callable[[], None] = _nothing,
        on_reset: Callable[[], None] = _nothing,
        blocked: Callable[[], bool] = _never,
    ) -> None:
        # Hooks into the owning client: on_close runs when a session is closed
        # on purpose (before its DeleteObject), on_reset whenever the session
        # state is cleared, and blocked says whether another task's reconnect
        # owns the stream, so this task's requests must not use it.
        self._on_close = on_close
        self._on_reset = on_reset
        self._blocked = blocked
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._session_id: int = 0
        self._subscription_container_id: int = 0
        self._sequence_number: int = 0
        self._protocol_version: int = 0
        self._transport_connected = False
        self._request_timeout = 5.0
        # The same bound for the reply to an EXPLORE, which can be large.
        self._explore_timeout = _DEFAULT_EXPLORE_TIMEOUT
        self._notification_timeout: Optional[float] = None
        # True while part of a message (a frame, or a reply still missing
        # fragments) has been read: a wait cut short then closes the session.
        self._rx_partial = False
        self._session_ready = False
        self._connected = False
        self._lock = asyncio.Lock()
        self._notification_frames: deque[bytes] = deque(maxlen=_MAX_QUEUED_NOTIFICATION_FRAMES)
        self._notification_frame_overflows = 0

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
        # Pinned TLS certificate: expected SHA-256 (set by connect) and the one
        # the PLC actually presented (captured during the handshake).
        self._tls_cert_fingerprint: Optional[bytes] = None
        self._peer_certificate_fingerprint: Optional[bytes] = None
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
        self._last_response_function: int | None = None
        self._public_key_fingerprint: Optional[str] = None
        self._public_key_checksum: Optional[bytes] = None
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

    async def connect(self, p: dict[str, Any], fingerprint: Optional[str] = None) -> None:
        """Open one transport and session with the client's ``connect()`` arguments ``p``.

        ``fingerprint`` is the SessionKey candidate to try, if any. Legitimation
        with a password over TLS is left to the client.
        """
        self._host = p["host"]
        use_tls = p["use_tls"]
        self._legacy_s7_1500 = p["legacy_s7_1500"]
        self._session_key_refresh_interval = p["legacy_session_key_refresh_interval"]
        self._session_key_refresh_error = None
        self._session_key_fingerprint_override = fingerprint
        self._tls_cert_fingerprint = _check_certificate_pin(p["tls_cert_fingerprint"], use_tls)
        self._peer_certificate_fingerprint = None
        self._request_timeout = p["timeout"] if p["request_timeout"] is None else p["request_timeout"]
        self._explore_timeout = self._request_timeout if p["explore_timeout"] is None else p["explore_timeout"]
        self._notification_timeout = p["notification_timeout"]

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
                if _sends_session_activation(self._v1_session_key_family):
                    await self._session_activate()
                else:
                    logger.info("Skipping the address-323 session activation for %s", self._v1_session_key_family)
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
        """Legitimate the session with ``password``; see :meth:`S7CommPlusAsyncClient.authenticate`."""
        if not self._connected:
            raise S7NotConnectedError("Not connected")
        plan = self._plan_legitimation(password)
        if plan is None:
            return
        mode, level_before = plan
        reply = self._legitimation_reply(mode, await self._get_legitimation_challenge(), password, username)
        if mode is LegitimationType.LEGACY:
            await self._send_legitimation_legacy(reply)
        else:
            await self._send_legitimation_new(reply)
        self._legitimation_sent(mode)
        # Renewing the protection level is what verifies the outcome.
        self._protection_level = await self._get_effective_protection_level()
        self._check_legitimation_outcome(level_before)

    async def _activate_tls(
        self,
        tls_cert: Optional[str] = None,
        tls_key: Optional[str] = None,
        tls_ca: Optional[str] = None,
    ) -> None:
        """Activate TLS over the COTP connection."""
        if self._writer is None:
            raise S7ConnectionError("Cannot activate TLS: not connected")
        ctx = self._setup_ssl_context(cert_path=tls_cert, key_path=tls_key, ca_path=tls_ca)
        with _tls_key_log(ctx) as keylog_path:
            # Read the host only when it is checked: it is set by connect().
            self._start_tls_session(ctx, self._host if ctx.check_hostname else None)
            # TLS handshake: records tunnel through COTP frames
            try:
                await self._do_tls_handshake()
            except ssl.SSLCertVerificationError as exc:
                raise S7CertificateError(f"PLC TLS certificate failed verification: {exc.verify_message}") from exc
            except (ssl.SSLError, OSError, EOFError, asyncio.TimeoutError, S7Error) as exc:
                raise S7TlsHandshakeError(f"TLS handshake with the PLC did not complete: {exc}") from exc
            self._tls_session_established(keylog_path)

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
        """Read the session's effective protection level (see `AccessLevel`), None if the PLC did not report one.

        Raises:
            S7ConnectionError: The connection was lost during the read. Until then the
                session can look established, so this is the first request to find out.
        """
        try:
            reply = await self.send_request(FunctionCode.GET_VAR_SUBSTREAMED, self._protection_level_payload(), integrity_tail=4)
            return _parse_protection_level_response(reply)
        except S7ConnectionError as exc:
            if self._writer is None:
                raise
            logger.warning(f"PLC did not report a protection level: {exc}")
            return None

    async def _get_legitimation_challenge(self) -> bytes:
        """Request legitimation challenge from PLC."""
        reply = await self.send_request(
            FunctionCode.GET_VAR_SUBSTREAMED, self._legitimation_challenge_payload(), integrity_tail=4
        )
        return _parse_get_var_substreamed_response(reply)

    async def _send_legitimation_new(self, encrypted_response: bytes) -> None:
        """Send new-style legitimation response (AES-256-CBC encrypted)."""
        reply = await self.send_request(
            FunctionCode.SET_VARIABLE, self._new_legitimation_payload(encrypted_response), integrity_tail=4
        )
        _check_set_variable_response(reply, self._last_response_function)

    async def _send_legitimation_legacy(self, response: bytes) -> None:
        """Send legacy legitimation response (SHA-1 XOR)."""
        reply = await self.send_request(FunctionCode.SET_VARIABLE, self._legacy_legitimation_payload(response), integrity_tail=4)
        _check_set_variable_response(reply, self._last_response_function)

    async def _close(self) -> None:
        """Tear down the session and transport, keeping the connect parameters and any renewal failure."""
        self._stop_session_key_refresh()
        self._on_close()
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
        raises ``S7NotConnectedError("Not connected")``. The connect parameters
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
        self._clear_session_state()
        self._transport_connected = False
        self._on_reset()
        self._rx_partial = False

        writer = self._writer
        self._writer = None
        self._reader = None
        return writer

    async def _invalidate_integrity_failure(self) -> None:
        """Discard authenticated state without writing to an untrusted stream."""
        self._session_ready = False
        await self._close()

    def _stop_session_key_refresh(self) -> None:
        """Cancel the renewal task, unless it is the task doing the stopping."""
        task = self._session_key_refresh_task
        self._session_key_refresh_task = None
        if task is not None and task is not asyncio.current_task():
            task.cancel()

    def _schedule_session_key_refresh(self) -> None:
        """Start renewing an authenticated legacy session's key periodically."""
        interval = self._renewal_interval()
        if interval is None:
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
        challenge_reply = await self._send_request_locked(FunctionCode.GET_VAR_SUBSTREAMED, self._renewal_challenge_payload(), 4)
        payload, new_session_key = self._renewal_request(challenge_reply)
        self._renewed(await self._send_request_locked(FunctionCode.SET_VARIABLE, payload, 4), new_session_key)

    def _notification_wait(self, timeout: Optional[float]) -> float:
        """Seconds a notification wait may take: per call, else notification_timeout, else the request timeout."""
        if timeout is not None:
            return timeout
        if self._notification_timeout is not None:
            return self._notification_timeout
        return self._request_timeout

    # Longest a notification wait holds the request lock while no frame is arriving.
    _NOTIFICATION_LOCK_SLICE = 0.05

    async def _recv_notification_frame(self, deadline: float, wait: float) -> Optional[bytes]:
        """Receive one unsolicited frame by ``deadline`` (``time.monotonic()``), else raise S7TimeoutError.

        Called with the request lock held. It waits at most
        :attr:`_NOTIFICATION_LOCK_SLICE` for a frame to start and returns
        ``None`` if none did, so that the caller can release the lock for other
        requests and call again. A frame that has started is read to its end
        by ``deadline``. A wait that runs out before any byte of the frame was
        read keeps the session; one cut off part-way closes it.
        """
        message = f"No notification from the PLC within {wait}s"
        left = deadline - time.monotonic()
        if left <= 0:
            raise S7TimeoutError(message)
        receive = asyncio.ensure_future(self._recv_cotp_dt())
        try:
            done, _ = await asyncio.wait({receive}, timeout=min(left, self._NOTIFICATION_LOCK_SLICE))
        except asyncio.CancelledError:
            receive.cancel()
            # Let the read finish cancelling before the lock is released.
            with contextlib.suppress(asyncio.CancelledError):
                await asyncio.wait({receive})
            if self._rx_partial:
                self._connection_lost("a read was cancelled part-way through a frame")
            raise
        if done:
            return receive.result()
        if not self._rx_partial:
            # Nothing of a frame was read, so cancelling loses nothing.
            receive.cancel()
            await asyncio.wait({receive})
            return None if receive.cancelled() else receive.result()
        left = deadline - time.monotonic()
        return await self._receive_bounded(receive, max(left, 0.0), message, idle_ok=True)

    async def _send_subscription_credit(self, subscription_id: int, credit_limit: int) -> None:
        """Send a fire-and-forget update before finite credits expire."""
        if not 1 <= credit_limit <= 255:
            raise ValueError("credit_limit must be between 1 and 255")
        async with self._lock:
            if not self._connected or self._writer is None or self._reader is None or self._blocked():
                raise S7NotConnectedError("Not connected")
            frame = _build_subscription_credit_frame(
                subscription_id,
                credit_limit,
                self._next_sequence_number(),
                self._session_id,
                self._integrity_id_write if self._with_integrity_id else None,
                self._protocol_version,
                self._session_key,
            )
            await self._send_cotp_dt(frame)
            if self._with_integrity_id:
                self._integrity_id_write = (self._integrity_id_write + 1) & 0xFFFFFFFF

    async def send_request(
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
        """:meth:`send_request` for a caller that already holds the request lock."""
        if self._session_key_refresh_error is not None:
            raise self._session_key_refresh_error
        if not (self._connected or self._transport_connected) or self._writer is None or self._reader is None:
            raise S7NotConnectedError("Not connected")
        if self._blocked():
            # Another task's reconnect owns the stream until its handshake is done.
            raise S7NotConnectedError("Not connected")

        pending = self._encode_request(function_code, payload, integrity_tail)
        await self._send_cotp_dt(pending.frame)
        self._request_sent(pending)

        reply_timeout = self._reply_timeout(function_code)
        response_data = await self._receive_bounded(
            self._recv_response_frame(pending.sequence),
            reply_timeout,
            f"No reply from the PLC within {reply_timeout}s",
        )

        # Large responses (e.g. Explore) are split across several S7CommPlus PDUs;
        # any response whose first PDU has no trailer is reassembled the same way.
        if reassemble or _response_continues(response_data):
            data = await self._recv_reassembled_payload(response_data, reply_timeout)
            return self._decode_reassembled(pending, data)
        try:
            return self._decode_response(pending, response_data)
        except S7IntegrityError:
            await self._invalidate_integrity_failure()
            raise

    async def _verified_incoming_data(self, frame: bytes) -> bytes:
        """Return application data after authenticating the complete frame."""
        try:
            return self._authenticated_data(frame)
        except S7IntegrityError:
            await self._invalidate_integrity_failure()
            raise

    def _reply_timeout(self, function_code: int) -> float:
        """Seconds each wait for the reply to ``function_code`` may take: the EXPLORE timeout, else the request timeout."""
        return self._explore_timeout if function_code == FunctionCode.EXPLORE else self._request_timeout

    async def _receive_bounded(self, receive: Awaitable[_T], timeout: float, message: str, *, idle_ok: bool = False) -> _T:
        """Await one receive for at most ``timeout`` seconds.

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
        wait = _ReplyWait()
        while True:
            response_data = await self._recv_cotp_dt()
            try:
                step = self._sort_incoming(response_data, expected_sequence, wait)
            except S7IntegrityError:
                await self._invalidate_integrity_failure()
                raise
            if step is _Incoming.REPLY:
                return response_data
            if step is _Incoming.DRAIN:
                await self._recv_reassembled_payload(response_data)

    async def _recv_reassembled_payload(self, initial_data: bytes = b"", timeout: Optional[float] = None) -> bytes:
        """Receive a possibly-fragmented S7CommPlus response, returning its data section.

        A large response is split into several S7CommPlus PDUs. Each fragment is
        ``0x72 <ver> <len:2> <data:len>`` with no trailer; only the final fragment is
        followed by the ``0x72 <ver> 0x0000`` trailer. We concatenate the data parts
        of every fragment until the trailer is seen. Works for single-PDU responses
        too (one fragment immediately followed by the trailer). After SessionKey
        auth every fragment must be V3, and its HMAC covers the fragments so far.
        ``timeout`` bounds the wait for each further part in seconds (``None``:
        the request timeout).
        """
        wait = self._request_timeout if timeout is None else timeout
        # Until the trailer is read the stream sits inside this reply.
        self._rx_partial = True
        reassembly = self._reassemble(initial_data)
        try:
            next(reassembly)
            while True:
                chunk = await self._receive_bounded(
                    self._recv_cotp_dt(),
                    wait,
                    f"The PLC's multi-part reply stopped for {wait}s",
                )
                self._rx_partial = True
                if not chunk:
                    raise S7ConnectionError("Connection closed during response reassembly")
                reassembly.send(chunk)
        except StopIteration as done:
            self._rx_partial = False
            data: bytes = done.value
            return data
        except S7IntegrityError:
            await self._invalidate_integrity_failure()
            raise

    async def _cotp_connect(self, local_tsap: int, remote_tsap: bytes) -> None:
        """Perform COTP Connection Request / Confirm handshake."""
        if self._writer is None or self._reader is None:
            raise S7NotConnectedError("Not connected")

        base_pdu = struct.pack(">BBHHB", 6, _COTP_CR, 0x0000, 0x0001, 0x00)
        calling_tsap = struct.pack(">BBH", 0xC1, 2, local_tsap)
        called_tsap = struct.pack(">BB", 0xC2, len(remote_tsap)) + remote_tsap
        pdu_size_param = struct.pack(">BBB", 0xC0, 1, 0x0A)

        params = calling_tsap + called_tsap + pdu_size_param
        cr_pdu = struct.pack(">B", 6 + len(params)) + base_pdu[1:] + params

        tpkt = struct.pack(">BBH", 3, 0, 4 + len(cr_pdu)) + cr_pdu
        await self._write_tpkt(tpkt)

        payload = await self._read_tpkt()

        if len(payload) < 7:
            raise S7ConnectionError(f"COTP CC response too short: {len(payload)} bytes")
        if payload[1] != _COTP_CC:
            raise S7ConnectionError(f"Expected COTP CC, got {payload[1]:#04x}")

    async def _init_ssl(self) -> None:
        """Send InitSSL request (required before CreateObject)."""
        pending = self._encode_init_ssl()
        await self._send_cotp_dt(pending.frame)
        self._check_init_ssl_reply(await self._recv_cotp_dt())

    async def _create_session(self) -> None:
        """Send CreateObject to establish S7CommPlus session."""
        pending = self._encode_create_object()
        await self._send_cotp_dt(pending.frame)
        self._apply_create_object_reply(await self._recv_cotp_dt())

    async def _setup_session(self) -> bool:
        """Echo ServerSessionVersion back to the PLC via SetMultiVariables.

        On V1-initial PLCs this also carries the SecurityKey blob, in the same
        V2-framed request the synchronous connection sends.
        """
        setup = self._encode_session_setup()
        if setup is None:
            return False
        pending, auth_result = setup
        async with self._lock:
            await self._send_cotp_dt(pending.frame)
            # A SystemEvent before the reply is routed like one during any
            # request, so a fatal event is not taken for the reply.
            reply = await self._receive_bounded(
                self._recv_response_frame(pending.sequence),
                self._request_timeout,
                f"No session setup reply from the PLC within {self._request_timeout}s",
            )
        return self._apply_session_setup_reply(pending, auth_result, reply)

    async def _session_activate(self) -> None:
        """Activate the V3 session after the SecurityKey handshake (SET_VARIABLE addr 323 = USINT(5))."""
        async with self._lock:  # the payload carries the next sequence number
            await self._send_request_locked(FunctionCode.SET_VARIABLE, self._session_activate_payload(), integrity_tail=3)
        self._session_activated()

    async def _post_auth_legitimation(self, password: str = "") -> None:
        """Solve the V1 legitimation challenge after the SessionKey handshake (see the sync connection)."""
        async with self._lock:  # the payload carries the next sequence number
            payload, tail = self._post_auth_challenge_request()
            challenge_reply = await self._send_request_locked(FunctionCode.GET_VAR_SUBSTREAMED, payload, integrity_tail=tail)
        blob = self._solve_post_auth_challenge(challenge_reply, password)
        async with self._lock:
            payload, tail = self._post_auth_blob_request(blob)
            response = await self._send_request_locked(FunctionCode.SET_VAR_SUBSTREAMED, payload, integrity_tail=tail)
        _check_v1_legitimation_response(response, self._last_raw_response_payload)
        logger.info("Post-auth legitimation completed")

    async def _delete_session(self) -> None:
        """Send DeleteObject to close the session."""
        await self._send_cotp_dt(self._encode_delete_session())
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
        cotp_dt = struct.pack(">BBB", 2, _COTP_DT, 0x80) + data
        tpkt = struct.pack(">BBH", 3, 0, 4 + len(cotp_dt)) + cotp_dt
        await self._write_tpkt(tpkt)

    async def _recv_cotp_raw(self) -> bytes:
        """Receive one TPKT + COTP DT frame and return the payload (no TLS)."""
        payload = await self._read_tpkt()

        if len(payload) < 3:
            raise S7ConnectionError(f"COTP DT response too short: {len(payload)} bytes")
        if payload[1] != _COTP_DT:
            raise S7ConnectionError(f"Expected COTP DT, got {payload[1]:#04x}")

        return payload[3:]

    async def _write_tpkt(self, tpkt: bytes) -> None:
        """Write one TPKT frame; a peer that closed or reset the stream is a dropped connection."""
        writer = self._writer
        if writer is None:
            raise S7NotConnectedError("Not connected")
        try:
            writer.write(tpkt)
            await asyncio.wait_for(writer.drain(), self._request_timeout)
        except asyncio.TimeoutError as exc:
            # The frame is still queued, so the session cannot be resumed.
            message = f"The PLC accepted no data for {self._request_timeout}s"
            self._connection_lost(message)
            raise S7TimeoutError(message) from exc
        except OSError as exc:
            self._close_failed_stream(writer)
            raise S7ConnectionError(f"Send failed: {exc}") from exc

    async def _read_tpkt(self) -> bytes:
        """Read one TPKT frame and return what follows its header.

        A peer that closed (end of stream) or reset the connection raises
        ``S7ConnectionError``, as the synchronous transport does, and closes
        the session so the next request fails fast with "Not connected".
        """
        reader, writer = self._reader, self._writer
        if reader is None:
            raise S7NotConnectedError("Not connected")
        try:
            # readexactly() consumes nothing until all its bytes are buffered, so a
            # cancelled header read loses nothing; after it, part of a frame is read.
            tpkt_header = await reader.readexactly(4)
            self._rx_partial = True
            _, _, length = struct.unpack(">BBH", tpkt_header)
            return await reader.readexactly(length - 4)
        except asyncio.IncompleteReadError as exc:
            self._close_failed_stream(writer)
            raise S7ConnectionError("Connection closed by peer") from exc
        except OSError as exc:
            self._close_failed_stream(writer)
            raise S7ConnectionError(f"Receive failed: {exc}") from exc

    def _close_failed_stream(self, writer: Optional[asyncio.StreamWriter]) -> None:
        """Close the session whose stream failed, keeping the connect parameters.

        Only the stream that failed is closed: a reconnect may already have
        replaced it. No DeleteObject is sent over the dead stream, and the
        subscription registries are left for ``disconnect()`` or a reconnect to
        clear.
        """
        if writer is None or writer is not self._writer:
            return
        self._connected = False
        self._session_ready = False
        self._transport_connected = False
        self._reader = None
        self._writer = None
        writer.close()
