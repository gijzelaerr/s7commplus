"""Async S7CommPlus client for S7-1200/1500 PLCs.

Reference: thomas-v2/S7CommPlusDriver (C#, LGPL-3.0)
"""

import asyncio
import functools
import logging
import struct
import time
from collections import deque
from collections.abc import AsyncIterator, Coroutine, Mapping, Sequence
from typing import Any, Awaitable, Callable, Concatenate, Literal, Optional, ParamSpec, TypeVar

from .error import (
    S7ConnectionError,
    S7NotConnectedError,
    S7ProtocolError,
    S7RequestError,
    S7TlsHandshakeError,
)

from . import typeinfo
from .vlq import decode_uint64_vlq
from .async_connection import S7CommPlusAsyncConnection
from .blob_decompressor import find_and_decompress
from .client import (
    _ClientMethods,
    _AUTO_REFRESH_MIN_INTERVAL,
    _block_signature,
    _type_info_times,
    _AUTO_RECONNECT_ACTIVE,
    _AUTO_RECONNECT_MARKER,
    _AUTO_RECONNECT_MIN_INTERVAL,
    _AUTO_RECONNECT_STAND_DOWN,
    _ValuePlan,
    _assemble_values,
    _encode_values,
    _raise_failures,
    _value_plans,
    _LEGACY_KEY_CACHE,
    DBWriteItem,
    OperatingStateChange,
    SymbolicReadItem,
    SymbolicWriteItem,
    _build_area_read_payload,
    _build_area_write_payload,
    _build_explore_payload_v3,
    _build_explore_request,
    _build_multi_symbolic_write_payload,
    _build_multi_symbolic_read_payload,
    _build_read_payload,
    _build_symbolic_read_payload,
    _build_symbolic_write_payload,
    _build_write_payload,
    ProgramObject,
    _PROGRAM_TREE_EXPLORE,
    _parse_program_objects,
    _parse_explore_datablocks,
    _parse_cpu_state,
    _parse_read_response,
    _parse_write_response,
    _db_read_values,
    _interrupt_tag_writes,
    _record_tag_writes,
    _write_interrupted,
    _write_item_errors,
    _write_refused,
    _check_subscription_size,
    _normalize_subscription_items,
    _plan_subscription_groups,
    _plan_tag_writes,
    _subscriptions_interrupted,
)
from .catalog import SymbolCatalog, SymbolicTag, TagResult
from .codec import (
    parse_create_object_session_id,
    parse_or_raise_for_return_value,
)
from .connection import (
    _DEFAULT_LEGACY_SESSION_KEY_REFRESH_INTERVAL,
    FamilyOnlyFingerprintError,
    SessionKeyCandidateRejectedError,
    _build_set_operating_state_payload,
    _check_timeout,
    _check_certificate_pin,
    _check_plaintext_fallback,
    _resolve_use_tls,
    _request_frame_overhead,
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
from .protocol import (
    DataType,
    FunctionCode,
    Ids,
    remote_tsap_for_connection_type,
)

logger = logging.getLogger(__name__)

_T = TypeVar("_T")
_P = ParamSpec("_P")


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


def _retry_on_dropped_connection(
    method: Callable[Concatenate["S7CommPlusAsyncClient", _P], Coroutine[Any, Any, _T]],
) -> Callable[Concatenate["S7CommPlusAsyncClient", _P], Coroutine[Any, Any, _T]]:
    """Retry a read coroutine once on a fresh session when auto-reconnect is on.

    The asyncio counterpart of the sync client's decorator, with the same
    policy (see ``s7commplus.client._retry_on_dropped_connection``): reads
    only, never writes; only an ``S7ConnectionError``; once, by the outermost
    decorated call of a task. The wrapper keeps the method's name, docstring
    and signature, and sets ``_AUTO_RECONNECT_MARKER``.
    """

    @functools.wraps(method)
    async def wrapper(self: "S7CommPlusAsyncClient", /, *args: _P.args, **kwargs: _P.kwargs) -> _T:
        active = _AUTO_RECONNECT_ACTIVE.get()
        if not self._auto_reconnect or id(self) in active:
            return await method(self, *args, **kwargs)
        token = _AUTO_RECONNECT_ACTIVE.set(active | {id(self)})
        try:
            generation = self._generation
            try:
                return await method(self, *args, **kwargs)
            except S7ConnectionError as exc:
                if not await self._recover_dropped_connection(generation, exc):
                    raise
            logger.info("Retrying %s() on the new session", method.__name__)
            return await method(self, *args, **kwargs)
        finally:
            _AUTO_RECONNECT_ACTIVE.reset(token)

    setattr(wrapper, _AUTO_RECONNECT_MARKER, True)
    return wrapper


class S7CommPlusAsyncClient(_ClientMethods):
    """Async S7CommPlus client for S7-1200/1500 PLCs.

    Use ``from s7commplus import AsyncClient`` to instantiate.

    Attributes:
        max_items_per_request: Most items one multi-item read or write request
            carries (default 50; ``0`` sends a batch in one request). A larger
            batch is split over several requests, in order. A CPU 1215C FW V4.2
            refuses a read of more than 50 items; S7-1500 hardware has not been
            measured.
        max_request_bytes: Largest request frame a multi-item read or write,
            or a subscription, sends (default 900; ``0`` disables the check),
            counted as for :class:`S7CommPlusClient`. A larger batch is split;
            an item too large for one request raises ``ValueError`` before
            anything is sent.
    """

    def __init__(self) -> None:
        # One connection for the client's lifetime: a reconnect resets and
        # reopens it, so tasks waiting on its request lock keep the same lock.
        self._connection = S7CommPlusAsyncConnection(
            on_close=self._clear_subscription_state,
            on_reset=self._forget_tag_catalog,
            blocked=self._blocked_by_rebuild,
        )
        self._connect_params: Optional[dict[str, Any]] = None
        self._symbol_catalog: Optional[SymbolCatalog] = None
        # Most items per request and largest request frame of a multi-item read
        # or write; see S7CommPlusClient for the defaults' evidence.
        self.max_items_per_request = 50
        self.max_request_bytes = 900
        # What the cached catalog was built from, for refresh_caches_if_program_changed:
        # the data-block list, and type-info RID -> VariableTypeStructModificationTime
        # of each data block whose time the PLC reported.
        self._block_layout_signature: Optional[list[tuple[str, int, int]]] = None
        self._type_info_times: dict[int, bytes] = {}
        # Opt-in: an unknown tag name, or a failed item in read_tags(), runs that
        # check (once per call, at most every _AUTO_REFRESH_MIN_INTERVAL seconds)
        # and, if the program changed, resolves and reads again. Writes that reached
        # the PLC are never resent.
        self.auto_refresh_tags: bool = False
        self._last_auto_refresh_check: Optional[float] = None
        # Sessions rebuilt by a reconnect. Reconnects are serialized so that one
        # never tears down the session another has just built, and while one
        # runs only its task may use the stream (see _blocked_by_rebuild).
        self._generation = 0
        self._reconnect_lock = asyncio.Lock()
        self._rebuild_task: Optional[asyncio.Task[Any]] = None
        # Opt-in: a read that finds the connection dropped reconnects and retries once.
        self._auto_reconnect = False
        self._auto_reconnect_min_interval = _AUTO_RECONNECT_MIN_INTERVAL
        self._last_auto_reconnect = float("-inf")
        self._subscription_change_counter = 1
        self._subscription_relation_id = 0x7FFFC001
        self._subscriptions = SubscriptionRegistry()
        self._alarm_subscription_ids: set[int] = set()
        self._alarm_notification_frames: deque[bytes] = deque(maxlen=100)

    @property
    def connected(self) -> bool:
        return self._connection.connected

    @property
    def protocol_version(self) -> int:
        return self._connection.protocol_version

    @property
    def session_id(self) -> int:
        return self._connection.session_id

    @property
    def subscription_container_id(self) -> int:
        """Object ID assigned to the session's subscription container."""
        return self._connection.subscription_container_id

    @property
    def session_setup_ok(self) -> bool:
        """Whether the S7CommPlus session setup succeeded for data operations."""
        return self._connection.session_setup_ok

    @property
    def tls_active(self) -> bool:
        """Whether TLS is active on the connection."""
        return self._connection.tls_active

    @property
    def secured_session(self) -> bool:
        """Whether the PLC advertised a secured session requiring SessionKey auth.

        Read from the ServerSession.Role attribute of the CreateObject
        response (bit 0x20000000, observed set on secured PLCs in TIA Portal
        captures; not verified against a live PLC). ``False`` when the PLC did
        not report a role, which includes every PLC that does not implement
        the attribute.
        """
        return self._connection.secured_session

    @property
    def server_session_roles(self) -> Optional[int]:
        """The ServerSession.Roles mask (attribute 305), or ``None``.

        The mask of every role the session may take, as opposed to the single
        `Role` that `secured_session` reads. The individual bit meanings are
        not decoded; ``None`` when the PLC did not send the attribute.
        """
        return self._connection.server_session_roles

    @property
    def oms_secret(self) -> Optional[bytes]:
        """OMS exporter secret from TLS session (None if TLS not active)."""
        return self._connection.oms_secret

    @property
    def protection_level(self) -> Optional[int]:
        """Effective protection level reported by the PLC (see `AccessLevel`)."""
        return self._connection.protection_level

    @property
    def session_oms_version(self) -> Optional[tuple[int, Optional[int]]]:
        """(SystemOMS, ProjectOMS) negotiated for the session, or ``None``.

        SystemOMS is the OMS session version (64..448, V1..V7); ProjectOMS is
        the loaded project's version, where an explicit 0 means the controller
        has no project loaded and ``None`` means the element was not sent.
        ``None`` for the whole tuple before connect or when unreadable.
        """
        return self._connection.session_oms_version

    @property
    def object_qualifier_version(self) -> int:
        """Protocol version whose ObjectQualifier layout data requests use.

        The opt-in non-TLS profile sends the V2 layout although the session
        negotiated V1; its PLCs reset the connection on the V1 layout.
        """
        return self._connection.object_qualifier_version

    @property
    def write_delete_qualifier_version(self) -> int:
        """ObjectQualifier layout version of ``write_symbolic`` and the subscription deletes.

        See ``_write_delete_qualifier_version``: PLCSIM and the S7-1200 use
        :attr:`object_qualifier_version`, the S7-1500 the negotiated protocol version.
        """
        return self._connection.write_delete_qualifier_version

    @property
    def alarm_texts_and_domain_filter(self) -> bool:
        """Whether an alarm subscription may send the domain filter and texts; see ``_alarm_texts_and_domain_filter``."""
        return self._connection.alarm_texts_and_domain_filter

    @property
    def legacy_s7_1500(self) -> bool:
        """Whether the V1 SessionKey profile is active (automatic unless overridden)."""
        return self._connection.legacy_s7_1500

    def peer_certificate_fingerprint(self) -> Optional[bytes]:
        """SHA-256 of the TLS certificate the PLC presented, or None without TLS.

        The raw 32-byte digest; ``.hex()`` gives the hex string that
        ``tls_cert_fingerprint`` takes.
        """
        return self._connection.peer_certificate_fingerprint()

    def _clear_subscription_state(self) -> None:
        """Forget the data and alarm subscriptions; the connection calls this when it closes a session."""
        self._subscriptions.clear()
        self._alarm_subscription_ids.clear()
        self._alarm_notification_frames.clear()

    def _frame_overhead(self) -> int:
        """Bytes this session's request frames add to a payload."""
        return _request_frame_overhead(self._connection._with_integrity_id, self._connection._session_key is not None)

    async def connect(
        self,
        host: str,
        port: int = 102,
        rack: int = 0,
        slot: int = 1,
        *,
        use_tls: bool | Literal["auto"] = False,
        tls_cert: Optional[str] = None,
        tls_key: Optional[str] = None,
        tls_ca: Optional[str] = None,
        tls_cert_fingerprint: Optional[str] = None,
        password: Optional[str] = None,
        allow_legacy_key_fallback: bool = True,
        legacy_session_key_refresh_interval: Optional[float] = _DEFAULT_LEGACY_SESSION_KEY_REFRESH_INTERVAL,
        timeout: float = 5.0,
        request_timeout: Optional[float] = None,
        explore_timeout: Optional[float] = 30.0,
        notification_timeout: Optional[float] = None,
        legacy_s7_1500: bool | None = None,
        connection_type: int | str | None = None,
        auto_reconnect: bool = False,
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
            tls_cert_fingerprint: Expected SHA-256 fingerprint of the PLC's TLS
                certificate, as hex (``:``/``-``/spaces allowed). Refuses the
                connection unless the PLC presents that exact certificate; use it
                instead of ``tls_ca`` for a self-signed PLC certificate. Requires
                ``use_tls=True``: a pin is never used on a plaintext connection.
            password: PLC password. V1 SessionKey sessions use it for the
                post-handshake legitimation; TLS sessions pass it to
                :meth:`authenticate` after connecting.
            allow_legacy_key_fallback: Try known same-family public keys on
                fresh sessions when a legacy PLC omits its key id.
            legacy_session_key_refresh_interval: Seconds between legacy
                SessionKey renewals, or ``None`` to disable them. Only an
                S7-1200 (key family 01) renews; an S7-1500 or PLCSIM session
                without TLS refuses the renewal, so none is sent and the PLC
                ends the session when the key expires (after one hour on a
                CPU 1517-3).
            timeout: Seconds for the TCP connect and the COTP, InitSSL, TLS
                and CreateObject handshake together.
            request_timeout: Seconds to wait for each reply once the handshake
                is done (and for each further part of a multi-part reply, and
                for a send the PLC does not accept), or ``None`` to use
                ``timeout``. Running out raises ``S7TimeoutError`` and closes
                the session, as its state is then unknown; ``connected`` turns
                ``False``.
            explore_timeout: The same bound for the reply to an EXPLORE (sent
                by :meth:`browse`, :meth:`list_datablocks`, :meth:`explore`,
                :meth:`get_cpu_state` and :meth:`read_alarms`, among others),
                whose answer can be large; 30 s by default, or ``None`` to use
                the request timeout.
            notification_timeout: Seconds a notification receiver waits by
                default (subscriptions and alarms), or ``None`` to use the
                request timeout.
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
            auto_reconnect: When a read finds the connection dropped, reconnect
                and run it once more (see :attr:`auto_reconnect`). Writes are
                never retried. Off by default.
        """
        tls_first, auto_tls = _resolve_use_tls(use_tls)
        if legacy_s7_1500 and tls_first:
            raise ValueError("legacy_s7_1500 requires use_tls=False")
        if legacy_session_key_refresh_interval is not None and legacy_session_key_refresh_interval <= 0:
            raise ValueError("legacy_session_key_refresh_interval must be positive or None")
        _check_certificate_pin(tls_cert_fingerprint, tls_first)  # validate early
        remote_tsap_for_connection_type(connection_type)  # validate early
        _check_timeout("timeout", timeout, optional=False)
        _check_timeout("request_timeout", request_timeout)
        _check_timeout("explore_timeout", explore_timeout)
        _check_timeout("notification_timeout", notification_timeout)
        self._forget_tag_catalog()
        self._connect_params = {
            "host": host,
            "port": port,
            "rack": rack,
            "slot": slot,
            "use_tls": tls_first,
            "auto_tls": auto_tls,
            "tls_cert": tls_cert,
            "tls_key": tls_key,
            "tls_ca": tls_ca,
            "tls_cert_fingerprint": tls_cert_fingerprint,
            "password": password,
            # A successful authenticate() replaces both, so a reconnect legitimates the same way.
            "username": "",
            "allow_legacy_key_fallback": allow_legacy_key_fallback,
            "legacy_session_key_refresh_interval": legacy_session_key_refresh_interval,
            "timeout": timeout,
            "request_timeout": request_timeout,
            "explore_timeout": explore_timeout,
            "notification_timeout": notification_timeout,
            "legacy_s7_1500": legacy_s7_1500,
            "connection_type": connection_type,
        }
        self._auto_reconnect = auto_reconnect
        try:
            await self._open_connection()
        except Exception:
            self._connect_params = None
            raise

    async def _open_connection(self) -> None:
        """(Re)open the connection using the stored ``connect()`` arguments.

        With ``use_tls="auto"`` every (re)connect tries TLS first, so a
        fallback to plaintext never outlives the connection it was made for.
        """
        assert self._connect_params is not None
        p = self._connect_params
        if not p["auto_tls"]:
            await self._open_connection_with_key_fallback()
            return
        p["use_tls"] = True
        try:
            await self._open_connection_with_key_fallback()
        except S7TlsHandshakeError as exc:
            _check_plaintext_fallback(p, exc)
            p["use_tls"] = False
            await self._open_connection_with_key_fallback()

    async def _open_connection_with_key_fallback(self) -> None:
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
        await self._connection.connect(p, fingerprint)
        if p["password"] is not None and self._connection.tls_active:
            logger.info("Performing PLC legitimation (password authentication)")
            await self.authenticate(p["password"], p["username"])

    async def authenticate(self, password: str, username: str = "") -> None:
        """Perform PLC password authentication (legitimation).

        Once the PLC confirms the legitimation, the password and username
        replace those of ``connect()``, so :meth:`reconnect` legitimates the new
        session the same way. A refused attempt changes nothing.

        Args:
            password: PLC password
            username: Username for the new-mode exchange (leave empty for legacy)

        Raises:
            S7NotConnectedError: If not connected.
            S7ConnectionError: If TLS is not active, the firmware does not
                support legitimation, or the password was refused.
        """
        connection = self._require_connected()
        level_before = connection.protection_level
        await connection.authenticate(password, username)
        level_after = connection.protection_level
        # The level only drops when the PLC confirmed a legitimation; a CPU that
        # already grants full access returns early and keeps the old parameters.
        legitimated = level_before is not None and level_after is not None and level_after < level_before
        if legitimated and self._connect_params is not None:
            self._connect_params["password"] = password
            self._connect_params["username"] = username

    async def reconnect(self) -> None:
        """Re-establish the connection with the parameters from the last connect().

        The new session is legitimated with the password given to ``connect()``,
        or with the password and username of the last successful
        :meth:`authenticate`. Data subscriptions that were live are remembered
        so :meth:`resubscribe` can recreate them; alarm subscriptions must be
        created again, and notifications from the gap are not replayed. A failed
        attempt keeps the parameters, so ``reconnect()`` can be repeated once
        the PLC is back. Concurrent reconnects run one after the other.

        Raises:
            RuntimeError: ``connect()`` was never called, or ``disconnect()``
                cleared its parameters.
        """
        if self._connect_params is None:
            raise S7NotConnectedError("Not connected")
        logger.info("Reconnecting to the PLC")
        await self._reconnect()

    async def disconnect(self) -> None:
        """Disconnect from PLC."""
        await self._connection._close()
        self._connection._session_key_refresh_error = None
        self._connect_params = None

    async def _reconnect(self) -> None:
        """Tear down and re-establish the connection with the same parameters."""
        async with self._reconnect_lock:
            await self._rebuild_session()

    async def _rebuild_session(self) -> None:
        """Replace the session using the stored parameters; the caller holds the reconnect lock.

        A failed attempt keeps the parameters, so a later reconnect can still
        succeed once the PLC is reachable again. Until this returns, the stream
        belongs to this task: other tasks' requests fail with "Not connected"
        instead of interleaving with the handshake.
        """
        if self._connect_params is None:
            raise S7NotConnectedError("Not connected")
        self._rebuild_task = asyncio.current_task()
        try:
            await self._connection._close()
            await self._open_connection()
        finally:
            self._rebuild_task = None
        self._generation += 1

    def _require_connected(self) -> S7CommPlusAsyncConnection:
        """The connection, or ``S7NotConnectedError`` when its session is not up.

        Operations call this before doing any work, as the sync client does.
        """
        if not self._connection._connected:
            raise S7NotConnectedError("Not connected")
        return self._connection

    def _blocked_by_rebuild(self) -> bool:
        """Whether another task is rebuilding the session right now."""
        return self._rebuild_task is not None and asyncio.current_task() is not self._rebuild_task

    async def _with_reconnect(self, op: Callable[[], Awaitable[_T]]) -> _T:
        """Run ``op``; if the PLC dropped the socket, reconnect once and retry."""
        try:
            return await op()
        except S7ConnectionError as exc:
            logger.info("Connection dropped by PLC (%s); reconnecting and retrying", exc)
            try:
                await self._reconnect()
            finally:
                # Counts as an automatic attempt, so an auto-reconnecting browse()
                # does not try again at once when this one failed.
                self._last_auto_reconnect = time.monotonic()
            return await op()

    async def _recover_dropped_connection(self, generation: int, exc: S7ConnectionError) -> bool:
        """Prepare the retry of an auto-reconnecting read that found the connection dropped.

        ``generation`` is the session the read started on. Returns ``False``
        to hand the original error to the caller instead of retrying. Tasks
        that see the same drop queue on the reconnect lock; the first rebuilds
        the session and the others retry on it.
        """
        async with self._reconnect_lock:
            if self._generation != generation:
                return True  # another task already rebuilt the session; retry on it
            if self._connect_params is None:
                return False
            if self._subscriptions.subscription_ids or self._subscriptions.pending_restore or self._alarm_subscription_ids:
                raise S7ConnectionError(_AUTO_RECONNECT_STAND_DOWN) from exc
            if time.monotonic() - self._last_auto_reconnect < self._auto_reconnect_min_interval:
                logger.debug("Connection lost (%s); the last automatic reconnect ended too recently to try again", exc)
                return False
            logger.info("Connection lost (%s); reconnecting", exc)
            try:
                await self._rebuild_session()
            finally:
                self._last_auto_reconnect = time.monotonic()
            return True

    @_retry_on_dropped_connection
    async def db_read(self, db_number: int, start: int, size: int) -> bytes:
        """Read raw bytes from a data block."""
        connection = self._require_connected()
        payload = _build_read_payload([(db_number, start, size)], connection.object_qualifier_version)
        response = await connection.send_request(FunctionCode.GET_MULTI_VARIABLES, payload)

        results = _parse_read_response(response)
        if not results:
            raise S7RequestError("Read returned no data")
        if results[0] is None:
            raise S7RequestError("Read failed: PLC returned error for item")
        return results[0]

    async def db_write(self, db_number: int, start: int, data: bytes, datatype: DataType = DataType.BLOB) -> None:
        """Write raw bytes to a data block with an optional explicit PValue datatype."""
        await self.db_write_multi([(db_number, start, data, datatype)])

    async def db_write_multi(self, items: list[DBWriteItem]) -> None:
        """Write (db_number, start_offset, data, datatype) tuples matching the PLC target types.

        A batch over :attr:`max_items_per_request` items or
        :attr:`max_request_bytes` is split over several requests, sent in order,
        so it is not atomic. The PLC writes every item it does not refuse, and a
        refused item does not stop the batch.

        Raises:
            S7WriteError: After the last request, if the PLC refused any item;
                ``item_errors`` is keyed by position in ``items``. Also when a
                connection, timeout or protocol failure interrupts a split batch
                after its first request (the failure is the ``__cause__``):
                ``unknown`` and ``not_sent`` then name the items that may or may
                not have been written and the ones never sent. A failure of the
                first request propagates unchanged, as for a single request.
            ValueError: An item is too large for one request on its own;
                nothing is sent.
        """

        connection = self._require_connected()

        def build_write(chunk: list[DBWriteItem]) -> bytes:
            return _build_write_payload(chunk, connection.object_qualifier_version)

        item_errors: dict[int, int] = {}
        answered = 0
        for chunk, payload in self._plan_requests(items, build_write):
            try:
                response = await connection.send_request(FunctionCode.SET_MULTI_VARIABLES, payload)
                errors = _write_item_errors(response, len(chunk))
            except Exception as error:
                if answered == 0:
                    raise
                raise _write_interrupted(item_errors, answered, len(chunk), len(items), error) from error
            item_errors.update((answered + number, code) for number, code in errors.items())
            answered += len(chunk)
        if item_errors:
            raise _write_refused(item_errors)

    async def write_multi(self, items: list[DBWriteItem]) -> None:
        """Alias for :meth:`db_write_multi`."""
        await self.db_write_multi(items)

    @_retry_on_dropped_connection
    async def db_read_multi(self, items: list[tuple[int, int, int]]) -> list[bytes]:
        """Read multiple data block regions, one value per item in item order.

        A batch over :attr:`max_items_per_request` items or
        :attr:`max_request_bytes` is split over several requests. An item the
        PLC could not read, including every item of a request it refused as a
        whole, is ``b""``; see :meth:`S7CommPlusClient.db_read_multi`.
        """

        connection = self._require_connected()

        def build_read(chunk: list[tuple[int, int, int]]) -> bytes:
            return _build_read_payload(chunk, connection.object_qualifier_version)

        results: list[bytes] = []
        for chunk, payload in self._plan_requests(items, build_read):
            response = await connection.send_request(FunctionCode.GET_MULTI_VARIABLES, payload)
            results.extend(_db_read_values(response, len(chunk)))
        return results

    @_retry_on_dropped_connection
    async def read_area(self, area_rid: int, start: int, size: int) -> bytes:
        """Read raw bytes from a controller memory area (M, I, Q, counters, timers)."""
        connection = self._require_connected()
        payload = _build_area_read_payload(area_rid, start, size, connection.object_qualifier_version)
        response = await connection.send_request(FunctionCode.GET_MULTI_VARIABLES, payload)
        results = _parse_read_response(response)
        if not results or results[0] is None:
            raise S7RequestError("Area read failed")
        return results[0]

    async def write_area(self, area_rid: int, start: int, data: bytes, *, datatype: DataType = DataType.BLOB) -> None:
        """Write a controller memory area, specifying the target datatype for scalar writes."""
        connection = self._require_connected()
        payload = _build_area_write_payload(area_rid, start, data, connection.object_qualifier_version, datatype=datatype)
        response = await connection.send_request(FunctionCode.SET_MULTI_VARIABLES, payload)
        _parse_write_response(response)

    async def explore(self, explore_id: int = 0, attributes: Sequence[int] | None = None) -> bytes:
        """Browse the PLC object tree.

        Args:
            explore_id: RID of the object to explore. 0 explores the PLC program (`Ids.NATIVE_THE_PLC_PROGRAM_RID`).
            attributes: Attribute IDs to request. None or empty returns every attribute. Ignored on V1 SessionKey
                sessions, whose EXPLORE format carries no attribute list.

        Returns:
            Raw response payload. Read the compressed XML documents in it with `s7commplus.iter_preset_streams`.

        Raises:
            S7ReturnValueError: If the PLC answers with a non-zero ReturnValue, e.g. for an object that does not exist.
        """
        connection = self._require_connected()
        if connection._session_key is not None:
            explore_id = explore_id or 0x38
            payload = _build_explore_payload_v3(explore_id)
        else:
            explore_id = explore_id or Ids.NATIVE_THE_PLC_PROGRAM_RID
            payload = _build_explore_request(explore_id, list(attributes or []))
        response = await connection.send_request(FunctionCode.EXPLORE, payload, integrity_tail=5, reassemble=True)
        parse_or_raise_for_return_value(response, f"EXPLORE of 0x{explore_id:08X}")
        return response

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

        Raises:
            S7ReturnValueError: If the PLC answers with a non-zero ReturnValue (see `explore`).
        """
        raw = await self.explore(explore_id, attributes)
        return find_and_decompress(raw)

    async def set_plc_operating_state(self, state: int) -> None:
        """Change the PLC operating state (RUN/STOP). Not implemented yet.

        Earlier versions sent a guessed INVOKE request, never checked the PLC's
        answer and numbered the states differently from the PLC's
        ``OperatingStateREQ`` values (`OperatingStateRequest`), so they could
        report success when nothing changed. The request that
        :meth:`request_operating_state` sends has been confirmed on one PLC
        only (issue #8); until it is validated more widely, this refuses
        without sending anything.

        Args:
            state: Target operating state.

        Raises:
            NotImplementedError: Always.
        """
        raise NotImplementedError(
            "Changing the PLC operating state is not implemented yet: the request has been validated "
            "on one PLC only (https://github.com/gijzelaerr/s7commplus/issues/8)"
        )

    @_retry_on_dropped_connection
    async def get_cpu_state(self) -> str:
        """Get PLC CPU operating state via S7CommPlus.

        .. warning:: This method is **experimental** and may change.

        Returns:
            One of ``"RUN"``, ``"STOP"``, or ``"UNKNOWN"``.
        """
        connection = self._require_connected()
        payload = _build_explore_request(Ids.NATIVE_THE_CPU_EXEC_UNIT_RID, [])
        response = await connection.send_request(FunctionCode.EXPLORE, payload, integrity_tail=5, reassemble=True)
        parse_or_raise_for_return_value(response, "CPU state read")
        return _parse_cpu_state(response)

    async def request_operating_state(self, state: int) -> OperatingStateChange:
        """Send an operating-state (RUN/STOP) request and return the raw exchange.

        .. warning::

            **Experimental.** ``STOP`` and ``RUN`` have been confirmed on one
            PLC only, a CPU 1512C-1 PN with firmware V2.9, over TLS. Other CPUs,
            firmware versions and the other
            :class:`~s7commplus.protocol.OperatingStateRequest` values are
            untested; the validation of this write path is issue
            `#8 <https://github.com/gijzelaerr/s7commplus/issues/8>`_. Use only
            against a dedicated, non-production, non-safety-critical controller.

        Mirrors :meth:`s7commplus.Client.request_operating_state`: it does **not**
        raise on a non-zero ReturnValue, and makes no claim that the state
        actually changed — read it back with :meth:`get_cpu_state` to confirm.

        Args:
            state: Target operating state, an ``OperatingStateRequest`` value
                (``STOP=1``, ``RESET_RETENTIVE=2``, ``RUN=3``, ``RUN_REDUNDANT=4``).

        Returns:
            An :class:`~s7commplus.client.OperatingStateChange` with the sent and
            received bytes.
        """
        connection = self._require_connected()
        payload = _build_set_operating_state_payload(Ids.NATIVE_THE_CPU_EXEC_UNIT_RID, int(state))
        response = await connection.send_request(FunctionCode.SET_VARIABLE, payload, integrity_tail=4)
        return_value, _ = decode_uint64_vlq(response, 0)
        return OperatingStateChange(state=int(state), request=payload, response=response, return_value=return_value)

    async def upload_block(self, block_type: int, block_number: int) -> bytes:
        """Upload (read) a program block from the PLC. Not implemented yet.

        Earlier versions sent a guessed GET_VAR_SUBSTREAMED request that follows
        no captured exchange, and returned whatever came back without checking
        the PLC's return value. Until the request is derived from a real block
        upload and validated on hardware, this refuses without sending anything.

        Args:
            block_type: Block type.
            block_number: Block number.

        Raises:
            NotImplementedError: Always.
        """
        raise NotImplementedError(
            "Uploading a block is not implemented yet: the request has not been derived from a capture or validated on a real PLC"
        )

    async def download_block(self, block_type: int, block_number: int, data: bytes) -> None:
        """Download (write) a program block to the PLC. Not implemented yet.

        Earlier versions sent a guessed SET_VAR_SUBSTREAMED request that follows
        no captured exchange, and ignored the PLC's answer, so they could report
        success when nothing was written. Until the request is derived from a
        real block download and validated on hardware, this refuses without
        sending anything.

        Args:
            block_type: Block type.
            block_number: Block number.
            data: Raw block data to write.

        Raises:
            NotImplementedError: Always.
        """
        raise NotImplementedError(
            "Downloading a block is not implemented yet: the request has not been derived from a capture or validated on a real PLC"
        )

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

        Raises:
            ValueError: The request would exceed :attr:`max_request_bytes`; use
                :meth:`create_subscriptions` for that many items.
        """
        connection = self._require_connected()
        if connection.subscription_container_id == 0:
            raise S7RequestError("PLC did not provide a subscription container object")
        if not 0 <= credit_step <= 255:
            raise ValueError("credit_step must be between 0 and 255")
        normalized = _normalize_subscription_items(items)
        change_counter = self._subscription_change_counter
        payload, integrity_tail = build_subscription_request(
            connection.subscription_container_id,
            normalized,
            cycle_ms=cycle_ms,
            credit_limit=credit_limit,
            change_counter=change_counter,
            relation_id=self._subscription_relation_id,
        )
        _check_subscription_size(payload, self.max_request_bytes, self._frame_overhead())
        response = await connection.send_request(FunctionCode.CREATE_OBJECT, payload, integrity_tail=integrity_tail)
        object_ids, _, return_value = parse_create_object_session_id(response)
        if return_value != 0 or not object_ids:
            raise S7RequestError(f"Subscription creation failed: PLC returned 0x{return_value:X}")

        self._subscription_change_counter = self._subscription_change_counter % 0xFF + 1
        self._subscription_relation_id = (self._subscription_relation_id + 1) & 0xFFFFFFFF
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
        logger.info(f"Subscription created, id={subscription_id:#x}")
        return subscription_id

    async def create_subscriptions(
        self,
        items: Sequence[SubscriptionItem | SymbolicTag | str],
        cycle_ms: int = 100,
        credit_limit: int = 10,
        credit_step: int = 5,
        queue_size: int = 100,
    ) -> list[int]:
        """Create as many data change subscriptions as ``items`` needs.

        .. warning:: This method is **experimental** and may change.

        Splits ``items``, in order, into groups whose request fits
        :attr:`max_request_bytes` and creates one subscription per group. The
        reference ids, errors and :meth:`delete_subscription` caveat are those
        of :meth:`S7CommPlusClient.create_subscriptions`.

        Returns:
            The subscription object IDs, one per group, in item order.
        """
        connection = self._require_connected()
        groups = _plan_subscription_groups(
            items,
            connection.subscription_container_id,
            cycle_ms,
            credit_limit,
            self.max_request_bytes,
            self._frame_overhead(),
        )
        created: list[int] = []
        for group in groups:
            try:
                created.append(
                    await self.create_subscription(
                        group, cycle_ms=cycle_ms, credit_limit=credit_limit, credit_step=credit_step, queue_size=queue_size
                    )
                )
            except Exception as error:
                if not created:
                    raise
                raise _subscriptions_interrupted(created, len(groups), error) from error
        return created

    async def receive_subscription_notification(
        self, subscription_id: int | None = None, timeout: Optional[float] = None
    ) -> SubscriptionNotification:
        """Wait for one routed data notification.

        ``timeout`` bounds the whole call in seconds; the default is the
        ``notification_timeout`` passed to ``connect()``, else the request
        timeout. Raises :class:`~s7commplus.error.S7TimeoutError` when it runs
        out; the session stays usable unless a frame was cut off part-way.
        """
        _check_timeout("timeout", timeout)
        wait = self._connection._notification_wait(timeout)
        deadline = time.monotonic() + wait
        if subscription_id is not None:
            queued = self._subscriptions.pop(subscription_id)
            if queued is not None:
                return queued
        while True:
            async with self._connection._lock:
                if not self._connection._connected or self._blocked_by_rebuild():
                    raise S7NotConnectedError("Not connected")
                if self._connection._notification_frames:
                    frame: Optional[bytes] = self._connection._notification_frames.popleft()
                else:
                    frame = await self._connection._recv_notification_frame(deadline, wait)
                if frame is not None:
                    await self._connection._verified_incoming_data(frame)
            if frame is None:
                continue  # the lock was free for other requests; wait on
            frame_subscription_id = notification_subscription_id(frame)
            if frame_subscription_id in self._alarm_subscription_ids:
                self._alarm_notification_frames.append(frame)
                continue
            notification = parse_subscription_notification(frame)
            matched, credit_update = self._subscriptions.route(notification)
            if not matched:
                continue
            if credit_update is not None:
                await self._connection._send_subscription_credit(notification.subscription_id, credit_update)
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
            self._connection._notification_frame_overflows,
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

    async def delete_subscription(self, subscription_id: int) -> None:
        """Delete the session's data change subscriptions.

        .. warning:: This method is **experimental** and may change.

        Like the reference driver, this deletes the session's subscription
        container rather than the one subscription, so every data and alarm
        subscription of the session goes, not only ``subscription_id``.

        Args:
            subscription_id: ID returned by :meth:`create_subscription`, used
                for logging.
        """
        connection = self._require_connected()
        if connection.subscription_container_id == 0:
            raise S7RequestError("PLC did not provide a subscription container object")
        payload = build_delete_subscription_request(
            connection.subscription_container_id, connection.write_delete_qualifier_version
        )
        await connection.send_request(FunctionCode.DELETE_OBJECT, payload)
        for active_id in self._subscriptions.subscription_ids:
            self._subscriptions.unregister(active_id)
        self._alarm_subscription_ids.clear()
        self._alarm_notification_frames.clear()
        connection._notification_frames.clear()
        logger.info(f"Subscription {subscription_id:#x} deleted")

    async def create_alarm_subscription(
        self,
        language_ids: Optional[list[LanguageId | int]] = None,
        domains: Optional[list[int]] = None,
        credit_limit: int = 10,
    ) -> int:
        """Subscribe to PLC alarm events and return the subscription ID.

        See :meth:`S7CommPlusClient.create_alarm_subscription`: on an S7-1200
        without TLS (key family 01), ``language_ids`` and ``domains`` must be
        ``None`` (#173).
        """
        connection = self._require_connected()
        if connection.subscription_container_id == 0:
            raise S7RequestError("PLC did not provide a subscription container object")
        payload = build_alarm_subscription_request(
            connection.subscription_container_id,
            language_ids,
            domains,
            credit_limit,
            texts_and_domain_filter=connection.alarm_texts_and_domain_filter,
        )
        response = await connection.send_request(FunctionCode.CREATE_OBJECT, payload, integrity_tail=len(payload) - 11)
        object_ids, _, return_value = parse_create_object_session_id(response)
        if return_value != 0 or not object_ids:
            raise S7RequestError(f"Alarm subscription failed: PLC returned {return_value:#x}")
        subscription_id = object_ids[0]
        self._alarm_subscription_ids.add(subscription_id)
        return subscription_id

    async def delete_alarm_subscription(self, subscription_id: int) -> None:
        """Delete an alarm subscription created by this client.

        Like :meth:`delete_subscription`, this deletes the session's whole
        subscription container, data subscriptions included.
        """
        connection = self._require_connected()
        if connection.subscription_container_id == 0:
            raise S7RequestError("PLC did not provide a subscription container object")
        payload = build_delete_alarm_subscription_request(
            connection.subscription_container_id, connection.write_delete_qualifier_version
        )
        await connection.send_request(FunctionCode.DELETE_OBJECT, payload)
        for active_id in self._subscriptions.subscription_ids:
            self._subscriptions.unregister(active_id)
        self._alarm_subscription_ids.clear()
        self._alarm_notification_frames.clear()
        connection._notification_frames.clear()
        logger.info(f"Alarm subscription {subscription_id:#x} deleted")

    async def receive_alarm_notification(
        self, language_ids: Optional[list[LanguageId | int]] = None, timeout: Optional[float] = None
    ) -> AlarmNotification:
        """Wait for one alarm notification.

        ``timeout`` bounds the whole call in seconds; the default is the
        ``notification_timeout`` passed to ``connect()``, else the request
        timeout. Raises :class:`~s7commplus.error.S7TimeoutError` when it runs
        out; the session stays usable unless a frame was cut off part-way.
        Data notifications encountered first are routed to their bounded queues.
        """
        _check_timeout("timeout", timeout)
        wait = self._connection._notification_wait(timeout)
        deadline = time.monotonic() + wait
        while True:
            frame: Optional[bytes]
            if self._alarm_notification_frames:
                frame = self._alarm_notification_frames.popleft()
            else:
                async with self._connection._lock:
                    if not self._connection._connected or self._blocked_by_rebuild():
                        raise S7NotConnectedError("Not connected")
                    if self._connection._notification_frames:
                        frame = self._connection._notification_frames.popleft()
                    else:
                        frame = await self._connection._recv_notification_frame(deadline, wait)
                    if frame is not None:
                        await self._connection._verified_incoming_data(frame)
                if frame is None:
                    continue  # the lock was free for other requests; wait on
            frame_subscription_id = notification_subscription_id(frame)
            if self._subscriptions.contains(frame_subscription_id):
                notification = parse_subscription_notification(frame)
                matched, credit_update = self._subscriptions.route(notification)
                if matched and credit_update is not None:
                    await self._connection._send_subscription_credit(frame_subscription_id, credit_update)
                continue
            return parse_alarm_notification(frame, language_ids)

    async def read_alarms(self, language_ids: Optional[list[LanguageId | int]] = None) -> list[Alarm]:
        """Return a snapshot of the PLC's active alarms without consuming notifications.

        Raises:
            S7ReturnValueError: If the PLC answers with a non-zero ReturnValue.
        """
        connection = self._require_connected()
        response = await connection.send_request(
            FunctionCode.EXPLORE, build_alarm_explore_request(), integrity_tail=5, reassemble=True
        )
        return parse_alarm_explore_response(response, language_ids)

    @_retry_on_dropped_connection
    async def read_symbolic(self, access_area: int, lids: list[int], symbol_crc: int = 0) -> bytes:
        """Read a variable using S7CommPlus symbolic (LID-based) access.

        .. warning:: This method is **experimental** and may change.
        """
        connection = self._require_connected()
        payload = _build_symbolic_read_payload(access_area, lids, symbol_crc, connection.object_qualifier_version)
        response = await connection.send_request(FunctionCode.GET_MULTI_VARIABLES, payload)
        results = _parse_read_response(response)
        if not results or results[0] is None:
            raise S7RequestError("Symbolic read failed")
        return results[0]

    @_retry_on_dropped_connection
    async def read_symbolic_multi(self, items: Sequence[SymbolicReadItem]) -> list[Optional[bytes]]:
        """Read multiple variables using S7CommPlus symbolic (LID-based) access.

        .. warning:: This method is **experimental** and may change.

        A batch over :attr:`max_items_per_request` items or
        :attr:`max_request_bytes` is split over several requests, sent in order,
        and the values are merged.

        Args:
            items: `(access_area, lids)` tuples, or three-tuples adding a
                symbol CRC.

        Returns:
            One entry per requested item, in request order.

        Raises:
            S7RequestError: If the PLC does not answer every requested item.
        """
        connection = self._require_connected()
        if not items:
            return []

        def build_read(chunk: list[SymbolicReadItem]) -> bytes:
            return _build_multi_symbolic_read_payload(chunk, connection.object_qualifier_version)

        results: list[Optional[bytes]] = []
        for chunk, payload in self._plan_requests(items, build_read):
            response = await connection.send_request(FunctionCode.GET_MULTI_VARIABLES, payload)
            parsed = _parse_read_response(response, expected_count=len(chunk))
            if len(parsed) != len(chunk):
                raise S7RequestError(f"Symbolic multi-read failed: PLC returned {len(parsed)} of {len(chunk)} items")
            results.extend(parsed)
        return results

    async def write_symbolic(
        self, access_area: int, lids: list[int], data: bytes, symbol_crc: int = 0, *, datatype: DataType = DataType.BLOB
    ) -> None:
        """Write a variable using S7CommPlus symbolic (LID-based) access.

        .. warning:: This method is **experimental** and may change.

        Set ``datatype`` to the target PLC datatype reported by browse().
        The legacy BLOB default is not a generic replacement for scalar types.
        """
        connection = self._require_connected()
        payload = _build_symbolic_write_payload(
            access_area, lids, data, symbol_crc, protocol_version=connection.write_delete_qualifier_version, datatype=datatype
        )
        response = await connection.send_request(FunctionCode.SET_MULTI_VARIABLES, payload)
        _parse_write_response(response)

    async def refresh_tag_catalog(self) -> SymbolCatalog:
        """Browse the PLC and replace the cached symbolic tag catalog."""
        variables, signature, times = await self._browse_layout()
        self._symbol_catalog = SymbolCatalog.from_browse(variables)
        self._block_layout_signature, self._type_info_times = signature, times
        return self._symbol_catalog

    async def refresh_caches_if_program_changed(self) -> bool:
        """Refresh the tag catalog when the PLC program changed.

        Named reads and writes send SymbolCRC 0, so the PLC does not verify that a
        cached address still names the same variable. After a download that changes
        a block, the cached addresses can point at the wrong variable. This compares
        the data-block list with the one the catalog was built from and, when that is
        unchanged, the type-info modification time of every cached data block (one
        small EXPLORE each), and rebuilds the catalog when either changed. A recorded
        time that no longer answers counts as a change, since a download may have
        replaced the type-info object. Without a cached catalog it browses one. It is
        opt-in: nothing is refreshed implicitly.

        This narrows the window in which a stale address is used; it does not close
        it. A change confined to a nested UDT or the PLC tag table may not show in the
        block's own modification time; an instance DB moved to another FB keeps its
        name, number and RID, and only its old type-info object is checked; a block
        whose time the PLC does not report is checked by block list only. Call
        ``refresh_tag_catalog()`` after a known download, and this method before
        writing after a possible one.

        Returns:
            ``True`` when the catalog was refreshed.

        Raises:
            S7NotConnectedError: If not connected.
        """
        self._require_connected()
        if _block_signature(await self.list_datablocks()) != self._block_layout_signature:
            logger.info("The PLC data-block list changed; refreshing the tag catalog")
            await self.refresh_tag_catalog()
            return True
        for ti_rid, seen in list(self._type_info_times.items()):
            current = await self._read_type_info_time(ti_rid)
            if current != seen:
                logger.info("Type info %#x changed or no longer answers; refreshing the tag catalog", ti_rid)
                await self.refresh_tag_catalog()
                if current is None and self._type_info_times.get(ti_rid) == seen:
                    # Still there, unchanged: the PLC does not answer the filtered EXPLORE
                    # for it. Check that block by its list entry only, not rebrowse every time.
                    del self._type_info_times[ti_rid]
                return True
        return False

    async def _read_type_info_time(self, ti_rid: int) -> Optional[bytes]:
        """EXPLORE one type-info object for its modification time (``None`` if not reported)."""
        connection = self._require_connected()
        payload = _build_explore_request(ti_rid, [Ids.VARIABLE_TYPE_STRUCT_MODIFICATION_TIME])
        response = await connection.send_request(FunctionCode.EXPLORE, payload, integrity_tail=5, reassemble=True)
        return typeinfo.find_object_attribute(response, ti_rid, Ids.VARIABLE_TYPE_STRUCT_MODIFICATION_TIME)

    async def resolve_tag(self, name: str) -> SymbolicTag:
        """Resolve a browsed tag name to its typed symbolic descriptor."""
        catalog = self._symbol_catalog or await self.refresh_tag_catalog()
        return catalog.resolve(name)

    @_retry_on_dropped_connection
    async def read_tag(self, name: str) -> bytes:
        """Read one symbolic tag by name."""
        result = (await self.read_tags([name]))[0]
        if result.error is not None:
            raise result.error
        assert result.value is not None
        return result.value

    @_retry_on_dropped_connection
    async def read_tags(self, names: Sequence[str]) -> list[TagResult]:
        """Read names and return a success/error for every item.

        A batch over :attr:`max_items_per_request` names or
        :attr:`max_request_bytes` is split over several requests, as in
        :meth:`read_symbolic_multi`.

        With ``auto_refresh_tags`` set, an unknown name or a failed item runs
        :meth:`refresh_caches_if_program_changed` and, when the program did
        change, resolves and reads the names again, once. The check runs at
        most once per call, not when this call browsed the catalog itself, and
        not within 10 seconds of the previous automatic check. A failed item
        carries no PLC error code, so any failure triggers it; a name still
        unknown afterwards raises ``KeyError``.
        """
        if not names:
            return []
        tags, may_check = await self._resolve_tags(names)
        results = await self._read_resolved_tags(tags)
        if may_check and any(result.error is not None for result in results) and await self._auto_refresh_check():
            results = await self._read_resolved_tags([await self.resolve_tag(name) for name in names])
        return results

    async def _resolve_tags(self, names: Sequence[str]) -> tuple[list[SymbolicTag], bool]:
        """Resolve names; with ``auto_refresh_tags``, an unknown name checks for a program change.

        Also returns whether the caller may still run an automatic check: not
        after one ran here, and not when resolving browsed the catalog, which is
        then current.
        """
        may_check = bool(self._symbol_catalog)  # resolve_tag() browses a missing or empty catalog
        try:
            return [await self.resolve_tag(name) for name in names], may_check
        except KeyError:
            if not (may_check and await self._auto_refresh_check()):
                raise
        return [await self.resolve_tag(name) for name in names], False

    async def _auto_refresh_check(self) -> bool:
        """Run the automatic program-change check, unless one ran recently; ``True`` if it refreshed."""
        if not self.auto_refresh_tags:
            return False
        now = time.monotonic()
        last = self._last_auto_refresh_check
        if last is not None and now - last < _AUTO_REFRESH_MIN_INTERVAL:
            logger.debug("Skipping the automatic program-change check; the last one ran %.1f s ago", now - last)
            return False
        self._last_auto_refresh_check = now
        return await self.refresh_caches_if_program_changed()

    async def _read_resolved_tags(self, tags: Sequence[SymbolicTag]) -> list[TagResult]:
        values = await self.read_symbolic_multi([(tag.access_area, list(tag.lids), 0) for tag in tags])
        return [
            TagResult(tag=tag, value=value)
            if value is not None
            else TagResult(tag=tag, error=S7RequestError(f"Symbolic read failed for {tag.name!r}"))
            for tag, value in zip(tags, values)
        ]

    async def write_tag(self, name: str, data: bytes) -> None:
        """Write one symbolic tag by name using its resolved PValue datatype."""
        result = (await self.write_tags({name: data}))[0]
        if result.error is not None:
            raise result.error

    async def write_tags(self, values: Mapping[str, bytes]) -> list[TagResult]:
        """Write names once and return per-item results without automatic retry.

        A batch over :attr:`max_items_per_request` names or
        :attr:`max_request_bytes` is split over several requests, sent in order,
        so it is not atomic; a tag the PLC refuses does not stop the batch. If a
        connection, timeout or protocol failure interrupts the batch after its
        first request, the tags written so far keep their results and every
        later tag gets one :class:`~s7commplus.error.S7WriteError`, raised from
        that failure, whose ``unknown`` positions may or may not have been
        written and whose ``not_sent`` positions were never sent. A failure of
        the first request propagates unchanged, as for a single request.

        Each value is the tag's raw big-endian bytes in the layout
        :meth:`read_tags` returns. A STRING is the bytes ``[max length, length,
        characters...]`` and a WSTRING the same as big-endian UINTs, both padded
        with zeros to the declared length (``SymbolicTag.string_length``); a
        DATE_AND_TIME is its eight BCD bytes. :meth:`SymbolicTag.encode_value`
        builds these from Python values. A CHAR goes out as a USINT, and a
        STRING, WSTRING or DATE_AND_TIME as an array of that layout.

        Writes are deliberately never retried: a transport failure can leave
        the caller unable to know whether the PLC applied the request.

        With ``auto_refresh_tags`` set, an unknown name, before anything is sent,
        runs the program-change check as in :meth:`read_tags`; a write to a stale
        address does not, so call :meth:`refresh_caches_if_program_changed` before
        writing after a possible download.

        Raises:
            ValueError: A value is too large for one request on its own;
                nothing is sent.
        """
        self._require_connected()
        if not values:
            return []
        tags, _ = await self._resolve_tags(list(values))
        # Resolving may browse and reconnect, which gives the sync client a new connection.
        connection = self._require_connected()
        items = _plan_tag_writes(tags, values.values())

        def build_write(chunk: list[SymbolicWriteItem]) -> bytes:
            return _build_multi_symbolic_write_payload(chunk, connection.object_qualifier_version)

        results: list[TagResult] = [TagResult(tag=tag) for tag in tags]
        answered = 0
        for chunk, payload in self._plan_requests(items, build_write):
            try:
                response = await connection.send_request(FunctionCode.SET_MULTI_VARIABLES, payload)
            except Exception as error:
                if answered == 0:
                    raise
                _interrupt_tag_writes(results, answered, len(chunk), error)
                break
            _record_tag_writes(results, answered, len(chunk), response)
            answered += len(chunk)
        return results

    @_retry_on_dropped_connection
    async def read_value(self, name: str) -> Any:
        """Read a tag, struct or array by name as a Python value.

        A leaf tag gives its decoded value (see :func:`s7commplus.values.decode`).
        The name of a struct, UDT instance or array gives a ``dict`` or ``list``
        built from all its leaves, read as one batch (split over several requests
        like :meth:`read_tags` when it is large); a DTL gives a
        :class:`datetime.datetime`.

        With ``auto_refresh_tags`` set, a name not in the catalog runs the
        program-change check of :meth:`read_tags` once (rate-limited, and not
        when this call browsed the catalog itself) and is looked up again; a
        failed item does too, inside :meth:`read_tags`. A struct or array is read
        with the members known when the call started, or after that lookup: if a
        refresh during the read changes them, the call raises ``KeyError`` for a
        member that is gone and leaves out one that is new.

        Raises:
            KeyError: ``name`` is neither a tag nor a struct or array in the catalog.
            S7RequestError: The PLC reported an error for one of the items.
        """
        return (await self.read_values([name]))[0]

    @_retry_on_dropped_connection
    async def read_values(self, names: Sequence[str]) -> list[Any]:
        """Read several tags, structs or arrays as one batch of leaves; see :meth:`read_value`."""
        plans = await self._plan_values(names)
        results = await self.read_tags([tag.name for _, _, tags in plans for tag in tags])
        return _assemble_values(plans, results)

    async def write_value(self, name: str, value: Any) -> None:
        """Write a Python value to a tag, struct or array by name.

        Accepts what :meth:`read_value` returns. A ``dict`` for a struct may give
        only some members; a ``list`` for an array must give every element. Every
        leaf is encoded before anything is sent, then the leaves are written as
        one batch through :meth:`write_tags`, which splits a large batch over
        several requests; such a batch is not atomic. Like every write, it is
        never retried. With ``auto_refresh_tags`` set, a name not in the catalog
        runs the program-change check once, as for :meth:`read_value`, before
        anything is encoded or sent.

        Raises:
            KeyError: ``name`` is neither a tag nor a struct or array in the catalog.
            TypeError, ValueError: ``value`` does not fit the PLC type, or a
                leaf is too large for one request; nothing is sent.
            S7RequestError: The PLC rejected one of the items, or a failure
                interrupted a split batch; it is raised from the first failed
                item's error, and the other items may have been written.
        """
        await self.write_values({name: value})

    async def write_values(self, values: Mapping[str, Any]) -> None:
        """Write several tags, structs or arrays as one batch of leaves; see :meth:`write_value`."""
        encoded = _encode_values(await self._plan_values(list(values)), values)
        _raise_failures(await self.write_tags(encoded), "writes")

    async def _plan_values(self, names: Sequence[str]) -> list[_ValuePlan]:
        """Look up each name's leaf tags; with ``auto_refresh_tags``, an unknown name checks once for a program change.

        Only the lookup is retried after the check, never an encoding or a
        request. As in :meth:`_resolve_tags`, no check runs when this call
        browsed the catalog, which is then current.
        """
        may_check = bool(self._symbol_catalog)  # refresh_tag_catalog() browses a missing or empty catalog
        catalog = self._symbol_catalog or await self.refresh_tag_catalog()
        try:
            return _value_plans(catalog, names)
        except KeyError:
            if not (may_check and await self._auto_refresh_check()):
                raise
        return _value_plans(self._symbol_catalog or await self.refresh_tag_catalog(), names)

    async def list_datablocks(self) -> list[ProgramObject]:
        """List all datablocks on the PLC via EXPLORE.

        .. warning:: This method is **experimental** and may change.

        See `S7CommPlusClient.list_datablocks`.
        """
        connection = self._require_connected()
        if connection._session_key is not None and not connection.legacy_s7_1500:
            # V1-initial PLCs: explore the DB wildcard address (0x8A11FFFF)
            # matching TIA Portal's browse pattern
            payload = _build_explore_payload_v3(0x8A11FFFF)
            response = await connection.send_request(FunctionCode.EXPLORE, payload, integrity_tail=5, reassemble=True)
            parse_or_raise_for_return_value(response, "Data block list")
            return _parse_explore_datablocks(response)
        return [obj for obj in await self.program_objects() if obj.is_datablock]

    async def program_objects(self) -> list[ProgramObject]:
        """List every object of the PLC program: blocks, UDTs and the objects that contain them.

        .. warning:: This method is **experimental** and may change.

        See `S7CommPlusClient.program_objects`.

        Raises:
            NotImplementedError: On a V1 SessionKey session, which does not explore the program.
            S7ReturnValueError: If the PLC answers with a non-zero ReturnValue.
        """
        connection = self._require_connected()
        if connection._session_key is not None and not connection.legacy_s7_1500:
            raise NotImplementedError("program_objects() is not supported on V1 SessionKey sessions")

        response = await connection.send_request(FunctionCode.EXPLORE, _PROGRAM_TREE_EXPLORE, integrity_tail=5, reassemble=True)
        parse_or_raise_for_return_value(response, "Program object list")
        return _parse_program_objects(response)

    @_retry_on_dropped_connection
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
        return (await self._browse_layout())[0]

    async def _browse_layout(self) -> tuple[list[dict[str, Any]], list[tuple[str, int, int]], dict[int, bytes]]:
        """:meth:`browse`, also returning the block-list signature and type-info modification times."""
        self._require_connected()
        # Phase A: enumerate data blocks. Phase B/C: resolve each DB's type-info RID
        # (a LID=1 read — needed for instance DBs whose TI is not their own RID) and seed
        # a root node per DB.
        root_nodes: list[typeinfo.Node] = []
        blocks = await self.list_datablocks()
        for db_info in blocks:
            if not db_info.number or db_info.rid == 0:
                continue
            ti_rid = await self._with_reconnect(lambda: self._read_typeinfo_rid(db_info.rid))
            if ti_rid == 0:
                continue  # load-memory-only DB, skip
            root_nodes.append(
                typeinfo.Node(node_type=typeinfo.NodeType.ROOT, name=db_info.name, access_id=db_info.rid, relation_id=ti_rid)
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
        return variables, _block_signature(blocks), _type_info_times(root_nodes, type_objects)

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
        connection = self._require_connected()
        payload = _build_explore_request(Ids.OBJECT_OMS_TYPE_INFO_CONTAINER, [])
        response = await connection.send_request(FunctionCode.EXPLORE, payload, integrity_tail=5, reassemble=True)
        parse_or_raise_for_return_value(response, "Type-info browse")
        return typeinfo.extract_type_info_objects(response)

    async def __aenter__(self) -> "S7CommPlusAsyncClient":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.disconnect()
