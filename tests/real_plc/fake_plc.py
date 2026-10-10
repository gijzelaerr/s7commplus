"""In-memory stand-ins for Client and AsyncClient, for a dry run of the real-PLC scenarios.

Load it as a pytest plugin (``-p tests.real_plc.fake_plc``) together with
``--e2e``: every scenario then runs against a fake PLC that holds the canonical
fixture DBs, so CI checks that each Gherkin step is bound and that the step
code works, for both clients, without a PLC. It proves nothing about the
protocol; that is what the real-PLC run is for.

The fake accepts the password in ``S7COMMPLUS_TEST_PASSWORD``, trusts no CA
file (any ``tls_ca`` is refused) and presents a fixed certificate fingerprint.
"""

from __future__ import annotations

import functools
import os
import ssl
from collections.abc import Callable, Sequence
from typing import Any, Optional

import pytest

from s7commplus.catalog import SymbolicTag, TagResult
from s7commplus.error import S7AuthenticationError, S7ConnectionError
from s7commplus.subscription import SubscriptionNotification
from tests.real_plc import support

FAKE_CERTIFICATE_FINGERPRINT = bytes(range(32))
_DB_NAMES = {1: "Read_only", 2: "Data_block_2"}


class FakePLC:
    """The PLC state every fake client of one test session shares."""

    def __init__(self) -> None:
        self.images = {number: bytearray(support.canonical_fixture_bytes()) for number in _DB_NAMES}
        self.next_object_id = 0x70000001

    def object_id(self) -> int:
        self.next_object_id += 1
        return self.next_object_id

    def browse(self) -> list[dict[str, Any]]:
        entries = []
        for number, db_name in _DB_NAMES.items():
            for index, member in enumerate(support.FIXTURE_MEMBERS, 1):
                entries.append(
                    {
                        "name": f"{db_name}.{member.name}",
                        "access_sequence": f"{support.db_access_prefix(number)}A.{index:X}",
                        "data_type": member.data_type,
                        "opt_address": 0,
                        "opt_bitoffset": 0,
                        "nonopt_address": member.offset,
                        "nonopt_bitoffset": member.bit or 0,
                        "symbol_crc": 0,
                        "array_dimensions": [],
                        "string_length": 0,
                    }
                )
        return entries

    def locate(self, key: str, field: str) -> tuple[int, support.FixtureMember]:
        for entry in self.browse():
            if entry[field] == key:
                db_name, member = entry["name"].split(".")
                number = next(number for number, name in _DB_NAMES.items() if name == db_name)
                return number, support.MEMBERS_BY_NAME[member]
        raise KeyError(f"Unknown tag {key!r}")

    def write_member(self, number: int, member: support.FixtureMember, data: bytes) -> None:
        image = self.images[number]
        if len(data) != member.size:
            raise RuntimeError(f"Symbolic write failed for {member.name!r}: wrong size")
        if member.bit is None:
            image[member.offset : member.offset + member.size] = data
        elif data[0]:
            image[member.offset] |= 1 << member.bit
        else:
            image[member.offset] &= ~(1 << member.bit) & 0xFF


_PLC = FakePLC()


class FakeClient:
    """Enough of :class:`s7commplus.Client` for the acceptance scenarios."""

    def __init__(self) -> None:
        self.connected = False
        self.tls_active = False
        self.protocol_version = 0
        self.protection_level: Optional[int] = None
        self._subscriptions: dict[int, str] = {}
        self._sequence = 0
        self._last_connect: dict[str, Any] = {}

    def connect(
        self,
        host: str,
        port: int = 102,
        rack: int = 0,
        slot: int = 1,
        use_tls: bool = False,
        tls_cert: Optional[str] = None,
        tls_key: Optional[str] = None,
        tls_ca: Optional[str] = None,
        password: Optional[str] = None,
        *,
        tls_cert_fingerprint: Optional[str] = None,
    ) -> None:
        del host, port, rack, slot, tls_cert, tls_key
        self._last_connect = {"use_tls": use_tls, "password": password, "tls_cert_fingerprint": tls_cert_fingerprint}
        if tls_ca is not None:
            raise ssl.SSLCertVerificationError("certificate verify failed: unable to get local issuer certificate")
        if tls_cert_fingerprint is not None and bytes.fromhex(tls_cert_fingerprint) != FAKE_CERTIFICATE_FINGERPRINT:
            raise S7ConnectionError("PLC TLS certificate does not match the pinned fingerprint")
        if password is not None and password != os.environ.get(support.PASSWORD_ENV):
            raise S7AuthenticationError("Post-auth legitimation rejected by PLC (wrong password)")
        self.connected = True
        self.tls_active = use_tls
        self.protocol_version = 2 if use_tls else 1
        self.protection_level = 1 if password is not None else 3

    def disconnect(self) -> None:
        self.connected = False
        self.tls_active = False
        self._subscriptions.clear()

    def reconnect(self) -> None:
        # Called explicitly on FakeClient: the async subclass turns both into coroutines.
        FakeClient.disconnect(self)
        FakeClient.connect(self, "fake", **self._last_connect)

    def peer_certificate_fingerprint(self) -> Optional[bytes]:
        return FAKE_CERTIFICATE_FINGERPRINT if self.tls_active else None

    def _require_connection(self) -> None:
        if not self.connected:
            raise S7ConnectionError("Not connected")

    def db_read(self, db_number: int, start: int, size: int) -> bytes:
        self._require_connection()
        return bytes(_PLC.images[db_number][start : start + size])

    def db_write(self, db_number: int, start: int, data: bytes) -> None:
        self._require_connection()
        _PLC.images[db_number][start : start + len(data)] = data

    def db_read_multi(self, items: Sequence[tuple[int, int, int]]) -> list[bytes]:
        return [FakeClient.db_read(self, db_number, start, size) for db_number, start, size in items]

    def list_datablocks(self) -> list[dict[str, Any]]:
        self._require_connection()
        return [{"name": name, "number": number, "rid": 0x8A0E0000 | number} for number, name in _DB_NAMES.items()]

    def browse(self) -> list[dict[str, Any]]:
        self._require_connection()
        return _PLC.browse()

    def read_tags(self, names: Sequence[str]) -> list[TagResult]:
        self._require_connection()
        entries = {entry["name"]: entry for entry in _PLC.browse()}
        results = []
        for name in names:
            number, member = _PLC.locate(name, "name")
            tag = SymbolicTag.from_browse(entries[name])
            results.append(TagResult(tag=tag, value=member.raw(bytes(_PLC.images[number]))))
        return results

    def write_tag(self, name: str, data: bytes) -> None:
        self._require_connection()
        number, member = _PLC.locate(name, "name")
        _PLC.write_member(number, member, data)

    def get_cpu_state(self) -> str:
        self._require_connection()
        return "RUN"

    def create_subscription(self, items: Sequence[str]) -> int:
        self._require_connection()
        (access_sequence,) = items
        subscription_id = _PLC.object_id()
        self._subscriptions[subscription_id] = access_sequence
        return subscription_id

    def receive_subscription_notification(
        self, subscription_id: int | None = None, timeout: Optional[float] = None
    ) -> SubscriptionNotification:
        del timeout
        self._require_connection()
        assert subscription_id is not None
        number, member = _PLC.locate(self._subscriptions[subscription_id], "access_sequence")
        self._sequence += 1
        return SubscriptionNotification(
            subscription_id=subscription_id,
            credit_tick=0,
            sequence_number=self._sequence,
            change_counter=0,
            values={1: member.raw(bytes(_PLC.images[number]))},
            errors={},
        )

    def delete_subscription(self, subscription_id: int) -> None:
        self._require_connection()
        del self._subscriptions[subscription_id]

    def read_alarms(self) -> list[Any]:
        self._require_connection()
        return []

    def create_alarm_subscription(self) -> int:
        self._require_connection()
        return _PLC.object_id()

    def delete_alarm_subscription(self, subscription_id: int) -> None:
        del subscription_id
        self._require_connection()


def _coroutine(method: Callable[..., Any]) -> Callable[..., Any]:
    @functools.wraps(method)
    async def call(*args: Any, **kwargs: Any) -> Any:
        return method(*args, **kwargs)

    return call


_ASYNC_METHODS = (
    "connect",
    "disconnect",
    "reconnect",
    "db_read",
    "db_write",
    "db_read_multi",
    "list_datablocks",
    "browse",
    "read_tags",
    "write_tag",
    "get_cpu_state",
    "create_subscription",
    "receive_subscription_notification",
    "delete_subscription",
    "read_alarms",
    "create_alarm_subscription",
    "delete_alarm_subscription",
)


class FakeAsyncClient(FakeClient):
    """The same fake with the coroutine methods of :class:`s7commplus.AsyncClient`."""


for _name in _ASYNC_METHODS:
    setattr(FakeAsyncClient, _name, _coroutine(getattr(FakeClient, _name)))
del _name


def pytest_configure(config: pytest.Config) -> None:
    del config
    support.Client = FakeClient  # type: ignore[assignment,misc]
    support.AsyncClient = FakeAsyncClient  # type: ignore[assignment,misc]
