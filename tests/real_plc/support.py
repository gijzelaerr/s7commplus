"""S7CommPlus helpers for safe real-PLC acceptance scenarios."""

from __future__ import annotations

import asyncio
import datetime
import inspect
import math
import struct
from collections.abc import Callable, Coroutine, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, TypeVar

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from s7commplus import AsyncClient, Client
from s7commplus.protocol import Ids

DB_SIZE = 37
OFFSET_INT1 = 0
OFFSET_INT2 = 2
OFFSET_FLOAT1 = 4
OFFSET_FLOAT2 = 8
OFFSET_BYTE1 = 12
OFFSET_BYTE2 = 13
OFFSET_WORD1 = 14
OFFSET_WORD2 = 16
OFFSET_DWORD1 = 18
OFFSET_DWORD2 = 22
OFFSET_DINT1 = 26
OFFSET_DINT2 = 30
OFFSET_CHAR1 = 34
OFFSET_CHAR2 = 35
OFFSET_BOOLS = 36

EXPECTED_INT1 = 10
EXPECTED_INT2 = 255
EXPECTED_FLOAT1 = 123.45
EXPECTED_FLOAT2 = 543.21
EXPECTED_BYTE1 = 0x0F
EXPECTED_BYTE2 = 0xF0
EXPECTED_WORD1 = 0xABCD
EXPECTED_WORD2 = 0x1234
EXPECTED_DWORD1 = 0x12345678
EXPECTED_DWORD2 = 0x89ABCDEF
EXPECTED_DINT1 = 2147483647
EXPECTED_DINT2 = 42
EXPECTED_CHAR1 = "F"
EXPECTED_CHAR2 = "-"
EXPECTED_BOOLS = (True, False, False, False, False, False, False, False)

# Environment variable holding the PLC password for the @password scenarios. A
# password is never taken from the command line, so it stays out of the shell
# history, the process list and the pytest invocation recorded in reports.
PASSWORD_ENV = "S7COMMPLUS_TEST_PASSWORD"

# Seconds a scenario waits for one subscription notification.
NOTIFICATION_TIMEOUT = 10.0

CLIENT_KINDS = ("sync", "async")

MetadataValue = str | int | bool


@dataclass(frozen=True)
class FixtureMember:
    """One member of the canonical fixture DB (tests/plc_setup/e2e_test_dbs.scl)."""

    name: str
    data_type: str
    offset: int
    size: int
    bit: int | None = None

    def raw(self, image: bytes) -> bytes:
        """The member's value as a symbolic read returns it, taken from a DB byte image."""
        if self.bit is not None:
            return bytes([1 if image[self.offset] & (1 << self.bit) else 0])
        return image[self.offset : self.offset + self.size]


FIXTURE_MEMBERS: tuple[FixtureMember, ...] = (
    FixtureMember("int1", "INT", OFFSET_INT1, 2),
    FixtureMember("int2", "INT", OFFSET_INT2, 2),
    FixtureMember("float1", "REAL", OFFSET_FLOAT1, 4),
    FixtureMember("float2", "REAL", OFFSET_FLOAT2, 4),
    FixtureMember("byte1", "BYTE", OFFSET_BYTE1, 1),
    FixtureMember("byte2", "BYTE", OFFSET_BYTE2, 1),
    FixtureMember("word1", "WORD", OFFSET_WORD1, 2),
    FixtureMember("word2", "WORD", OFFSET_WORD2, 2),
    FixtureMember("dword1", "DWORD", OFFSET_DWORD1, 4),
    FixtureMember("dword2", "DWORD", OFFSET_DWORD2, 4),
    FixtureMember("dint1", "DINT", OFFSET_DINT1, 4),
    FixtureMember("dint2", "DINT", OFFSET_DINT2, 4),
    FixtureMember("char1", "CHAR", OFFSET_CHAR1, 1),
    FixtureMember("char2", "CHAR", OFFSET_CHAR2, 1),
    *(FixtureMember(f"bool{bit}", "BOOL", OFFSET_BOOLS, 1, bit) for bit in range(8)),
)
MEMBERS_BY_NAME = {member.name: member for member in FIXTURE_MEMBERS}


@dataclass(frozen=True)
class PLCConfig:
    """Connection settings; sensitive values are deliberately not reportable."""

    host: str
    port: int
    rack: int
    slot: int
    read_db: int
    write_db: int
    use_tls: bool
    tls_cert: str | None
    tls_key: str | None
    tls_ca: str | None
    client_kind: str = "sync"
    password: str | None = field(default=None, repr=False)
    expected_cpu_state: str | None = None


class PLCAdapter(Protocol):
    """Small surface used by the Gherkin acceptance scenarios, for either client."""

    client_kind: str

    def connect(self, **overrides: Any) -> None: ...

    def disconnect(self) -> None: ...

    def close(self) -> None: ...

    def is_connected(self) -> bool: ...

    def read(self, db_number: int, offset: int, size: int) -> bytes: ...

    def write(self, db_number: int, offset: int, data: bytes) -> None: ...

    def read_multi(self, db_number: int, regions: Sequence[tuple[int, int]]) -> list[bytes]: ...

    def list_datablocks(self) -> list[dict[str, Any]]: ...

    def browse(self) -> list[dict[str, Any]]: ...

    def read_tags(self, names: Sequence[str]) -> list[Any]: ...

    def write_tag(self, name: str, data: bytes) -> None: ...

    def cpu_state(self) -> str: ...

    def protection_level(self) -> int | None: ...

    def create_subscription(self, access_sequences: Sequence[str]) -> int: ...

    def receive_notification(self, subscription_id: int) -> Any: ...

    def delete_subscription(self, subscription_id: int) -> None: ...

    def read_alarms(self) -> list[Any]: ...

    def create_alarm_subscription(self) -> int: ...

    def delete_alarm_subscription(self, subscription_id: int) -> None: ...

    def supports(self, feature: str) -> bool: ...

    def reconnect(self) -> None: ...

    def peer_certificate_fingerprint(self) -> bytes | None: ...

    def runtime_metadata(self) -> dict[str, MetadataValue]: ...


# Features from open pull requests; a scenario that needs one is skipped with
# the PR named until the API is on master.
PENDING_FEATURES = {
    "reconnect": "reconnect() (gijzelaerr/s7commplus#99)",
    "certificate_pinning": "tls_cert_fingerprint (gijzelaerr/s7commplus#97)",
}


def _client_supports(client: Any, feature: str) -> bool:
    if feature == "reconnect":
        return callable(getattr(client, "reconnect", None))
    if feature == "certificate_pinning":
        return "tls_cert_fingerprint" in inspect.signature(client.connect).parameters and callable(
            getattr(client, "peer_certificate_fingerprint", None)
        )
    raise ValueError(f"unknown feature {feature!r}")


def _connect_arguments(config: PLCConfig, overrides: dict[str, Any]) -> dict[str, Any]:
    arguments: dict[str, Any] = {
        "port": config.port,
        "rack": config.rack,
        "slot": config.slot,
        "use_tls": config.use_tls,
        "tls_cert": config.tls_cert,
        "tls_key": config.tls_key,
        "tls_ca": config.tls_ca,
    }
    arguments.update(overrides)
    return arguments


def _metadata(client: Any, config: PLCConfig, kind: str) -> dict[str, MetadataValue]:
    return {
        "protocol_path": "s7commplus",
        "protocol_version": f"V{client.protocol_version}",
        "tls_enabled": bool(client.tls_active),
        "tls_client_certificate": config.tls_cert is not None,
        "tls_ca_verification": config.tls_ca is not None,
        f"client_{kind}": True,
    }


class S7CommPlusAdapter:
    """The synchronous :class:`s7commplus.Client` behind the scenario surface."""

    client_kind = "sync"

    def __init__(self, config: PLCConfig) -> None:
        self.config = config
        self.client = Client()

    def connect(self, **overrides: Any) -> None:
        self.client.connect(self.config.host, **_connect_arguments(self.config, overrides))

    def disconnect(self) -> None:
        self.client.disconnect()

    def close(self) -> None:
        if self.client.connected:
            self.client.disconnect()

    def is_connected(self) -> bool:
        return self.client.connected

    def read(self, db_number: int, offset: int, size: int) -> bytes:
        return self.client.db_read(db_number, offset, size)

    def write(self, db_number: int, offset: int, data: bytes) -> None:
        self.client.db_write(db_number, offset, data)

    def read_multi(self, db_number: int, regions: Sequence[tuple[int, int]]) -> list[bytes]:
        return self.client.db_read_multi([(db_number, offset, size) for offset, size in regions])

    def list_datablocks(self) -> list[dict[str, Any]]:
        return self.client.list_datablocks()

    def browse(self) -> list[dict[str, Any]]:
        return self.client.browse()

    def read_tags(self, names: Sequence[str]) -> list[Any]:
        return list(self.client.read_tags(names))

    def write_tag(self, name: str, data: bytes) -> None:
        self.client.write_tag(name, data)

    def cpu_state(self) -> str:
        return self.client.get_cpu_state()

    def protection_level(self) -> int | None:
        return self.client.protection_level

    def create_subscription(self, access_sequences: Sequence[str]) -> int:
        return self.client.create_subscription(list(access_sequences))

    def receive_notification(self, subscription_id: int) -> Any:
        # The synchronous client has no per-call timeout on master; the socket
        # timeout of the transport bounds the wait instead.
        return self.client.receive_subscription_notification(subscription_id)

    def delete_subscription(self, subscription_id: int) -> None:
        self.client.delete_subscription(subscription_id)

    def read_alarms(self) -> list[Any]:
        return list(self.client.read_alarms())

    def create_alarm_subscription(self) -> int:
        return self.client.create_alarm_subscription()

    def delete_alarm_subscription(self, subscription_id: int) -> None:
        self.client.delete_alarm_subscription(subscription_id)

    def supports(self, feature: str) -> bool:
        return _client_supports(self.client, feature)

    def reconnect(self) -> None:
        self.client.reconnect()  # type: ignore[attr-defined]

    def peer_certificate_fingerprint(self) -> bytes | None:
        fingerprint: bytes | None = self.client.peer_certificate_fingerprint()  # type: ignore[attr-defined]
        return fingerprint

    def runtime_metadata(self) -> dict[str, MetadataValue]:
        return _metadata(self.client, self.config, self.client_kind)


_T = TypeVar("_T")


class AsyncS7CommPlusAdapter:
    """The :class:`s7commplus.AsyncClient` behind the same synchronous surface.

    pytest-bdd steps are synchronous, so each call runs to completion on one
    event loop the adapter owns for its whole life: the client's streams are
    bound to the loop that opened them, so ``asyncio.run()`` per call would not
    work.
    """

    client_kind = "async"

    def __init__(self, config: PLCConfig) -> None:
        self.config = config
        self.loop = asyncio.new_event_loop()
        self.client = AsyncClient()

    def _run(self, call: Callable[[], Coroutine[Any, Any, _T]]) -> _T:
        return self.loop.run_until_complete(call())

    def connect(self, **overrides: Any) -> None:
        self._run(lambda: self.client.connect(self.config.host, **_connect_arguments(self.config, overrides)))

    def disconnect(self) -> None:
        self._run(self.client.disconnect)

    def close(self) -> None:
        try:
            if self.client.connected:
                self.disconnect()
        finally:
            self.loop.close()

    def is_connected(self) -> bool:
        return self.client.connected

    def read(self, db_number: int, offset: int, size: int) -> bytes:
        return self._run(lambda: self.client.db_read(db_number, offset, size))

    def write(self, db_number: int, offset: int, data: bytes) -> None:
        self._run(lambda: self.client.db_write(db_number, offset, data))

    def read_multi(self, db_number: int, regions: Sequence[tuple[int, int]]) -> list[bytes]:
        return self._run(lambda: self.client.db_read_multi([(db_number, offset, size) for offset, size in regions]))

    def list_datablocks(self) -> list[dict[str, Any]]:
        return self._run(self.client.list_datablocks)

    def browse(self) -> list[dict[str, Any]]:
        return self._run(self.client.browse)

    def read_tags(self, names: Sequence[str]) -> list[Any]:
        return list(self._run(lambda: self.client.read_tags(names)))

    def write_tag(self, name: str, data: bytes) -> None:
        self._run(lambda: self.client.write_tag(name, data))

    def cpu_state(self) -> str:
        return self._run(self.client.get_cpu_state)

    def protection_level(self) -> int | None:
        return self.client.protection_level

    def create_subscription(self, access_sequences: Sequence[str]) -> int:
        return self._run(lambda: self.client.create_subscription(list(access_sequences)))

    def receive_notification(self, subscription_id: int) -> Any:
        return self._run(lambda: self.client.receive_subscription_notification(subscription_id, timeout=NOTIFICATION_TIMEOUT))

    def delete_subscription(self, subscription_id: int) -> None:
        self._run(lambda: self.client.delete_subscription(subscription_id))

    def read_alarms(self) -> list[Any]:
        return list(self._run(self.client.read_alarms))

    def create_alarm_subscription(self) -> int:
        return self._run(self.client.create_alarm_subscription)

    def delete_alarm_subscription(self, subscription_id: int) -> None:
        self._run(lambda: self.client.delete_alarm_subscription(subscription_id))

    def supports(self, feature: str) -> bool:
        return _client_supports(self.client, feature)

    def reconnect(self) -> None:
        self._run(self.client.reconnect)  # type: ignore[attr-defined]

    def peer_certificate_fingerprint(self) -> bytes | None:
        fingerprint: bytes | None = self.client.peer_certificate_fingerprint()  # type: ignore[attr-defined]
        return fingerprint

    def runtime_metadata(self) -> dict[str, MetadataValue]:
        return _metadata(self.client, self.config, self.client_kind)


def make_adapter(config: PLCConfig) -> PLCAdapter:
    if config.client_kind == "async":
        return AsyncS7CommPlusAdapter(config)
    if config.client_kind == "sync":
        return S7CommPlusAdapter(config)
    raise ValueError(f"unknown client kind {config.client_kind!r}")


def db_access_prefix(db_number: int) -> str:
    """The access-sequence prefix ``browse()`` gives every member of a data block."""
    return f"{Ids.DB_ACCESS_AREA_BASE | (db_number & 0xFFFF):08X}."


def fixture_entries(browsed: Sequence[dict[str, Any]], db_number: int) -> dict[str, dict[str, Any]]:
    """Map each canonical member name to its browse entry in ``db_number``.

    Members are found by access-sequence prefix and by the last component of
    the browsed name, so the DB name in TIA Portal does not matter.
    """
    prefix = db_access_prefix(db_number)
    entries: dict[str, dict[str, Any]] = {}
    for entry in browsed:
        if not str(entry.get("access_sequence", "")).upper().startswith(prefix):
            continue
        member = str(entry.get("name", "")).rsplit(".", 1)[-1]
        if member in MEMBERS_BY_NAME:
            entries[member] = entry
    return entries


def untrusted_ca_certificate(directory: Path) -> str:
    """Write a freshly generated self-signed CA certificate no PLC certificate chains to."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "s7commplus acceptance untrusted CA")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    path = directory / "untrusted-ca.pem"
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return str(path)


def canonical_fixture_bytes() -> bytes:
    """Return the canonical 37-byte non-optimized DB image."""
    return b"".join(
        (
            struct.pack(
                ">hhffBBHHIIii",
                EXPECTED_INT1,
                EXPECTED_INT2,
                EXPECTED_FLOAT1,
                EXPECTED_FLOAT2,
                EXPECTED_BYTE1,
                EXPECTED_BYTE2,
                EXPECTED_WORD1,
                EXPECTED_WORD2,
                EXPECTED_DWORD1,
                EXPECTED_DWORD2,
                EXPECTED_DINT1,
                EXPECTED_DINT2,
            ),
            EXPECTED_CHAR1.encode() + EXPECTED_CHAR2.encode() + bytes([1]),
        )
    )


def assert_canonical_fixture(data: bytes) -> None:
    """Validate every documented scalar in the canonical fixture."""
    assert len(data) == DB_SIZE
    assert struct.unpack_from(">h", data, OFFSET_INT1)[0] == EXPECTED_INT1
    assert struct.unpack_from(">h", data, OFFSET_INT2)[0] == EXPECTED_INT2
    assert math.isclose(struct.unpack_from(">f", data, OFFSET_FLOAT1)[0], EXPECTED_FLOAT1, abs_tol=0.001)
    assert math.isclose(struct.unpack_from(">f", data, OFFSET_FLOAT2)[0], EXPECTED_FLOAT2, abs_tol=0.001)
    assert data[OFFSET_BYTE1] == EXPECTED_BYTE1
    assert data[OFFSET_BYTE2] == EXPECTED_BYTE2
    assert struct.unpack_from(">H", data, OFFSET_WORD1)[0] == EXPECTED_WORD1
    assert struct.unpack_from(">H", data, OFFSET_WORD2)[0] == EXPECTED_WORD2
    assert struct.unpack_from(">I", data, OFFSET_DWORD1)[0] == EXPECTED_DWORD1
    assert struct.unpack_from(">I", data, OFFSET_DWORD2)[0] == EXPECTED_DWORD2
    assert struct.unpack_from(">i", data, OFFSET_DINT1)[0] == EXPECTED_DINT1
    assert struct.unpack_from(">i", data, OFFSET_DINT2)[0] == EXPECTED_DINT2
    assert chr(data[OFFSET_CHAR1]) == EXPECTED_CHAR1
    assert chr(data[OFFSET_CHAR2]) == EXPECTED_CHAR2
    assert tuple(bool(data[OFFSET_BOOLS] & (1 << bit)) for bit in range(8)) == EXPECTED_BOOLS


WRITE_VALUES: dict[str, tuple[int, bytes, Callable[[bytes], object], object]] = {
    "INT": (0, struct.pack(">h", -1234), lambda data: struct.unpack(">h", data)[0], -1234),
    "REAL": (4, struct.pack(">f", 456.75), lambda data: struct.unpack(">f", data)[0], 456.75),
    "BYTE": (12, b"\xa5", lambda data: data[0], 0xA5),
    "WORD": (14, struct.pack(">H", 0x5AA5), lambda data: struct.unpack(">H", data)[0], 0x5AA5),
    "DWORD": (18, struct.pack(">I", 0xDEADBEEF), lambda data: struct.unpack(">I", data)[0], 0xDEADBEEF),
    "DINT": (26, struct.pack(">i", -123456789), lambda data: struct.unpack(">i", data)[0], -123456789),
    "CHAR": (34, b"X", lambda data: chr(data[0]), "X"),
    "BOOL": (36, b"\x81", lambda data: bool(data[0] & 0x80), True),
}

# Named writes: the scratch DB member each type writes, and the raw value a
# symbolic write sends (a BOOL is one byte, 0 or 1). The scratch byte range is
# saved and restored by byte offset around each write.
NAMED_WRITE_VALUES: dict[str, tuple[str, bytes]] = {
    "INT": ("int1", struct.pack(">h", -1234)),
    "REAL": ("float1", struct.pack(">f", 456.75)),
    "BYTE": ("byte1", b"\xa5"),
    "WORD": ("word1", struct.pack(">H", 0x5AA5)),
    "DWORD": ("dword1", struct.pack(">I", 0xDEADBEEF)),
    "DINT": ("dint1", struct.pack(">i", -123456789)),
    "CHAR": ("char1", b"X"),
    "BOOL": ("bool7", b"\x01"),
}


class ScratchRestoreGuard:
    """Save, restore, and verify one scratch region; restoration is idempotent."""

    def __init__(self, adapter: PLCAdapter, db_number: int, offset: int, size: int) -> None:
        self.adapter = adapter
        self.db_number = db_number
        self.offset = offset
        self.original = adapter.read(db_number, offset, size)
        self.restored = False

    def restore(self) -> None:
        if self.restored:
            return
        self.adapter.write(self.db_number, self.offset, self.original)
        restored = self.adapter.read(self.db_number, self.offset, len(self.original))
        if restored != self.original:
            raise AssertionError("scratch DB restoration verification failed")
        self.restored = True
