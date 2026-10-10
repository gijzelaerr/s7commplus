"""PLCSIM (key family 03) V1 SessionKey authentication: ECIES seed, 216-byte blob and client flow."""

from __future__ import annotations

import hashlib
import struct
import time
from collections.abc import Generator
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from s7commplus.async_client import S7CommPlusAsyncClient
from s7commplus.client import _LEGACY_KEY_CACHE, S7CommPlusClient
from s7commplus.connection import _build_v1_get_var_substreamed_payload, _v1_integrity_tail
from s7commplus.server import S7CommPlusServer
from s7commplus.v1_session_key import handshake, legitimation
from s7commplus.v1_session_key.blob_metadata import ENCRYPTED_BLOB_LENGTH_PLCSIM, write_metadata
from s7commplus.v1_session_key.key_derivation import derive_challenge_encryption_key, derive_session_key
from s7commplus.v1_session_key.keys import _PUBLIC_KEYS, KeyFamily, get_public_key
from s7commplus.v1_session_key.plcsim.authenticator import authenticate
from s7commplus.v1_session_key.plcsim.seed import ORDER, encrypt_seed
from tests.conftest import get_free_tcp_port

# HarpoS7's GenerateEncryptedSeedTest: its test PRNG fills the scalar with 0x33.
HARPO_PUBLIC_KEY = bytes.fromhex(
    "eca6d799ddf03eaadd16b5d7245331e426c9e6ba8997877a7394f3286532a6b0"
    "53e4229818085223432483fba4d5c43bd6c354c10febc903908ed271697f39e9"
)
HARPO_CHALLENGE_KEY = bytes.fromhex("4e001016db625dcce9105bdcd8a1b42c")
HARPO_SCALAR = int.from_bytes(b"\x33" * 32, "big")
HARPO_SEED = bytes.fromhex(
    "51a758083389"
    "8ea1b183cbd7350a4099078c6ef1c1e18e970cd7683035f25e7d0110522712b0b5a7cff081685486"
    "984a94e6831edac46e7360fa9d834a7a81a1436d6fe9ae2435c7de4a8234d810f5aa2e5f612c49d50559f8da6502"
    "572b3add"
)

TEST_FINGERPRINT = "03:5A9B6B015F48D284"
TEST_CHALLENGE = bytes(range(20))
TEST_SESSION_KEY = bytes(range(24))
PLCSIM_KEYS = [(fingerprint, key) for (family, fingerprint), key in _PUBLIC_KEYS.items() if family == KeyFamily.PLCSIM]


def _seed_independently(public_key: bytes, challenge_key: bytes, scalar: int) -> bytes:
    """The seed again, from the issue's description and ``cryptography``'s own AES-GCM."""
    curve = ec.SECP256R1()
    ephemeral = ec.derive_private_key(scalar, curve)
    point = ephemeral.public_key().public_numbers()
    ephemeral_xy = point.x.to_bytes(32, "big") + point.y.to_bytes(32, "big")
    peer = ec.EllipticCurvePublicNumbers(
        int.from_bytes(public_key[:32], "big"), int.from_bytes(public_key[32:], "big"), curve
    ).public_key()
    shared_x = ephemeral.exchange(ec.ECDH(), peer)
    # SHA-256(shared x || ephemeral x||y || counter) for counters 0 and 32, the KDF's 48 bytes.
    material = b"".join(hashlib.sha256(shared_x + ephemeral_xy + bytes([counter])).digest() for counter in (0, 32))
    sealed = AESGCM(material[:16]).encrypt(material[32:48], challenge_key, None)
    return ephemeral_xy + sealed


# --- Seed ---


def test_seed_matches_harpos7_known_answer() -> None:
    assert len(HARPO_SEED) == 96
    assert encrypt_seed(HARPO_PUBLIC_KEY, HARPO_CHALLENGE_KEY, HARPO_SCALAR) == HARPO_SEED


@pytest.mark.parametrize(("fingerprint", "public_key"), PLCSIM_KEYS)
def test_seed_matches_an_independent_computation_for_every_bundled_key(fingerprint: str, public_key: bytes) -> None:
    scalar = int.from_bytes(hashlib.sha256(fingerprint.encode()).digest(), "big") % (ORDER - 1) + 1
    assert encrypt_seed(public_key, HARPO_CHALLENGE_KEY, scalar) == _seed_independently(public_key, HARPO_CHALLENGE_KEY, scalar)


def test_seed_uses_a_fresh_scalar_by_default() -> None:
    first = encrypt_seed(HARPO_PUBLIC_KEY, HARPO_CHALLENGE_KEY)
    second = encrypt_seed(HARPO_PUBLIC_KEY, HARPO_CHALLENGE_KEY)
    assert len(first) == 96
    assert first != second


@pytest.mark.parametrize("length", [0, 40, 63, 65])
def test_seed_rejects_a_public_key_of_the_wrong_length(length: int) -> None:
    with pytest.raises(ValueError, match="public_key must be 64 bytes"):
        encrypt_seed(bytes(length), HARPO_CHALLENGE_KEY, 5)


def test_seed_rejects_a_point_that_is_not_on_the_curve() -> None:
    off_curve = HARPO_PUBLIC_KEY[:63] + bytes([HARPO_PUBLIC_KEY[63] ^ 1])
    with pytest.raises(ValueError):
        encrypt_seed(off_curve, HARPO_CHALLENGE_KEY, 5)
    with pytest.raises(ValueError):
        encrypt_seed(bytes(64), HARPO_CHALLENGE_KEY, 5)


@pytest.mark.parametrize("scalar", [0, -1, ORDER, ORDER + 1])
def test_seed_rejects_a_scalar_outside_the_group_order(scalar: int) -> None:
    with pytest.raises(ValueError, match="scalar"):
        encrypt_seed(HARPO_PUBLIC_KEY, HARPO_CHALLENGE_KEY, scalar)


@pytest.mark.parametrize("length", [0, 15, 17, 32])
def test_seed_rejects_a_challenge_key_of_the_wrong_length(length: int) -> None:
    with pytest.raises(ValueError, match="challenge_key must be 16 bytes"):
        encrypt_seed(HARPO_PUBLIC_KEY, bytes(length), 5)


# --- Blob ---

KEY1 = bytes(range(0x10, 0x28))
KEY2 = bytes(range(0x40, 0x58))
IV = bytes(range(0x80, 0x90))
SCALAR = 0x1234567890ABCDEF


@pytest.mark.parametrize(("fingerprint", "public_key"), PLCSIM_KEYS)
def test_blob_layout_for_every_bundled_key(fingerprint: str, public_key: bytes) -> None:
    blob, session_key = authenticate(TEST_CHALLENGE, public_key, key1=KEY1, key2=KEY2, iv=IV, scalar=SCALAR)
    challenge_key = derive_challenge_encryption_key(KEY2)

    assert len(blob) == ENCRYPTED_BLOB_LENGTH_PLCSIM == 216
    expected_metadata = bytearray(48)
    write_metadata(expected_metadata, public_key, KEY1, KeyFamily.PLCSIM)
    assert blob[:48] == expected_metadata
    assert blob[48:144] == _seed_independently(public_key, challenge_key, SCALAR)
    assert blob[144:160] == IV

    sealed = AESGCM(challenge_key).encrypt(IV, TEST_CHALLENGE[2:18] + KEY1, None)
    assert blob[160:200] == sealed[:40]  # encrypted challenge[2:18] and key1
    assert blob[200:216] == sealed[40:]  # tag
    assert session_key == derive_session_key(KEY1, TEST_CHALLENGE)
    assert len(session_key) == 24


def test_blob_session_key_derives_from_key1_and_metadata_names_key1() -> None:
    public_key = get_public_key(TEST_FINGERPRINT)
    assert public_key is not None
    blob, session_key = authenticate(TEST_CHALLENGE, public_key, key1=KEY1, key2=KEY2, iv=IV, scalar=SCALAR)
    other, other_key = authenticate(TEST_CHALLENGE, public_key, key1=KEY2, key2=KEY2, iv=IV, scalar=SCALAR)
    assert session_key != other_key
    assert blob[16:24] != other[16:24]  # the symmetric key id in the metadata
    assert blob[144:160] == other[144:160]


def test_blob_is_random_by_default() -> None:
    public_key = get_public_key(TEST_FINGERPRINT)
    assert public_key is not None
    first = authenticate(TEST_CHALLENGE, public_key)
    second = authenticate(TEST_CHALLENGE, public_key)
    assert first[0] != second[0]
    assert first[1] != second[1]


def test_blob_rejects_malformed_inputs() -> None:
    public_key = get_public_key(TEST_FINGERPRINT)
    assert public_key is not None
    with pytest.raises(ValueError, match="challenge"):
        authenticate(bytes(17), public_key)
    with pytest.raises(ValueError, match="24 bytes"):
        authenticate(TEST_CHALLENGE, public_key, key1=bytes(23))
    with pytest.raises(ValueError, match="iv"):
        authenticate(TEST_CHALLENGE, public_key, iv=bytes(15))
    with pytest.raises(ValueError):
        authenticate(TEST_CHALLENGE, bytes(40))


def test_handshake_dispatches_by_family() -> None:
    plcsim_key = get_public_key(TEST_FINGERPRINT)
    s7_1500_fingerprint = next(f"00:{fingerprint}" for (family, fingerprint) in _PUBLIC_KEYS if family == KeyFamily.S7_1500)
    s7_1500_key = get_public_key(s7_1500_fingerprint)
    assert plcsim_key is not None and s7_1500_key is not None

    blob, key = handshake.authenticate_session_key(TEST_CHALLENGE, plcsim_key, KeyFamily.PLCSIM)
    assert len(blob) == 216 and len(key) == 24

    blob, key = handshake.authenticate_session_key(TEST_CHALLENGE, s7_1500_key, KeyFamily.S7_1500)
    assert len(blob) == 180 and len(key) == 24

    with pytest.raises(ValueError):
        handshake.authenticate_real_plc(TEST_CHALLENGE, plcsim_key, KeyFamily.PLCSIM)


# --- Request layouts ---


def test_plcsim_uses_the_s7_1500_request_layouts() -> None:
    assert _v1_integrity_tail(KeyFamily.PLCSIM) == _v1_integrity_tail(KeyFamily.S7_1500) == 4
    for sequence in (1, 7, 0x1234):
        assert _build_v1_get_var_substreamed_payload(
            KeyFamily.PLCSIM, 0x0A5A, 303, sequence
        ) == _build_v1_get_var_substreamed_payload(KeyFamily.S7_1500, 0x0A5A, 303, sequence)
    assert _build_v1_get_var_substreamed_payload(KeyFamily.PLCSIM, 0x0A5A, 303, 1) != _build_v1_get_var_substreamed_payload(
        KeyFamily.S7_1200, 0x0A5A, 303, 1
    )


# --- Against the emulator in family-03 mode ---


@pytest.fixture(autouse=True)
def clear_key_cache() -> None:
    _LEGACY_KEY_CACHE.clear()


@pytest.fixture()
def blobs(monkeypatch: pytest.MonkeyPatch) -> list[bytes]:
    """Build the real 216-byte blob, but negotiate a known session key (the emulator has no private key)."""
    built: list[bytes] = []
    real = handshake.authenticate_plcsim

    def authenticate_plcsim(challenge: bytes, public_key: bytes) -> tuple[bytes, bytes]:
        assert challenge == TEST_CHALLENGE
        blob, _ = real(challenge, public_key)
        built.append(blob)
        return blob, TEST_SESSION_KEY

    def no_legitimation(*args: Any) -> bytes:
        raise AssertionError("PLCSIM must not run the real-PLC legitimation")

    monkeypatch.setattr(handshake, "authenticate_plcsim", authenticate_plcsim)
    monkeypatch.setattr(legitimation, "solve_legitimate_challenge_real_plc", no_legitimation)
    return built


@pytest.fixture()
def plcsim_server(blobs: list[bytes]) -> Generator[tuple[S7CommPlusServer, int], None, None]:
    srv = S7CommPlusServer(
        public_key_fingerprint=TEST_FINGERPRINT,
        session_challenge=TEST_CHALLENGE,
        session_key=TEST_SESSION_KEY,
    )
    srv.register_db(1, {"temperature": ("Real", 0)})
    db1 = srv.get_db(1)
    assert db1 is not None
    struct.pack_into(">f", db1.data, 0, 23.5)
    port = get_free_tcp_port()
    srv.start(port=port)
    time.sleep(0.1)
    yield srv, port
    srv.stop()


def test_sync_client_authenticates_against_family_03(plcsim_server: tuple[S7CommPlusServer, int], blobs: list[bytes]) -> None:
    server, port = plcsim_server
    client = S7CommPlusClient()
    client.connect("127.0.0.1", port=port)
    try:
        assert client.connected
        assert client._connection._v1_session_key_family == KeyFamily.PLCSIM
        assert client._connection._session_key == TEST_SESSION_KEY
        assert server._accepted_session_key_setups == 1
        assert [len(blob) for blob in blobs] == [216]
        assert abs(struct.unpack(">f", client.db_read(1, 0, 4))[0] - 23.5) < 0.001
        client.db_write(1, 0, struct.pack(">f", 42.0))
        assert abs(struct.unpack(">f", client.db_read(1, 0, 4))[0] - 42.0) < 0.001
        assert client.list_datablocks() == [
            {
                "name": "DB1",
                "number": 1,
                "rid": 0x8A0E0001,
                "language": None,
                "knowhow_protected": False,
                "unlinked": False,
            }
        ]
    finally:
        client.disconnect()


@pytest.mark.asyncio
async def test_async_client_authenticates_against_family_03(
    plcsim_server: tuple[S7CommPlusServer, int], blobs: list[bytes]
) -> None:
    server, port = plcsim_server
    client = S7CommPlusAsyncClient()
    await client.connect("127.0.0.1", port=port)
    try:
        assert client.connected
        assert client._v1_session_key_family == KeyFamily.PLCSIM
        assert client._session_key == TEST_SESSION_KEY
        assert server._accepted_session_key_setups == 1
        assert [len(blob) for blob in blobs] == [216]
        assert abs(struct.unpack(">f", await client.db_read(1, 0, 4))[0] - 23.5) < 0.001
        await client.db_write(1, 0, struct.pack(">f", 42.0))
        assert abs(struct.unpack(">f", await client.db_read(1, 0, 4))[0] - 42.0) < 0.001
        assert await client.list_datablocks() == [
            {
                "name": "DB1",
                "number": 1,
                "rid": 0x8A0E0001,
                "language": None,
                "knowhow_protected": False,
                "unlinked": False,
            }
        ]
    finally:
        await client.disconnect()


def test_sync_client_legitimates_with_a_password_on_plcsim(plcsim_server: tuple[S7CommPlusServer, int]) -> None:
    _, port = plcsim_server
    client = S7CommPlusClient()
    client.connect("127.0.0.1", port=port, password="secret")
    try:
        assert client.connected
        assert abs(struct.unpack(">f", client.db_read(1, 0, 4))[0] - 23.5) < 0.001
    finally:
        client.disconnect()


@pytest.mark.asyncio
async def test_async_client_legitimates_with_a_password_on_plcsim(plcsim_server: tuple[S7CommPlusServer, int]) -> None:
    _, port = plcsim_server
    client = S7CommPlusAsyncClient()
    await client.connect("127.0.0.1", port=port, password="secret")
    try:
        assert client.connected
        assert abs(struct.unpack(">f", await client.db_read(1, 0, 4))[0] - 23.5) < 0.001
    finally:
        await client.disconnect()


# A real PLCSIM Advanced ServerSessionVersion (captured CreateObject response):
# elements 315-318 carry the emulator values, 319/320 are the PAOM and
# order-number WStrings.
_PLCSIM_SSV = bytes.fromhex(
    "00170000013a"
    "823b00048800"
    "823c00048500"
    "823d000484818640"
    "823e000484818400"
    "823f00151a313b364553372053494d2d30313530302d41504c433b53342e31"
    "8240001508323b373436323838"
    "00"
)
_PLCSIM_SSV_PATCHED = bytes.fromhex(
    "00170000013a"
    "823b00048400"
    "823c00048400"
    "823d000484818240"
    "823e000484818240"
    "823f00151a313b364553372053494d2d30313530302d41504c433b53342e31"
    "8240001508323b373436323838"
    "00"
)


def test_plcsim_session_version_patch_rewrites_315_to_318() -> None:
    from s7commplus.connection import _patch_plcsim_server_session_version

    assert _patch_plcsim_server_session_version(_PLCSIM_SSV) == _PLCSIM_SSV_PATCHED


def test_plcsim_session_version_patch_ignores_marker_bytes_in_values() -> None:
    """The patch walks elements, so marker bytes inside a BLOB value are not rewritten."""
    from s7commplus.connection import _patch_plcsim_server_session_version

    lookalike = bytes.fromhex("823b00048800")
    blob_element = bytes.fromhex("822c0014") + bytes([len(lookalike)]) + lookalike  # element 300, BLOB
    value = bytes.fromhex("00170000013a") + blob_element + bytes.fromhex("823b00048800") + bytes([0x00])
    expected = bytes.fromhex("00170000013a") + blob_element + bytes.fromhex("823b00048400") + bytes([0x00])
    assert _patch_plcsim_server_session_version(value) == expected


def test_plcsim_session_version_patch_leaves_non_structs_alone() -> None:
    from s7commplus.connection import _patch_plcsim_server_session_version

    bare_udint = bytes.fromhex("00048400")  # flags, datatype UDINT, value; not a struct
    assert _patch_plcsim_server_session_version(bare_udint) == bare_udint
