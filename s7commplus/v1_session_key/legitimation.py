"""V1 password legitimation after the SessionKey handshake (HarpoS7's LegitimateScheme).

After the SessionKey handshake, V1-initial PLCs require a second
cryptographic exchange before they unlock data operations. The PLC
sends a DEADBEEF-prefixed challenge blob; we solve it by running
a second RealPlcAuthenticator round with keys derived from the
session key and password hash.

Manual port of ``HarpoS7.Auth.LegitimateScheme``.
"""

from __future__ import annotations

import hashlib
import secrets
import struct

from .aes_gcm import AesGcm24
from .blob_metadata import (
    ENCRYPTED_BLOB_LENGTH_PLCSIM,
    get_encrypted_seed_length,
    get_public_key_flags,
    get_symmetric_key_flags_legitimation,
)
from .key_derivation import derive_challenge_encryption_key, derive_legitimation_challenge_key
from .keys import KeyFamily
from .plcsim.seed import SEED_LENGTH as PLCSIM_SEED_LENGTH
from .plcsim.seed import encrypt_seed as encrypt_plcsim_seed
from .real_plc.authenticator import RealPlcAuthenticator
from .utils import derive_key_id

DEADBEEF = 0xDEADBEEF
BEEF_FRAGMENT_METADATA_LENGTH = 12
BEEF_SEED_METADATA_LENGTH = 0x40
OUTPUT_BLOB_LENGTH_REAL_PLC = 180 + 68  # 248 bytes
OUTPUT_BLOB_LENGTH_PLCSIM = ENCRYPTED_BLOB_LENGTH_PLCSIM + 68  # 284 bytes


def _write_fragment_metadata(buf: bytearray, offset: int, index: int, length: int) -> None:
    struct.pack_into("<III", buf, offset, DEADBEEF, index, length)


def _write_seed_beef_metadata(
    buf: bytearray,
    public_key: bytes,
    family: KeyFamily,
    symmetric_key: bytes,
) -> None:
    seed_length = get_encrypted_seed_length(family)

    struct.pack_into("<I", buf, 0, DEADBEEF)

    struct.pack_into("<I", buf, 4, BEEF_SEED_METADATA_LENGTH + seed_length)
    struct.pack_into("<I", buf, 8, 1)
    struct.pack_into("<I", buf, 12, 2)
    buf[0x15] = 0x04

    pub_key_id = derive_key_id(public_key)
    buf[0x1C : 0x1C + 8] = pub_key_id

    struct.pack_into("<I", buf, 0x24, get_public_key_flags(family))
    struct.pack_into("<I", buf, 0x28, 0)

    sym_key_id = derive_key_id(symmetric_key)
    buf[0x2C : 0x2C + 8] = sym_key_id

    struct.pack_into("<I", buf, 0x34, get_symmetric_key_flags_legitimation(family))
    struct.pack_into("<I", buf, 0x38, 0)

    struct.pack_into("<I", buf, 0x3C, seed_length)


def solve_legitimate_challenge_real_plc(
    challenge: bytes,
    public_key: bytes,
    family: KeyFamily,
    session_key: bytes,
    password: str = "",
) -> bytes:
    password_hash = hashlib.sha1(password.encode("utf-8")).digest()

    challenge_key = derive_legitimation_challenge_key(session_key)

    key2 = password_hash + challenge[:20]

    blob = bytearray(OUTPUT_BLOB_LENGTH_REAL_PLC)

    _write_seed_beef_metadata(blob, public_key, family, challenge_key)

    offset = BEEF_SEED_METADATA_LENGTH
    auth = RealPlcAuthenticator(key1=challenge_key, key2=key2)
    offset += auth.write_seed(memoryview(blob)[offset:], public_key)

    _write_fragment_metadata(blob, offset, 0, 0x10 + 0x30)
    offset += BEEF_FRAGMENT_METADATA_LENGTH

    zero_challenge = bytes(20)
    offset += auth.encrypt_full_blocks(memoryview(blob)[offset:], zero_challenge)

    leftover = auth.key2_leftover_length
    _write_fragment_metadata(blob, offset, 1, leftover + 16)
    offset += BEEF_FRAGMENT_METADATA_LENGTH
    offset += auth.encrypt_final_block(memoryview(blob)[offset:])

    _write_fragment_metadata(blob, offset, 2, 0)

    return bytes(blob)


def solve_legitimate_challenge_plcsim(
    challenge: bytes,
    public_key: bytes,
    session_key: bytes,
    password: str = "",
    *,
    password_hash: bytes | None = None,
    seed: bytes | None = None,
    iv: bytes | None = None,
) -> bytes:
    """Build the 284-byte legitimation blob for a PlcSim (family 03) PLC.

    PLCSIM's legitimation differs from the real-PLC scheme: the seed is the same
    ECIES-over-P-256 blob as the session handshake, and the password hash and
    challenge are encrypted with AES-GCM (24-bit counter). Ported from
    ``HarpoS7.Auth.LegitimateScheme.SolveLegitimateChallengePlcSim`` (MIT).

    Args:
        challenge: 20-byte challenge from the address-303 read.
        public_key: 64-byte family-03 public key.
        session_key: 24-byte session key from the SessionKey handshake.
        password: PLC password (UTF-8); ignored when ``password_hash`` is given.
        password_hash: SHA-1 of the password. Defaults to ``sha1(password)``.
        seed: 96-byte seed to inject (tests); built from ``public_key`` otherwise.
        iv: 16-byte AES-GCM IV to inject (tests); random otherwise.

    Returns:
        The 284-byte blob to write to address 1846.
    """
    if password_hash is None:
        password_hash = hashlib.sha1(password.encode("utf-8")).digest()
    if len(password_hash) < 20:
        raise ValueError("password_hash must be at least 20 bytes (SHA-1)")
    if len(challenge) < 20:
        raise ValueError(f"challenge must be at least 20 bytes, got {len(challenge)}")

    symmetric_key = derive_legitimation_challenge_key(session_key)
    challenge_key = derive_challenge_encryption_key(symmetric_key)

    if seed is None:
        seed = encrypt_plcsim_seed(public_key, challenge_key)
    if len(seed) != PLCSIM_SEED_LENGTH:
        raise ValueError(f"seed must be {PLCSIM_SEED_LENGTH} bytes, got {len(seed)}")
    if iv is None:
        iv = secrets.token_bytes(16)
    if len(iv) != 16:
        raise ValueError("iv must be 16 bytes")

    blob = bytearray(OUTPUT_BLOB_LENGTH_PLCSIM)
    _write_seed_beef_metadata(blob, public_key, KeyFamily.PLCSIM, symmetric_key)

    offset = BEEF_SEED_METADATA_LENGTH
    blob[offset : offset + PLCSIM_SEED_LENGTH] = seed

    # IV + zero block + password-hash/challenge block
    fragment_offset = offset + PLCSIM_SEED_LENGTH
    _write_fragment_metadata(blob, fragment_offset, 0, 0x40)
    iv_offset = fragment_offset + BEEF_FRAGMENT_METADATA_LENGTH
    blob[iv_offset : iv_offset + 16] = iv

    gcm = AesGcm24(challenge_key)
    gcm.start(iv)

    zero_offset = iv_offset + 16
    blob[zero_offset : zero_offset + 16] = gcm.encrypt(bytes(16))

    hash_offset = zero_offset + 16
    blob[hash_offset : hash_offset + 32] = gcm.encrypt(password_hash[:20] + challenge[:12])

    # Last partial challenge + checksum
    checksum_fragment_offset = hash_offset + 32
    _write_fragment_metadata(blob, checksum_fragment_offset, 1, 0x18)
    challenge_part_offset = checksum_fragment_offset + BEEF_FRAGMENT_METADATA_LENGTH
    blob[challenge_part_offset : challenge_part_offset + 8] = gcm.encrypt(challenge[12:20])

    checksum_offset = challenge_part_offset + 8
    blob[checksum_offset : checksum_offset + 16] = gcm.tag(16)

    _write_fragment_metadata(blob, checksum_offset + 16, 2, 0)

    return bytes(blob)


def solve_legitimate_challenge(
    challenge: bytes,
    public_key: bytes,
    family: KeyFamily,
    session_key: bytes,
    password: str = "",
) -> bytes:
    """Build the legitimation blob for any supported key family."""
    if family == KeyFamily.PLCSIM:
        return solve_legitimate_challenge_plcsim(challenge, public_key, session_key, password)
    return solve_legitimate_challenge_real_plc(challenge, public_key, family, session_key, password)
