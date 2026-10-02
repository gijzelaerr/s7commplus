"""The encrypted seed and the three blob keys, from key1 and the PLC public key.

HarpoS7 builds these with four transforms. Recovery showed that they are
PRESENT-80 (``present``) and an elliptic-curve Diffie-Hellman (``curve``):

- PreSeedTransform, ``pre_seed``: key1's three 64-bit blocks, each encrypted
  under ``PRE_SEED_KEY``, as one 160-bit value.
- SeedTransform, ``write_seed``: an ephemeral ECDH with the PLC public key.
  The blob gets the ephemeral x-coordinate, and ``seed_mask`` of the shared
  x-coordinate masks the pre-seed.
- Transform13, ``seed_mask``: three fixed blocks encrypted under halves of
  the shared secret.
- KeyDerivationTransform, ``derive_keys``: six fixed blocks encrypted under
  halves of the pre-seed. They give the challenge key, the checksum key and
  the checksum's hash key.

HarpoS7 passes these values between its transforms in an encoded
three-words-per-bit form. The runtime passes the decoded integers instead. The
encoded ports, and the original Transform7 chain that ``write_seed``'s ladder
replaces, are kept in ``old/family0`` in the repository and pinned against
this module by tests.
"""

from __future__ import annotations

import os
import struct
from typing import NamedTuple

from . import curve, present

KEY1_LENGTH = 0x18
SEED_LENGTH = 0x3C
PUBLIC_KEY_LENGTH = 0x28

# Key register whose Monolith10 round-key layout is HarpoS7's TRANSFORM1_DATA.
# HarpoS7 also appends a fixed 96-bit tag that Monolith9 compares with each
# block's tag; it never matched in testing, so only the encrypted path exists.
PRE_SEED_KEY = 0xA98DE7C5164AD032538F

# Fixed plaintext blocks: HarpoS7's SHARED_DATA words 0..11 and 12..17, as
# little-endian 64-bit values.
KEY_PLAINTEXTS = (
    0xEFFCB975BC8864FD,
    0x20B6407AF0433F14,
    0x610806EFE0358644,
    0xFF78C6D5C660CEDC,
    0xC5E88FDB01AF4AE1,
    0x2AE2BA517C0D93F6,
)
SEED_MASK_PLAINTEXTS = (0xF5EA1E69CBDF8EF1, 0xF4C52FEBC1C01D1A, 0xADF3602156A724DE)


class BlobKeys(NamedTuple):
    challenge_key: bytes
    """AES-128 key that encrypts the challenge and key2."""
    checksum_key: bytes
    """AES-128 key that encrypts the final checksum."""
    hash_key: int
    """The checksum's multiplier ``H`` in ``checksum.multiply``."""


def pre_seed(key1: bytes) -> int:
    """PreSeedTransform: key1's three blocks encrypted under ``PRE_SEED_KEY``."""
    if len(key1) < KEY1_LENGTH:
        raise ValueError(f"key1 too small ({len(key1)}, need {KEY1_LENGTH})")
    return present.encrypt_blocks(struct.unpack("<3Q", key1[:KEY1_LENGTH]), (PRE_SEED_KEY,) * 3)


def seed_mask(shared_x: int) -> int:
    """Transform13: the fixed blocks under the low, low and high 80 bits of the shared secret."""
    low, high = present.key_halves(shared_x)
    return present.encrypt_blocks(SEED_MASK_PLAINTEXTS, (low, low, high))


def write_seed(destination: bytearray | memoryview, public_key: bytes, pre_seed: int) -> None:
    """SeedTransform: write the 60-byte seed field (masked pre-seed, ephemeral x, blinding bytes)."""
    if len(destination) < SEED_LENGTH:
        raise ValueError(f"destination too small ({len(destination)}, need {SEED_LENGTH})")
    if len(public_key) < PUBLIC_KEY_LENGTH:
        raise ValueError(f"public key too small ({len(public_key)}, need {PUBLIC_KEY_LENGTH})")

    blinding = os.urandom(0x14)  # Only blinds HarpoS7's Transform7 encoding, but is still sent.
    ephemeral = 0
    while ephemeral == 0:
        scalar = curve.ladder_scalar(os.urandom(0x14))
        ephemeral = curve.x_multiply(scalar, curve.GENERATOR_X)
    shared = curve.x_multiply(scalar, int.from_bytes(public_key[:0x14], "little"))

    destination[:0x14] = (pre_seed ^ seed_mask(shared)).to_bytes(0x14, "little")
    destination[0x14:0x28] = ephemeral.to_bytes(0x14, "little")
    destination[0x28:0x3C] = blinding


def derive_keys(pre_seed: int) -> BlobKeys:
    """KeyDerivationTransform: three blocks under the pre-seed's low 80 bits, three under its high 80 bits."""
    low, high = present.key_halves(pre_seed)
    derived = struct.pack(
        "<6Q", *(present.encrypt(block, low if index < 3 else high) for index, block in enumerate(KEY_PLAINTEXTS))
    )
    return BlobKeys(derived[:16], derived[16:32], int.from_bytes(derived[32:48], "little"))
