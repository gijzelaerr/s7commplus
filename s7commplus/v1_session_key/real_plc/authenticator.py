"""RealPlcAuthenticator — builds the 180-byte SecurityKeyEncryptedKey blob.

Combines the seed and keys from ``seed``, the ``checksum`` field and AES-ECB
into the encrypted authentication blob for S7-1200/1500 PLCs.

The blob encryption is GCM-like: AES-ECB of a counter masks the challenge and
key2, and the counter advances by a multiplication by x in GCM's field. A
GHASH-style checksum over the ciphertext, ``c = (c ^ block) * H`` in
``checksum``'s field, is encrypted under a second key.

Manual port of ``HarpoS7.Family0.Auth.RealPlcAuthenticator``.
"""

from __future__ import annotations

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from ..blob_metadata import write_metadata
from ..keys import KeyFamily
from . import checksum, seed


class RealPlcAuthenticator:
    def __init__(
        self,
        key1: bytes | None = None,
        key2: bytes | None = None,
    ) -> None:
        # Order must match C#: key2, key1, IV (for deterministic test vectors)
        if key2 is not None:
            self._key2 = bytearray(key2)
        else:
            self._key2 = bytearray(os.urandom(24))

        self._key1 = bytearray(key1 if key1 is not None else os.urandom(24))
        self._iv = bytearray(os.urandom(16))

        self._hash_key = 0
        self._checksum = 0
        self._challenge_key = bytearray(16)
        self._checksum_key = bytearray(16)
        self._encrypted_bytes = 0

    @property
    def key2_leftover_length(self) -> int:
        return len(self._key2) % 16

    def write_metadata(
        self,
        blob: bytearray | memoryview,
        public_key: bytes,
        family: KeyFamily,
    ) -> int:
        if family not in (KeyFamily.S7_1200, KeyFamily.S7_1500):
            raise ValueError(f"{family.name} is not supported by this authenticator")
        return write_metadata(blob, public_key, bytes(self._key2), family)

    def write_seed(self, blob: bytearray | memoryview, public_key: bytes) -> int:
        pre_seed = seed.pre_seed(bytes(self._key1))
        seed.write_seed(blob, public_key, pre_seed)

        keys = seed.derive_keys(pre_seed)
        self._challenge_key[:] = keys.challenge_key
        self._checksum_key[:] = keys.checksum_key
        self._hash_key = keys.hash_key
        self._checksum = checksum.multiply(int.from_bytes(self._iv, "little"), self._hash_key)

        return seed.SEED_LENGTH

    def encrypt_full_blocks(self, blob: bytearray | memoryview, challenge: bytes) -> int:
        offset = 0

        # Copy starting IV
        blob[offset : offset + 16] = self._iv
        offset += 16

        # Encrypt 16 bytes of challenge (skip first 2)
        ct_block = self._aes_ecb_encrypt(bytes(self._iv))
        ct_block = _xor_bytes(ct_block, challenge[2:18])
        blob[offset : offset + 16] = ct_block
        offset += 16
        self._encrypted_bytes += 16

        self._advance_counter()
        self._update_checksum(ct_block)

        # Encrypt full 16-byte blocks of key2
        for i in range(len(self._key2) // 16):
            ct_block = self._aes_ecb_encrypt(bytes(self._iv))
            ct_block = _xor_bytes(ct_block, bytes(self._key2[i * 16 : (i + 1) * 16]))
            blob[offset : offset + 16] = ct_block
            offset += 16
            self._encrypted_bytes += 16

            self._advance_counter()
            self._update_checksum(ct_block)

        return offset

    def encrypt_final_block(self, blob: bytearray | memoryview) -> int:
        leftover = self.key2_leftover_length
        leftover_start = len(self._key2) - leftover

        ct_block = bytearray(self._aes_ecb_encrypt(bytes(self._iv)))
        ct_block = bytearray(
            _xor_bytes(bytes(ct_block[:leftover]), bytes(self._key2[leftover_start : leftover_start + leftover]))
        )

        blob[:leftover] = ct_block[:leftover]
        self._encrypted_bytes += leftover
        offset = leftover

        # Pad the rest of the block with zeros for checksum
        ct_padded = bytearray(16)
        ct_padded[:leftover] = ct_block[:leftover]

        self._update_checksum(bytes(ct_padded))

        # Final checksum calculation: fold in the length (little-endian dword 3)
        final_checksum = checksum.multiply(self._checksum ^ self._encrypted_bytes << 96, self._hash_key)

        # Encrypt checksum with checksum encryption key
        cipher = Cipher(algorithms.AES(bytes(self._checksum_key)), modes.ECB())
        enc = cipher.encryptor()
        encrypted_checksum = enc.update(final_checksum.to_bytes(16, "little")) + enc.finalize()

        blob[offset : offset + 16] = encrypted_checksum
        offset += 16

        return offset

    def extract_key2(self) -> bytes:
        return bytes(self._key2)

    def _aes_ecb_encrypt(self, plaintext: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(bytes(self._challenge_key)), modes.ECB())
        enc = cipher.encryptor()
        return bytes(enc.update(plaintext[:16]) + enc.finalize())

    def _advance_counter(self) -> None:
        """Multiply the little-endian counter by x in GCM's bit-reflected field.

        HarpoS7 calls this ``BigIntOperations.RotateLeft31``.
        """
        value = int.from_bytes(self._iv, "little")
        self._iv[:] = (value >> 1 ^ (0xE1 << 120 if value & 1 else 0)).to_bytes(16, "little")

    def _update_checksum(self, ct_block: bytes) -> None:
        block = int.from_bytes(ct_block[:16], "little")
        self._checksum = checksum.multiply(self._checksum ^ block, self._hash_key)


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))
