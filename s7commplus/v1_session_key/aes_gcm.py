"""AES-GCM encryption with a 24-bit counter (HarpoS7's HarpoAesCtr).

This is AES-GCM (NIST SP 800-38D) without associated data:

- ``start`` sets ``H = AES(key, 0^128)``, builds its GHASH table
  (``ghash``), and derives the pre-counter block
  ``J0 = GHASH(iv || 0^64 || [8 * len(iv)]_64)``, GCM's rule for IVs that
  are not 96 bits long.
- ``encrypt`` XORs the plaintext with ``AES(key, counter)`` blocks,
  incrementing the counter before each block, and folds the ciphertext into
  the running GHASH. Calls may split blocks anywhere.
- ``tag`` folds in the length block ``0^64 || [8 * len(C)]_64`` and returns
  the GCM tag ``AES(key, J0) ^ GHASH``.

Tests match ciphertexts and tags against ``cryptography``'s AES-GCM. The one
difference is the counter: HarpoS7 increments only bytes 13..15, while GCM's
inc32 also carries into byte 12, so the two diverge after the low 24 bits of
the counter wrap. That is why the class is called ``AesGcm24``. HarpoS7
rejects 12-byte IVs and IVs that are not a multiple of 16 bytes; so does this
module.

Ported from HarpoS7 (MIT) — ``HarpoS7.Aes.HarpoAesCtr``, whose ``Init``,
``EncryptCtr`` and ``CalculateChecksum`` are ``start``, ``encrypt`` and
``tag``.
"""

from __future__ import annotations

from .aes_ecb import AES_BLOCK_SIZE, AesEcb
from .ghash import TABLE_SIZE, multiplication_table, multiply


class AesGcm24:
    """AES-GCM encryption, without associated data and with a 24-bit counter, under a 16-byte key.

    Call ``start(iv)``, then ``encrypt`` as often as needed, then ``tag``
    once.
    """

    def __init__(self, key: bytes) -> None:
        self._aes = AesEcb(key)
        self._hash_table = bytearray(TABLE_SIZE)  # GHASH table for H
        self._j0 = bytearray(AES_BLOCK_SIZE)  # pre-counter block; its encryption masks the tag
        self._counter = bytearray(AES_BLOCK_SIZE)
        self._keystream = bytearray(AES_BLOCK_SIZE)  # AES(counter) for the current block
        self._ghash = bytearray(AES_BLOCK_SIZE)  # running GHASH of the ciphertext
        self._length = 0  # ciphertext bytes produced since start

    @property
    def counter(self) -> bytes:
        """The current counter block."""
        return bytes(self._counter)

    def _ghash_block(self) -> None:
        self._ghash[:] = multiply(bytes(self._ghash), bytes(self._hash_table))

    def start(self, iv: bytes) -> None:
        """Start a message under ``iv``, whose length must be a non-zero multiple of 16.

        Raises:
            ValueError: For an empty IV.
            NotImplementedError: For the IV lengths HarpoS7 does not implement.
        """
        if len(iv) == 0:
            raise ValueError("iv must not be empty")
        if len(iv) == 0xC:
            raise NotImplementedError("12-byte IV path not implemented")
        if len(iv) % AES_BLOCK_SIZE != 0:
            raise NotImplementedError("non-multiple-of-16 IV tail not implemented")

        self._hash_table[:] = multiplication_table(self._aes.encrypt(bytes(AES_BLOCK_SIZE)))

        self._ghash[:] = bytes(AES_BLOCK_SIZE)
        for offset in range(0, len(iv), AES_BLOCK_SIZE):
            self._fold(iv[offset : offset + AES_BLOCK_SIZE])
        self._fold((8 * len(iv)).to_bytes(AES_BLOCK_SIZE, "big"))
        self._j0[:] = self._ghash
        self._counter[:] = self._j0

        self._ghash[:] = bytes(AES_BLOCK_SIZE)
        self._length = 0

    def _fold(self, block: bytes) -> None:
        """``ghash = (ghash ^ block) * H`` for a full block."""
        for index, byte in enumerate(block):
            self._ghash[index] ^= byte
        self._ghash_block()

    def _increment_counter(self) -> None:
        """Add 1 to the 24-bit big-endian counter in bytes 13..15, wrapping without carry."""
        value = (int.from_bytes(self._counter[13:16], "big") + 1) & 0xFFFFFF
        self._counter[13:16] = value.to_bytes(3, "big")

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt ``plaintext`` (any length), continuing the keystream and GHASH of earlier calls."""
        out = bytearray(len(plaintext))
        for index, byte in enumerate(plaintext):
            position = self._length % AES_BLOCK_SIZE
            if position == 0:
                self._increment_counter()
                self._keystream[:] = self._aes.encrypt(bytes(self._counter))
            out[index] = byte ^ self._keystream[position]
            self._ghash[position] ^= out[index]
            self._length += 1
            if position == AES_BLOCK_SIZE - 1:
                self._ghash_block()
        return bytes(out)

    def tag(self, length: int = AES_BLOCK_SIZE) -> bytes:
        """The first ``length`` bytes (1..16) of the GCM tag for everything encrypted since ``start``."""
        if length < 1 or length > AES_BLOCK_SIZE:
            raise ValueError(f"length must be 1..{AES_BLOCK_SIZE}, got {length}")

        if self._length % AES_BLOCK_SIZE:
            self._ghash_block()  # the zero-padded final partial block
        self._fold((8 * self._length).to_bytes(AES_BLOCK_SIZE, "big"))  # no associated data
        mask = self._aes.encrypt(bytes(self._j0))
        return bytes(tag ^ m for tag, m in zip(self._ghash[:length], mask))
