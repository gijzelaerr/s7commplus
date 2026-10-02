"""AES-128 in ECB mode, the block cipher under ``aes_gcm``.

HarpoS7's ``HarpoAes`` is a thin .NET-Framework wrapper around its
built-in AES, configured for 128-bit keys, 128-bit blocks, ECB mode,
zero padding. This module wraps ``cryptography``, the package's only
runtime dependency, the same way. HarpoS7 uses it only as the block cipher
of ``HarpoAesCtr`` (``aes_gcm.AesGcm24`` here).
"""

from __future__ import annotations

#: Block and key length in bytes of AES-128.
AES_BLOCK_SIZE = 16
AES_KEY_LENGTH = 16


class AesEcb:
    """AES-128-ECB bound to a 16-byte key.

    The cipher object is built once, and each ``encrypt`` call uses a fresh
    encryptor.

    Args:
        key: Exactly 16 bytes.

    Raises:
        ValueError: If the key is not 16 bytes.
    """

    def __init__(self, key: bytes) -> None:
        if len(key) != AES_KEY_LENGTH:
            raise ValueError(f"key must be {AES_KEY_LENGTH} bytes, got {len(key)}")

        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        self._cipher = Cipher(algorithms.AES(key), modes.ECB())

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt one or more 16-byte blocks, each independently.

        Raises:
            ValueError: If the plaintext length isn't a multiple of 16.
        """
        if len(plaintext) % AES_BLOCK_SIZE != 0:
            raise ValueError(f"plaintext must be a multiple of {AES_BLOCK_SIZE} bytes, got {len(plaintext)}")
        encryptor = self._cipher.encryptor()
        result: bytes = encryptor.update(plaintext) + encryptor.finalize()
        return result
