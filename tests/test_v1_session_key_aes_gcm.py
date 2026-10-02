"""Tests for AesGcm24, AES-GCM with a 24-bit counter (HarpoS7's HarpoAesCtr).

Vectors reproduced from ``HarpoS7.Tests/Aes/HarpoAesCtrTests.cs``, plus
differential tests against ``cryptography``'s AES-GCM.
"""

from __future__ import annotations

import random
import pytest

from s7commplus.v1_session_key.aes_gcm import AesGcm24

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    _has_cryptography = True
except ImportError:
    _has_cryptography = False


_KEY = bytes.fromhex("4E001016DB625DCCE9105BDCD8A1B42C")


@pytest.mark.skipif(not _has_cryptography, reason="requires cryptography package")
class TestStart:
    def test_counter_after_start(self) -> None:
        # HarpoAesCtrTests.TestInit — Init with IV = 0xCC * 16 must
        # produce this specific 16-byte counter value.
        cipher = AesGcm24(_KEY)
        cipher.start(b"\xcc" * 16)
        assert cipher.counter == bytes.fromhex("D478DE8B1A40ED2F89F80166EEFCD513")


@pytest.mark.skipif(not _has_cryptography, reason="requires cryptography package")
class TestEncrypt:
    def test_two_calls_back_to_back(self) -> None:
        # HarpoAesCtrTests.TestEncrypt2Times — encrypt 16 bytes then
        # 24 bytes back-to-back; both ciphertexts must match.
        cipher = AesGcm24(_KEY)
        cipher.start(b"\xcc" * 16)

        data1 = bytes.fromhex("B1B3D9484C6E4240403F63C6B5012CC5")
        ct1 = cipher.encrypt(data1)
        assert ct1 == bytes.fromhex("CDF986A8C7975D5390535C1D7954FA7F")

        data2 = b"\xdd" * 24
        ct2 = cipher.encrypt(data2)
        assert ct2 == bytes.fromhex("33FF1BD50184486B897ADB64154B785FAB877A290783240A")

    def test_empty_plaintext(self) -> None:
        # Sanity: encrypting nothing returns nothing and doesn't
        # advance state.
        cipher = AesGcm24(_KEY)
        cipher.start(b"\xcc" * 16)
        before = cipher.counter
        assert cipher.encrypt(b"") == b""
        assert cipher.counter == before


@pytest.mark.skipif(not _has_cryptography, reason="requires cryptography package")
class TestTag:
    def test_harpos7_vector(self) -> None:
        # HarpoAesCtrTests.CalculateChecksumTest — mocks the internal
        # state directly, then verifies the finalised tag. The C# test
        # sets HarpoS7's fields by reflection: _var2 (ciphertext length)
        # is _length, _var1 (associated-data length, always 0) no longer
        # exists, the LUT is _hash_table, _aes3 is _ghash and
        # _iv_extension is _j0. Its _aes2 value is overwritten before use.
        cipher = AesGcm24(bytes.fromhex("43950F7B8B896E30457824DC8A591E32"))
        cipher._length = 0x10

        # The 4096-byte fixture vendored from the C# test's _mockChecksumLut literal.
        from pathlib import Path

        fixture = Path(__file__).parent / "fixtures" / "harpo_aes_ctr_mock_checksum_lut.bin"
        cipher._hash_table[:] = fixture.read_bytes()

        cipher._ghash[:] = bytes.fromhex("738FA8A07EF0893A97CBF681250AD2FA")
        cipher._j0[:] = bytes.fromhex("585CE8585DF132FA4C7FD9BECEB97461")

        checksum = cipher.tag()
        assert checksum == bytes.fromhex("5A948DB51DC34FF25808ED3ABE15EB12")

    def test_invalid_length_too_large(self) -> None:
        cipher = AesGcm24(_KEY)
        cipher.start(b"\xcc" * 16)
        with pytest.raises(ValueError, match="length must be 1..16"):
            cipher.tag(17)

    def test_invalid_length_zero(self) -> None:
        cipher = AesGcm24(_KEY)
        cipher.start(b"\xcc" * 16)
        with pytest.raises(ValueError, match="length must be 1..16"):
            cipher.tag(0)


@pytest.mark.skipif(not _has_cryptography, reason="requires cryptography package")
class TestStartGuardClauses:
    def test_empty_iv_rejected(self) -> None:
        cipher = AesGcm24(_KEY)
        with pytest.raises(ValueError, match="iv must not be empty"):
            cipher.start(b"")

    def test_12_byte_iv_not_implemented(self) -> None:
        cipher = AesGcm24(_KEY)
        with pytest.raises(NotImplementedError, match="12-byte"):
            cipher.start(b"\x00" * 12)

    def test_unaligned_iv_not_implemented(self) -> None:
        cipher = AesGcm24(_KEY)
        with pytest.raises(NotImplementedError, match="non-multiple-of-16"):
            cipher.start(b"\x00" * 17)


@pytest.mark.skipif(not _has_cryptography, reason="requires cryptography package")
class TestIsAesGcm:
    """AesGcm24 is AES-GCM without associated data, except for its 24-bit counter."""

    def test_ciphertext_and_tag_match_aes_gcm(self) -> None:
        rng = random.Random(4802)
        for _ in range(30):
            key, iv = rng.randbytes(16), rng.randbytes(16 * rng.randint(1, 3))
            parts = [rng.randbytes(rng.randint(0, 40)) for _ in range(rng.randint(1, 3))]
            cipher = AesGcm24(key)
            cipher.start(iv)
            ciphertext = b"".join(cipher.encrypt(part) for part in parts)
            reference = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
            assert ciphertext == reference.update(b"".join(parts))
            reference.finalize()
            assert cipher.tag() == reference.tag

    def test_counter_increment_wraps_at_24_bits_unlike_gcm(self) -> None:
        # GCM's inc32 would carry into byte 12; HarpoS7 (and this port) only increment bytes 13..15.
        cipher = AesGcm24(_KEY)
        cipher.start(bytes(16))
        cipher._counter[12:16] = b"\x00\xff\xff\xff"
        keystream = cipher.encrypt(bytes(16))
        counter = cipher.counter[:12] + b"\x00\x00\x00\x00"
        ecb = Cipher(algorithms.AES(_KEY), modes.ECB()).encryptor()
        assert keystream == ecb.update(counter)
