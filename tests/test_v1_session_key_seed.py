"""``present`` and ``seed`` match the generated Monolith9/Monolith10, the encoded HarpoS7 ports and upstream vectors."""

from __future__ import annotations

import os
import random
import struct
from pathlib import Path
from unittest import mock

import pytest

from s7commplus.v1_session_key.real_plc import authenticator, present, seed
from old.family0 import checksum_transform, encoding, lut_generator, monolith11_compact, transform7_compact, transform13
from old.family0 import pre_seed_transform as old_pre_seed_transform
from old.family0 import key_derivation_transform as old_key_derivation_transform
from old.family0 import seed_transform as old_seed_transform
from old.family0._generated import monolith2, monolith8, monolith9, monolith10
from old.family0._generated.data import SHARED_DATA, TRANSFORM1_DATA, TRANSFORM7_DATA
from s7commplus.v1_session_key.keys import KeyFamily, fingerprints_for_family, get_public_key
from s7commplus.v1_session_key.handshake import authenticate_real_plc
from tools.recover_monolith4_span_identity import normalized_terms
from tools.recover_monolith5_span_decoder import local_gate

_FIXTURES = Path(__file__).parent / "fixtures" / "family0" / "transforms"
_SHARED = struct.unpack("<36I", SHARED_DATA)


def _derived_bytes(pre_seed: int) -> bytes:
    keys = seed.derive_keys(pre_seed)
    return keys.challenge_key + keys.checksum_key + keys.hash_key.to_bytes(16, "little")


def test_inlined_plaintexts_are_the_shared_data_blocks() -> None:
    blocks = tuple(_SHARED[2 * block] | _SHARED[2 * block + 1] << 32 for block in range(9))
    assert seed.KEY_PLAINTEXTS == blocks[:6]
    assert seed.SEED_MASK_PLAINTEXTS == blocks[6:]


def _standard_round_keys(key: int) -> list[int]:
    keys = []
    for counter in range(1, 33):
        keys.append(key >> 16)
        key = ((key << 61) | (key >> 19)) & ((1 << 80) - 1)
        key = (present.SBOX[key >> 76] << 76) | (key & ((1 << 76) - 1))
        key ^= counter << 15
    return keys


@pytest.mark.parametrize(
    ("plaintext", "key", "ciphertext"),
    [
        (0, 0, 0x5579C1387B228445),
        (0, (1 << 80) - 1, 0xE72C46C0F5945049),
        ((1 << 64) - 1, 0, 0xA112FFC72F68417B),
        ((1 << 64) - 1, (1 << 80) - 1, 0x3333DCD3213210D2),
    ],
)
def test_rounds_reproduce_the_published_present80_vectors(plaintext: int, key: int, ciphertext: int) -> None:
    assert present.present_rounds(plaintext, _standard_round_keys(key)) == ciphertext


def _monolith10_table(flags: tuple[int, int, int], encoded: bytes) -> bytearray:
    table = bytearray(0xC5 * 4)
    monolith10.execute(table, struct.pack("<3I", *flags) + encoded[:60] + bytes(24))
    return table


def _monolith9(table: bytearray, block: int, postfix: tuple[int, ...]) -> bytes:
    struct.pack_into("<Q3I", table, 0xC0 * 4, block, *postfix)
    output = bytearray(24)
    monolith9.execute(output, bytes(table))
    return bytes(output)


def _tagged(index: int) -> tuple[int, tuple[int, ...]]:
    """SHARED_DATA block ``index`` and the postfix tag KeyDerivationTransform pairs with it."""
    return _SHARED[2 * index] | _SHARED[2 * index + 1] << 32, _SHARED[0x12 + 3 * index : 0x15 + 3 * index]


def _span(rng: random.Random) -> bytes:
    """A Transform7/Monolith1 span as seed_transform produces one."""
    span = bytearray(transform7_compact.DESTINATION_SIZE)
    transform7_compact.execute(span, bytearray(rng.randbytes(20)), bytearray(rng.randbytes(20)), rng.randbytes(40))
    old_seed_transform._monolith1_loop(span)
    return bytes(span)


def _monolith8(span: bytes) -> bytes:
    encoded = bytearray(60)
    monolith8.execute(encoded, span)
    return bytes(encoded)


def test_monolith9_with_a_tagged_postfix_is_the_cipher_under_the_monolith10_key() -> None:
    rng = random.Random(1300)
    for flags, half in (((0xFFFFFFFF, 0xFFFFFFFF, 0x0000FFFF), 0), ((0, 0, 0), 1)):
        span = _span(rng)
        table = _monolith10_table(flags, _monolith8(span))
        key = present.key_halves(encoding.span_value(span))[half]
        for index in range(6):
            block, tag = _tagged(index)
            words = struct.unpack("<6I", _monolith9(table, block, tag))
            assert words[0] | words[1] << 32 == present.encrypt(block, key)


def test_monolith9_ignores_any_other_postfix() -> None:
    table = _monolith10_table((0xFFFFFFFF, 0xFFFFFFFF, 0x0000FFFF), _monolith8(_span(random.Random(1301))))
    block, tag = _tagged(0)
    others = ((0, 0, 0), (tag[0] ^ 1, tag[1], tag[2]), (tag[0], tag[1], tag[2] ^ 1 << 31))
    untagged = {_monolith9(table, block, postfix) for postfix in others}
    assert len(untagged) == 1
    assert _monolith9(table, block, tag) not in untagged


def test_decode_reads_monolith8_encodings() -> None:
    rng = random.Random(1302)
    for _ in range(10):
        span = _span(rng)
        assert encoding.decode(_monolith8(span)) == encoding.span_value(span)


def test_span_value_matches_the_recovered_gate_decoder() -> None:
    boundary, terms = normalized_terms()
    rng = random.Random(1303)
    for _ in range(20):
        span = _span(rng)
        words = struct.unpack("<18I", span)
        payload = sum((local_gate(term, words) ^ int(term.weight < 0)) << bit for bit, term in enumerate(terms))
        assert encoding.span_value(span) == (2 * payload + local_gate(boundary, words)) % encoding.MODULUS


def test_span_value_rejects_short_spans() -> None:
    with pytest.raises(ValueError, match="span too small"):
        encoding.span_value(bytes(71))


def test_transform13_matches_the_handwritten_port() -> None:
    rng = random.Random(1304)
    for _ in range(8):
        span = _span(rng)
        output = bytearray(transform13.DESTINATION_SIZE)
        transform13.execute(output, _monolith8(span))
        assert encoding.decode(output) == seed.seed_mask(encoding.span_value(span))


def test_transform13_upstream_vector() -> None:
    source = (_FIXTURES / "transform13-src.bin").read_bytes()
    expected = (_FIXTURES / "transform13-dst.bin").read_bytes()
    assert seed.seed_mask(encoding.decode(source)) == encoding.decode(expected)


def test_pre_seed_key_is_the_transform1_data_round_key_layout() -> None:
    table = bytearray(0xC5 * 4)
    table[: len(TRANSFORM1_DATA)] = TRANSFORM1_DATA
    block, tag = _tagged(0)
    words = struct.unpack("<6I", _monolith9(table, block, tag))
    assert words[0] | words[1] << 32 == present.encrypt(block, seed.PRE_SEED_KEY)


def test_pre_seed_value_matches_the_handwritten_port() -> None:
    rng = random.Random(1305)
    sources = [(_FIXTURES / "transform1-src.bin").read_bytes(), *(rng.randbytes(24) for _ in range(20))]
    for source in sources:
        encoded = bytearray(old_pre_seed_transform.DESTINATION_SIZE)
        old_pre_seed_transform.execute(encoded, source)
        assert seed.pre_seed(source) == encoding.decode(encoded)
    expected = (_FIXTURES / "transform1-dst.bin").read_bytes()
    assert seed.pre_seed(sources[0]) == encoding.decode(expected)


def test_pre_seed_value_rejects_short_sources() -> None:
    with pytest.raises(ValueError, match="key1 too small"):
        seed.pre_seed(bytes(23))


def test_key_derivation_value_matches_the_handwritten_port() -> None:
    rng = random.Random(1306)
    sources = [(_FIXTURES / "transform2-src.bin").read_bytes()]
    for _ in range(6):
        encoded = bytearray(old_pre_seed_transform.DESTINATION_SIZE)
        old_pre_seed_transform.execute(encoded, rng.randbytes(24))
        sources.append(bytes(encoded))
    for source in sources:
        expected = bytearray(old_key_derivation_transform.DESTINATION_SIZE)
        old_key_derivation_transform.execute(expected, source)
        assert _derived_bytes(encoding.decode(source)) == bytes(expected)
    upstream = (_FIXTURES / "transform2-dst.bin").read_bytes()
    assert _derived_bytes(encoding.decode(sources[0])) == upstream


def _generated_seed_transform(destination: bytearray, public_key: bytes, transform1: bytes) -> None:
    """``old_seed_transform.execute`` as it ran through the generated Monolith8/Transform13/Monolith11 chain."""
    prng1 = bytearray(os.urandom(0x14))
    span = bytearray(transform7_compact.DESTINATION_SIZE)
    work = bytearray(20)
    while True:
        prng2 = bytearray(os.urandom(0x14))
        transform7_compact.execute(span, prng1, prng2, TRANSFORM7_DATA[0xD8:])
        old_seed_transform._monolith1_loop(span)
        monolith2.execute(work, bytes(span))
        if any(work):
            break
    destination[0x14:0x28] = work
    destination[0x28:0x3C] = prng1
    transform7_compact.execute(span, prng1, prng2, public_key)
    old_seed_transform._monolith1_loop(span)
    m8_buf = bytearray(20 + 72)
    monolith8.execute(memoryview(m8_buf)[20:], bytes(span))  # type: ignore[arg-type]
    m11_src = bytearray(120)
    transform13.execute(memoryview(m11_src)[0x3C:], bytes(m8_buf[20:]))  # type: ignore[arg-type]
    m11_src[:0x3C] = transform1[:0x3C]
    monolith11_compact.execute(m8_buf, bytes(m11_src))
    destination[:0x14] = m8_buf[:0x14]


def test_seed_transform_matches_the_generated_chain() -> None:
    for trial in range(6):
        rng = random.Random(1307 + trial)
        public_key = rng.randbytes(40)
        transform1 = bytearray(old_pre_seed_transform.DESTINATION_SIZE)
        old_pre_seed_transform.execute(transform1, rng.randbytes(24))
        outputs = []
        for implementation in (old_seed_transform.execute, _generated_seed_transform):
            entropy = random.Random(2307 + trial)
            destination = bytearray(seed.SEED_LENGTH)
            with mock.patch("os.urandom", entropy.randbytes):
                implementation(destination, public_key, bytes(transform1))
            outputs.append(bytes(destination))
        assert outputs[0] == outputs[1]


def _encoded_write_seed(self: authenticator.RealPlcAuthenticator, blob: bytearray | memoryview, public_key: bytes) -> int:
    """``write_seed`` passing encoded buffers through the handwritten ports, as before the value migration."""
    transform1 = bytearray(old_pre_seed_transform.DESTINATION_SIZE)
    old_pre_seed_transform.execute(transform1, bytes(self._key1))
    old_seed_transform.execute(blob, public_key, bytes(transform1))
    derived = bytearray(old_key_derivation_transform.DESTINATION_SIZE)
    old_key_derivation_transform.execute(derived, bytes(transform1))
    self._challenge_key[:] = derived[:16]
    self._checksum_key[:] = derived[16:32]
    lookup_table, checksum = bytearray(lut_generator.DESTINATION_SIZE), bytearray(16)
    lut_generator.execute(lookup_table, bytes(derived[32:]))
    checksum_transform.execute(checksum, bytes(self._iv), bytes(lookup_table))
    self._hash_key = int.from_bytes(derived[32:48], "little")
    self._checksum = int.from_bytes(checksum, "little")
    return seed.SEED_LENGTH


@pytest.mark.parametrize("family", [KeyFamily.S7_1500, KeyFamily.S7_1200])
def test_authentication_matches_the_encoded_transform_chain(family: KeyFamily) -> None:
    public_key = get_public_key(fingerprints_for_family(family)[0])
    for trial in range(2):
        challenge = random.Random(1308 + trial).randbytes(20)
        results = []
        for write_seed in (authenticator.RealPlcAuthenticator.write_seed, _encoded_write_seed):
            entropy = random.Random(2308 + trial)
            with (
                mock.patch("os.urandom", entropy.randbytes),
                mock.patch.object(authenticator.RealPlcAuthenticator, "write_seed", write_seed),
            ):
                results.append(authenticate_real_plc(challenge, public_key, family))
        assert results[0] == results[1]
