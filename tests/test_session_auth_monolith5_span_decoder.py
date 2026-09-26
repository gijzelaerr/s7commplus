"""Exact additive identity, independently checked against generated streams."""

from __future__ import annotations

import itertools
import random
import struct
from pathlib import Path

import pytest

from s7commplus.session_auth.family0._generated import monolith5
from tools.recover_monolith5_span_decoder import MODULUS, P, combined_payload, decode_span, recover
from tools.transform7_setup_merge import decode_payload


def generated_sum(source: list[int]) -> int:
    output = bytearray(48)
    monolith5.execute(output, struct.pack("<54I", *source))
    return (decode_payload(output[:24]) + decode_payload(output[24:])) % MODULUS


def test_recovered_coefficients_and_boundary_identity() -> None:
    model = recover()
    assert len(model.terms) == 169
    assert model.constant == 51698806077986350461380052348415547004375582574557
    assert model.boundary_weight == -P
    for bits in itertools.product((0, 1), repeat=3):
        parity = sum(bits) % 2
        majority = int(sum(bits) >= 2)
        unequal = int(len(set(bits)) != 1)
        assert parity + 2 * majority == sum(bits)
        assert 2 * int(any(bits)) - unequal == sum(bits) - majority


def test_additive_identity_matches_known_answer() -> None:
    directory = Path(__file__).parent / "fixtures/family0/monoliths"
    source = list(struct.unpack("<54I", (directory / "monolith5-src.bin").read_bytes()))
    output = (directory / "monolith5-dst.bin").read_bytes()
    assert combined_payload(source) == (decode_payload(output[:24]) + decode_payload(output[24:])) % MODULUS


def test_additive_identity_matches_generated_arbitrary_words() -> None:
    rng = random.Random(0x5DEC0DE)
    sources = [[word] * 54 for word in (0, 0xFFFFFFFF, 0xAAAAAAAA, 0x55555555)]
    sources.extend([rng.getrandbits(32) for _ in range(54)] for _ in range(1000))
    for word in range(54):
        for bit in (0, 1, 2, 29, 30, 31):
            source = [0] * 54
            source[word] = 1 << bit
            sources.append(source)
    for source in sources:
        assert combined_payload(source) == generated_sum(source)


def test_boundary_correction_and_span_symmetry() -> None:
    model = recover()
    for bits in itertools.product((0, 1), repeat=3):
        spans = [[0, bit, 0] + [0] * 15 for bit in bits]
        expected = (model.constant + sum(map(decode_span, spans)) - P * int(sum(bits) >= 2)) % MODULUS
        for permutation in itertools.permutations(spans):
            source = [word for span in permutation for word in span]
            assert combined_payload(source) == expected == generated_sum(source)


@pytest.mark.parametrize("span", ([0] * 17, [0] * 19, [-1] + [0] * 17, [1 << 32] + [0] * 17))
def test_decoder_rejects_invalid_spans(span: list[int]) -> None:
    with pytest.raises(ValueError, match="eighteen uint32"):
        decode_span(span)


def test_identity_rejects_invalid_sources() -> None:
    with pytest.raises(ValueError, match="three encoded spans"):
        combined_payload([0] * 53)
    with pytest.raises(ValueError, match="eighteen uint32"):
        combined_payload([0] * 53 + [-1])
