"""Decoder normalization, bounded source proof, and full candidate controls."""

from __future__ import annotations

import itertools
import random
import struct

import pytest

from s7commplus.session_auth.family0 import transform7
from tools.recover_monolith4_span_identity import (
    candidate_add,
    normalized_combined,
    normalized_span,
    normalized_terms,
    prove_prefix,
)
from tools.recover_monolith5_span_decoder import MODULUS, P, combined_payload, local_gate, recover
from tools.trace_transform7_setup_shadows import span_shadow


def test_source_proves_boundary_and_eight_payload_bits() -> None:
    proof = prove_prefix()
    assert proof["proved_boundary_bits"] == 1
    assert proof["proved_payload_prefix_bits"] == 8
    assert proof["overflow_residue"] == 12032


def test_normalization_is_exact_before_any_modular_reduction() -> None:
    boundary, terms = normalized_terms()
    assert boundary.weight == (P + 1) // 2
    offset = sum(term.weight for term in terms if term.weight < 0)
    assert recover().constant == -3 * offset
    rng = random.Random(0x4DEC)
    for _ in range(100):
        words = [rng.getrandbits(32) for _ in range(18)]
        payload, bit = normalized_span(words)
        signed = sum(term.weight * local_gate(term, words) for term in recover().terms)
        assert signed - offset == payload + boundary.weight * bit
        assert span_shadow(struct.pack("<18I", *words)) == (payload + boundary.weight * bit) % P


def test_normalized_monolith5_identity_has_no_fitted_constant() -> None:
    rng = random.Random(0x45ADD)
    for _ in range(1000):
        source = [rng.getrandbits(32) for _ in range(54)]
        assert normalized_combined(source) == combined_payload(source)
    half = (P + 1) // 2
    for bits in itertools.product((0, 1), repeat=3):
        majority = int(sum(bits) >= 2)
        assert half * sum(bits) - P * majority == half * (sum(bits) % 2) + majority


def test_full_candidate_and_carry_correction_on_arbitrary_raw_spans() -> None:
    rng = random.Random(0xBAD4)
    overflows = set()
    for _ in range(1000):
        left, right = rng.randbytes(72), rng.randbytes(72)
        predicted, boundary, overflow = candidate_add(left, right)
        output = bytearray(72)
        transform7.monolith4_with_copy(output, left, right)
        assert normalized_span(struct.unpack("<18I", output)) == (predicted, boundary)
        delta = (span_shadow(bytes(output)) - span_shadow(left) - span_shadow(right)) % P
        assert delta == (-MODULUS * overflow) % P
        overflows.add(overflow)
    assert overflows == {False, True}


def test_exact_signed_decoder_addition_retains_boundary_and_overflow_corrections() -> None:
    model = recover()
    offset = sum(term.weight for term in model.terms if term.weight < 0)

    def signed(span: bytes) -> int:
        words = struct.unpack("<18I", span)
        return sum(term.weight * local_gate(term, words) for term in model.terms)

    rng = random.Random(0x4DADD)
    branches = set()
    for _ in range(128):
        left, right = rng.randbytes(72), rng.randbytes(72)
        _, h0 = normalized_span(struct.unpack("<18I", left))
        _, h1 = normalized_span(struct.unpack("<18I", right))
        _, _, overflow = candidate_add(left, right)
        output = bytearray(72)
        transform7.monolith4_with_copy(output, left, right)
        # Exact integers, not just residues modulo p or 2^168.
        assert signed(bytes(output)) == signed(left) + signed(right) - offset - P * (h0 & h1) - MODULUS * overflow
        branches.add((h0, h1, overflow))
    assert branches == set(itertools.product((0, 1), (0, 1), (False, True)))


@pytest.mark.parametrize("bits", (-1, 169))
def test_proof_rejects_invalid_prefix(bits: int) -> None:
    with pytest.raises(ValueError, match="0..168"):
        prove_prefix(bits)


def test_normalization_and_candidate_validate_inputs() -> None:
    for words in ([0] * 17, [0] * 19, [-1] + [0] * 17, [1 << 32] + [0] * 17):
        with pytest.raises(ValueError, match="eighteen uint32"):
            normalized_span(words)
    with pytest.raises(ValueError, match="three eighteen-word"):
        normalized_combined([0] * 53)
    with pytest.raises(ValueError, match="72-byte"):
        candidate_add(bytes(71), bytes(72))
