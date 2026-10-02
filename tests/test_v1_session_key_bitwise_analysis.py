"""Exact Boolean recovery and independent vectors for Monolith11."""

from __future__ import annotations

import random
import struct
from pathlib import Path

import pytest

from old.family0._generated import monolith11
from tools.analyze_bitwise_monolith import _anf_coefficients, _variable_masks, analyze_bitwise_output, anf_monomial_masks
from tools.monolith11_model import EVEN_COEFFICIENTS, ODD_COEFFICIENTS, execute_words


pytestmark = pytest.mark.analysis  # studies retired HarpoS7 code in old/; pass --analysis

_FIXTURES = Path(__file__).parent / "fixtures/family0/monoliths"


def test_truth_masks_and_boolean_mobius_transform() -> None:
    masks = _variable_masks(3)
    assert masks == (0b10101010, 0b11001100, 0b11110000)
    # x0 XOR x1 has ANF coefficients at subsets {0} and {1} only.
    truth = masks[0] ^ masks[1]
    assert _anf_coefficients(truth, masks) == 0b110


def _expected_kernel_terms(base: int, coefficients: tuple[int, ...]) -> dict[tuple[int, ...], int]:
    a, b, c = base, base + 1, base + 2
    return {
        (a,): coefficients[0],
        (b,): coefficients[1],
        (a, b): coefficients[2],
        (c,): coefficients[3],
        (a, c): coefficients[4],
        (b, c): coefficients[5],
    }


@pytest.mark.parametrize("output_word", range(5))
def test_all_monolith11_outputs_have_exact_twelve_term_form(output_word: int) -> None:
    analysis = analyze_bitwise_output(11, output_word)
    coefficients = EVEN_COEFFICIENTS if output_word % 2 == 0 else ODD_COEFFICIENTS
    expected = _expected_kernel_terms(3 * output_word, coefficients)
    expected.update(_expected_kernel_terms(15 + 3 * output_word, coefficients))

    # Each of the 32 output-bit truth tables exhausts 2^N source-bit rows.
    # The analyzer rejects cross-bit operators, so matching ANFs prove the
    # compact model equivalent for every 30-word source vector.
    assert anf_monomial_masks(analysis) == dict(sorted(expected.items()))
    assert all(item.anf_degree == 2 for item in analysis.bits)
    assert all(len(item.essential_source_words) == 6 for item in analysis.bits)


def test_compact_model_matches_upstream_monolith11_fixture() -> None:
    source = (_FIXTURES / "monolith11-src.bin").read_bytes()
    expected = (_FIXTURES / "monolith11-dst.bin").read_bytes()
    words = struct.unpack("<30I", source)
    assert struct.pack("<5I", *execute_words(words)) == expected


def test_compact_model_matches_generated_code_on_random_vectors() -> None:
    rng = random.Random(0x711C011)
    analyses = [analyze_bitwise_output(11, word) for word in range(5)]
    for _ in range(100):
        words = tuple(rng.getrandbits(32) for _ in range(30))
        destination = bytearray(20)
        monolith11.execute(destination, struct.pack("<30I", *words))
        compact = execute_words(words)
        assert struct.unpack("<5I", destination) == compact
        assert tuple(item.evaluate(dict(enumerate(words))) for item in analyses) == compact


def test_non_bitwise_monolith_is_rejected() -> None:
    with pytest.raises(ValueError, match="non-bitwise expression"):
        analyze_bitwise_output(1, 0)
