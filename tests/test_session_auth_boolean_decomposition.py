"""Exhaustive truth-table checks of exact functional decomposition."""

from __future__ import annotations

import random

import pytest

from tools.analyze_bitwise_monolith import _anf_coefficients, _variable_masks
from tools.decompose_boolean_polynomial import FactoredFunction, Kernel, expand_function, factor_function
from tools.recover_monolith5 import _term_source_ids


def _circuit_truth(function: FactoredFunction, kernels: list[Kernel]) -> int:
    """Evaluate all input assignments in parallel with independent bitsets."""
    values = list(_variable_masks(function["inputs"]))
    universe = (1 << (1 << function["inputs"])) - 1

    def evaluate(terms: list[int], arguments: list[int]) -> int:
        result = 0
        for term in terms:
            product = universe
            for index in _term_source_ids(term):
                product &= arguments[index]
            result ^= product
        return result

    for kernel_id, refs, inversions in function["steps"]:
        arguments = [values[reference] ^ (universe if inversions & (1 << index) else 0) for index, reference in enumerate(refs)]
        values.append(evaluate(kernels[kernel_id]["terms"], arguments))
    return evaluate(function["terms"], values)


def test_dense_mux_majority_formula_is_exactly_decomposed() -> None:
    truth = 0
    for assignment in range(128):
        a, b, c, d, e, f, g = ((assignment >> bit) & 1 for bit in range(7))
        selected = (a if c else b) ^ d
        majority = int(e + f + g >= 2)
        truth |= int(not (selected or majority)) << assignment
    coefficients = _anf_coefficients(truth, _variable_masks(7))
    polynomial = frozenset(_term_source_ids(coefficients))
    kernels: list[Kernel] = []
    function = factor_function(7, polynomial, kernels)
    assert function["steps"]
    assert len(function["terms"]) < len(polynomial)
    assert _circuit_truth(function, kernels) == truth
    assert expand_function(function, kernels) == polynomial


def test_random_small_functions_match_every_assignment() -> None:
    rng = random.Random(0xDEC0DE)
    kernels: list[Kernel] = []
    for _ in range(64):
        truth = rng.getrandbits(64)
        coefficients = _anf_coefficients(truth, _variable_masks(6))
        polynomial = frozenset(_term_source_ids(coefficients))
        function = factor_function(6, polynomial, kernels)
        assert _circuit_truth(function, kernels) == truth
        assert expand_function(function, kernels) == polynomial


@pytest.mark.parametrize("inputs,polynomial,truth", [(0, frozenset(), 0), (0, frozenset({0}), 1), (3, frozenset({0, 1}), 0x55)])
def test_constants_and_small_functions(inputs: int, polynomial: frozenset[int], truth: int) -> None:
    kernels: list[Kernel] = []
    function = factor_function(inputs, polynomial, kernels)
    assert _circuit_truth(function, kernels) == truth
    assert expand_function(function, kernels) == polynomial


def test_decomposition_rejects_out_of_range_input() -> None:
    with pytest.raises(ValueError, match="declared input count"):
        factor_function(3, frozenset({8}), [])
