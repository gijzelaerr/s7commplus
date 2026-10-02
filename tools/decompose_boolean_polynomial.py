"""Find exact disjoint functional decompositions of small Boolean ANFs.

For a chosen input subset, collect the ANF coefficient of each monomial in
the remaining inputs. If every nonconstant coefficient is the same function
Q, the polynomial is exactly A XOR Q*B. Q can replace the chosen input subset
with one intermediate value. No sampling or solver is used.
"""

from __future__ import annotations

from functools import lru_cache
from itertools import combinations, permutations
from typing import TypedDict

from tools.analyze_bitwise_monolith import _variable_masks
from tools.recover_monolith5 import Polynomial, _multiply, _term_source_ids

MUX_XOR = frozenset({2, 5, 6, 8})  # b XOR ((a XOR b) AND c) XOR d.
MUX = frozenset({2, 5, 6})
CORE_FORMULAS = {
    (2, frozenset({1, 2})): ("xor2", "a XOR b"),
    (3, MUX): ("choose", "b XOR ((a XOR b) AND c)"),
    (3, frozenset({3, 5, 6})): ("majority", "(a AND b) XOR (a AND c) XOR (b AND c)"),
    (3, frozenset({1, 2, 4})): ("xor3", "a XOR b XOR c"),
    (4, MUX_XOR): ("mux_xor", "choose(a, b, c) XOR d"),
    (4, frozenset({5, 11, 13})): ("gated_choose", "a AND choose(b, c, d)"),
    (4, frozenset({7, 11, 13})): ("gated_majority", "a AND majority(b, c, d)"),
    (4, frozenset({1, 6, 10, 12})): ("majority_xor", "a XOR majority(b, c, d)"),
}


class Kernel(TypedDict):
    inputs: int
    terms: list[int]


class FactoredFunction(TypedDict):
    inputs: int
    steps: list[tuple[int, list[int], int]]  # Kernel ID, input indices, input inversion mask.
    terms: list[int]


@lru_cache(maxsize=None)
def _permuted_kernel(count: int, polynomial: Polynomial) -> tuple[tuple[int, ...], Polynomial]:
    terms, order = min(
        (
            tuple(
                sorted(sum(1 << index for index, variable in enumerate(order) if term & (1 << variable)) for term in polynomial)
            ),
            order,
        )
        for order in permutations(range(count))
    )
    return order, frozenset(terms)


@lru_cache(maxsize=None)
def _recognized_kernel(count: int, polynomial: Polynomial) -> tuple[tuple[int, ...], Polynomial, int]:
    """Exhaustively recognize a small core under input permutation/inversion."""
    variables = _variable_masks(count)
    universe = (1 << (1 << count)) - 1

    def truth(terms: Polynomial, arguments: tuple[int, ...]) -> int:
        result = 0
        for term in terms:
            product = universe
            for variable in _term_source_ids(term):
                product &= arguments[variable]
            result ^= product
        return result

    expected = truth(polynomial, variables)
    for arity, core in CORE_FORMULAS:
        if arity != count:
            continue
        for inversions in sorted(range(1 << count), key=lambda mask: (mask.bit_count(), mask)):
            for order in permutations(range(count)):
                arguments = tuple(
                    variables[variable] ^ (universe if inversions & (1 << index) else 0) for index, variable in enumerate(order)
                )
                if truth(core, arguments) == expected:
                    return order, core, inversions
    order, normalized = _permuted_kernel(count, polynomial)
    return order, normalized, 0


def _component(polynomial: Polynomial) -> tuple[list[int], Polynomial, Polynomial] | None:
    variables = sorted({variable for term in polynomial for variable in _term_source_ids(term)})
    best: tuple[list[int], Polynomial, Polynomial] | None = None
    best_gain = 1
    for size in (4, 3, 2):
        if size >= len(variables):
            continue
        for selected in combinations(variables, size):
            mask = sum(1 << variable for variable in selected)
            coefficients: dict[int, set[int]] = {}
            for term in polynomial:
                coefficients.setdefault(term & ~mask, set()).add(term & mask)
            nonconstant = {frozenset(terms - {0}) for terms in coefficients.values()} - {frozenset()}
            if len(nonconstant) != 1:
                continue
            kernel = next(iter(nonconstant))
            used = 0
            for term in kernel:
                used |= term
            if used != mask or len(kernel) <= 1:
                continue
            # A fresh variable comes after every current variable; callers
            # remap it to the next available step index.
            intermediate = 1 << (variables[-1] + 1)
            remainder = frozenset(
                [outside for outside, terms in coefficients.items() if 0 in terms]
                + [outside | intermediate for outside, terms in coefficients.items() if terms - {0}]
            )
            gain = len(polynomial) - len(remainder)
            if gain > best_gain:
                normalized = frozenset(
                    sum(1 << position for position, variable in enumerate(selected) if term & (1 << variable)) for term in kernel
                )
                best = list(selected), normalized, remainder
                best_gain = gain
    return best


def factor_function(inputs: int, polynomial: Polynomial, kernels: list[Kernel]) -> FactoredFunction:
    """Factor a function and intern shared small cores in ``kernels``."""
    if inputs < 0 or any(term < 0 or term >= 1 << inputs for term in polynomial):
        raise ValueError("ANF term exceeds declared input count")
    steps: list[tuple[int, list[int], int]] = []
    current = polynomial
    while (component := _component(current)) is not None:
        refs, normalized, remainder = component
        order, normalized, inversions = _recognized_kernel(len(refs), normalized)
        refs = [refs[index] for index in order]
        kernel: Kernel = {"inputs": len(refs), "terms": sorted(normalized)}
        if kernel not in kernels:
            kernels.append(kernel)
        steps.append((kernels.index(kernel), refs, inversions))
        temporary = max(term.bit_length() for term in current)
        intermediate = inputs + len(steps) - 1
        current = frozenset(
            (term ^ (1 << temporary)) | (1 << intermediate) if term & (1 << temporary) else term for term in remainder
        )
    result: FactoredFunction = {"inputs": inputs, "steps": steps, "terms": sorted(current)}
    if expand_function(result, kernels) != polynomial:
        raise ValueError("functional decomposition failed exact ANF reconstruction")
    return result


def expand_function(function: FactoredFunction, kernels: list[Kernel]) -> Polynomial:
    """Substitute every intermediate to reconstruct the unique original ANF."""
    values: list[Polynomial] = [frozenset({1 << variable}) for variable in range(function["inputs"])]
    for kernel_id, refs, inversions in function["steps"]:
        kernel = kernels[kernel_id]
        if len(refs) != kernel["inputs"] or not 0 <= inversions < 1 << len(refs):
            raise ValueError("kernel arity or inversion mask mismatch")
        if any(reference < 0 or reference >= len(values) for reference in refs):
            raise ValueError("kernel references an unavailable input")
        arguments = [
            values[reference] ^ (frozenset({0}) if inversions & (1 << index) else frozenset())
            for index, reference in enumerate(refs)
        ]
        result: Polynomial = frozenset()
        for term in kernel["terms"]:
            product: Polynomial = frozenset({0})
            for variable in _term_source_ids(term):
                product = _multiply(product, arguments[variable])
            result ^= product
        values.append(result)
    result = frozenset()
    for term in function["terms"]:
        product = frozenset({0})
        for variable in _term_source_ids(term):
            product = _multiply(product, values[variable])
        result ^= product
    return result
