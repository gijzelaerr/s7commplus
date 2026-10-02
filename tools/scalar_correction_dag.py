"""Bounded correction cofactors with independent coefficient certificates.

On errors E in {0,c}, select F|E=0 or F|E=c. Unlike monomial zero cuts,
the nonzero branch can cancel other error dependencies. Budget exhaustion
keeps an exact polynomial leaf, never a sampled approximation.
Research only; domains must come from a checked scalar plan.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass

from tools.scalar_stage_plan import Polynomial

P = (1 << 160) - 47
Terms = tuple[tuple[tuple[tuple[int, int], ...], int], ...]


@dataclass(frozen=True)
class Leaf:
    terms: Terms


@dataclass(frozen=True)
class Decision:
    variable: int
    low: int
    high: int


@dataclass(frozen=True)
class Graph:
    nodes: tuple[Leaf | Decision, ...]
    root: int
    domains: tuple[tuple[int, int], ...]


@dataclass(frozen=True)
class Certificate:
    identities: int
    decisions: int
    leaves: int
    polynomial_sha256: str
    graph_sha256: str
    domains: tuple[tuple[int, int], ...]


def specialize(poly: Polynomial, assigned: dict[int, int]) -> Polynomial:
    """Fold only already-known field values; never demand an extra binding."""
    result: Polynomial = {}
    for monomial, coefficient in poly.items():
        rest = []
        for variable, exponent in monomial:
            if variable in assigned:
                coefficient = coefficient * pow(assigned[variable], exponent, P) % P
            else:
                rest.append((variable, exponent))
        key = tuple(rest)
        result[key] = (result.get(key, 0) + coefficient) % P
    return {m: c for m, c in result.items() if c}


def verify_specialization(original: Polynomial, reduced: Polynomial, assigned: dict[int, int]) -> None:
    """Independent coefficient grouping after substituting concrete values."""
    coefficients: dict[frozenset[tuple[int, int]], int] = defaultdict(int)
    for monomial, coefficient in original.items():
        known = ((v, e) for v, e in monomial if v in assigned)
        value = coefficient
        for variable, exponent in known:
            value *= pow(assigned[variable], exponent, P)
            value %= P
        support = frozenset((v, e) for v, e in monomial if v not in assigned)
        coefficients[support] += value
    expected = {m: c % P for m, c in coefficients.items() if c % P}
    if {frozenset(m): c for m, c in reduced.items()} != expected:
        raise ValueError("specialized coefficient identity failed")


def build(poly: Polynomial, weights: dict[int, int], *, max_decisions: int = 64, max_work: int = 65536) -> Graph:
    if type(max_decisions) is not int or max_decisions < 0 or type(max_work) is not int or max_work < 0:
        raise ValueError("nonnegative integer cofactor budgets required")
    nodes: list[Leaf | Decision] = []
    interned: dict[Leaf | Decision, int] = {}
    cache: dict[Terms, int] = {}
    used = {v for m in poly for v, _ in m if v in weights}
    if any(e.bit_length() > 4096 for m in poly for _, e in m):
        raise ValueError("cofactor exponent budget exceeded")
    domains = {v: weights[v] for v in used}
    decisions = 0
    work = 0

    def node(value: Leaf | Decision) -> int:
        if value not in interned:
            interned[value] = len(nodes)
            nodes.append(value)
        return interned[value]

    def compile_terms(terms: Terms) -> int:
        nonlocal decisions, work
        if terms in cache:
            return cache[terms]
        variables = {v for m, _ in terms for v, _ in m if v in domains}
        if not variables or decisions >= max_decisions or work + len(terms) > max_work:
            result = node(Leaf(terms))
        else:
            variable = min(variables)
            decisions += 1
            work += len(terms)
            low: Polynomial = {}
            high: Polynomial = {}
            for monomial, coefficient in terms:
                powers = dict(monomial)
                exponent = powers.pop(variable, 0)
                rest = tuple(sorted(powers.items()))
                if exponent == 0:
                    low[rest] = (low.get(rest, 0) + coefficient) % P
                high[rest] = (high.get(rest, 0) + coefficient * pow(domains[variable], exponent, P)) % P
            left = compile_terms(tuple(sorted((m, c) for m, c in low.items() if c)))
            right = compile_terms(tuple(sorted((m, c) for m, c in high.items() if c)))
            result = left if left == right else node(Decision(variable, left, right))
        cache[terms] = result
        return result

    root = compile_terms(tuple(sorted(poly.items())))
    return Graph(tuple(nodes), root, tuple(sorted(domains.items())))


def verify(graph: Graph, poly: Polynomial, weights: dict[int, int]) -> Certificate:
    """Independently restrict original coefficients; never call the builder.

    This certifies only polynomial cofactors under the recorded domains;
    scalar field identities/domain provenance are checked separately.
    """
    expected_domains = tuple(sorted((v, weights[v]) for v in {v for m in poly for v, _ in m if v in weights}))
    original_variables = {v for m in poly for v, _ in m}
    if graph.domains != expected_domains or len(dict(graph.domains)) != len(graph.domains):
        raise ValueError("cofactor correction domain mismatch")
    if any(type(v) is not int or v < 0 or type(c) is not int or not 0 <= c < P for v, c in graph.domains):
        raise ValueError("noncanonical correction domain")
    if type(graph.root) is not int or not 0 <= graph.root < len(graph.nodes):
        raise ValueError("cofactor root outside node inventory")
    for index, current in enumerate(graph.nodes):
        if isinstance(current, Decision):
            if current.variable not in dict(graph.domains) or type(current.variable) is not int:
                raise ValueError("undefined cofactor decision variable")
            if any(type(child) is not int or not 0 <= child < index for child in (current.low, current.high)):
                raise ValueError("cofactor graph contains a forward or cyclic edge")
        elif not isinstance(current, Leaf):
            raise ValueError("unsupported cofactor node")

    def read(terms: Terms) -> dict[frozenset[tuple[int, int]], int]:
        if tuple(sorted(terms)) != terms or len(dict(terms)) != len(terms):
            raise ValueError("noncanonical cofactor terms")
        result = {}
        for monomial, coefficient in terms:
            if type(coefficient) is not int or not 0 < coefficient < P:
                raise ValueError("noncanonical cofactor coefficient")
            previous = -1
            for variable, exponent in monomial:
                if type(variable) is not int or variable <= previous or type(exponent) is not int or exponent <= 0:
                    raise ValueError("noncanonical cofactor monomial")
                if variable not in original_variables:
                    raise ValueError("cofactor introduced an undefined polynomial variable")
                if exponent.bit_length() > 4096:
                    raise ValueError("cofactor exponent budget exceeded")
                previous = variable
            result[frozenset(monomial)] = coefficient
        return result

    domains = dict(graph.domains)
    checked: dict[int, dict[frozenset[tuple[int, int]], int]] = {}

    def truth_class(value: dict[frozenset[tuple[int, int]], int]) -> dict[frozenset[tuple[int, int]], int]:
        # Substitute E_i=c_i*B_i, B_i in {0,1}, and reduce B_i^n=B_i.
        # Unlike division by c_i, this is sound for zero/nonunit weights.
        coefficients: dict[frozenset[tuple[int, int]], int] = defaultdict(int)
        for support, coefficient in value.items():
            powers = dict(support)
            for variable in powers.keys() & domains.keys():
                coefficient *= pow(domains[variable], powers[variable], P)
                powers[variable] = 1
            coefficients[frozenset(powers.items())] += coefficient
        return {m: c % P for m, c in coefficients.items() if c % P}

    def check(index: int, expected: dict[frozenset[tuple[int, int]], int], previous: int = -1) -> None:
        current = graph.nodes[index]
        if isinstance(current, Decision) and current.variable <= previous:
            raise ValueError("cofactor decisions are not in ascending error order")
        if index in checked:
            if truth_class(checked[index]) != truth_class(expected):
                raise ValueError("shared cofactor polynomial identity failed")
            return
        checked[index] = expected
        if isinstance(current, Leaf):
            if truth_class(read(current.terms)) != truth_class(expected):
                raise ValueError("cofactor leaf coefficient identity failed")
            return
        branches: tuple[dict[frozenset[tuple[int, int]], int], ...] = ({}, {})
        for branch, value in zip(branches, (0, domains[current.variable])):
            coefficients: dict[frozenset[tuple[int, int]], int] = defaultdict(int)
            for support, coefficient in expected.items():
                exponent = next((e for v, e in support if v == current.variable), 0)
                rest = frozenset((v, e) for v, e in support if v != current.variable)
                coefficients[rest] += coefficient * pow(value, exponent, P)
            branch.update({m: c % P for m, c in coefficients.items() if c % P})
        check(current.low, branches[0], current.variable)
        check(current.high, branches[1], current.variable)

    check(graph.root, read(tuple(sorted(poly.items()))))
    return Certificate(
        len(checked),
        sum(isinstance(graph.nodes[i], Decision) for i in checked),
        sum(isinstance(graph.nodes[i], Leaf) for i in checked),
        hashlib.sha256(repr(tuple(sorted(poly.items()))).encode()).hexdigest(),
        hashlib.sha256(repr(graph).encode()).hexdigest(),
        graph.domains,
    )


def evaluate(graph: Graph, lookup: Callable[[int], int]) -> int:
    index = graph.root
    while isinstance(graph.nodes[index], Decision):
        current = graph.nodes[index]
        assert isinstance(current, Decision)
        value = lookup(current.variable)
        weight = dict(graph.domains)[current.variable]
        if value not in (0, weight):
            raise ValueError("correction outside the certified two-value domain")
        index = current.low if value == 0 else current.high
    leaf = graph.nodes[index]
    assert isinstance(leaf, Leaf)
    result = 0
    for monomial, coefficient in leaf.terms:
        term = coefficient
        for variable, exponent in monomial:
            term = term * pow(lookup(variable), exponent, P) % P
            if term == 0:
                break
        result += term
    return result % P
