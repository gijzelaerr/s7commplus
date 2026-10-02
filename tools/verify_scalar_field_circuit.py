"""Independent formal-ring expansion of actual scalar field-circuit data.

No builder routines, field compiler algebra, correction-domain reductions,
curve relation, primality assumptions, source replay or numerical sampling.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from tools.scalar_field_circuit import Circuit, Terms

P = (1 << 160) - 47
Support = frozenset[tuple[int, int]]
Polynomial = dict[Support, int]


@dataclass(frozen=True)
class Certificate:
    identities: int
    reachable_nodes: int
    data_sha256: str
    dependencies_checked: bool


def verify(
    circuit: Circuit,
    roots: tuple[int, ...],
    fields: tuple[Terms, ...],
    *,
    max_terms: int = 256,
    strict_dependencies: bool = True,
) -> Certificate:
    if type(max_terms) is not int or max_terms < 1 or len(roots) != len(fields):
        raise ValueError("field circuit identity inventory or term budget mismatch")
    if type(strict_dependencies) is not bool:
        raise ValueError("Boolean field dependency proof mode required")
    expected: list[Polynomial] = []
    for terms in fields:
        polynomial: Polynomial = {}
        if tuple(sorted(terms)) != terms or len(dict(terms)) != len(terms) or len(terms) > max_terms:
            raise ValueError("noncanonical circuit coefficient target")
        for monomial, coefficient in terms:
            if type(coefficient) is not int or not 0 < coefficient < P:
                raise ValueError("noncanonical circuit coefficient target")
            if tuple(sorted(monomial)) != monomial or len(dict(monomial)) != len(monomial):
                raise ValueError("noncanonical circuit power target")
            if any(type(v) is not int or v < 0 or type(e) is not int or not 1 <= e < 1 << 16 for v, e in monomial):
                raise ValueError("invalid circuit power target")
            polynomial[frozenset(monomial)] = coefficient
        expected.append(polynomial)

    expanded: dict[int, Polynomial] = {}
    dependencies: dict[int, frozenset[int]] = {}
    for root, target in zip(roots, expected):
        if type(root) is not int or not 0 <= root < len(circuit.nodes):
            raise ValueError("field circuit root outside inventory")
        pending = [root]
        while pending:
            index = pending[-1]
            if index in expanded:
                pending.pop()
                continue
            node = circuit.nodes[index]
            op, args = node.operation, node.arguments
            if op in ("constant", "variable"):
                if len(args) != 1 or type(args[0]) is not int:
                    raise ValueError("invalid field circuit leaf")
                if op == "constant":
                    if not 0 <= args[0] < P:
                        raise ValueError("noncanonical circuit literal")
                    expanded[index] = {frozenset(): args[0]} if args[0] else {}
                    dependencies[index] = frozenset()
                else:
                    if args[0] < 0:
                        raise ValueError("negative circuit variable")
                    expanded[index] = {frozenset(((args[0], 1),)): 1}
                    dependencies[index] = frozenset((args[0],))
                continue
            if op not in ("add", "multiply", "power") or len(args) != 2:
                raise ValueError("unsupported field circuit node")
            children = args[:1] if op == "power" else args
            if any(type(child) is not int or not 0 <= child < index for child in children):
                raise ValueError("field circuit reads a future or cyclic node")
            if op == "power":
                child = circuit.nodes[args[0]]
                if child.operation != "variable" or type(args[1]) is not int or not 1 <= args[1] < 1 << 16:
                    raise ValueError("field circuit power must have a variable base and bounded exponent")
            missing = next((child for child in children if child not in expanded), None)
            if missing is not None:
                pending.append(missing)
                continue
            if op == "power":
                expanded[index] = {frozenset(((circuit.nodes[args[0]].arguments[0], args[1]),)): 1}
                dependencies[index] = dependencies[args[0]]
                continue
            left, right = (expanded[child] for child in args)
            result: Polynomial = dict(left) if op == "add" else {}
            if op == "add":
                for support, coefficient in right.items():
                    result[support] = (result.get(support, 0) + coefficient) % P
            else:
                if len(left) * len(right) > max_terms * max_terms:
                    raise ValueError("field circuit expansion work budget exceeded")
                for first, a in left.items():
                    for second, b in right.items():
                        powers = dict(first)
                        for variable, exponent in second:
                            powers[variable] = powers.get(variable, 0) + exponent
                        support = frozenset(powers.items())
                        result[support] = (result.get(support, 0) + a * b) % P
            result = {m: c for m, c in result.items() if c}
            if len(result) > max_terms:
                raise ValueError("field circuit expansion term budget exceeded")
            expanded[index] = result
            dependencies[index] = dependencies[args[0]] | dependencies[args[1]]
        if expanded[root] != target:
            raise ValueError("field circuit coefficient identity failed")
        # A zero-cancelled variable is still an operational dependency: asking
        # for it could read an unknown/future correction or cyclic anchor.
        # Pure ring equality alone is insufficient for causal stage evaluation.
        input_support = frozenset(v for monomial in target for v, _ in monomial)
        if strict_dependencies and not dependencies[root] <= input_support:
            raise ValueError("field circuit introduces an extraneous binding dependency")
    data = (tuple((i, circuit.nodes[i]) for i in sorted(expanded)), roots, fields, strict_dependencies)
    return Certificate(len(roots), len(expanded), hashlib.sha256(repr(data).encode()).hexdigest(), strict_dependencies)
