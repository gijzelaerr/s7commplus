"""Compact intermediate-stage raw bounds in the saturated0..47 semiring.

Research only. Inputs are min(raw_entry,47), not field residues. Saturated
addition/multiplication distribute. Coefficients saturate at47; powers can be
clipped once coefficient*2**power>=47 (but never below1). A coefficient47
monomial eliminates every term whose variable support contains its support.
No subtraction nodes, field algebra, curve assumptions or correction deletion.
"""

from __future__ import annotations

from tools.scalar_raw_bound_dag import Graph

Powers = tuple[int, ...]
Polynomial = tuple[tuple[Powers, int], ...]


def normalize(terms: dict[Powers, int]) -> Polynomial:
    if (
        len({len(powers) for powers in terms}) > 1
        or any(type(c) is not int or c < 0 for c in terms.values())
        or any(type(power) is not int or power < 0 for powers in terms for power in powers)
    ):
        raise ValueError("nonnegative integer coefficients and consistent nonnegative powers required")
    current = {powers: min(coefficient, 47) for powers, coefficient in terms.items() if coefficient}
    while True:
        result: dict[Powers, int] = {}
        for powers, coefficient in current.items():
            cutoff = 1
            while coefficient * (1 << cutoff) < 47:
                cutoff += 1
            clipped = tuple(min(power, cutoff) for power in powers)
            result[clipped] = min(result.get(clipped, 0) + coefficient, 47)
        if result == current:
            break
        current = result
    saturating = [frozenset(i for i, power in enumerate(powers) if power) for powers, c in result.items() if c == 47]
    return tuple(
        sorted(
            (powers, coefficient)
            for powers, coefficient in result.items()
            if not any(
                support <= frozenset(i for i, power in enumerate(powers) if power)
                and tuple(int(i in support) for i in range(len(powers))) != powers
                for support in saturating
            )
        )
    )


class Catalogue:
    def __init__(self, graph: Graph, input_count: int = 5, max_terms: int = 1024) -> None:
        if type(input_count) is not int or input_count < 1 or type(max_terms) is not int or max_terms < 1:
            raise ValueError("positive polynomial bounds required")
        self.input_count = input_count
        self.polynomials: list[Polynomial] = []
        interned: dict[Polynomial, int] = {}
        self.roots: list[int] = []
        for index, node in enumerate(graph.nodes):
            op, args = node.operation, node.arguments
            if op == "literal":
                polynomial = normalize({(0,) * input_count: args[0]})
            elif op == "input":
                if not 0 <= args[0] < input_count:
                    raise ValueError("raw bound input ordinal outside polynomial layout")
                polynomial = ((tuple(int(i == args[0]) for i in range(input_count)), 1),)
            else:
                if op not in ("add", "multiply") or any(not 0 <= child < index for child in args):
                    raise ValueError("only acyclic positive-semiring bound equations supported")
                a, b = (self.polynomials[self.roots[child]] for child in args)
                terms: dict[Powers, int] = dict(a) if op == "add" else {}
                if op == "add":
                    for powers, coefficient in b:
                        terms[powers] = min(terms.get(powers, 0) + coefficient, 47)
                else:
                    for first, ac in a:
                        for second, bc in b:
                            powers = tuple(min(x + y, 6) for x, y in zip(first, second))
                            terms[powers] = min(terms.get(powers, 0) + ac * bc, 47)
                polynomial = normalize(terms)
            if len(polynomial) > max_terms:
                raise ValueError("raw-bound polynomial term budget exceeded")
            if polynomial not in interned:
                interned[polynomial] = len(self.polynomials)
                self.polynomials.append(polynomial)
            self.roots.append(interned[polynomial])

    def evaluate(self, root: int, raw_inputs: tuple[int, ...]) -> int:
        if type(root) is not int or not 0 <= root < len(self.polynomials):
            raise ValueError("defined raw-bound polynomial root required")
        if len(raw_inputs) != self.input_count or any(type(v) is not int or not 0 <= v < 1 << 160 for v in raw_inputs):
            raise ValueError("uint160 raw entry layout required")
        inputs = tuple(min(v, 47) for v in raw_inputs)
        result = 0
        for powers, coefficient in self.polynomials[root]:
            term = coefficient
            for value, power in zip(inputs, powers):
                term = min(term * pow(value, power), 47)
                if term == 0:
                    break
            result = min(result + term, 47)
            if result == 47:
                break
        return result
