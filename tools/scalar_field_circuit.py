"""Shared modular arithmetic circuits for compiled scalar-field equations.

Research only: exact coefficient normalization by units, common monomial
extraction and multivariate Horner factoring. No curve, primality, correction
domain or source-instruction assumptions. Variable ordinals are abstract: each
stage supplies its own bindings and a fresh numerical cache.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable
from dataclasses import dataclass
from math import gcd

P = (1 << 160) - 47
Monomial = tuple[tuple[int, int], ...]
Terms = tuple[tuple[Monomial, int], ...]


@dataclass(frozen=True)
class Node:
    operation: str
    arguments: tuple[int, ...]


@dataclass(frozen=True)
class Circuit:
    nodes: tuple[Node, ...]


@dataclass(frozen=True)
class Kernel:
    circuit: Circuit
    roots: tuple[int, ...]


class Builder:
    """Hash-cons polynomial DATA, not source arithmetic or operand metadata."""

    def __init__(self, max_nodes: int = 1_000_000) -> None:
        if type(max_nodes) is not int or max_nodes < 2:
            raise ValueError("integer circuit budget >=2 required")
        self.max_nodes = max_nodes
        self.nodes: list[Node] = []
        self.interned: dict[Node, int] = {}
        self.cache: dict[Terms, int] = {}
        self.zero = self.node("constant", (0,))
        self.one = self.node("constant", (1,))

    def node(self, operation: str, arguments: tuple[int, ...]) -> int:
        node = Node(operation, arguments)
        if node not in self.interned:
            if len(self.nodes) >= self.max_nodes:
                raise ValueError("field circuit node budget exhausted")
            self.interned[node] = len(self.nodes)
            self.nodes.append(node)
        return self.interned[node]

    def multiply(self, first: int, second: int) -> int:
        if self.zero in (first, second):
            return self.zero
        if first == self.one:
            return second
        if second == self.one:
            return first
        return self.node("multiply", tuple(sorted((first, second))))

    def add(self, first: int, second: int) -> int:
        if first == self.zero:
            return second
        if second == self.zero:
            return first
        return self.node("add", tuple(sorted((first, second))))

    def power(self, variable: int, exponent: int) -> int:
        if not exponent:
            return self.one
        base = self.node("variable", (variable,))
        return base if exponent == 1 else self.node("power", (base, exponent))

    def compile(self, terms: Terms) -> int:
        if tuple(sorted(terms)) != terms or len(dict(terms)) != len(terms):
            raise ValueError("canonical field terms required")
        for monomial, coefficient in terms:
            if type(coefficient) is not int or not 0 < coefficient < P:
                raise ValueError("canonical nonzero field coefficients required")
            if tuple(sorted(monomial)) != monomial or len(dict(monomial)) != len(monomial):
                raise ValueError("canonical monomial required")
            if any(type(v) is not int or v < 0 or type(e) is not int or not 1 <= e < 1 << 16 for v, e in monomial):
                raise ValueError("bounded positive integer powers required")
        return self._compile(terms)

    def _compile(self, terms: Terms) -> int:
        if terms in self.cache:
            return self.cache[terms]
        if not terms:
            return self.zero
        leading = terms[0][1]
        if leading != 1 and gcd(leading, P) == 1:
            inverse = pow(leading, -1, P)
            normalized = tuple((m, c * inverse % P) for m, c in terms)
            result = self.multiply(self.node("constant", (leading,)), self._compile(normalized))
        elif len(terms) == 1:
            monomial, coefficient = terms[0]
            result = self.node("constant", (coefficient,))
            for variable, exponent in monomial:
                result = self.multiply(result, self.power(variable, exponent))
        else:
            support = {v for m, _ in terms for v, _ in m}
            common = {v: min(dict(m).get(v, 0) for m, _ in terms) for v in support}
            common = {v: e for v, e in common.items() if e}
            if common:
                reduced = tuple((tuple((v, e - common.get(v, 0)) for v, e in m if e > common.get(v, 0)), c) for m, c in terms)
                result = self._compile(reduced)
                for variable, exponent in sorted(common.items()):
                    result = self.multiply(result, self.power(variable, exponent))
            else:
                variable = max(support, key=lambda v: (sum(any(w == v for w, _ in m) for m, _ in terms), -v))
                groups: dict[int, list[tuple[Monomial, int]]] = {}
                for monomial, coefficient in terms:
                    exponent = dict(monomial).get(variable, 0)
                    rest = tuple((v, e) for v, e in monomial if v != variable)
                    groups.setdefault(exponent, []).append((rest, coefficient))
                exponents = sorted(groups, reverse=True)
                previous = exponents[0]
                result = self._compile(tuple(sorted(groups[previous])))
                for exponent in exponents[1:]:
                    result = self.add(
                        self.multiply(result, self.power(variable, previous - exponent)),
                        self._compile(tuple(sorted(groups[exponent]))),
                    )
                    previous = exponent
                result = self.multiply(result, self.power(variable, previous))
        self.cache[terms] = result
        return result

    def freeze(self) -> Circuit:
        return Circuit(tuple(self.nodes))


def evaluate(circuit: Circuit, root: int, variable: Callable[[int], int], cache: dict[int, int]) -> int:
    """Iterative modular evaluation; missing-binding exceptions propagate.

    Cache entries are scoped to one set of variable bindings. Zero products
    short-circuit; this evaluator never requests source instructions or helpers.
    Use independent coefficient verification before evaluating compiled data.
    """
    if type(root) is not int or not 0 <= root < len(circuit.nodes):
        raise ValueError("field circuit root outside inventory")
    pending = [root]
    while pending:
        index = pending[-1]
        if index in cache:
            pending.pop()
            continue
        node = circuit.nodes[index]
        op, args = node.operation, node.arguments
        if op == "constant":
            cache[index] = args[0]
        elif op == "variable":
            value = variable(args[0])
            if type(value) is not int or not 0 <= value < P:
                raise ValueError("field circuit binding must be a canonical residue")
            cache[index] = value
        else:
            if op == "multiply" and any(cache.get(child) == 0 for child in args):
                cache[index] = 0
                continue
            children = args[:1] if op == "power" else args
            if any(type(child) is not int or not 0 <= child < index for child in children):
                raise ValueError("field circuit has a future or cyclic edge")
            missing = next((child for child in children if child not in cache), None)
            if missing is not None:
                pending.append(missing)
            elif op == "add":
                cache[index] = (cache[args[0]] + cache[args[1]]) % P
            elif op == "multiply":
                cache[index] = cache[args[0]] * cache[args[1]] % P
            elif op == "power":
                cache[index] = pow(cache[args[0]], args[1], P)
            else:
                raise ValueError("unsupported field circuit operation")
    return cache[root]


def report(max_nodes: int = 1_000_000, max_terms: int = 256) -> dict[str, object]:
    from tools.scalar_compiled_stage import compile_stage
    from tools.recover_transform12_phase1 import recover
    from tools.transform7_reference import tail_program
    from tools.verify_scalar_field_circuit import verify

    builder = Builder(max_nodes)
    roots_total = terms_total = identities = coefficient_words = 0
    for source in (*(p for row in recover() for p in row.choices), tail_program()):
        stage = compile_stage(source, max_terms, exclusive_corrections=True)
        roots = tuple(builder.compile(terms) for terms in stage.fields)
        identities += verify(builder.freeze(), roots, stage.fields, max_terms=stage.max_terms).identities
        roots_total += len(roots)
        terms_total += sum(len(terms) for terms in stage.fields)
        coefficient_words += sum(1 + 2 * len(m) for terms in stage.fields for m, _ in terms)
    circuit_words = sum(1 + len(node.arguments) for node in builder.nodes) + roots_total
    return {
        "scope": "exact source-specific field DATA factoring, independently expanded; NOT compact stage-independent curve algorithm",
        "programs": 321,
        "term_budget": max_terms,
        "field_roots": roots_total,
        "field_terms": terms_total,
        "verified_coefficient_identities": identities,
        "circuit_nodes": len(builder.nodes),
        "arithmetic_nodes": sum(n.operation in ("add", "multiply", "power") for n in builder.nodes),
        "coefficient_data_integer_words": coefficient_words,
        "circuit_data_integer_words_including_roots": circuit_words,
        "word_metric_note": "integer item count, not byte size, memory, evaluation work or speed",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-nodes", type=int, default=1_000_000)
    parser.add_argument("--max-terms", type=int, default=256)
    args = parser.parse_args()
    if args.max_nodes < 2 or args.max_terms < 2:
        parser.error("integer node and term budgets>=2 required")
    print(json.dumps(report(args.max_nodes, args.max_terms), indent=2))


if __name__ == "__main__":
    main()
