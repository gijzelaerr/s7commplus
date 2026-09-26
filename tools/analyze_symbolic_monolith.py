"""Exact per-output-bit Boolean analysis of generated, single-file monoliths.

This is deliberately bit-granular: a whole-word BDD may explode even when
each output bit has a small exact representation. The conservative bit trace
selects candidate variables; the ROBDD removes algebraic cancellations.
"""

from __future__ import annotations

import argparse
import ast
import json
from dataclasses import asdict, dataclass
from pathlib import Path

from tools.recover_monolith5 import BDD, Polynomial, _literal, _term_source_ids
from tools.trace_session_auth_bits import BitRef, trace_output_bits
from tools.trace_session_auth_output import REPOSITORY_ROOT, trace_monolith


@dataclass(frozen=True)
class SymbolicBitAnalysis:
    monolith: int
    output_word: int
    bit: int
    candidate_source_bits: tuple[BitRef, ...]
    essential_source_bits: tuple[BitRef, ...]
    assignment_count: int
    bdd_nodes: int
    anf_degree: int
    anf_terms: int
    polynomial: Polynomial

    def evaluate(self, source_words: dict[int, int]) -> int:
        """Evaluate the exact recovered Boolean polynomial at one input."""
        result = 0
        for monomial in self.polynomial:
            product = 1
            for source_id in _term_source_ids(monomial):
                word, bit = divmod(source_id, 32)
                product &= (source_words[word] >> bit) & 1
            result ^= product
        return result


def analyze_output_bit(
    monolith: int,
    output_word: int,
    bit: int,
    root: Path = REPOSITORY_ROOT,
    max_inputs: int = 64,
) -> SymbolicBitAnalysis:
    """Recover one bit's exact ANF within the supported uint32 AST subset."""
    if not 0 <= bit < 32:
        raise ValueError("output bit must be 0..31")
    trace = trace_monolith(monolith, output_word, root=root)
    paths = {assignment["path"] for assignment in trace["assignments"]}
    if len(paths) != 1 or any(not ref.startswith("source[") for ref in trace["inputs"]):
        raise ValueError("only single-file, source-only slices are supported")
    candidates = tuple(sorted(trace_output_bits(monolith, output_word, root=root)[bit], key=lambda ref: (ref[1], ref[0])))
    if len(candidates) > max_inputs:
        raise ValueError(f"{len(candidates)} candidate source bits exceed limit {max_inputs}")

    path = root / next(iter(paths))
    module = ast.parse(path.read_text(encoding="utf-8"))
    execute = next(node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == "execute")
    wanted = {(assignment["line"], assignment["target"]) for assignment in trace["assignments"]}
    bdd = BDD(list(candidates))
    values: dict[str, tuple[int, ...]] = {}
    output: tuple[int, ...] | None = None
    for statement in execute.body:
        if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
            continue
        target = statement.targets[0]
        if isinstance(target, ast.Name):
            name = target.id
        elif isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name) and target.value.id == "dst_dwords":
            name = f"dst_dwords[{_literal(target.slice)}]"
        else:
            continue
        if (statement.lineno, name) not in wanted:
            continue
        value = bdd.expression(statement.value, values)
        values[name] = value
        if name == f"dst_dwords[{output_word}]":
            output = value
    if output is None:
        raise ValueError(f"no output word {output_word}")

    polynomial = bdd.source_polynomial(output[bit])
    essential = tuple(sorted({divmod(source_id, 32) for term in polynomial for source_id in _term_source_ids(term)}))
    return SymbolicBitAnalysis(
        monolith=monolith,
        output_word=output_word,
        bit=bit,
        candidate_source_bits=candidates,
        essential_source_bits=essential,
        assignment_count=len(trace["assignments"]),
        bdd_nodes=len(bdd.nodes),
        anf_degree=max((term.bit_count() for term in polynomial), default=0),
        anf_terms=len(polynomial),
        polynomial=polynomial,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("monolith", type=int)
    parser.add_argument("output_word", type=int)
    parser.add_argument("bit", type=int)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--monomials", action="store_true", help="include the full ANF term list in JSON")
    args = parser.parse_args()
    result = analyze_output_bit(args.monolith, args.output_word, args.bit)
    if args.json:
        record = asdict(result)
        record.pop("polynomial")
        if args.monomials:
            record["monomials"] = [
                [divmod(source_id, 32) for source_id in _term_source_ids(term)] for term in sorted(result.polynomial)
            ]
        print(json.dumps(record, indent=2))
    else:
        print(f"Monolith{result.monolith} output word {result.output_word} bit {result.bit}")
        print(f"Candidate source bits: {len(result.candidate_source_bits)}")
        print(f"Essential source bits: {list(result.essential_source_bits)}")
        print(f"ANF: {result.anf_terms} terms, degree {result.anf_degree}; BDD nodes: {result.bdd_nodes}")


if __name__ == "__main__":
    main()
