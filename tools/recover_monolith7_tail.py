"""Recover an exact, compact model for Monolith7 output words 15–17.

These three words form a small source-only subgraph. Every output bit is
reduced symbolically to ANF, then stored as a short input selector and a
truth table shared with any other bit having the same Boolean function.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import TypedDict

from tools.analyze_symbolic_monolith import analyze_output_bit
from tools.recover_monolith5 import _term_source_ids
from tools.trace_session_auth_output import REPOSITORY_ROOT


class Function(TypedDict):
    inputs: int
    truth: str


class Model(TypedDict):
    version: int
    output_words: list[int]
    functions: list[Function]
    bits: list[tuple[int, list[tuple[int, int]]]]


def _truth_table(inputs: int, polynomial: frozenset[int]) -> str:
    truth = 0
    for assignment in range(1 << inputs):
        if sum(assignment & monomial == monomial for monomial in polynomial) & 1:
            truth |= 1 << assignment
    width = max(1, (1 << inputs) // 4)
    return f"{truth:0{width}x}"


def recover_model(root: Path = REPOSITORY_ROOT) -> Model:
    """Derive all 96 selected bits from the generated Monolith7 source."""
    functions: list[Function] = []
    function_ids: dict[tuple[int, frozenset[int]], int] = {}
    bits: list[tuple[int, list[tuple[int, int]]]] = []
    for word in (15, 16, 17):
        for bit in range(32):
            analysis = analyze_output_bit(7, word, bit, root=root, max_inputs=16)
            source_ids = sorted(
                {source_id for monomial in analysis.polynomial for source_id in _term_source_ids(monomial)},
                key=lambda source_id: (source_id % 32, source_id // 32),
            )
            if len(source_ids) > 10:
                raise ValueError(f"Monolith7 output word {word} bit {bit} exceeds ten essential inputs")
            index = {source_id: position for position, source_id in enumerate(source_ids)}
            normalized = frozenset(
                sum(1 << index[source_id] for source_id in _term_source_ids(monomial)) for monomial in analysis.polynomial
            )
            key = (len(source_ids), normalized)
            if key not in function_ids:
                function_ids[key] = len(functions)
                functions.append({"inputs": len(source_ids), "truth": _truth_table(*key)})
            bits.append((function_ids[key], [divmod(source_id, 32) for source_id in source_ids]))
    if len(functions) != 63 or len(bits) != 96:
        raise ValueError(f"unexpected tail model size: {len(functions)} functions, {len(bits)} bits")
    return {"version": 1, "output_words": [15, 16, 17], "functions": functions, "bits": bits}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--verify", type=Path)
    args = parser.parse_args()
    model = recover_model()
    if args.verify is not None:
        saved = json.loads(args.verify.read_text(encoding="utf-8"))
        if saved != json.loads(json.dumps(model)):
            raise SystemExit("Monolith7 tail model differs from generated source")
        print("Monolith7 tail model exactly matches the generated source")
    elif args.json:
        print(json.dumps(model, separators=(",", ":")))
    else:
        print(f"Recovered {len(model['functions'])} functions for {len(model['bits'])} output bits")


if __name__ == "__main__":
    main()
