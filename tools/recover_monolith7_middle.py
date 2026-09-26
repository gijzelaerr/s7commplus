"""Recover exact, factored Boolean formulas for Monolith7 output words 3–5.

The backward slices are substantially larger than the previously recovered
15–17 triplet, but each individual output bit still has a short polynomial.
The ANFs decompose into shared conditional-selection and majority cores.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import TypedDict

from tools.analyze_symbolic_monolith import analyze_output_bit
from tools.decompose_boolean_polynomial import CORE_FORMULAS, FactoredFunction, Kernel, factor_function
from tools.recover_monolith5 import _term_source_ids
from tools.trace_session_auth_output import REPOSITORY_ROOT


class Model(TypedDict):
    version: int
    output_words: list[int]
    kernels: list[Kernel]
    functions: list[FactoredFunction]
    bits: list[tuple[int, list[tuple[int, int]]]]


def recover_model(root: Path = REPOSITORY_ROOT) -> Model:
    """Derive all 96 selected bits from the pinned generated source."""
    kernels: list[Kernel] = []
    functions: list[FactoredFunction] = []
    function_ids: dict[tuple[int, frozenset[int]], int] = {}
    bits: list[tuple[int, list[tuple[int, int]]]] = []
    for word in (3, 4, 5):
        for bit in range(32):
            analysis = analyze_output_bit(7, word, bit, root=root)
            source_ids = sorted(
                {source_id for monomial in analysis.polynomial for source_id in _term_source_ids(monomial)},
                key=lambda source_id: (source_id % 32, source_id // 32),
            )
            if len(source_ids) > 14:
                raise ValueError(f"Monolith7 output word {word} bit {bit} exceeds 14 essential inputs")
            index = {source_id: position for position, source_id in enumerate(source_ids)}
            normalized = frozenset(
                sum(1 << index[source_id] for source_id in _term_source_ids(monomial)) for monomial in analysis.polynomial
            )
            key = (len(source_ids), normalized)
            if key not in function_ids:
                function_ids[key] = len(functions)
                functions.append(factor_function(len(source_ids), normalized, kernels))
            bits.append((function_ids[key], [divmod(source_id, 32) for source_id in source_ids]))
    if len(functions) != 68 or len(bits) != 96:
        raise ValueError(f"unexpected middle model size: {len(functions)} functions, {len(bits)} bits")
    return {"version": 2, "output_words": [3, 4, 5], "kernels": kernels, "functions": functions, "bits": bits}


def format_formula(model: Model, word: int, bit: int) -> str:
    """Describe one exact output bit using named cores and source-bit selectors."""
    if word not in model["output_words"] or not 0 <= bit < 32:
        raise ValueError("formula requires output word 3, 4, or 5 and bit 0..31")
    function_id, refs = model["bits"][model["output_words"].index(word) * 32 + bit]
    function = model["functions"][function_id]

    def expression(terms: list[int], names: list[str]) -> str:
        variables = sorted({index for term in terms for index in _term_source_ids(term)})
        if len(variables) == 2:
            normalized = frozenset(
                sum(1 << position for position, variable in enumerate(variables) if term & (1 << variable)) for term in terms
            )
            first, second = (names[index] for index in variables)
            if normalized in (frozenset({1, 2, 3}), frozenset({0, 1, 2, 3})):
                formula = f"{first} OR {second}"
                return f"NOT ({formula})" if 0 in normalized else formula
        monomials = []
        for term in terms:
            factors = [names[index] for index in _term_source_ids(term)]
            monomials.append("(" + " AND ".join(factors) + ")" if len(factors) > 1 else factors[0] if factors else "1")
        return " XOR ".join(monomials) if monomials else "0"

    def kernel_name(index: int) -> str:
        kernel = model["kernels"][index]
        known = CORE_FORMULAS.get((kernel["inputs"], frozenset(kernel["terms"])))
        return known[0] if known is not None else f"core{index}"

    definitions = {}
    for index in sorted({step[0] for step in function["steps"]}):
        kernel = model["kernels"][index]
        names = list("abcd"[: kernel["inputs"]])
        known = CORE_FORMULAS.get((kernel["inputs"], frozenset(kernel["terms"])))
        formula = known[1] if known is not None else expression(kernel["terms"], names)
        for name, prerequisite in CORE_FORMULAS.values():
            if name in ("choose", "majority") and f"{name}(" in formula:
                definitions[name] = f"{name}(a, b, c) = {prerequisite}"
        definitions[kernel_name(index)] = f"{kernel_name(index)}({', '.join(names)}) = {formula}"
    lines = list(definitions.values())
    names = [f"x{index}" for index in range(len(refs))]
    lines.extend(f"{name} = source[{source_word}].bit[{source_bit}]" for name, (source_word, source_bit) in zip(names, refs))
    for step_index, (kernel_id, arguments, inversions) in enumerate(function["steps"]):
        selected = [
            f"({names[reference]} XOR 1)" if inversions & (1 << position) else names[reference]
            for position, reference in enumerate(arguments)
        ]
        name = f"t{step_index}"
        lines.append(f"{name} = {kernel_name(kernel_id)}({', '.join(selected)})")
        names.append(name)
    lines.append(f"output[{word}].bit[{bit}] = {expression(function['terms'], names)}")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--json", action="store_true")
    mode.add_argument("--verify", type=Path)
    mode.add_argument("--formula", nargs=2, type=int, metavar=("WORD", "BIT"))
    args = parser.parse_args()
    model = recover_model()
    if args.formula is not None:
        print(format_formula(model, *args.formula))
    elif args.verify is not None:
        saved = json.loads(args.verify.read_text(encoding="utf-8"))
        if saved != json.loads(json.dumps(model)):
            raise SystemExit("Monolith7 middle model differs from generated source")
        print("Monolith7 middle model exactly matches the generated source")
    elif args.json:
        print(json.dumps(model, separators=(",", ":")))
    else:
        print(f"Recovered {len(model['functions'])} functions for {len(model['bits'])} output bits")


if __name__ == "__main__":
    main()
