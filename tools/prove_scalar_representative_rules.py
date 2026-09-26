"""Optional source-AST SMT proof of standalone addition/subtraction rules.

No whole-ladder or generated packed-kernel certificate is claimed.
Multiplication uses the previously proved fold/lift lemmas and numeric controls;
it is deliberately not included in this solver report.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from tools import scalar_representative_rules as rules
from tools import transform12_residue_defects as arithmetic
from tools.prove_scalar_predicate_guards import compile_guard
from tools.prove_transform12_residue_defects import compile_source

# Signed sums/differences of uint160 operands fit162 bits. Multiplication
# is not compiled here and retains322-bit obligations in the fold prover.
WIDTH = 162


def prove(timeout_ms: int = 10000) -> dict[str, object]:
    import z3

    if timeout_ms <= 0:
        raise ValueError("positive solver timeout required")
    ctx = z3.Context()
    a, b = [z3.ZeroExt(WIDTH - 160, z3.BitVec(n, 160, ctx=ctx)) for n in ("a", "b")]
    p = rules.MODULUS
    ta, tb = a >= p, b >= p
    ra, rb = z3.If(ta, a - p, a), z3.If(tb, b - p, b)
    s = ra + rb
    zero, one = z3.BitVecVal(0, WIDTH, ctx=ctx), z3.BitVecVal(1, WIDTH, ctx=ctx)
    k = z3.If(ta, one, zero) + z3.If(tb, one, zero)

    def guard(name: str, **inputs: Any) -> Any:
        return compile_guard(z3, name, inputs, module=rules)

    add_defect = guard("addition_defect", s=s, k=k)
    sub_inputs = {"a": ra, "b": rb, "ta": ta, "tb": tb}
    sub_defect = guard("subtraction_defect", **sub_inputs)
    add_tag = guard("addition_tag", s=s, k=k, defective=add_defect)
    sub_tag = guard("subtraction_tag", **sub_inputs)
    source_add, source_sub = compile_source(z3, "add", a, b), compile_source(z3, "subtract", a, b)

    def canonical(value: Any) -> Any:
        # Every corrected residue expression lies in (-p, 2p).
        return z3.If(value < 0, value + p, z3.If(value >= p, value - p, value))

    sum_expression = s + z3.If(add_defect, z3.BitVecVal(arithmetic.ADD_DEFECT, WIDTH, ctx=ctx), zero)
    difference_expression = ra - rb + z3.If(sub_defect, z3.BitVecVal(47, WIDTH, ctx=ctx), zero)
    add_result = canonical(sum_expression) + z3.If(add_tag, z3.BitVecVal(p, WIDTH, ctx=ctx), zero)
    sub_result = canonical(difference_expression) + z3.If(sub_tag, z3.BitVecVal(p, WIDTH, ctx=ctx), zero)
    source_add_defect = z3.And(a + b >= p + 47, ((a + b) & (arithmetic.LOW_LIMIT - 1)) >= arithmetic.LOW_LIMIT - 47)
    queries = {
        "addition_defect_rule": z3.Xor(add_defect, source_add_defect),
        "subtraction_defect_rule": z3.Xor(sub_defect, a - b < -p),
        "addition_corrected_expression_bounds": z3.Or(sum_expression <= -p, sum_expression >= 2 * p),
        "subtraction_corrected_expression_bounds": z3.Or(difference_expression <= -p, difference_expression >= 2 * p),
        "addition_exact_representative": source_add != add_result,
        "subtraction_exact_representative": source_sub != sub_result,
        "constant_addition_exclusion": z3.And(guard("addition_constant_safe", c=b), source_add_defect),
        "constant_right_subtraction_exclusion": z3.And(guard("subtraction_right_constant_safe", c=b), a - b < -p),
        "constant_left_subtraction_exclusion": z3.And(guard("subtraction_left_constant_safe", c=a), a - b < -p),
    }
    rows = []
    for name, mismatch in queries.items():
        # The lift count is constructed from two Booleans, so 0/1/2 is
        # an exhaustive partition, not an additional domain assumption.
        # Splitting addition avoids expensive branch search under load.
        partitions = (0, 1, 2) if name.startswith("addition_") else (None,)
        cases = []
        for lift_count in partitions:
            solver = z3.Solver(ctx=ctx)
            solver.set(timeout=timeout_ms)
            solver.add(mismatch)
            if lift_count is not None:
                solver.add(k == lift_count)
            result = solver.check()
            case = {"lift_count": lift_count, "result": str(result), "proved": result == z3.unsat}
            if result == z3.unknown:
                case["reason"] = solver.reason_unknown()
            cases.append(case)
        proved = all(case["proved"] for case in cases)
        row = {"name": name, "result": "unsat" if proved else "unproved", "proved": proved, "cases": cases}
        rows.append(row)
    return {
        "scope": "actual rule and integer-model AST, all uint160 addition/subtraction inputs and constant carry exclusions; NOT multiplication or whole-ladder SMT proof",
        "full_proof": all(row["proved"] for row in rows),
        "obligations": rows,
        "source_sha256": {
            name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in (
                "scalar_representative_rules.py",
                "prove_scalar_representative_rules.py",
                "prove_scalar_predicate_guards.py",
                "prove_transform12_residue_defects.py",
                "transform12_integer_model.py",
            )
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout-ms", type=int, default=10000)
    args = parser.parse_args()
    report = prove(args.timeout_ms)
    print(json.dumps(report, indent=2))
    if not report["full_proof"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
