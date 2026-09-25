"""Prove exact lazy carry decisions against rule and integer-source ASTs.

Optional development-only Z3. All uint160 pairs, exhaustive lift-count
partitions. Models stable Boolean callback results, not Python execution,
packed kernels or whole-stage equivalence.
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

WIDTH = 162


def prove(timeout_ms: int = 10000) -> dict[str, object]:
    import z3

    if timeout_ms <= 0:
        raise ValueError("positive solver timeout required")
    context = z3.Context()
    a, b = [z3.ZeroExt(2, z3.BitVec(n, 160, ctx=context)) for n in ("a", "b")]
    p = rules.MODULUS
    ta, tb = a >= p, b >= p
    ra, rb = z3.If(ta, a - p, a), z3.If(tb, b - p, b)
    zero, one = z3.BitVecVal(0, WIDTH, ctx=context), z3.BitVecVal(1, WIDTH, ctx=context)
    k = z3.If(ta, one, zero) + z3.If(tb, one, zero)
    inputs = {"a": ra, "b": rb, "lift_a": ta, "lift_b": tb}
    lazy_add = compile_guard(z3, "lazy_addition_defect", inputs, module=rules)
    lazy_sub = compile_guard(z3, "lazy_subtraction_defect", inputs, module=rules)
    reference_add = compile_guard(z3, "addition_defect", {"s": ra + rb, "k": k}, module=rules)
    reference_sub = compile_guard(z3, "subtraction_defect", {"a": ra, "b": rb, "ta": ta, "tb": tb}, module=rules)

    def canonical(value: Any) -> Any:
        return z3.If(value < 0, value + p, z3.If(value >= p, value - p, value))

    sum_expression = ra + rb + z3.If(lazy_add, z3.BitVecVal(arithmetic.ADD_DEFECT, WIDTH, ctx=context), zero)
    difference_expression = ra - rb + z3.If(lazy_sub, z3.BitVecVal(47, WIDTH, ctx=context), zero)
    add_tag = compile_guard(z3, "addition_tag", {"s": ra + rb, "k": k, "defective": lazy_add}, module=rules)
    sub_tag = compile_guard(z3, "subtraction_tag", {"a": ra, "b": rb, "ta": ta, "tb": tb}, module=rules)
    add_result = canonical(sum_expression) + z3.If(add_tag, z3.BitVecVal(p, WIDTH, ctx=context), zero)
    sub_result = canonical(difference_expression) + z3.If(sub_tag, z3.BitVecVal(p, WIDTH, ctx=context), zero)
    queries = {
        "addition_matches_original_defect": z3.Xor(lazy_add, reference_add),
        "subtraction_matches_original_defect": z3.Xor(lazy_sub, reference_sub),
        "addition_reconstructs_integer_source": compile_source(z3, "add", a, b) != add_result,
        "subtraction_reconstructs_integer_source": compile_source(z3, "subtract", a, b) != sub_result,
        "addition_large_sum_has_no_operand_lifts": z3.And(ra + rb >= p + 47, z3.Or(ta, tb)),
        "addition_small_defect_requires_both_lifts": z3.And(ra + rb >= 47, ra + rb <= 92, z3.Xor(lazy_add, z3.And(ta, tb))),
        "subtraction_true_left_lift_settles_false": z3.And(ta, lazy_sub),
    }
    rows = []
    for name, mismatch in queries.items():
        cases = []
        for count in range(3):
            solver = z3.Solver(ctx=context)
            solver.set(timeout=timeout_ms)
            solver.add(k == count, mismatch)
            result = solver.check()
            case = {"lift_count": count, "result": str(result), "proved": result == z3.unsat}
            if result == z3.unknown:
                case["reason"] = solver.reason_unknown()
            cases.append(case)
        rows.append({"name": name, "proved": all(case["proved"] for case in cases), "cases": cases})
    return {
        "scope": "actual lazy/rule/integer-source AST, all uint160 pairs; stable Boolean callback results only; NOT callback-execution, packed-kernel or whole-stage proof",
        "full_proof": all(row["proved"] for row in rows),
        "z3_version": z3.get_version_string(),
        "obligations": rows,
        "source_sha256": {
            name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in (
                "prove_scalar_lazy_guards.py",
                "scalar_representative_rules.py",
                "scalar_stage_plan.py",
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
