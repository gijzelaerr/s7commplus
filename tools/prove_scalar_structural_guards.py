"""Prove the primitive lemmas used by raw-value structural guard analysis.

Actual integer-source ASTs; optional development-only Z3. Product folds are
quantified over arbitrary uint320 products, followed by an independent exact
integer factor lemma. This is NOT a proof of generated kernels or the analyzer.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from tools.prove_transform12_residue_defects import compile_source
from tools.prove_scalar_predicate_guards import compile_guard
from tools import scalar_representative_rules as rules
from tools.scalar_representative_rules import MODULUS


def prove(timeout_ms: int = 10000) -> dict[str, object]:
    import z3

    if timeout_ms <= 0:
        raise ValueError("positive solver timeout required")
    context = z3.Context()
    a, b, right = [z3.ZeroExt(2, z3.BitVec(n, 160, ctx=context)) for n in ("a", "b", "right")]
    summed = compile_source(z3, "add", a, b)
    subtracted = compile_source(z3, "subtract", a, b)
    ta, tb = a >= MODULUS, b >= MODULUS
    ra, rb = z3.If(ta, a - MODULUS, a), z3.If(tb, b - MODULUS, b)
    addition_defect = compile_guard(z3, "lazy_addition_defect", {"a": ra, "b": rb, "lift_a": ta, "lift_b": tb}, module=rules)
    bound = z3.ZeroExt(156, z3.BitVec("bound", 6, ctx=context))
    queries: dict[str, Any] = {
        "small_raw_add_is_exact_sum": z3.And(summed <= 46, z3.Or(summed != a + b, a > summed, b > summed)),
        "add_saturated_lower_bound": z3.And(a + b >= 47, summed < 47),
        "subtraction_raw_second_wrap_condition": z3.Xor(a - b < -MODULUS, z3.And(a < MODULUS, b >= MODULUS, a < b - MODULUS)),
        "subtraction_source_wrap_reconstruction": subtracted
        != z3.If(a - b >= 0, a - b, a - b + MODULUS)
        + z3.If(a - b < -MODULUS, z3.BitVecVal(1 << 160, 162, ctx=context), z3.BitVecVal(0, 162, ctx=context)),
        "subtraction_defect_requires_small_raw_left": z3.And(a >= 47, a - b < -MODULUS),
        "raw_lower_bound_settles_small_residue_lift": z3.And(a >= 47, z3.If(a >= MODULUS, a - MODULUS, a) <= 46, a < MODULUS),
        "defective_addition_raw_output_is_large": z3.And(addition_defect, summed < 47),
        "defective_subtraction_raw_output_is_large": z3.And(a - b < -MODULUS, subtracted < 47),
        "addition_left_subtraction_dominance": z3.And(summed - right < -MODULUS, a - right >= -MODULUS),
        "addition_right_subtraction_dominance": z3.And(summed - right < -MODULUS, b - right >= -MODULUS),
        "addition_subtraction_cancellation_has_no_second_wrap": summed - b < -MODULUS,
        "subtraction_nonnegative_lower_bound": z3.And(bound <= 47, a >= bound, b <= bound, subtracted < bound - b),
        "subtraction_zero_is_identity": compile_source(z3, "subtract", a, z3.BitVecVal(0, 162, ctx=context)) != a,
    }
    product = z3.ZeroExt(2, z3.BitVec("arbitrary_product", 320, ctx=context))
    placeholder = z3.BitVecVal(0, 322, ctx=context)
    folded = compile_source(z3, "multiply", placeholder, placeholder, product)
    queries["small_raw_product_is_unfolded"] = z3.And(folded <= 46, z3.Or(product >= 47, folded != product))
    queries["product_saturated_lower_bound"] = z3.And(product >= 47, folded < 47)
    u, v = z3.Ints("factor_u factor_v", ctx=context)
    queries["positive_factor_small_product_dominance"] = z3.And(u >= 0, v >= 1, u * v <= 46, u > u * v)
    queries["square_small_product_dominance"] = z3.And(u >= 0, u * u <= 46, u > u * u)
    # Negative controls prevent confusing raw and modular monotonicity or
    # inheriting ancestors through a zero multiplier.
    queries["reject_zero_factor_ancestry"] = z3.And(u >= 0, v == 0, u * v <= 46, u > u * v)
    queries["reject_unconditional_add_monotonicity"] = summed < a
    rows = []
    for name, mismatch in queries.items():
        solver = z3.Solver(ctx=context)
        solver.set(timeout=timeout_ms)
        solver.add(mismatch)
        result = solver.check()
        expected = z3.sat if name.startswith("reject_") else z3.unsat
        row = {"name": name, "result": str(result), "expected": str(expected), "proved": result == expected}
        if result == z3.unknown:
            row["reason"] = solver.reason_unknown()
        rows.append(row)
    return {
        "scope": "actual integer-source primitive AST lemmas plus exact integer factors; NOT analyzer, packed-kernel or whole-stage proof",
        "full_proof": all(row["proved"] for row in rows),
        "obligations": rows,
        "z3_version": z3.get_version_string(),
        "source_sha256": {
            name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in (
                "prove_scalar_structural_guards.py",
                "scalar_structural_guards.py",
                "transform12_integer_model.py",
                "scalar_representative_rules.py",
                "prove_scalar_predicate_guards.py",
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
