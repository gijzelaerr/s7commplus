"""Prove the actual seven-state lift table and lazy addition/subtraction ASTs.

Optional development-only Z3. Addition/subtraction cover the full uint160
operand domain with actual defect/tag ASTs. Products use exact integer product
and a quotient equation, NOT an abstract product. Actual output residue and
defect decisions are preconditions; not a whole-stage/kernel proof.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from tools import predict_scalar_defects as predictor
from tools import scalar_lift_categories as categories
from tools import scalar_representative_rules as rules
from tools.prove_scalar_predicate_guards import compile_guard


def prove(timeout_ms: int = 10000) -> dict[str, object]:
    import z3

    if timeout_ms <= 0:
        raise ValueError("positive solver timeout required")
    context = z3.Context()
    p = categories.P
    rows = []

    def state(a: Any, lifted: bool) -> Any:
        return z3.If(
            a == 0,
            z3.BitVecVal(int(lifted), 4, ctx=context),
            z3.If(
                a <= 6,
                z3.BitVecVal(2 + int(lifted), 4, ctx=context),
                z3.If(a <= 46, z3.BitVecVal(4 + int(lifted), 4, ctx=context), z3.BitVecVal(6, 4, ctx=context)),
            ),
        )

    def check(name: str, mismatch: Any) -> None:
        solver = z3.Solver(ctx=context)
        solver.set(timeout=timeout_ms)
        solver.add(mismatch)
        result = solver.check()
        row = {"name": name, "result": str(result), "proved": result == z3.unsat}
        if result == z3.unknown:
            row["reason"] = solver.reason_unknown()
        rows.append(row)

    for ta in (False, True):
        for tb in (False, True):
            suffix = f"{int(ta)}{int(tb)}"
            la, lb = z3.BoolVal(ta, ctx=context), z3.BoolVal(tb, ctx=context)
            a, b = [z3.ZeroExt(2, z3.BitVec(name, 160, ctx=context)) for name in ("a", "b")]
            domain = z3.And(
                a < p, b < p, a <= 46 if ta else z3.BoolVal(True, ctx=context), b <= 46 if tb else z3.BoolVal(True, ctx=context)
            )
            for operation in ("addition", "subtraction"):
                if operation == "addition":
                    s = a + b
                    k = z3.BitVecVal(int(ta) + int(tb), 162, ctx=context)
                    defective = compile_guard(z3, "addition_defect", {"s": s, "k": k}, rules)
                    tag = compile_guard(z3, "addition_tag", {"s": s, "k": k, "defective": defective}, rules)
                    value = s + z3.If(
                        defective, z3.BitVecVal(94 - (1 << 128), 162, ctx=context), z3.BitVecVal(0, 162, ctx=context)
                    )
                else:
                    source_inputs = {"a": a, "b": b, "ta": la, "tb": lb}
                    defective = compile_guard(z3, "subtraction_defect", source_inputs, rules)
                    tag = compile_guard(z3, "subtraction_tag", source_inputs, rules)
                    value = a - b + z3.If(defective, z3.BitVecVal(47, 162, ctx=context), z3.BitVecVal(0, 162, ctx=context))
                residue = z3.If(value < 0, value + p, z3.If(value >= p, value - p, value))
                invalid_defect = residue < 94 if operation == "addition" else z3.Or(residue <= 0, residue > 46, z3.Not(tag))
                check(f"{operation}_defect_output_class_tag{suffix}", z3.And(domain, defective, invalid_defect))
                finite = compile_guard(
                    z3, f"{operation}_lift", {"a": state(a, ta), "b": state(b, tb), "defective": defective}, categories
                )
                lazy = compile_guard(
                    z3,
                    f"small_{operation}_lift",
                    {"a": a, "b": b, "defective": defective, "lift_a": la, "lift_b": lb},
                    categories,
                )
                check(f"{operation}_finite_table_tag{suffix}", z3.And(domain, residue <= 46, z3.Xor(finite, tag)))
                check(f"{operation}_lazy_table_tag{suffix}", z3.And(domain, residue <= 46, z3.Xor(lazy, tag)))
            ai, bi, quotient, residue_i = [z3.Int(name, ctx=context) for name in ("ai", "bi", "quotient", "residue")]
            product_domain = z3.And(
                0 <= ai,
                ai < p,
                0 <= bi,
                bi < p,
                quotient >= 0,
                ai <= 46 if ta else z3.BoolVal(True, ctx=context),
                bi <= 46 if tb else z3.BoolVal(True, ctx=context),
                ai * bi == p * quotient + residue_i,
            )
            threshold = compile_guard(z3, "multiplication_lift", {"a": ai + p * int(ta), "b": bi + p * int(tb)}, predictor)
            for name, extra in (("zero", residue_i == 0), ("nonzero", z3.And(0 < residue_i, residue_i <= 46))):
                finite = compile_guard(z3, f"{name}_product_lift", {"a": state(ai, ta), "b": state(bi, tb)}, categories)
                check(f"{name}_product_finite_table_tag{suffix}", z3.And(product_domain, extra, z3.Xor(finite, threshold)))
    for ta in (False, True):
        a, quotient, residue = [z3.Int(name, ctx=context) for name in ("square_a", "square_q", "square_r")]
        domain = z3.And(
            0 <= a,
            a < p,
            a <= 46 if ta else z3.BoolVal(True, ctx=context),
            quotient >= 0,
            0 <= residue,
            residue <= 46,
            a * a == p * quotient + residue,
        )
        finite = compile_guard(z3, "square_lift", {"a": state(a, ta)}, categories)
        raw = a + p * int(ta)
        threshold = compile_guard(z3, "multiplication_lift", {"a": raw, "b": raw}, predictor)
        check(f"square_finite_table_tag{int(ta)}", z3.And(domain, z3.Xor(finite, threshold)))
    return {
        "scope": "actual seven-state/lazy lift ASTs vs exact primitive defect/tag/product-threshold ASTs; true corrected output0..46; exact product; NOT full stage/kernel proof",
        "full_proof": all(row["proved"] for row in rows),
        "z3_version": z3.get_version_string(),
        "obligations": rows,
        "source_sha256": {
            name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in (
                "scalar_lift_categories.py",
                "prove_scalar_lift_categories.py",
                "prove_scalar_predicate_guards.py",
                "scalar_representative_rules.py",
                "predict_scalar_defects.py",
            )
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout-ms", type=int, default=10000)
    report = prove(parser.parse_args().timeout_ms)
    print(json.dumps(report, indent=2))
    if not report["full_proof"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
