"""Conditional source-AST proof of the lazy nonzero multiplication lift rule.

Optional development-only Z3. Residue products are abstracted to nonnegative
integers; the four distributive lift expansions are checked separately. Uses
the previously source-AST-proved product-threshold/fold lemmas, not a new
packed-kernel proof. Does NOT prove callback execution or whole-stage behavior.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from tools import predict_scalar_defects as predictor
from tools import scalar_representative_rules as rules
from tools.prove_scalar_predicate_guards import compile_guard


def prove(timeout_ms: int = 10000) -> dict[str, object]:
    import z3

    if timeout_ms <= 0:
        raise ValueError("positive solver timeout required")
    context = z3.Context()
    a, b, product, quotient, residue = [z3.Int(name, ctx=context) for name in ("a", "b", "product", "quotient", "residue")]
    ta, tb = [z3.Bool(name, ctx=context) for name in ("ta", "tb")]
    p = rules.MODULUS
    domain = z3.And(0 < a, a < p, 0 < b, b < p, product >= 0, product < p * p, z3.Implies(ta, a <= 46), z3.Implies(tb, b <= 46))

    def expanded(v: Any, lift_a: Any, lift_b: Any) -> Any:
        return v + p * z3.If(lift_a, b, 0) + p * z3.If(lift_b, a, 0) + p * p * z3.If(z3.And(lift_a, lift_b), 1, 0)

    full_product = expanded(product, ta, tb)
    shortcut = compile_guard(
        z3, "nonzero_product_lift", {"a": a, "b": b, "product": product, "lift_a": ta, "lift_b": tb}, module=rules
    )
    settled = compile_guard(
        z3,
        "nonzero_product_lift",
        {"a": a, "b": b, "product": product, "lift_a": z3.BoolVal(False, ctx=context), "lift_b": z3.BoolVal(False, ctx=context)},
        module=rules,
    )
    source_threshold = compile_guard(
        z3,
        "multiplication_lift",
        {"a": a + p * z3.If(ta, 1, 0), "b": b + p * z3.If(tb, 1, 0), "product": full_product},
        module=predictor,
    )
    queries = {
        "nonzero_lazy_lift_matches_source_threshold": z3.And(domain, z3.Xor(shortcut, source_threshold)),
        "settled_product_needs_no_operand_lifts": z3.And(domain, settled, z3.Not(source_threshold)),
        "nonzero_residue_requires_nonzero_operand_residues": z3.And(
            a >= 0,
            a < p,
            b >= 0,
            b < p,
            product >= 0,
            quotient >= 0,
            0 < residue,
            residue <= 46,
            product == p * quotient + residue,
            z3.Or(a == 0, b == 0),
            z3.Implies(z3.Or(a == 0, b == 0), product == 0),
        ),
    }
    # No nonlinear solver assumption is needed for the product abstraction:
    # each exact distributive expansion normalizes to zero coefficients.
    for lift_a in (False, True):
        for lift_b in (False, True):
            actual = (a + p * int(lift_a)) * (b + p * int(lift_b))
            expansion = expanded(a * b, z3.BoolVal(lift_a, ctx=context), z3.BoolVal(lift_b, ctx=context))
            difference = z3.simplify(actual - expansion, som=True)
            queries[f"lift_product_expansion_{int(lift_a)}{int(lift_b)}"] = difference != 0
    rows = []
    for name, mismatch in queries.items():
        solver = z3.Solver(ctx=context)
        solver.set(timeout=timeout_ms)
        solver.add(mismatch)
        result = solver.check()
        row = {"name": name, "result": str(result), "proved": result == z3.unsat}
        if result == z3.unknown:
            row["reason"] = solver.reason_unknown()
        rows.append(row)
    return {
        "scope": "actual lazy-rule/product-threshold AST; positive canonical operand residues; abstract nonnegative residue product and four exact lift expansions; NOT callback-execution, packed-kernel or whole-stage proof",
        "full_proof": all(row["proved"] for row in rows),
        "z3_version": z3.get_version_string(),
        "obligations": rows,
        "source_sha256": {
            name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in (
                "scalar_representative_rules.py",
                "prove_scalar_product_shortcuts.py",
                "prove_scalar_predicate_guards.py",
                "predict_scalar_defects.py",
                "scalar_stage_plan.py",
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
