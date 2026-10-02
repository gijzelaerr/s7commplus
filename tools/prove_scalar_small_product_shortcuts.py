"""Conditional actual-AST proof eliminating small-output product thresholds.

Optional development-only Z3. Exact canonical product, exhaustive four lift
pairs and residue1..46, with no product abstraction or prime assumption.
Uses the separately proved source product-threshold/fold lemma; not a packed
kernel, callback-execution, stage or whole-pipeline SMT proof.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from tools import predict_scalar_defects as predictor
from tools import scalar_representative_rules as rules
from tools.prove_scalar_predicate_guards import compile_guard


def prove(timeout_ms: int = 10000) -> dict[str, object]:
    import z3

    if timeout_ms <= 0:
        raise ValueError("positive solver timeout required")
    context = z3.Context()
    a, b, quotient, residue = [z3.Int(name, ctx=context) for name in ("a", "b", "quotient", "residue")]
    p = rules.MODULUS
    rows = []
    for ta in (False, True):
        for tb in (False, True):
            la, lb = z3.BoolVal(ta, ctx=context), z3.BoolVal(tb, ctx=context)
            domain = z3.And(
                0 <= a,
                a < p,
                0 <= b,
                b < p,
                a <= 46 if ta else z3.BoolVal(True, ctx=context),
                b <= 46 if tb else z3.BoolVal(True, ctx=context),
                quotient >= 0,
                0 < residue,
                residue <= 46,
                a * b == p * quotient + residue,
            )
            inputs = {"a": a, "b": b, "lift_a": la, "lift_b": lb}
            shortcut = compile_guard(z3, "small_nonzero_product_lift", inputs, module=rules)
            previous = compile_guard(z3, "nonzero_product_lift", inputs, module=rules)
            source = compile_guard(z3, "multiplication_lift", {"a": a + p * int(ta), "b": b + p * int(tb)}, module=predictor)
            queries = {
                f"small_product_matches_source_threshold_tag{int(ta)}{int(tb)}": z3.And(domain, z3.Xor(shortcut, source)),
                f"small_product_matches_previous_lazy_rule_tag{int(ta)}{int(tb)}": z3.And(domain, z3.Xor(shortcut, previous)),
            }
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
        "scope": "actual small-product/previous-lazy/source-threshold ASTs; exact residue product; residue1..46; four legal lift pairs; NOT whole-stage proof",
        "full_proof": all(row["proved"] for row in rows),
        "z3_version": z3.get_version_string(),
        "obligations": rows,
        "source_sha256": {
            name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in (
                "scalar_representative_rules.py",
                "prove_scalar_small_product_shortcuts.py",
                "prove_scalar_predicate_guards.py",
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
