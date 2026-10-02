"""Conditional exact source-AST square-lift obligations; optional dev-only Z3."""

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
    a, quotient, residue = [z3.Int(name, ctx=context) for name in ("a", "quotient", "residue")]
    p = rules.MODULUS
    rows = []
    for ta in (False, True):
        lift = z3.BoolVal(ta, ctx=context)
        domain = z3.And(
            0 <= a,
            a < p,
            a <= 46 if ta else z3.BoolVal(True, ctx=context),
            quotient >= 0,
            0 <= residue,
            residue <= 46,
            a * a == p * quotient + residue,
        )
        shortcut = compile_guard(z3, "square_lift", {"a": a, "lift_a": lift}, module=rules)
        raw = a + p * int(ta)
        source = compile_guard(z3, "multiplication_lift", {"a": raw, "b": raw}, module=predictor)
        queries = {
            f"square_lift_matches_source_threshold_tag{int(ta)}": z3.And(domain, z3.Xor(shortcut, source)),
            f"settled_square_needs_no_input_lift_tag{int(ta)}": z3.And(domain, a >= 7, z3.Not(source)),
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
        "scope": "actual square-lift/product-threshold AST; output residue0..46; exact integer square; NOT a whole-stage proof",
        "full_proof": all(row["proved"] for row in rows),
        "z3_version": z3.get_version_string(),
        "obligations": rows,
        "source_sha256": {
            name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in (
                "scalar_representative_rules.py",
                "prove_scalar_square_shortcuts.py",
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
