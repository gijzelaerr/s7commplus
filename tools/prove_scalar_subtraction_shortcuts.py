"""Source-AST uint160 proof of lazy subtraction lifts, including zero.

Optional development-only Z3. The actual lazy-rule AST is compared with both
the standalone tag AST and the integer-model subtraction AST. Boolean
callbacks denote stable results; their execution is tested, not SMT-proved.
Not a packed-kernel or whole-stage certificate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from tools import scalar_representative_rules as rules
from tools.prove_scalar_predicate_guards import compile_guard
from tools.prove_transform12_residue_defects import compile_source

WIDTH = 162  # Every signed uint160 subtraction intermediate fits.


def prove(timeout_ms: int = 10000) -> dict[str, object]:
    import z3

    if timeout_ms <= 0:
        raise ValueError("positive solver timeout required")
    context = z3.Context()
    a, b = [z3.ZeroExt(WIDTH - 160, z3.BitVec(name, 160, ctx=context)) for name in ("a", "b")]
    p = rules.MODULUS
    ta, tb = a >= p, b >= p
    ra, rb = z3.If(ta, a - p, a), z3.If(tb, b - p, b)
    defect = compile_guard(z3, "subtraction_defect", {"a": ra, "b": rb, "ta": ta, "tb": tb}, module=rules)
    lazy = compile_guard(
        z3, "subtraction_lift", {"a": ra, "b": rb, "defective": defect, "lift_a": ta, "lift_b": tb}, module=rules
    )
    tag = compile_guard(z3, "subtraction_tag", {"a": ra, "b": rb, "ta": ta, "tb": tb}, module=rules)
    source = compile_source(z3, "subtract", a, b)
    queries = {
        "lazy_subtraction_lift_matches_rule": z3.Xor(lazy, tag),
        "lazy_subtraction_lift_matches_source": z3.Xor(lazy, source >= p),
        "large_residue_settles_unlifted": z3.And(z3.Or(ra > 46, rb > 46), lazy),
        "known_defect_settles_lifted": z3.And(defect, z3.Or(z3.Not(lazy), source < p)),
        "zero_output_matches_raw_comparison": z3.And(z3.Or(source == 0, source == p), z3.Xor(lazy, a > b)),
        "identical_source_operands_need_no_lift": z3.And(a == b, z3.Or(lazy, source != 0)),
        "declining_residues_or_false_left_lift_settle_unlifted": z3.And(z3.Not(defect), z3.Or(ra < rb, z3.Not(ta)), lazy),
    }
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
        "scope": "actual lazy/tag/integer-subtraction AST, all uint160 operand pairs, exact decided defect; Boolean callback results only; NOT callback-execution, packed-kernel or whole-stage proof",
        "full_proof": all(row["proved"] for row in rows),
        "z3_version": z3.get_version_string(),
        "obligations": rows,
        "source_sha256": {
            name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in (
                "scalar_representative_rules.py",
                "prove_scalar_subtraction_shortcuts.py",
                "prove_scalar_predicate_guards.py",
                "prove_transform12_residue_defects.py",
                "transform12_integer_model.py",
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
