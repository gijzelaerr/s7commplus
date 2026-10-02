"""Source-AST uint160 proof of lazy addition lifts, including zero.

Optional development-only Z3. Compare the actual lazy-rule AST with both
the original lift-count tag AST and the integer-model addition AST.
Callbacks denote stable Boolean results, not their Python execution.
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

WIDTH = 162  # All signed uint160 addition intermediates fit.


def prove(timeout_ms: int = 10000) -> dict[str, object]:
    import z3

    if timeout_ms <= 0:
        raise ValueError("positive solver timeout required")
    context = z3.Context()
    a, b = [z3.ZeroExt(WIDTH - 160, z3.BitVec(name, 160, ctx=context)) for name in ("a", "b")]
    p = rules.MODULUS
    ta, tb = a >= p, b >= p
    ra, rb = z3.If(ta, a - p, a), z3.If(tb, b - p, b)
    s = ra + rb
    k = z3.If(ta, 1, 0) + z3.If(tb, 1, 0)
    defect = compile_guard(z3, "addition_defect", {"s": s, "k": k}, module=rules)
    lazy = compile_guard(z3, "addition_lift", {"s": s, "lift_a": ta, "lift_b": tb}, module=rules)
    tag = compile_guard(z3, "addition_tag", {"s": s, "k": k, "defective": defect}, module=rules)
    source = compile_source(z3, "add", a, b)
    queries = {
        "lazy_addition_lift_matches_rule": z3.Xor(lazy, tag),
        "lazy_addition_lift_matches_source": z3.Xor(lazy, source >= p),
        "known_defect_settles_unlifted": z3.And(defect, z3.Or(lazy, source >= p)),
        "wrap_interval_settles_lifted": z3.And(z3.Not(defect), s >= p, s < p + 47, z3.Not(lazy)),
        "outside_small_sum_and_wrap_settles_unlifted": z3.And(s > 46, z3.Or(s < p, s >= p + 47), lazy),
        "small_sum_requires_operand_or": z3.And(s <= 46, z3.Not(defect), z3.Xor(lazy, z3.Or(ta, tb))),
        "zero_output_matches_positivity": z3.And(z3.Or(source == 0, source == p), z3.Xor(lazy, z3.Or(a > 0, b > 0))),
    }
    rows = []
    for name, mismatch in queries.items():
        cases = []
        # Exhaustive legal operand-lift counts; no randomized fallback.
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
        "scope": "actual lazy/tag/integer-addition AST, all uint160 operand pairs, no defect decision needed by lazy rule; Boolean callback results only; NOT callback-execution, packed-kernel or whole-stage proof",
        "full_proof": all(row["proved"] for row in rows),
        "z3_version": z3.get_version_string(),
        "obligations": rows,
        "source_sha256": {
            name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in (
                "scalar_representative_rules.py",
                "prove_scalar_addition_shortcuts.py",
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
