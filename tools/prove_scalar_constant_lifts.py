"""Source-AST constant-product lift checks; optional development-only Z3.

Exact factors for c1..46 and the entire c>=47 class. A separate source-AST
product-threshold lemma uses arbitrary nonnegative products with exact small
residues and necessary factor-positivity constraints. NOT a whole-stage proof.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from tools import predict_scalar_defects as predictor
from tools import scalar_constant_lifts as rules
from tools.prove_scalar_predicate_guards import compile_guard
from tools.scalar_representative_rules import MODULUS


def prove(timeout_ms: int = 10000) -> dict[str, object]:
    import z3

    if timeout_ms <= 0:
        raise ValueError("positive solver timeout required")
    context = z3.Context()
    a, c, product, quotient, residue, b = z3.Ints("a c product quotient residue b", ctx=context)
    queries: dict[str, Any] = {}
    for ta in (False, True):
        tag = z3.BoolVal(ta, ctx=context)
        domain = z3.And(a >= 0, a < MODULUS, a <= 46 if ta else z3.BoolVal(True, ctx=context))
        raw = a + MODULUS * int(ta)
        for constant in range(1, 47):
            shortcut = compile_guard(z3, "lift", {"a": a, "cutoff": rules.threshold(constant), "lift_a": tag}, module=rules)
            queries[f"constant_{constant}_tag{int(ta)}"] = z3.And(domain, z3.Xor(shortcut, raw * constant >= 47))
        shortcut = compile_guard(z3, "lift", {"a": a, "cutoff": 1, "lift_a": tag}, module=rules)
        queries[f"all_constants_ge47_tag{int(ta)}"] = z3.And(domain, c >= 47, c < 1 << 160, z3.Xor(shortcut, raw * c >= 47))
    source = compile_guard(z3, "multiplication_lift", {"a": a, "b": b, "product": product}, module=predictor)
    queries["small_output_source_threshold_equals_raw47"] = z3.And(
        a >= 0,
        b >= 0,
        product >= 0,
        product < 1 << 320,
        quotient >= 0,
        residue >= 0,
        residue <= 46,
        product == MODULUS * quotient + residue,
        z3.Implies(z3.Or(a == 0, b == 0), product == 0),
        z3.Xor(source, product >= 47),
    )
    # Establish the high-constant threshold mathematically; concrete producer
    # calls are separately tested, rather than certifying a different producer.
    queries["all_constants_ge47_floor_threshold_is_one"] = z3.And(c >= 47, c < 1 << 160, 46 / c != 0)
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
        "scope": "actual lift/product-threshold AST; exact factor bounds and conditional source-threshold lemma; NOT threshold-producer AST, callback-execution, packed-kernel or whole-stage proof",
        "full_proof": all(row["proved"] for row in rows),
        "obligations": rows,
        "z3_version": z3.get_version_string(),
        "source_sha256": {
            name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in ("prove_scalar_constant_lifts.py", "scalar_constant_lifts.py", "predict_scalar_defects.py")
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
