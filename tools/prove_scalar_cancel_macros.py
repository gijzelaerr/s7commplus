"""Check arbitrary-operand cancellation against composed actual integer ASTs."""

from __future__ import annotations

import argparse
import json

from tools import scalar_cancel_macros as macros
from tools.prove_scalar_predicate_guards import compile_guard
from tools.prove_transform12_residue_defects import compile_source
from tools.scalar_shift_macros import CORRECTION, LIMIT, LOW, P


def prove(timeout_ms: int = 10000) -> dict[str, object]:
    import z3

    if type(timeout_ms) is not int or timeout_ms <= 0:
        raise ValueError("positive solver timeout required")
    ctx = z3.Context()
    a, b = [z3.ZeroExt(2, z3.BitVec(name, 160, ctx=ctx)) for name in ("raw_a", "raw_b")]
    mu = z3.If(b >= P, b - P, b)
    mu_a = z3.If(a >= P, a - P, a)
    symbols = {"a": a, "b": b, "mu_a": mu_a, "mu_b": mu, "P": P, "LIMIT": LIMIT, "LOW": LOW}
    carry = compile_guard(z3, "cancellation_carry", symbols, module=macros)
    lift = compile_guard(z3, "cancellation_lift", symbols, module=macros)
    canceled = compile_source(z3, "subtract", compile_source(z3, "add", a, b), a)
    corrected = mu + z3.If(carry, z3.BitVecVal(CORRECTION, 162, ctx=ctx), z3.BitVecVal(0, 162, ctx=ctx))
    residue = z3.If(corrected < 0, corrected + P, corrected)
    result = residue + z3.If(lift, z3.BitVecVal(P, 162, ctx=ctx), z3.BitVecVal(0, 162, ctx=ctx))
    small_lift = compile_guard(z3, "restore_small_lift", symbols, module=macros)
    restored = compile_source(z3, "add", compile_source(z3, "subtract", a, b), b)
    small_result = mu_a + z3.If(small_lift, z3.BitVecVal(P, 162, ctx=ctx), z3.BitVecVal(0, 162, ctx=ctx))
    queries = {
        "arbitrary_cancel_add_source_ast_contract": canceled != result,
        "large_canceled_operand_has_canonical_output": z3.And(a >= 47, canceled >= P),
        "small_subtraction_restore_source_ast_contract": z3.And(b < 47, restored != small_result),
        "reject_cancel_add_as_raw_identity": canceled != b,
        "reject_small_restore_as_raw_identity": z3.And(b < 47, restored != a),
    }
    rows = []
    for name, mismatch in queries.items():
        solver = z3.Solver(ctx=ctx)
        solver.set(timeout=timeout_ms)
        solver.add(mismatch)
        result_status = solver.check()
        expected = z3.sat if name.startswith("reject_") else z3.unsat
        row = {"name": name, "result": str(result_status), "expected": str(expected), "proved": result_status == expected}
        if result_status == z3.unknown:
            row["reason"] = solver.reason_unknown()
        rows.append(row)
    return {
        "scope": "composed actual source and predicate ASTs; all uint160 operands; local proof, NOT whole-program equivalence",
        "full_proof": all(row["proved"] for row in rows),
        "obligations": rows,
        "z3_version": z3.get_version_string(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout-ms", type=int, default=10000)
    args = parser.parse_args()
    result = prove(args.timeout_ms)
    print(json.dumps(result, indent=2))
    if not result["full_proof"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
