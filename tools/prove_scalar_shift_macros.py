"""Prove representation-changing macros against composed source integer ASTs.

Alluint160 inputs and all47<=c<p. Optional development-only Z3, no prime or
curve assumptions. Proves local macro contracts, not a whole-tail replacement.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from tools import scalar_shift_macros as macros
from tools.prove_scalar_predicate_guards import compile_guard
from tools.prove_transform12_residue_defects import compile_source


def prove(timeout_ms: int = 10000) -> dict[str, object]:
    import z3

    if type(timeout_ms) is not int or timeout_ms <= 0:
        raise ValueError("positive solver timeout required")
    ctx = z3.Context()
    a, c = [z3.ZeroExt(2, z3.BitVec(n, 160, ctx=ctx)) for n in ("raw_a", "constant_c")]
    p, low = macros.P, macros.LOW
    mu = z3.If(a >= p, a - p, a)
    symbols = {"raw": a, "mu": mu, "c": c, "LIMIT": macros.LIMIT, "LOW": low}
    b1 = compile_guard(z3, "canonical_carry", symbols, module=macros)
    b2 = compile_guard(z3, "lifted_carry", symbols, module=macros)
    b1_mu = compile_guard(z3, "canonical_carry", symbols | {"raw": mu}, module=macros)
    independent = compile_guard(z3, "lift_independent_constant", {"c": c, "P": p, "LOW": low}, module=macros)
    near_p = compile_guard(z3, "near_p_carry", {"mu": mu, "n": p - c, "LOW": low}, module=macros)
    first = compile_source(z3, "subtract", compile_source(z3, "add", a, c), c)
    second = compile_source(z3, "add", compile_source(z3, "subtract", a, c), c)
    k = z3.BitVecVal(macros.CORRECTION, 162, ctx=ctx)
    zero = z3.BitVecVal(0, 162, ctx=ctx)
    t1, t2 = mu + z3.If(b1, k, zero), mu + z3.If(b2, k, zero)
    r1, r2 = z3.If(t1 < 0, t1 + p, t1), z3.If(t2 < 0, t2 + p, t2)
    queries = {
        "canonical_shift_source_ast_contract": first != r1,
        "lifted_shift_source_ast_contract": second != z3.If(r2 <= 46, r2 + p, r2),
        "canonicalizer_lift_independence_in_declared_domain": z3.And(independent, z3.Xor(b1, b1_mu)),
        "near_p_constant_carry_closed_formula": z3.And(p - c < low - 94, z3.Xor(b1, near_p)),
        "reject_canonical_shift_as_plain_residue": first != mu,
        "reject_lifted_shift_as_raw_identity": second != a,
    }
    rows = []
    for name, mismatch in queries.items():
        solver = z3.Solver(ctx=ctx)
        solver.set(timeout=timeout_ms)
        solver.add(c >= 47, c < p, mismatch)
        result = solver.check()
        expected = z3.sat if name.startswith("reject_") else z3.unsat
        row = {"name": name, "result": str(result), "expected": str(expected), "proved": result == expected}
        if result == z3.unknown:
            row["reason"] = solver.reason_unknown()
        rows.append(row)
    return {
        "scope": "composed actual integer-source and carry-predicate ASTs; NOT packed-kernel or whole-tail proof",
        "full_proof": all(row["proved"] for row in rows),
        "obligations": rows,
        "z3_version": z3.get_version_string(),
        "source_sha256": {
            name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in ("prove_scalar_shift_macros.py", "scalar_shift_macros.py", "transform12_integer_model.py")
        },
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
