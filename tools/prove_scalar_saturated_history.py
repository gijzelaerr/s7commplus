"""Check exact raw saturation, not just lower bounds, against source ASTs.

Optional development-only Z3. Addition and multiplication descend to the
48-element saturated semiring. Subtraction still needs canonical residues;
its exact saturation is reconstructed from those and the input saturations.
This does not prove packed kernels or a complete curve replacement.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from tools.prove_scalar_predicate_guards import compile_guard
from tools.prove_transform12_residue_defects import compile_source
from tools.scalar_representative_rules import MODULUS as P
from tools import scalar_saturated_history as model


def prove(timeout_ms: int = 10000) -> dict[str, object]:
    import z3

    if type(timeout_ms) is not int or timeout_ms <= 0:
        raise ValueError("positive solver timeout required")
    context = z3.Context()
    a, b = [z3.ZeroExt(2, z3.BitVec(n, 160, ctx=context)) for n in ("raw_a", "raw_b")]

    def cap(value: Any) -> Any:
        return z3.If(value >= 47, z3.BitVecVal(47, value.size(), ctx=context), value)

    sa, sb = cap(a), cap(b)
    ra, rb = z3.If(a >= P, a - P, a), z3.If(b >= P, b - P, b)
    actual_add = compile_source(z3, "add", a, b)
    actual_sub = compile_source(z3, "subtract", a, b)
    rs = z3.If(actual_sub >= P, actual_sub - P, actual_sub)
    tag = compile_guard(z3, "subtraction_small_lift", {"a": ra, "b": rb, "sa": sa, "sb": sb}, module=model)
    sub_cap = z3.If(z3.Or(rs >= 47, tag), z3.BitVecVal(47, 162, ctx=context), rs)
    symbols = {"a": ra, "b": rb, "wide_a": sa == 47, "wide_b": sb == 47, "P": P, "LOW": 1 << 128}
    add_carry = compile_guard(z3, "addition_carry", symbols, module=model)
    sub_carry = compile_guard(z3, "subtraction_carry", symbols, module=model)
    total, difference = a + b, a - b
    zero = z3.BitVecVal(0, 162, ctx=context)
    add_defect = z3.BitVecVal(94 - (1 << 128), 162, ctx=context)
    add_target = z3.If(total < 1 << 160, total, total - P + z3.If(add_carry, add_defect, zero))
    sub_target = z3.If(difference >= 0, difference, difference + P) + z3.If(
        sub_carry, z3.BitVecVal(1 << 160, 162, ctx=context), zero
    )
    product = z3.ZeroExt(2, z3.BitVec("arbitrary_uint320_product", 320, ctx=context))
    placeholder = z3.BitVecVal(0, 322, ctx=context)
    actual_product = compile_source(z3, "multiply", placeholder, placeholder, product)
    queries = {
        "addition_exact_saturation": cap(actual_add) != cap(a + b),
        "addition_saturated_input_transfer": cap(a + b) != cap(sa + sb),
        "actual_addition_carry_ast_reconstruction": actual_add != add_target,
        "actual_subtraction_carry_ast_reconstruction": actual_sub != sub_target,
        "product_exact_saturation": cap(actual_product) != cap(product),
        "subtraction_exact_saturation": cap(actual_sub) != sub_cap,
        "subtraction_large_residue_operand_canonicalizes_small_output": z3.And(
            z3.Or(ra >= 47, rb >= 47), rs <= 46, actual_sub >= P
        ),
        "lift_from_exact_saturation": z3.Xor(a >= P, z3.And(ra <= 46, sa == 47)),
        "equal_saturations_subtraction_canonicalizes": z3.And(sa == sb, actual_sub >= P),
        "zero_saturation_subtraction_is_identity": z3.And(sb == 0, actual_sub != a),
        # This is deliberately wrong: unlike + and *, subtraction does not
        # descend to the saturated semiring without field information.
        "reject_saturated_subtraction_without_residues": cap(actual_sub)
        != z3.If(sa >= sb, sa - sb, z3.BitVecVal(0, 162, ctx=context)),
    }
    # Independent nonnegative integer factor identity. Splitting at zero
    # avoids asking the solver to discover a nonlinear uint160 product lemma.
    u, v = z3.Ints("factor_u factor_v", ctx=context)

    def icap(x: Any) -> Any:
        return z3.If(x >= 47, 47, x)

    for name, condition in (
        ("zero", z3.Or(u == 0, v == 0)),
        ("small", z3.And(u < 47, v < 47)),
        ("large_left", z3.And(u >= 47, v >= 1)),
        ("large_right", z3.And(v >= 47, u >= 1)),
    ):
        queries[f"product_saturated_input_transfer_{name}"] = z3.And(
            u >= 0, v >= 0, condition, icap(u * v) != icap(icap(u) * icap(v))
        )
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
        "scope": "exact saturated raw primitive source-AST identities; NOT packed-kernel or whole-curve SMT proof",
        "full_proof": all(row["proved"] for row in rows),
        "obligations": rows,
        "z3_version": z3.get_version_string(),
        "source_sha256": {
            name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in ("prove_scalar_saturated_history.py", "scalar_saturated_history.py", "transform12_integer_model.py")
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
