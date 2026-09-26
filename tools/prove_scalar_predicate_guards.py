"""Prove source-AST carry exclusion guards and uint160 lift uniqueness.

Optional development-only Z3; these are primitive-domain obligations, NOT a
generated-kernel or whole-predictor SMT proof. Carry corrections themselves
have separate source-integer-model obligations in prove_transform12_residue_defects.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import inspect
import json
import operator
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from types import CodeType
from typing import Any

from tools import predict_scalar_defects as predictor
from tools import transform12_residue_defects as arithmetic
from tools.prove_transform12_residue_defects import WIDTH as SOURCE_WIDTH
from tools.prove_transform12_residue_defects import compile_source

WIDTH = 162  # Signed sums/differences of uint160 values fit without overflow.


def compile_guard(z3: Any, name: str, inputs: dict[str, Any], module: ModuleType = predictor) -> Any:
    """Compile the actual tiny Python guard AST, rejecting unfamiliar syntax."""
    target = getattr(module, name)
    tree = ast.parse(inspect.getsource(target))
    function = tree.body[0]
    if not isinstance(function, ast.FunctionDef) or not isinstance(function.body[-1], ast.Return):
        raise ValueError("guard must be a function ending in return")
    # inspect can read an edited file beneath an already imported function.
    # Never certify that new AST as though it were the loaded runtime code.
    compiled = compile(tree, inspect.getsourcefile(target) or "<guard>", "exec", dont_inherit=True)
    candidates = [value for value in compiled.co_consts if isinstance(value, CodeType) and value.co_name == function.name]
    runtime = target.__code__
    if len(candidates) != 1:
        raise ValueError("predicate source/runtime mismatch")
    source = candidates[0]
    if (
        function.name != runtime.co_name
        or source.co_code != runtime.co_code
        or source.co_names != runtime.co_names
        or source.co_varnames != runtime.co_varnames
        or tuple((type(value), value) for value in source.co_consts) != tuple((type(value), value) for value in runtime.co_consts)
    ):
        raise ValueError("predicate source/runtime mismatch; reload after editing source")
    body = function.body
    if isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
        body = body[1:]
    if len(body) != 1 or not isinstance(body[0], ast.Return):
        raise ValueError("guard must contain only a docstring and return")

    def expression(node: ast.expr) -> Any:
        if isinstance(node, ast.Name) and node.id in inputs:
            return inputs[node.id]
        if isinstance(node, ast.Name) and node.id == "MODULUS":
            return getattr(module, "MODULUS")
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in inputs
            and not node.args
            and not node.keywords
            and z3.is_bool(inputs[node.func.id])
        ):
            # A declared zero-argument Boolean callback is represented by
            # its result. This checks the returned predicate, not Python
            # short-circuit execution or callback side effects.
            return inputs[node.func.id]
        if isinstance(node, ast.Constant) and type(node.value) is int:
            return node.value
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "arithmetic"
            and node.attr == "LOW_LIMIT"
        ):
            return getattr(module, "arithmetic").LOW_LIMIT
        if isinstance(node, ast.BoolOp):
            values = [expression(n) for n in node.values]
            if isinstance(node.op, ast.And):
                return z3.And(*values)
            if isinstance(node.op, ast.Or):
                return z3.Or(*values)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            left, right = expression(node.left), expression(node.right)
            if type(right) is int and right > 0 and right & (right - 1) == 0:
                return left & (right - 1)  # Guard residues are nonnegative.
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            return -expression(node.operand)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return z3.Not(expression(node.operand))
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub, ast.Mult)):
            if "product" in inputs and ast.dump(node) == ast.dump(ast.parse("a*b", mode="eval").body):
                return inputs["product"]
            left, right = expression(node.left), expression(node.right)
            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.Sub):
                return left - right
            return left * right
        if isinstance(node, ast.Compare):
            comparisons: dict[type[ast.cmpop], Callable[[Any, Any], Any]] = {
                ast.Lt: operator.lt,
                ast.LtE: operator.le,
                ast.GtE: operator.ge,
                ast.Eq: operator.eq,
            }
            parts = []
            left = expression(node.left)
            for op, right_node in zip(node.ops, node.comparators):
                if type(op) not in comparisons:
                    raise ValueError("unsupported comparison")
                right = expression(right_node)
                parts.append(comparisons[type(op)](left, right))
                left = right
            return z3.And(*parts)
        raise ValueError(f"unsupported guard expression: {ast.dump(node)}")

    returned = function.body[-1].value
    if returned is None:
        raise ValueError("guard return has no expression")
    return expression(returned)


def prove(timeout_ms: int = 10000) -> dict[str, object]:
    import z3

    if timeout_ms <= 0:
        raise ValueError("positive solver timeout required")
    context = z3.Context()
    a, b = [z3.ZeroExt(WIDTH - 160, z3.BitVec(name, 160, ctx=context)) for name in ("a", "b")]
    p = arithmetic.P
    ra, rb = z3.If(a >= p, a - p, a), z3.If(b >= p, b - p, b)
    total = a + b
    r = z3.If(total >= 2 * p, total - 2 * p, z3.If(total >= p, total - p, total))
    exceptional_add = z3.And(total >= 1 << 160, (total & (arithmetic.LOW_LIMIT - 1)) >= arithmetic.LOW_LIMIT - 47)
    exceptional_sub = a - b < -p
    addition_guard = compile_guard(z3, "addition_possible", {"residue": r})
    subtraction_guard = compile_guard(z3, "subtraction_possible", {"a": ra, "b": rb})
    queries = {
        "addition_guard_excludes_no_real_defect": z3.And(exceptional_add, z3.Not(addition_guard)),
        "subtraction_guard_excludes_no_real_defect": z3.And(exceptional_sub, z3.Not(subtraction_guard)),
        "unique_lift_above46": z3.And(a != b, ra == rb, ra > 46),
        "ambiguous_lift_has_small_residue": z3.And(a >= p, ra > 46),
        "ordinary_sum_residue_is_canonical": z3.Or(r < 0, r >= p),
    }
    # Prove zero-tag shortcuts against the actual integer-model AST. A
    # zero residue has only the two possible representatives 0 and p.
    source_a, source_b = z3.ZeroExt(SOURCE_WIDTH - WIDTH, a), z3.ZeroExt(SOURCE_WIDTH - WIDTH, b)
    zero = z3.BitVecVal(0, SOURCE_WIDTH, ctx=context)
    modulus = z3.BitVecVal(p, SOURCE_WIDTH, ctx=context)
    add_rep = compile_source(z3, "add", source_a, source_b)
    sub_rep = compile_source(z3, "subtract", source_a, source_b)
    product = z3.ZeroExt(SOURCE_WIDTH - 320, z3.BitVec("arbitrary_product", 320, ctx=context))
    mul_rep = compile_source(z3, "multiply", source_a, source_b, product)

    def small(rep: Any) -> Any:
        return z3.Or(z3.And(rep >= 0, rep <= 46), z3.And(rep >= p, rep < 1 << 160))

    queries.update(
        {
            "small_add_lift": z3.And(
                small(add_rep), z3.Xor(add_rep >= p, compile_guard(z3, "addition_lift", {"a": source_a, "b": source_b}))
            ),
            "small_subtract_lift": z3.And(
                small(sub_rep), z3.Xor(sub_rep >= p, compile_guard(z3, "subtraction_lift", {"a": source_a, "b": source_b}))
            ),
            "small_product_lift": z3.And(
                small(mul_rep),
                z3.Xor(
                    mul_rep >= p, compile_guard(z3, "multiplication_lift", {"a": source_a, "b": source_b, "product": product})
                ),
            ),
        }
    )
    queries.update(
        {
            "zero_add_tag": z3.And(z3.Or(add_rep == 0, add_rep == p), add_rep != z3.If(z3.Or(a > 0, b > 0), modulus, zero)),
            "zero_subtract_tag": z3.And(z3.Or(sub_rep == 0, sub_rep == p), sub_rep != z3.If(a > b, modulus, zero)),
            "zero_product_tag": z3.And(z3.Or(mul_rep == 0, mul_rep == p), mul_rep != z3.If(product > 0, modulus, zero)),
        }
    )
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
        "scope": "actual guard/integer-model AST, uint160 guard/lift and zero-tag lemmas; multiplication product abstracted uint320; NOT whole-predictor SMT proof",
        "full_proof": all(row["proved"] for row in rows),
        "obligations": rows,
        "source_sha256": {
            name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in (
                "predict_scalar_defects.py",
                "prove_scalar_predicate_guards.py",
                "transform12_residue_defects.py",
                "transform12_integer_model.py",
                "prove_transform12_residue_defects.py",
            )
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
