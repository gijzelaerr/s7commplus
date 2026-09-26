"""Source-AST checks of residue-defect representatives and product fold bounds.

Optional development-only Z3. The multiplication check quantifies over every
unsigned 320-bit product, rather than solving a nonlinear input multiplication.
The source integer model's correspondence to packed runtime has separate
differential tests; this is not a source-SMT proof of the generated kernels.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import inspect
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from tools import transform12_integer_model as exact
from tools import transform12_residue_defects as defects

WIDTH = 322  # All source intermediates fit, including signed complements.


def compile_source(z3: Any, operation: str, a: Any, b: Any, product: Any | None = None) -> Any:
    tree = ast.parse(inspect.getsource(getattr(exact, operation)))
    function = tree.body[0]
    if not isinstance(function, ast.FunctionDef):
        raise ValueError("expected an integer-model function")
    env = {"a": a, "b": b, **{name: getattr(exact, name) for name in ("LIMIT", "MASK", "WORD_MASK", "FOLD", "BITS")}}

    def expression(node: ast.expr, state: dict[str, Any]) -> Any:
        if isinstance(node, ast.Name) and node.id in state:
            return state[node.id]
        if isinstance(node, ast.Constant) and type(node.value) is int:
            return node.value
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Invert):
            return ~expression(node.operand, state)
        if isinstance(node, ast.IfExp):
            condition = expression(node.test, state)
            first, second = expression(node.body, state), expression(node.orelse, state)
            if type(first) is int and type(second) is int:
                first, second = z3.BitVecVal(first, a.size(), ctx=a.ctx), z3.BitVecVal(second, a.size(), ctx=a.ctx)
            return z3.If(condition, first, second)
        if isinstance(node, ast.BinOp):
            left, right = expression(node.left, state), expression(node.right, state)
            operations: dict[type[ast.operator], Callable[[], Any]] = {
                ast.Add: lambda: left + right,
                ast.Sub: lambda: left - right,
                ast.Mult: lambda: left * right,
                ast.BitAnd: lambda: left & right,
                ast.BitOr: lambda: left | right,
                ast.LShift: lambda: left << right,
                ast.RShift: lambda: left >> right,
            }
            if type(node.op) in operations:
                return operations[type(node.op)]()
        if isinstance(node, ast.Compare) and len(node.ops) == len(node.comparators) == 1:
            left, right = expression(node.left, state), expression(node.comparators[0], state)
            if isinstance(node.ops[0], ast.Lt):
                return left < right
            if isinstance(node.ops[0], ast.GtE):
                return left >= right
        raise ValueError(f"unsupported integer-model expression: {ast.dump(node)}")

    def run(block: list[ast.stmt], state: dict[str, Any]) -> Any:
        if not block:
            raise ValueError("source path has no return")
        statement, rest = block[0], block[1:]
        if (
            isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
            and isinstance(statement.value.value, str)
        ):
            return run(rest, state)
        if isinstance(statement, ast.Assign) and len(statement.targets) == 1 and isinstance(statement.targets[0], ast.Name):
            name = statement.targets[0].id
            if (
                product is not None
                and name == "product"
                and isinstance(statement.value, ast.BinOp)
                and isinstance(statement.value.op, ast.Mult)
            ):
                if ast.dump(statement.value) != ast.dump(ast.parse("a*b", mode="eval").body):
                    raise ValueError("product abstraction is not the initial a*b expression")
                value = product
            else:
                value = expression(statement.value, state)
            return run(rest, {**state, name: value})
        if isinstance(statement, ast.If):
            condition = expression(statement.test, state)
            if type(condition) is bool or type(condition) is int:
                return run((statement.body if condition else statement.orelse) + rest, state)
            if z3.is_bv(condition):
                condition = condition != 0
            return z3.If(condition, run(statement.body + rest, dict(state)), run(statement.orelse + rest, dict(state)))
        if isinstance(statement, ast.For) and isinstance(statement.target, ast.Name):
            iterator = statement.iter
            if (
                isinstance(iterator, ast.Call)
                and isinstance(iterator.func, ast.Name)
                and iterator.func.id == "range"
                and not iterator.keywords
                and len(iterator.args) == 1
            ):
                count = expression(iterator.args[0], state)
                if type(count) is int and 0 <= count <= 3 and not statement.orelse:
                    return run(statement.body * count + rest, state)
        if isinstance(statement, ast.Return) and statement.value is not None:
            return expression(statement.value, state)
        raise ValueError(f"unsupported integer-model statement: {ast.dump(statement)}")

    return run(function.body, env)


def prove(timeout_ms: int = 10000) -> dict[str, object]:
    import z3

    if timeout_ms <= 0:
        raise ValueError("positive solver timeout required")
    # Keep these obligations independent of earlier symbolic analyses in
    # the same process (including AST allocation history in the full suite).
    context = z3.Context()
    a, b = [z3.ZeroExt(WIDTH - 160, z3.BitVec(name, 160, ctx=context)) for name in ("a", "b")]
    total = a + b
    low_mask = defects.LOW_LIMIT - 1
    exceptional = z3.And(total >= exact.LIMIT, (total & low_mask) >= defects.LOW_LIMIT - exact.FOLD)
    add_target = z3.If(
        total < exact.LIMIT,
        total,
        total
        - defects.P
        + z3.If(exceptional, z3.BitVecVal(defects.ADD_DEFECT, WIDTH, ctx=context), z3.BitVecVal(0, WIDTH, ctx=context)),
    )
    difference = a - b
    subtraction = z3.If(difference >= 0, difference, difference + defects.P)
    subtract_target = z3.If(subtraction < 0, subtraction + exact.LIMIT, subtraction)
    product = z3.ZeroExt(WIDTH - 320, z3.BitVec("arbitrary_product", 320, ctx=context))
    folded = product
    folds = []
    for _ in range(3):
        folded = z3.If(folded >= exact.LIMIT, (folded & exact.MASK) + (folded >> 160) * exact.FOLD, folded)
        folds.append(folded)
    queries = {
        "addition_fixed_defect_representative": compile_source(z3, "add", a, b) != add_target,
        "subtraction_second_wrap_representative": compile_source(z3, "subtract", a, b) != subtract_target,
        "multiplication_three_fold_representative": compile_source(z3, "multiply", a, b, product) != folded,
        "first_product_fold_bound": folds[0] >= 48 * exact.LIMIT,
        "second_product_fold_bound": folds[1] >= exact.LIMIT + 2209,
        "third_product_fold_bound": folded >= exact.LIMIT,
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
        "scope": "source AST of checkout integer model; product abstracted to arbitrary uint320; NOT generated-kernel SMT proof",
        "source_sha256": {
            name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in ("transform12_integer_model.py", "transform12_residue_defects.py", "prove_transform12_residue_defects.py")
        },
        "z3_version": z3.get_version_string(),
        "full_proof": all(row["proved"] for row in rows),
        "obligations": rows,
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
