"""Checkout-only exact raw-encoding references for the final Transform7 chain.

Monolith4/6 acyclic uint32 expression graphs are decoded on first use, then cached.
Monolith7 uses its reproducibly recovered full diagram. No generated execute
entry point is called. This is a symbolic reference, not a compact arithmetic
interpretation or a faster library implementation.
"""

from __future__ import annotations

import ast
import operator
import struct
from dataclasses import dataclass
from functools import lru_cache

from tools.monolith7_full_model import execute_words as execute_seven
from tools.recover_monolith5 import _literal
from tools.trace_session_auth_output import DependencyGraph, REPOSITORY_ROOT

OPERATIONS = {
    "and": operator.and_,
    "or": operator.or_,
    "xor": operator.xor,
    "left": operator.lshift,
    "right": operator.rshift,
    "multiply": operator.mul,
}


@dataclass(frozen=True)
class Program:
    nodes: tuple[tuple[str, tuple[int, ...]], ...]
    outputs: tuple[int, ...]


def compile_source(source: str, output_words: int) -> Program:
    """Fail-closed source lowering with versioned names and explicit shifts.

    Python integer intermediate semantics are preserved, including negative
    complements and logical _shr masking. Nodes are hash-consed, not exec'd.
    """
    graph = DependencyGraph()
    graph.add_execute("encoded-reference", source)
    function = next(node for node in ast.parse(source).body if isinstance(node, ast.FunctionDef) and node.name == "execute")
    nodes: list[tuple[str, tuple[int, ...]]] = []
    identifiers: dict[tuple[str, tuple[int, ...]], int] = {}
    bindings: dict[str, int] = {}
    initialized: set[str] = set()
    copies = 0

    def add(operation: str, *arguments: int) -> int:
        key = (operation, arguments)
        if key not in identifiers:
            identifiers[key] = len(nodes)
            nodes.append(key)
        return identifiers[key]

    def expression(node: ast.expr) -> int:
        if isinstance(node, ast.Constant) and type(node.value) is int:
            return add("constant", node.value)
        if isinstance(node, ast.Name):
            return add("constant", 0xFFFFFFFF) if node.id == "_U32" else bindings[node.id]
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id == "src_dwords":
            return add("input", _literal(node.slice))
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Invert):
            return add("invert", expression(node.operand))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "_shr":
            if len(node.args) == 2 and not node.keywords:
                return add("logical", expression(node.args[0]), add("constant", _literal(node.args[1])))
        if isinstance(node, ast.BinOp):
            operations = {
                ast.BitAnd: "and",
                ast.BitOr: "or",
                ast.BitXor: "xor",
                ast.LShift: "left",
                ast.RShift: "right",
                ast.Mult: "multiply",
            }
            if type(node.op) in operations:
                if isinstance(node.op, (ast.LShift, ast.RShift, ast.Mult)):
                    _literal(node.right)
                return add(operations[type(node.op)], expression(node.left), expression(node.right))
        raise ValueError(f"unsupported encoded reference expression: {ast.dump(node)}")

    for statement in function.body:
        if not isinstance(statement, ast.Assign):
            if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant):
                continue  # Function docstring only.
            raise ValueError("unsupported encoded reference statement")
        target = statement.targets[0]
        if isinstance(target, ast.Name) and target.id.startswith("uVar"):
            bindings[target.id] = expression(statement.value)
        elif isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name) and target.value.id == "dst_dwords":
            bindings[f"output{_literal(target.slice)}"] = expression(statement.value)
        elif isinstance(target, ast.Name) and target.id in ("src_dwords", "dst_dwords"):
            call = statement.value
            buffer = "source" if target.id == "src_dwords" else "destination"
            if (
                not (
                    isinstance(call, ast.Call)
                    and len(call.args) == 1
                    and not call.keywords
                    and isinstance(call.args[0], ast.Name)
                    and call.args[0].id == buffer
                )
                or target.id in initialized
            ):
                raise ValueError("unsupported encoded reference buffer initialization")
            initialized.add(target.id)
        elif isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name) and target.value.id == "destination":
            valid_slices = [
                ast.dump(ast.parse(text, mode="eval").body.slice)
                for text in ("destination[:]", "destination[:len(dst_dwords)*4]")
            ]
            if ast.dump(target.slice) not in valid_slices or statement.value.keywords or statement is not function.body[-1]:
                raise ValueError("unsupported encoded reference destination copy")
            copies += 1
        else:
            raise ValueError("unsupported encoded reference assignment")
    if initialized != {"src_dwords", "dst_dwords"} or copies != 1:
        raise ValueError("unsupported encoded reference buffer layout")
    if {name for name in bindings if name.startswith("output")} != {f"output{i}" for i in range(output_words)}:
        raise ValueError("encoded reference output layout differs")
    return Program(tuple(nodes), tuple(bindings[f"output{i}"] for i in range(output_words)))


def evaluate(program: Program, words: tuple[int, ...]) -> tuple[int, ...]:
    values: list[int] = []
    for operation, arguments in program.nodes:
        if operation == "constant":
            result = arguments[0]
        elif operation == "input":
            result = words[arguments[0]]
        elif operation == "invert":
            result = ~values[arguments[0]]
        elif operation == "logical":
            result = (values[arguments[0]] & 0xFFFFFFFF) >> values[arguments[1]]
        else:
            result = OPERATIONS[operation](values[arguments[0]], values[arguments[1]])
        values.append(result)
    return tuple(values[index] & 0xFFFFFFFF for index in program.outputs)


@lru_cache(maxsize=2)
def program(monolith: int) -> Program:
    if monolith not in (4, 6):
        raise ValueError("source-recovered reference supports Monolith4/6")
    path = REPOSITORY_ROOT / f"s7commplus/session_auth/family0/_generated/monolith{monolith}.py"
    return compile_source(path.read_text(encoding="utf-8"), 18 if monolith == 4 else 36)


def execute(monolith: int, *spans: bytes) -> tuple[bytes, ...]:
    """Evaluate byte-exact wrapper outputs, validating the complete input layout."""
    layouts = {4: (72, 72), 6: (72, 72, 72), 7: (24, 72)}
    if monolith not in layouts or tuple(map(len, spans)) != layouts[monolith]:
        raise ValueError("encoded reference input layout does not match the monolith")
    source = b"".join(spans)
    words = struct.unpack(f"<{len(source) // 4}I", source)
    if monolith == 7:
        output = execute_seven(words)
    else:
        output = evaluate(program(monolith), words)
    packed = struct.pack(f"<{len(output)}I", *output)
    return tuple(packed[offset : offset + 72] for offset in range(0, len(packed), 72))
