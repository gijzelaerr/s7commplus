"""Conservatively trace source *bits* through one generated monolith output.

Unlike the word-level trace, this accounts for constant masks and fixed shifts.
An input reported here may still cancel algebraically; an omitted input cannot
affect the output within the supported straight-line uint32 expression model.
"""

from __future__ import annotations

import argparse
import ast
import json
from dataclasses import dataclass
from pathlib import Path

from tools.trace_v1_session_key_output import REPOSITORY_ROOT, trace_monolith

BitRef = tuple[int, int]


@dataclass(frozen=True)
class Bit:
    constant: int | None
    sources: frozenset[BitRef] = frozenset()


ZERO = Bit(0)
ONE = Bit(1)
Word = tuple[Bit, ...]


def _constant(value: int) -> Word:
    return tuple(ONE if value & (1 << bit) else ZERO for bit in range(32))


def _shift(word: Word, amount: int, left: bool) -> Word:
    if amount < 0:
        raise ValueError("negative shift")
    result: list[Bit] = []
    for bit in range(32):
        source_bit = bit - amount if left else bit + amount
        result.append(word[source_bit] if 0 <= source_bit < 32 else ZERO)
    return tuple(result)


def _combine(left: Bit, right: Bit, op: ast.operator) -> Bit:
    if isinstance(op, ast.BitAnd):
        if left.constant == 0 or right.constant == 0:
            return ZERO
        if left.constant == 1:
            return right
        if right.constant == 1:
            return left
    elif isinstance(op, ast.BitOr):
        if left.constant == 1 or right.constant == 1:
            return ONE
        if left.constant == 0:
            return right
        if right.constant == 0:
            return left
    elif isinstance(op, ast.BitXor):
        if left.constant == 0:
            return right
        if right.constant == 0:
            return left
        if left.constant is not None and right.constant is not None:
            return ONE if left.constant ^ right.constant else ZERO
    else:
        raise ValueError(f"unsupported operator {type(op).__name__}")
    return Bit(None, left.sources | right.sources)


def _index(node: ast.Subscript, name: str) -> int:
    if not isinstance(node.value, ast.Name) or node.value.id != name:
        raise ValueError(f"unsupported subscript at line {node.lineno}")
    if not isinstance(node.slice, ast.Constant) or type(node.slice.value) is not int or node.slice.value < 0:
        raise ValueError(f"dynamic index at line {node.lineno}")
    return node.slice.value


def _literal(node: ast.expr) -> int:
    if not isinstance(node, ast.Constant) or type(node.value) is not int:
        raise ValueError(f"nonconstant shift or multiplier at line {node.lineno}")
    return node.value


def _evaluate(node: ast.expr, values: dict[str, Word]) -> Word:
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return _constant(node.value)
    if isinstance(node, ast.Name):
        if node.id == "_U32":
            return _constant(0xFFFFFFFF)
        if node.id not in values:
            raise ValueError(f"unassigned scalar {node.id} at line {node.lineno}")
        return values[node.id]
    if isinstance(node, ast.Subscript):
        index = _index(node, "src_dwords")
        return tuple(Bit(None, frozenset({(index, bit)})) for bit in range(32))
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Invert):
        return tuple(Bit(1 - bit.constant) if bit.constant is not None else bit for bit in _evaluate(node.operand, values))
    if isinstance(node, ast.Call):
        if not isinstance(node.func, ast.Name) or node.func.id != "_shr" or len(node.args) != 2 or node.keywords:
            raise ValueError(f"unsupported call at line {node.lineno}")
        return _shift(_evaluate(node.args[0], values), _literal(node.args[1]), left=False)
    if isinstance(node, ast.BinOp):
        if isinstance(node.op, (ast.LShift, ast.RShift)):
            return _shift(_evaluate(node.left, values), _literal(node.right), left=isinstance(node.op, ast.LShift))
        if isinstance(node.op, ast.Mult):
            multiplier = _literal(node.right)
            if multiplier <= 0 or multiplier & (multiplier - 1):
                raise ValueError(f"non-power-of-two multiplier at line {node.lineno}")
            return _shift(_evaluate(node.left, values), multiplier.bit_length() - 1, left=True)
        left, right = _evaluate(node.left, values), _evaluate(node.right, values)
        return tuple(_combine(a, b, node.op) for a, b in zip(left, right))
    raise ValueError(f"unsupported expression {type(node).__name__} at line {node.lineno}")


def trace_output_bits(monolith: int, output_word: int, root: Path = REPOSITORY_ROOT) -> tuple[frozenset[BitRef], ...]:
    """Return conservative source (word, bit) sets for each output bit."""
    trace = trace_monolith(monolith, output_word, root=root)
    paths = {assignment["path"] for assignment in trace["assignments"]}
    if len(paths) != 1 or any(not ref.startswith("source[") for ref in trace["inputs"]):
        raise ValueError("only single-file slices with source inputs are supported")
    path = next(iter(paths))
    module = ast.parse((root / path).read_text(encoding="utf-8"))
    execute = next(node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == "execute")
    wanted = {(assignment["line"], assignment["target"]) for assignment in trace["assignments"]}
    values: dict[str, Word] = {}
    output: Word | None = None
    for statement in execute.body:
        if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
            continue
        target = statement.targets[0]
        if isinstance(target, ast.Name):
            name = target.id
        elif isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name) and target.value.id == "dst_dwords":
            name = f"dst_dwords[{_index(target, 'dst_dwords')}]"
        else:
            continue
        if (statement.lineno, name) not in wanted:
            continue
        value = _evaluate(statement.value, values)
        values[name] = value
        if name == f"dst_dwords[{output_word}]":
            output = value
    if output is None:
        raise ValueError(f"no output word {output_word}")
    return tuple(bit.sources for bit in output)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("monolith", type=int)
    parser.add_argument("output_word", type=int)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    bits = trace_output_bits(args.monolith, args.output_word)
    if args.json:
        print(
            json.dumps(
                {
                    "monolith": args.monolith,
                    "output_word": args.output_word,
                    "bits": [{"bit": index, "sources": sorted(sources)} for index, sources in enumerate(bits)],
                },
                indent=2,
            )
        )
    else:
        for index, sources in enumerate(bits):
            words = sorted({word for word, _ in sources})
            print(f"bit {index:2}: {len(sources):3} possible source bits from words {words}")


if __name__ == "__main__":
    main()
