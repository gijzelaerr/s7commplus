"""Shared, saturated raw lower-bound equations for source scalar stages.

Research only. Compiles source SSA once; evaluation visits immutable equations,
not source instructions. Every value is in0..47. A bound of47 proves raw>=47,
but a smaller bound need not equal the raw value. Source primitive justification
is in prove_scalar_structural_guards, not a new whole-stage equivalence proof.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from tools.decompile_transform12 import Operand, Program


@dataclass(frozen=True)
class Node:
    operation: str
    arguments: tuple[int, ...]


class Graph:
    def __init__(self) -> None:
        self.nodes: list[Node] = []
        self.interned: dict[Node, int] = {}

    def node(self, operation: str, arguments: tuple[int, ...]) -> int:
        node = Node(operation, arguments)
        if node not in self.interned:
            self.interned[node] = len(self.nodes)
            self.nodes.append(node)
        return self.interned[node]

    def literal(self, value: int) -> int:
        if type(value) is not int or not 0 <= value <= 47:
            raise ValueError("raw bound literal0..47 required")
        return self.node("literal", (value,))

    def input(self, index: int) -> int:
        if type(index) is not int or index < 0:
            raise ValueError("nonnegative input ordinal required")
        return self.node("input", (index,))

    def combine(self, operation: str, a: int, b: int) -> int:
        if operation not in ("add", "multiply", "subtract"):
            raise ValueError("unsupported saturated operation")
        if any(type(i) is not int or not 0 <= i < len(self.nodes) for i in (a, b)):
            raise ValueError("undefined raw bound equation")
        first, last = self.nodes[a], self.nodes[b]
        ca = first.arguments[0] if first.operation == "literal" else None
        cb = last.arguments[0] if last.operation == "literal" else None
        if ca is not None and cb is not None:
            return self.literal(self.transfer(operation, ca, cb))
        if operation == "add":
            if 47 in (ca, cb):
                return self.literal(47)
            if ca == 0 or cb == 0:
                return b if ca == 0 else a
        elif operation == "multiply":
            if 0 in (ca, cb):
                return self.literal(0)
            if ca == 1 or cb == 1:
                return b if ca == 1 else a
        elif cb == 0 or cb == 47:
            return a if cb == 0 else self.literal(0)
        if operation != "subtract":
            a, b = sorted((a, b))
        return self.node(operation, (a, b))

    @staticmethod
    def transfer(operation: str, a: int, b: int) -> int:
        if operation == "add":
            return min(a + b, 47)
        if operation == "multiply":
            return min(a * b, 47)
        if operation == "subtract":
            return max(a - b, 0)
        raise ValueError("unsupported saturated operation")

    def compile(self, source: Program, slots: tuple[int, ...], constant: Callable[[Operand], int]) -> dict[int, int]:
        inputs = {slot: self.input(index) for index, slot in enumerate(slots)}
        values: dict[int, int] = {}

        def resolve(operand: Operand) -> int:
            if operand.kind == "input":
                return inputs[operand.index]
            if operand.kind == "value":
                if operand.index not in values:
                    raise ValueError("raw bound compiler requires acyclic unique SSA values")
                return values[operand.index]
            raw = constant(operand)
            if type(raw) is not int or not 0 <= raw < 1 << 160:
                raise ValueError("uint160 raw constant required")
            return self.literal(min(raw, 47))

        for instruction in source.instructions:
            if instruction.value in values:
                raise ValueError("raw bound compiler requires acyclic unique SSA values")
            a, b = resolve(instruction.operands[0]), resolve(instruction.operands[-1])
            if instruction.operation == "subtract":
                node = self.combine("subtract", a, b) if instruction.operands[-1].kind == "constant" else self.literal(0)
            else:
                node = self.combine("multiply" if instruction.operation == "square" else instruction.operation, a, b)
            values[instruction.value] = node
        return values

    def evaluate(self, root: int, raw_inputs: tuple[int, ...], cache: dict[int, int]) -> int:
        if type(root) is not int or not 0 <= root < len(self.nodes):
            raise ValueError("defined raw bound root required")
        pending = [root]
        while pending:
            index = pending[-1]
            if index in cache:
                pending.pop()
                continue
            node = self.nodes[index]
            op, args = node.operation, node.arguments
            if op == "literal":
                cache[index] = args[0]
            elif op == "input":
                value = raw_inputs[args[0]]
                if type(value) is not int or not 0 <= value < 1 << 160:
                    raise ValueError("uint160 raw entry value required")
                cache[index] = min(value, 47)
            elif any(not 0 <= child < index for child in args):
                raise ValueError("raw bound equation reads a future or undefined node")
            else:
                missing = next((child for child in args if child not in cache), None)
                if missing is not None:
                    pending.append(missing)
                else:
                    cache[index] = self.transfer(op, cache[args[0]], cache[args[1]])
        return cache[root]
