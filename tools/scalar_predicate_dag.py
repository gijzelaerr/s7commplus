"""Hash-cons tiny actual predicate ASTs into typed integer/Boolean equations.

Backend for the existing restricted AST compiler, not an SMT solver. Integer
field leaves are canonical residues. Folding uses exact literals, safe interval
bounds and Boolean identities; no sampled fitting or curve assumptions.
"""

from __future__ import annotations

import operator
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

P = (1 << 160) - 47


@dataclass(frozen=True)
class Node:
    operation: str
    arguments: tuple[int, ...]


class Expr:
    def __init__(self, backend: Backend, index: int) -> None:
        self.backend, self.index = backend, index

    def __bool__(self) -> bool:
        raise TypeError("symbolic predicate has no Python truth value")

    def __add__(self, other: object) -> Expr:
        return self.backend.number("add", self, other)

    __radd__ = __add__

    def __sub__(self, other: object) -> Expr:
        return self.backend.number("subtract", self, other)

    def __rsub__(self, other: object) -> Expr:
        return self.backend.number("subtract", other, self)

    def __neg__(self) -> Expr:
        return self.backend.number("subtract", 0, self)

    def __mul__(self, other: object) -> Expr:
        return self.backend.number("multiply", self, other)

    __rmul__ = __mul__

    def __and__(self, other: object) -> Expr:
        return self.backend.number("mask", self, other)

    def __lt__(self, other: object) -> Expr:
        return self.backend.compare("lt", self, other)

    def __le__(self, other: object) -> Expr:
        return self.backend.compare("le", self, other)

    def __ge__(self, other: object) -> Expr:
        return self.backend.compare("ge", self, other)

    def __eq__(self, other: object) -> Any:
        # Like Z3 expressions, symbolic equality returns an expression.
        return self.backend.compare("eq", self, other)


class Backend:
    def __init__(self) -> None:
        self.nodes: list[Node] = []
        self.sorts: list[str] = []
        self.bounds: list[tuple[int, int] | None] = []
        self.interned: dict[Node, int] = {}

    def node(self, operation: str, arguments: tuple[int, ...], sort: str, bounds: tuple[int, int] | None = None) -> Expr:
        value = Node(operation, arguments)
        if value not in self.interned:
            self.interned[value] = len(self.nodes)
            self.nodes.append(value)
            self.sorts.append(sort)
            self.bounds.append(bounds)
        return Expr(self, self.interned[value])

    def expression(self, value: object, sort: str) -> Expr:
        if isinstance(value, Expr) and value.backend is self and self.sorts[value.index] == sort:
            return value
        if sort == "number" and type(value) is int:
            return self.node("integer", (value,), sort, (value, value))
        if sort == "boolean" and type(value) is bool:
            return self.node("boolean", (int(value),), sort)
        raise ValueError("predicate expression sort or backend mismatch")

    def field(self, index: int) -> Expr:
        return self.node("field", (index,), "number", (0, P - 1))

    def lift(self, index: int) -> Expr:
        return self.node("lift", (index,), "boolean")

    def is_bool(self, value: object) -> bool:
        return isinstance(value, Expr) and value.backend is self and self.sorts[value.index] == "boolean"

    def number(self, operation: str, first: object, second: object) -> Expr:
        a, b = self.expression(first, "number"), self.expression(second, "number")
        an, bn = self.nodes[a.index], self.nodes[b.index]
        functions = {"add": operator.add, "subtract": operator.sub, "multiply": operator.mul, "mask": operator.and_}
        if operation not in functions:
            raise ValueError("unsupported integer predicate operation")
        if an.operation == bn.operation == "integer":
            return self.expression(functions[operation](an.arguments[0], bn.arguments[0]), "number")
        if operation == "subtract" and a.index == b.index:
            return self.expression(0, "number")
        if operation in ("add", "multiply") and a.index > b.index:
            a, b = b, a
        bounds_a, bounds_b = self.bounds[a.index], self.bounds[b.index]
        assert bounds_a is not None and bounds_b is not None
        if operation == "add":
            bounds = (bounds_a[0] + bounds_b[0], bounds_a[1] + bounds_b[1])
        elif operation == "subtract":
            bounds = (bounds_a[0] - bounds_b[1], bounds_a[1] - bounds_b[0])
        elif operation == "multiply":
            extremes = [x * y for x in bounds_a for y in bounds_b]
            bounds = min(extremes), max(extremes)
        else:
            if bounds_b[0] != bounds_b[1] or bounds_b[0] < 0:
                raise ValueError("predicate bit mask must be a nonnegative literal")
            bounds = 0, bounds_b[0]
        return self.node(operation, (a.index, b.index), "number", bounds)

    def compare(self, operation: str, first: object, second: object) -> Expr:
        a, b = self.expression(first, "number"), self.expression(second, "number")
        ba, bb = self.bounds[a.index], self.bounds[b.index]
        assert ba is not None and bb is not None
        if a.index == b.index:
            return self.expression(operation != "lt", "boolean")
        if operation == "eq":
            if ba[1] < bb[0] or bb[1] < ba[0]:
                return self.expression(False, "boolean")
            if ba[0] == ba[1] == bb[0] == bb[1]:
                return self.expression(True, "boolean")
        else:
            true = {"lt": ba[1] < bb[0], "le": ba[1] <= bb[0], "ge": ba[0] >= bb[1]}[operation]
            false = {"lt": ba[0] >= bb[1], "le": ba[0] > bb[1], "ge": ba[1] < bb[0]}[operation]
            if true or false:
                return self.expression(true, "boolean")
        # Canonical integer comparisons expose complements and repeated
        # category tests. Arithmetic is unbounded Python integer semantics.
        if operation == "ge":
            return self.Not(self.compare("lt", a, b))
        if operation == "le":
            if self.nodes[b.index].operation == "integer":
                return self.compare("lt", a, self.nodes[b.index].arguments[0] + 1)
            return self.Not(self.compare("lt", b, a))
        if operation == "eq":
            if self.nodes[b.index].operation == "integer" and bb[0] == ba[0]:
                return self.compare("le", a, b)
            if a.index > b.index:
                a, b = b, a
        return self.node(operation, (a.index, b.index), "boolean")

    def Not(self, value: object) -> Expr:
        expr = self.expression(value, "boolean")
        node = self.nodes[expr.index]
        if node.operation == "boolean":
            return self.expression(not node.arguments[0], "boolean")
        if node.operation == "not":
            return Expr(self, node.arguments[0])
        return self.node("not", (expr.index,), "boolean")

    def logic(self, operation: str, values: tuple[object, ...]) -> Expr:
        identity = operation == "and"
        children: set[int] = set()
        for value in values:
            expr = self.expression(value, "boolean")
            current = self.nodes[expr.index]
            if current.operation == "boolean":
                if bool(current.arguments[0]) != identity:
                    return self.expression(not identity, "boolean")
                continue
            children.update(current.arguments if current.operation == operation else (expr.index,))
        if any(self.nodes[i].operation == "not" and self.nodes[i].arguments[0] in children for i in children):
            return self.expression(not identity, "boolean")
        if not children:
            return self.expression(identity, "boolean")
        if len(children) == 1:
            return Expr(self, next(iter(children)))
        return self.node(operation, tuple(sorted(children)), "boolean")

    def And(self, *values: object) -> Expr:
        return self.logic("and", values)

    def Or(self, *values: object) -> Expr:
        return self.logic("or", values)

    def evaluate(
        self,
        root: int,
        field_lookup: Callable[[int], int],
        lifts: tuple[bool, ...],
        cache: dict[int, int | bool],
        *,
        override_lookup: Callable[[int], bool | None] | None = None,
    ) -> int | bool:
        pending = [root]
        functions = {
            "add": operator.add,
            "subtract": operator.sub,
            "multiply": operator.mul,
            "mask": operator.and_,
            "lt": operator.lt,
            "le": operator.le,
            "ge": operator.ge,
            "eq": operator.eq,
        }
        while pending:
            index = pending[-1]
            if index in cache:
                pending.pop()
                continue
            if override_lookup is not None:
                override = override_lookup(index)
                if override is not None:
                    if type(override) is not bool or self.sorts[index] != "boolean":
                        raise ValueError("predicate override requires a Boolean equation and result")
                    cache[index] = override
                    continue
            current = self.nodes[index]
            op, args = current.operation, current.arguments
            if op in ("boolean", "integer", "lift", "field"):
                if op == "boolean":
                    value: int | bool = bool(args[0])
                elif op == "integer":
                    value = args[0]
                elif op == "lift":
                    value = lifts[args[0]]
                else:
                    value = field_lookup(args[0])
                    if type(value) is not int or not 0 <= value < P:
                        raise ValueError("predicate field leaf must be a canonical residue")
                cache[index] = value
                continue
            if op in ("and", "or"):
                identity = op == "and"
                missing = None
                for child in args:
                    if child not in cache:
                        missing = child
                        break
                    if bool(cache[child]) != identity:
                        cache[index] = not identity
                        break
                else:
                    cache[index] = identity
                if index not in cache and missing is not None:
                    pending.append(missing)
                continue
            missing = next((child for child in args if child not in cache), None)
            if missing is not None:
                pending.append(missing)
            elif op == "not":
                cache[index] = not cache[args[0]]
            elif op in functions:
                cache[index] = functions[op](cache[args[0]], cache[args[1]])
            else:
                raise ValueError("unsupported predicate equation")
        return cache[root]
