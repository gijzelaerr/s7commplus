"""Sound raw-value implications between scalar subtraction guards.

Research only. Bounds are saturated at47 and refer to uint160 representatives,
NOT field residues. If an add/square/positive-constant product has raw output
at most46, its recorded ancestors are no larger than that output. Therefore
a second-wrap subtraction implies the same defect for each such ancestor
and the IDENTICAL right SSA operand. No curve or first-defect assumption.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from tools.decompile_transform12 import Operand, Program


@dataclass(frozen=True)
class Implications:
    safe: frozenset[int]
    dominated: dict[int, tuple[int, ...]]
    lower_bounds: dict[int, int]
    exclusive: frozenset[tuple[int, int]]


def analyze(program: Program, constant: Callable[[Operand], int], *, input_bounds: dict[int, int] | None = None) -> Implications:
    """Optional input bounds must be sound raw lower bounds, saturated at47.

    Unspecified inputs have lower bound zero. The evaluator constructs these
    facts from the actual entry representatives; the prefix compiler uses no
    entry facts. Never pass field residues as raw representative bounds.
    """
    inputs = dict(input_bounds or {})
    if any(type(slot) is not int or type(bound) is not int or not 0 <= bound <= 47 for slot, bound in inputs.items()):
        raise ValueError("integer input slots and raw bounds0..47 required")
    bounds: dict[Operand, int] = {}
    ancestors: dict[Operand, frozenset[Operand]] = {}
    earlier: dict[tuple[Operand, Operand], int] = {}
    safe: set[int] = set()
    dominated: dict[int, tuple[int, ...]] = {}
    earlier_errors: set[int] = set()
    exclusive: set[tuple[int, int]] = set()

    def facts(operand: Operand) -> tuple[int, frozenset[Operand]]:
        if operand.kind == "value":
            if operand not in bounds:
                raise ValueError("structural guards require acyclic unique SSA values")
            return bounds[operand], ancestors[operand]
        if operand.kind == "constant":
            value = constant(operand)
            if type(value) is not int or not 0 <= value < 1 << 160:
                raise ValueError("uint160 raw constant required")
            return min(value, 47), frozenset((operand,))
        if operand.kind != "input":
            raise ValueError("unsupported operand")
        return inputs.get(operand.index, 0), frozenset((operand,))

    for instruction in program.instructions:
        first, last = instruction.operands[0], instruction.operands[-1]
        a, aa = facts(first)
        b, bb = facts(last)
        inherited: frozenset[Operand] = frozenset()
        if instruction.operation == "add":
            lower, inherited = min(a + b, 47), aa | bb
        elif instruction.operation in ("multiply", "square"):
            lower = min(a * b, 47)
            if first == last:
                inherited = aa
            else:
                if a >= 1:
                    inherited |= bb
                if b >= 1:
                    inherited |= aa
        elif instruction.operation == "subtract":
            lower = 0
            if last.kind == "constant":
                lower = min(max(a - constant(last), 0), 47)
                if constant(last) == 0:
                    inherited = aa
            if a >= 47 or last in aa:
                safe.add(instruction.value)
            previous = sorted({earlier[o, last] for o in aa if (o, last) in earlier})
            if previous:
                dominated[instruction.value] = tuple(previous)
            exclusive.update((o.index, instruction.value) for o in aa if o.kind == "value" and o.index in earlier_errors)
            earlier[first, last] = instruction.value
        else:
            raise ValueError("unsupported structural operation")
        output = Operand("value", instruction.value)
        if output in bounds:
            raise ValueError("structural guards require acyclic unique SSA values")
        bounds[output] = lower
        ancestors[output] = inherited | frozenset((output,))
        if instruction.operation in ("add", "subtract"):
            earlier_errors.add(instruction.value)
    return Implications(frozenset(safe), dominated, {o.index: value for o, value in bounds.items()}, frozenset(exclusive))
