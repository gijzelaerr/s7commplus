"""Exact arbitrary-operand addition cancellation and small subtraction restore.

These are local source-arithmetic identities, not ordinary field no-ops.
The recovered annotations preserve shared inner uses and never change runtime
code. No curve, prime-modulus, inverse, or nonzero assumption is required.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass

from tools.decompile_transform12 import Operand, Program
from tools.scalar_shift_macros import CORRECTION, LIMIT, LOW, P
from tools.scalar_stage_plan import constant


def cancellation_carry(a: int, b: int) -> bool:
    return a + b >= LIMIT and (a + b) % LOW >= LOW - 47


def cancellation_lift(a: int, b: int, mu_b: int) -> bool:
    return a < 47 and b >= P and a + mu_b < 47


def restore_small_lift(a: int, b: int, mu_a: int) -> bool:
    return mu_a <= 46 and (a >= P or a < b)


def _validate(a: int, b: int) -> None:
    if any(type(value) is not int or not 0 <= value < LIMIT for value in (a, b)):
        raise ValueError("two uint160 operands required")


def cancel_add(a: int, b: int) -> int:
    """Exact subtract(add(a,b),a): retain add's field defect, never a SUB defect."""
    _validate(a, b)
    mu = (b % P + CORRECTION * cancellation_carry(a, b)) % P
    return mu + P * cancellation_lift(a, b, b % P)


def restore_small_subtract(a: int, b: int) -> int:
    """Exact add(subtract(a,b),b) for 0<=b<47, including conditional lift."""
    _validate(a, b)
    if b >= 47:
        raise ValueError("small subtraction restore requires b<47")
    return a % P + P * restore_small_lift(a, b, a % P)


@dataclass(frozen=True)
class Macro:
    operation: str
    inner_value: int
    output_value: int
    operands: tuple[Operand, Operand]


def recover(program: Program) -> tuple[Macro, ...]:
    """Find the actual matching SSA operands, not equality inferred from probes."""
    instructions = {instruction.value: instruction for instruction in program.instructions}
    rows = []
    for instruction in program.instructions:
        if instruction.operation == "subtract":
            summed, canceled = instruction.operands
            inner = instructions.get(summed.index) if summed.kind == "value" else None
            if inner is not None and inner.operation == "add" and canceled in inner.operands:
                remaining = inner.operands[1] if inner.operands[0] == canceled else inner.operands[0]
                rows.append(Macro("cancel_add", inner.value, instruction.value, (canceled, remaining)))
        elif instruction.operation == "add":
            for subtracted, restored in (instruction.operands, instruction.operands[::-1]):
                inner = instructions.get(subtracted.index) if subtracted.kind == "value" else None
                if (
                    inner is not None
                    and inner.operation == "subtract"
                    and inner.operands[1] == restored
                    and restored.kind == "constant"
                    and constant(restored) < 47
                ):
                    rows.append(Macro("restore_small_subtract", inner.value, instruction.value, (inner.operands[0], restored)))
                    break
    return tuple(rows)


def main() -> None:
    from tools.recover_transform12_phase1 import recover as stages
    from tools.transform7_reference import tail_program

    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    programs = [
        *((stage.index, bit, program) for stage in stages() for bit, program in enumerate(stage.choices)),
        (160, 0, tail_program()),
    ]
    rows = [
        {
            "stage": index,
            "branch": bit,
            "operation": row.operation,
            "inner_value": row.inner_value,
            "output_value": row.output_value,
            "operands": [
                {
                    "kind": operand.kind,
                    "index": operand.index,
                    **({"raw_constant": constant(operand)} if operand.kind == "constant" else {}),
                }
                for operand in row.operands
            ],
        }
        for index, bit, program in programs
        for row in recover(program)
    ]
    print(
        json.dumps(
            {"scope": "source-local semantic annotations, preserve other inner uses; NOT a program rewrite", "macros": rows},
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
