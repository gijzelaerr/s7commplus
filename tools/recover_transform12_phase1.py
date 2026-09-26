"""Recover the branch-sensitive live-state recurrence before Transform12's tail.

Backward SSA slicing considers both choices at every scalar-bit stage. The
independent recurrence retains exact integer compatibility corrections; it is
not a modular or elliptic-curve implementation.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from functools import lru_cache

from s7commplus.session_auth.family0._generated.data import TRANSFORM12_BIG_INT_DATA
from tools import transform12_integer_model as arithmetic
from tools.decompile_transform12 import Operand, Program, dispatch_program, external_operands, format_program, trace_outputs

INITIAL_SLOTS = (46, 48, 70, 94)
TAIL_INPUT_SLOTS = (5, 87)


@dataclass(frozen=True)
class Stage:
    index: int
    inputs: tuple[int, ...]
    outputs: tuple[int, ...]
    choices: tuple[Program, Program]


@lru_cache(maxsize=1)
def recover() -> tuple[Stage, ...]:
    """Propagate the union of required inputs backward through both alternatives."""
    needed: tuple[int, ...] = TAIL_INPUT_SLOTS
    reverse = []
    for index in range(159, -1, -1):
        choices = tuple(trace_outputs(dispatch_program(index * 2 + bit), list(needed)) for bit in (0, 1))
        inputs = tuple(
            sorted({operand.index for program in choices for operand in external_operands(program) if operand.kind == "input"})
        )
        reverse.append(Stage(index, inputs, needed, (choices[0], choices[1])))
        needed = inputs
    if needed != INITIAL_SLOTS:
        raise ValueError("initial live-state layout differs from the recovered model")
    return tuple(reversed(reverse))


def evaluate_stage(stage: Stage, state: dict[int, int], bit: int) -> dict[int, int]:
    """Evaluate only this boundary's live outputs, retaining exact representatives."""
    if bit not in (0, 1) or set(state) != set(stage.inputs):
        raise ValueError("branch or live-state layout does not match the stage")
    for value in state.values():
        arithmetic.encode(value)
    values: dict[int, int] = {}

    def resolve(operand: Operand) -> int:
        if operand.kind == "value":
            return values[operand.index]
        if operand.kind == "input":
            return state[operand.index]
        offset = operand.index * 24
        return arithmetic.decode(TRANSFORM12_BIG_INT_DATA[offset : offset + 24])

    program = stage.choices[bit]
    for instruction in program.instructions:
        operands = tuple(resolve(operand) for operand in instruction.operands)
        if instruction.operation == "square":
            result = arithmetic.square(operands[0])
        else:
            operation = {"multiply": arithmetic.multiply, "add": arithmetic.add, "subtract": arithmetic.subtract}[
                instruction.operation
            ]
            result = operation(*operands)
        values[instruction.value] = result
    return {slot: resolve(operand) for slot, operand in program.outputs}


def execute_state(initial: tuple[int, int, int, int], scalar: int) -> tuple[int, int]:
    """Map four initial representatives and a 160-bit selector to the two tail inputs."""
    if len(initial) != 4 or not 0 <= scalar < arithmetic.LIMIT:
        raise ValueError("four representatives and an unsigned 160-bit scalar are required")
    state = dict(zip(INITIAL_SLOTS, initial))
    for stage in recover():
        state = evaluate_stage(stage, state, (scalar >> (159 - stage.index)) & 1)
    return state[5], state[87]


def catalogue() -> dict[str, object]:
    stages = recover()
    original_count = sum(len(dispatch_program(index).instructions) for index in range(320))
    sliced_count = sum(len(program.instructions) for stage in stages for program in stage.choices)
    slot94_written = any(
        instruction.destination_slot == 94 for index in range(320) for instruction in dispatch_program(index).instructions
    )
    return {
        "semantics": "exact compatibility arithmetic; structural liveness across all scalar choices",
        "stages": len(stages),
        "initial_slots": INITIAL_SLOTS,
        "tail_input_slots": TAIL_INPUT_SLOTS,
        "maximum_boundary_width": max(len(stage.inputs) for stage in stages),
        "slot94_written_in_original_phase": slot94_written,
        "original_instructions_both_choices": original_count,
        "live_instructions_both_choices": sliced_count,
        "excluded_instructions_both_choices": original_count - sliced_count,
        "layouts": [
            {
                "stage": stage.index,
                "inputs": stage.inputs,
                "outputs": stage.outputs,
                "instructions": [len(program.instructions) for program in stage.choices],
            }
            for stage in stages
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", type=int, choices=range(160))
    parser.add_argument("--branch", type=int, choices=(0, 1), default=0)
    args = parser.parse_args()
    if args.stage is None:
        print(json.dumps(catalogue(), indent=2))
    else:
        print(format_program(recover()[args.stage].choices[args.branch], show_constants=True))


if __name__ == "__main__":
    main()
