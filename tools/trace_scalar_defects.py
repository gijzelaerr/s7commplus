"""Trace exact scalar-stage defects for public synthetic reference-point inputs."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass

from s7commplus.session_auth.family0._generated.data import TRANSFORM7_DATA, TRANSFORM12_BIG_INT_DATA
from tools import transform12_integer_model as exact
from tools import transform12_residue_defects as arithmetic
from tools.decompile_transform12 import Operand
from tools.recover_scalar_encodings import scalar_xor_mask
from tools.recover_transform12_phase1 import recover as stages
from tools.scalar_ladder_model import model as compact
from tools.transform7_setup_integer import model as setup


@dataclass(frozen=True)
class Defect:
    stage: int
    branch: int
    tape_index: int
    operation: str
    operands: tuple[int, ...]
    representative: int
    correction: int


def evaluate_stage(index: int, state: dict[int, int], bit: int) -> tuple[dict[int, int], tuple[Defect, ...]]:
    """Return the exact live exit and its locally observed residue defects."""
    stage = stages()[index]
    if bit not in (0, 1) or set(state) != set(stage.inputs):
        raise ValueError("branch or stage input layout mismatch")
    for value in state.values():
        exact.encode(value)
    events: list[Defect] = []
    values: dict[int, int] = {}

    def resolve(operand: Operand) -> int:
        if operand.kind == "value":
            return values[operand.index]
        if operand.kind == "input":
            return state[operand.index]
        offset = operand.index * 24
        return exact.decode(TRANSFORM12_BIG_INT_DATA[offset : offset + 24])

    program = stage.choices[bit]
    for instruction in program.instructions:
        operands = tuple(resolve(o) for o in instruction.operands)
        if instruction.operation == "square":
            result = arithmetic.multiply(operands[0], operands[0])
        else:
            result = {"add": arithmetic.add, "subtract": arithmetic.subtract, "multiply": arithmetic.multiply}[
                instruction.operation
            ](*operands)
        if result.correction:
            events.append(
                Defect(
                    index, bit, instruction.tape_index, instruction.operation, operands, result.representative, result.correction
                )
            )
        values[instruction.value] = result.representative
    return {s: resolve(o) for s, o in program.outputs}, tuple(events)


def execute(x: int, y: int, prng1: int, scalar: int) -> tuple[tuple[int, int], tuple[Defect, ...]]:
    """Evaluate source SSA using independently lifted representative equations."""
    if any(type(v) is not int or not 0 <= v < exact.LIMIT for v in (x, y, prng1, scalar)):
        raise ValueError("unsigned 160-bit synthetic inputs required")
    state = dict(zip(stages()[0].inputs, setup(x, y, prng1).slots))
    events: list[Defect] = []
    for stage in stages():
        bit = (scalar >> (159 - stage.index)) & 1
        state, local = evaluate_stage(stage.index, state, bit)
        events.extend(local)
    return (state[5], state[87]), tuple(events)


def reference_case(effective_scalar: int = 0, prng1: int = 0) -> dict[str, object]:
    x = int.from_bytes(TRANSFORM7_DATA[0xD8:0xEC], "little")
    y = int.from_bytes(TRANSFORM7_DATA[0xEC:0x100], "little")
    if type(effective_scalar) is not int or not 0 <= effective_scalar < exact.LIMIT:
        raise ValueError("unsigned 160-bit effective scalar required")
    scalar = effective_scalar ^ scalar_xor_mask()
    actual, events = execute(x, y, prng1, scalar)
    shadow = compact(x, y, prng1, scalar)
    return {
        "scope": "public synthetic on-curve reference point; exact representative defects, no live exchange",
        "effective_scalar": effective_scalar,
        "selector": scalar,
        "prng1": prng1,
        "tail_actual": actual,
        "tail_shadow": shadow,
        "tail_residues_match": tuple(v % arithmetic.P for v in actual) == shadow,
        "defect_count": len(events),
        "defects": [asdict(event) for event in events],
        "ordinary_inverse_precondition_holds": actual[0] % arithmetic.P != 0,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--effective-scalar", type=lambda v: int(v, 0), default=0)
    parser.add_argument("--prng1", type=lambda v: int(v, 0), default=0)
    args = parser.parse_args()
    print(json.dumps(reference_case(args.effective_scalar, args.prng1), indent=2))


if __name__ == "__main__":
    main()
