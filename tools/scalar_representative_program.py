"""Readable residue/lift execution of the recovered Transform7 source graph.

Standalone primitive rules replace folded arithmetic, NOT the source ladder.
The existing setup and encoded finalizer remain separate research models.
No packaged runtime, binary fixture, or authentication behavior is changed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from s7commplus.session_auth.family0._generated.data import TRANSFORM7_DATA, TRANSFORM12_BIG_INT_DATA
from tools import scalar_representative_rules as rules
from tools import transform12_integer_model as packing
from tools.decompile_transform12 import Operand, Program, external_operands
from tools.recover_scalar_encodings import scalar_xor_mask
from tools.recover_transform12_phase1 import recover as stages
from tools.transform7_reference import finalize, tail_program
from tools.transform7_setup_integer import model as setup


@dataclass(frozen=True)
class Evaluation:
    outputs: dict[int, int]
    corrections: tuple[tuple[int, int], ...]
    instructions: int


def execute(program: Program, state: dict[int, int]) -> Evaluation:
    expected = {o.index for o in external_operands(program) if o.kind == "input"}
    if set(state) != expected:
        raise ValueError("program input layout mismatch")
    inputs = {s: rules.Representative.from_integer(v) for s, v in state.items()}
    values: dict[int, rules.Representative] = {}

    def resolve(operand: Operand) -> rules.Representative:
        if operand.kind == "value":
            return values[operand.index]
        if operand.kind == "input":
            return inputs[operand.index]
        offset = operand.index * 24
        return rules.Representative.from_integer(packing.decode(TRANSFORM12_BIG_INT_DATA[offset : offset + 24]))

    corrections = []
    for instruction in program.instructions:
        a, b = resolve(instruction.operands[0]), resolve(instruction.operands[-1])
        if instruction.operation == "add":
            result, correction = rules.add(a, b)
        elif instruction.operation == "subtract":
            result, correction = rules.subtract(a, b)
        elif instruction.operation in ("multiply", "square"):
            result, correction = rules.multiply(a, b), 0
        else:
            raise ValueError("unsupported source operation")
        values[instruction.value] = result
        if correction:
            corrections.append((instruction.value, correction))
    return Evaluation({s: resolve(o).integer() for s, o in program.outputs}, tuple(corrections), len(program.instructions))


def full_output(x: int, y: int, prng1: int, scalar: int) -> tuple[bytes, tuple[Evaluation, ...]]:
    for value in (x, y, prng1, scalar):
        rules.Representative.from_integer(value)
    state = dict(zip(stages()[0].inputs, setup(x, y, prng1).slots))
    rows = []
    for stage in stages():
        row = execute(stage.choices[scalar >> (159 - stage.index) & 1], state)
        state = row.outputs
        rows.append(row)
    tail = execute(tail_program(), state)
    return finalize(tail.outputs), tuple(rows) + (tail,)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--effective-scalar", type=lambda v: int(v, 0), default=0)
    parser.add_argument("--prng1", type=lambda v: int(v, 0), default=0)
    args = parser.parse_args()
    if not 0 <= args.effective_scalar < 1 << 160 or not 0 <= args.prng1 < 1 << 160:
        parser.error("unsigned 160-bit synthetic inputs required")
    x, y = (int.from_bytes(TRANSFORM7_DATA[o : o + 20], "little") for o in (0xD8, 0xEC))
    output, rows = full_output(x, y, args.prng1, args.effective_scalar ^ scalar_xor_mask())
    from tools.predict_scalar_defects import source_hashes

    hashes = source_hashes()
    hashes["tools/scalar_representative_program.py"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    print(
        json.dumps(
            {
                "scope": "exact residue/lift primitive rules; still traverses recovered source SSA; NOT a compact ladder or hardware validation",
                "destination_hex": output.hex(),
                "tail": (rows[159].outputs[5], rows[159].outputs[87]),
                "source_instructions": sum(row.instructions for row in rows),
                "corrections_by_stage": [(i, row.corrections) for i, row in enumerate(rows) if row.corrections],
                "source_sha256": hashes,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
