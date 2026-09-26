"""Predict scalar carry sites and exact representatives without a full trace.

Source polynomials supply residues; only ambiguous residues 0..46 require
on-demand representative evaluation. Carry guards are visited in source order
and detected corrections repair descendant polynomials. This still uses the
source SSA dependency graph, not an independent compact curve algorithm.
Synthetic/public inputs only; no packaged runtime replacement is made.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from s7commplus.session_auth.family0._generated.data import TRANSFORM7_DATA, TRANSFORM12_BIG_INT_DATA
from tools import recover_scalar_curve as curve
from tools import scalar_representative_rules as representative_rules
from tools import transform12_integer_model as exact
from tools import transform12_residue_defects as arithmetic
from tools.decompile_transform12 import Instruction, Operand, Program, external_operands
from tools.recover_scalar_encodings import scalar_xor_mask
from tools.recover_scalar_shadow import MODULUS as MODULUS
from tools.recover_scalar_shadow import Polynomial, add, evaluate, multiply
from tools.recover_transform12_phase1 import recover as stages
from tools.trace_scalar_defects import Defect
from tools.transform7_setup_integer import model as setup
from tools.transform7_reference import finalize, tail_program

TERM_LIMIT = 4096


@dataclass(frozen=True)
class Prediction:
    outputs: dict[int, int]
    defects: tuple[Defect, ...]
    defect_values: tuple[int, ...]
    source_instructions: int
    guarded_sites: int
    potential_sites: int
    representative_operations: int
    positive_tag_rules: int
    zero_tag_rules: int
    repaired_nodes: int


def addition_possible(residue: int) -> bool:
    """Necessary defect condition valid for either representative of operands."""
    return 47 <= residue <= 92 or residue >= arithmetic.LOW_LIMIT and residue % arithmetic.LOW_LIMIT < 47


def subtraction_possible(a: int, b: int) -> bool:
    """Only a small canonical a and a larger small, p-lifted b can wrap twice."""
    return a < b <= 46


def addition_lift(a: int, b: int) -> bool:
    """p-lift bit, conditional on the operation's residue being 0..46."""
    return a + b >= MODULUS


def subtraction_lift(a: int, b: int) -> bool:
    """p-lift bit, conditional on the corrected residue being 0..46."""
    return a - b >= MODULUS or a - b < -MODULUS


def multiplication_lift(a: int, b: int) -> bool:
    """p-lift bit, conditional on the residue being 0..46."""
    return a * b >= MODULUS


def compact_multiply(a: int, b: int) -> int:
    """Exact uint160 multiplication representative, without three-fold code.

    Folding preserves residues; lifts above46 are unique. For residues0..46
    the proved product-threshold rule chooses between r and p+r.
    """
    arithmetic.validate(a, b)
    product = a * b
    residue = product % MODULUS
    return residue + (MODULUS if residue <= 46 and product >= MODULUS else 0)


def equation(instruction: Instruction, resolve: Callable[[Operand], Polynomial]) -> Polynomial:
    a, b = resolve(instruction.operands[0]), resolve(instruction.operands[-1])
    if instruction.operation in ("add", "subtract"):
        result = add(a, b, -1 if instruction.operation == "subtract" else 1)
    elif instruction.operation in ("multiply", "square"):
        result = multiply(a, b, TERM_LIMIT)
    else:
        raise ValueError("unsupported source operation")
    if len(result) > TERM_LIMIT:
        raise ValueError("predicate polynomial exceeds the term limit")
    return result


@lru_cache(maxsize=8)
def program_polynomials(program: Program, input_slots: tuple[int, ...]) -> dict[int, Polynomial]:
    values: dict[int, Polynomial] = {}
    width = len(input_slots)
    variables = dict(zip(input_slots, curve.variables(width)))

    def resolve(operand: Operand) -> Polynomial:
        if operand.kind == "value":
            return values[operand.index]
        if operand.kind == "input":
            return variables[operand.index]
        offset = operand.index * 24
        value = exact.decode(TRANSFORM12_BIG_INT_DATA[offset : offset + 24]) % MODULUS
        return {(0,) * width: value} if value else {}

    for instruction in program.instructions:
        values[instruction.value] = equation(instruction, resolve)
    return values


def predict_stage(index: int, state: dict[int, int], bit: int) -> Prediction:
    if type(index) is not int or not 0 <= index < 160:
        raise ValueError("stage index must be 0..159")
    stage = stages()[index]
    if bit not in (0, 1) or set(state) != set(stage.inputs):
        raise ValueError("stage input layout or branch mismatch")
    return predict_program(stage.choices[bit], state, index, bit)


def predict_program(program: Program, state: dict[int, int], index: int = 160, bit: int = 0) -> Prediction:
    """Predict a recovered SSA program; tail index160 labels the fixed group.

    Stitched tail tape words may repeat. defect_values records unique SSA
    identities, unlike tape_index alone. No exact-trace fallback is used.
    """
    input_slots = tuple(o.index for o in external_operands(program) if o.kind == "input")
    if bit not in (0, 1) or set(state) != set(input_slots):
        raise ValueError("program input layout or branch mismatch")
    for value in state.values():
        exact.encode(value)
    inputs = tuple(state[s] % MODULUS for s in input_slots)
    polynomials = dict(program_polynomials(program, input_slots))
    instructions = {i.value: i for i in program.instructions}
    residues: dict[int, int] = {}
    representatives: dict[int, int] = {}
    positive_rules = 0
    zero_rules = 0
    repaired = 0

    def constant(operand: Operand) -> int:
        offset = operand.index * 24
        return exact.decode(TRANSFORM12_BIG_INT_DATA[offset : offset + 24])

    def residue(operand: Operand) -> int:
        if operand.kind == "input":
            return state[operand.index] % MODULUS
        if operand.kind == "constant":
            return constant(operand) % MODULUS
        if operand.index not in residues:
            residues[operand.index] = evaluate(polynomials[operand.index], inputs)
        return residues[operand.index]

    def representative(operand: Operand) -> int:
        nonlocal positive_rules, zero_rules
        if operand.kind == "input":
            return state[operand.index]
        if operand.kind == "constant":
            return constant(operand)
        if operand.index not in representatives:
            value = residue(operand)
            if value > 46:
                representatives[operand.index] = value  # Unique uint160 lift.
            else:
                instruction = instructions[operand.index]
                if value == 0:
                    first, last = instruction.operands[0], instruction.operands[-1]

                    def positive(o: Operand) -> bool:
                        return residue(o) != 0 or representative(o) != 0

                    if instruction.operation in ("multiply", "square"):
                        output = MODULUS if positive(first) and positive(last) else 0
                    elif instruction.operation == "add":
                        output = MODULUS if positive(first) or positive(last) else 0
                    else:
                        output = MODULUS if representative(first) > representative(last) else 0
                    zero_rules += 1
                    representatives[operand.index] = output
                    return output
                a = representative(instruction.operands[0])
                b = representative(instruction.operands[-1])
                lifted = {
                    "add": addition_lift,
                    "subtract": subtraction_lift,
                    "multiply": multiplication_lift,
                    "square": multiplication_lift,
                }[instruction.operation](a, b)
                positive_rules += 1
                representatives[operand.index] = value + (MODULUS if lifted else 0)
        return representatives[operand.index]

    def repair(at: int, correction: int) -> None:
        nonlocal repaired
        affected = {at}
        width = len(inputs)
        polynomials[at] = add(polynomials[at], {(0,) * width: correction % MODULUS})

        def resolve(operand: Operand) -> Polynomial:
            if operand.kind == "value":
                return polynomials[operand.index]
            if operand.kind == "input":
                return curve.variables(width)[input_slots.index(operand.index)]
            value = constant(operand) % MODULUS
            return {(0,) * width: value} if value else {}

        for instruction in program.instructions:
            if instruction.value > at and any(o.kind == "value" and o.index in affected for o in instruction.operands):
                polynomials[instruction.value] = equation(instruction, resolve)
                affected.add(instruction.value)
        for value in affected:
            residues.pop(value, None)
            representatives.pop(value, None)
        repaired += len(affected)

    events = []
    event_values = []
    guards = 0
    potentials = 0
    for instruction in program.instructions:
        if instruction.operation not in ("add", "subtract"):
            continue
        guards += 1
        operands = instruction.operands
        if instruction.operation == "add":
            possible = addition_possible(residue(Operand("value", instruction.value)))
        else:
            possible = subtraction_possible(residue(operands[0]), residue(operands[1]))
        if not possible:
            continue
        potentials += 1
        a, b = representative(operands[0]), representative(operands[1])
        operation = representative_rules.add if instruction.operation == "add" else representative_rules.subtract
        result, correction = operation(
            representative_rules.Representative.from_integer(a), representative_rules.Representative.from_integer(b)
        )
        output = result.integer()
        if correction:
            events.append(Defect(index, bit, instruction.tape_index, instruction.operation, (a, b), output, correction))
            event_values.append(instruction.value)
            repair(instruction.value, correction)
    outputs = {s: representative(o) for s, o in program.outputs}
    return Prediction(
        outputs,
        tuple(events),
        tuple(event_values),
        len(program.instructions),
        guards,
        potentials,
        0,
        positive_rules,
        zero_rules,
        repaired,
    )


def predict(x: int, y: int, prng1: int, scalar: int) -> tuple[tuple[int, int], tuple[Prediction, ...]]:
    if any(type(v) is not int or not 0 <= v < exact.LIMIT for v in (x, y, prng1, scalar)):
        raise ValueError("four unsigned 160-bit synthetic inputs required")
    state = dict(zip(stages()[0].inputs, setup(x, y, prng1).slots))
    results = []
    for index in range(160):
        result = predict_stage(index, state, scalar >> (159 - index) & 1)
        state = result.outputs
        results.append(result)
    return (state[5], state[87]), tuple(results)


def full_output(x: int, y: int, prng1: int, scalar: int) -> tuple[bytes, tuple[Prediction, ...]]:
    """Complete 72-byte result using polynomial/tag prediction and encoded DAGs.

    This is a source-dependent checkout evaluator, not an independent compact
    authentication algorithm or hardware validation.
    """
    tail, rows = predict(x, y, prng1, scalar)
    fixed = predict_program(tail_program(), dict(zip((5, 87), tail)))
    return finalize(fixed.outputs), rows + (fixed,)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--effective-scalar", type=lambda v: int(v, 0), default=0)
    parser.add_argument("--prng1", type=lambda v: int(v, 0), default=0)
    args = parser.parse_args()
    x = int.from_bytes(TRANSFORM7_DATA[0xD8:0xEC], "little")
    y = int.from_bytes(TRANSFORM7_DATA[0xEC:0x100], "little")
    if type(args.effective_scalar) is not int or not 0 <= args.effective_scalar < exact.LIMIT:
        parser.error("unsigned 160-bit effective scalar required")
    output, rows = full_output(x, y, args.prng1, args.effective_scalar ^ scalar_xor_mask())
    print(
        json.dumps(
            {
                "scope": "source-polynomial carry prediction with sparse representative queries; still uses source SSA dependencies",
                "no_exact_trace_fallback": True,
                "tail": (rows[159].outputs[5], rows[159].outputs[87]),
                "destination_hex": output.hex(),
                "defects": [e.__dict__ for row in rows for e in row.defects],
                "defect_ssa_values_by_stage": [(index, row.defect_values) for index, row in enumerate(rows) if row.defects],
                "source_instructions": sum(row.source_instructions for row in rows),
                "representative_operations": sum(row.representative_operations for row in rows),
                "positive_tag_rules": sum(row.positive_tag_rules for row in rows),
                "zero_tag_rules": sum(row.zero_tag_rules for row in rows),
                "potential_guard_sites": sum(row.potential_sites for row in rows),
                "repaired_nodes": sum(row.repaired_nodes for row in rows),
                "source_sha256": source_hashes(),
            },
            indent=2,
        )
    )


def source_hashes() -> dict[str, str]:
    root = Path(__file__).resolve().parents[1]
    paths = (
        "tools/predict_scalar_defects.py",
        "tools/scalar_representative_rules.py",
        "tools/recover_scalar_curve.py",
        "tools/recover_scalar_shadow.py",
        "tools/recover_scalar_encodings.py",
        "tools/recover_transform12_phase1.py",
        "tools/decompile_transform12.py",
        "tools/transform12_residue_defects.py",
        "tools/transform12_integer_model.py",
        "tools/transform7_setup_integer.py",
        "tools/transform7_setup_merge.py",
        "tools/transform7_reference.py",
        "tools/monolith_encoded_reference.py",
        "s7commplus/session_auth/artifacts.json",
        "s7commplus/session_auth/family0/_generated/data/_constants.py",
        "s7commplus/session_auth/family0/_generated/data/transform12_metadata.bin",
        "s7commplus/session_auth/family0/_generated/data/transform12_big_int_data.bin",
    )
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in paths}


if __name__ == "__main__":
    main()
