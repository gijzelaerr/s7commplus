"""Decode Transform12's dispatched arithmetic tape into versioned equations.

Each arithmetic instruction operates on packed 24-byte values through the
existing BigInt Prepare/Finalize primitives. SSA versions preserve reads
before writes, including aliased operands. This tool does not substitute
ordinary modular arithmetic for those byte-level semantics.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from collections import Counter
from dataclasses import asdict, dataclass, replace
from typing import Literal

from s7commplus.session_auth.family0 import big_int_operations, big_int_transforms, transform12
from s7commplus.session_auth.family0._generated.data import TRANSFORM12_BIG_INT_DATA, TRANSFORM12_METADATA
from s7commplus.session_auth.family0._generated.data._constants import TRANSFORM7_COUNTS_INTS, TRANSFORM7_INDEXES_INTS

SLOT_BYTES = 24
CONTEXT_SLOTS = transform12.CONTEXT_SIZE // SLOT_BYTES
OPERATIONS = ("multiply", "square", "add", "subtract")


@dataclass(frozen=True)
class Operand:
    kind: Literal["input", "constant", "value"]
    index: int


@dataclass(frozen=True)
class Instruction:
    value: int
    tape_index: int
    destination_slot: int
    operation: str
    operands: tuple[Operand, ...]
    ignored_bits: int


@dataclass(frozen=True)
class Program:
    start: int
    count: int
    context_slots: int
    constant_slots: int
    instructions: tuple[Instruction, ...]
    outputs: tuple[tuple[int, Operand], ...]


def build_program(
    index: int,
    count: int,
    metadata: bytes = TRANSFORM12_METADATA,
    context_slots: int = CONTEXT_SLOTS,
    constant_slots: int = len(TRANSFORM12_BIG_INT_DATA) // SLOT_BYTES,
) -> Program:
    """Decode a complete range into an exact acyclic, versioned program."""
    if index < 0 or count < 0 or index + count > len(metadata) // 4:
        raise ValueError("metadata range is outside the complete tape words")
    if context_slots < 1 or constant_slots < 0:
        raise ValueError("invalid context or constant table size")
    latest: dict[int, Operand] = {}
    instructions = []

    def read(slot: int) -> Operand:
        if slot >= 0x100:
            row = slot - 0x100
            if row >= constant_slots:
                raise ValueError(f"constant row {row} is outside the declared table")
            return Operand("constant", row)
        if slot >= context_slots:
            raise ValueError(f"context slot {slot} is outside the declared buffer")
        return latest.get(slot, Operand("input", slot))

    for value in range(count):
        tape_index = index + value
        word = struct.unpack_from("<I", metadata, tape_index * 4)[0]
        destination = (word >> 22) & 0xFF
        if destination >= context_slots:
            raise ValueError(f"destination slot {destination} is outside the declared buffer")
        opcode = word >> 30
        first = read((word >> 11) & 0x3FF)
        # Square does not consume its encoded second operand.
        operands = (first,) if opcode == 1 else (first, read(word & 0x3FF))
        instructions.append(Instruction(value, tape_index, destination, OPERATIONS[opcode], operands, word & 0x200400))
        latest[destination] = Operand("value", value)
    return Program(index, count, context_slots, constant_slots, tuple(instructions), tuple(sorted(latest.items())))


def dispatch_program(dispatch: int) -> Program:
    """Decode one of the 498 Transform7 dispatch alternatives."""
    if not 0 <= dispatch < len(TRANSFORM7_INDEXES_INTS):
        raise ValueError("dispatch index must be 0..497")
    return build_program(TRANSFORM7_INDEXES_INTS[dispatch], TRANSFORM7_COUNTS_INTS[dispatch])


def same_equations(first: Program, second: Program) -> bool:
    """Prove identical packed-arithmetic programs despite different tape locations."""

    def signature(program: Program) -> tuple[object, ...]:
        return (
            program.context_slots,
            program.constant_slots,
            tuple(
                (instruction.value, instruction.destination_slot, instruction.operation, instruction.operands)
                for instruction in program.instructions
            ),
            program.outputs,
        )

    return signature(first) == signature(second)


def stitch_programs(programs: list[Program]) -> Program:
    """Compose SSA blocks while versioning context state across their boundaries."""
    if not programs:
        raise ValueError("at least one program is required")
    first = programs[0]
    latest: dict[int, Operand] = {}
    instructions = []
    for program in programs:
        if (program.context_slots, program.constant_slots) != (first.context_slots, first.constant_slots):
            raise ValueError("program buffers do not agree")
        entry = dict(latest)
        local: dict[int, Operand] = {}

        def translate(operand: Operand) -> Operand:
            if operand.kind == "input":
                return entry.get(operand.index, operand)
            return local[operand.index] if operand.kind == "value" else operand

        for instruction in program.instructions:
            value = len(instructions)
            instructions.append(
                replace(instruction, value=value, operands=tuple(translate(operand) for operand in instruction.operands))
            )
            local[instruction.value] = Operand("value", value)
        latest.update((slot, translate(operand)) for slot, operand in program.outputs)
    return Program(
        -1,
        sum(program.count for program in programs),
        first.context_slots,
        first.constant_slots,
        tuple(instructions),
        tuple(sorted(latest.items())),
    )


def phase2_program() -> Program:
    """Recover the fixed arithmetic tail after proving all branch pairs identical."""
    programs = []
    for stage in range(160, 249):
        first, second = dispatch_program(stage * 2), dispatch_program(stage * 2 + 1)
        if not same_equations(first, second):
            raise ValueError(f"phase-two alternatives differ at stage {stage}")
        programs.append(first)
    return stitch_programs(programs)


def trace_outputs(program: Program, slots: list[int]) -> Program:
    """Keep only equations needed for the selected final context slots."""
    if any(not 0 <= slot < program.context_slots for slot in slots):
        raise ValueError("output slot is outside the declared context")
    latest = dict(program.outputs)
    outputs = tuple((slot, latest.get(slot, Operand("input", slot))) for slot in sorted(set(slots)))
    by_value = {instruction.value: instruction for instruction in program.instructions}
    wanted: set[int] = set()
    pending = [operand for _, operand in outputs]
    while pending:
        operand = pending.pop()
        if operand.kind == "value" and operand.index not in wanted:
            wanted.add(operand.index)
            pending.extend(by_value[operand.index].operands)
    return replace(
        program,
        instructions=tuple(instruction for instruction in program.instructions if instruction.value in wanted),
        outputs=outputs,
    )


def external_operands(program: Program) -> tuple[Operand, ...]:
    external = {operand for instruction in program.instructions for operand in instruction.operands if operand.kind != "value"}
    external.update(operand for _, operand in program.outputs if operand.kind != "value")
    return tuple(sorted(external, key=lambda operand: (operand.kind, operand.index)))


def prepared_constant(row: int, constants: bytes = TRANSFORM12_BIG_INT_DATA) -> int:
    """Show the integer actually consumed by Prepare for a constant row."""
    if not 0 <= row < len(constants) // SLOT_BYTES:
        raise ValueError("constant row is outside the table")
    packed = constants[row * SLOT_BYTES : (row + 1) * SLOT_BYTES]
    prepared = bytearray(big_int_operations.PREPARE_DESTINATION_SIZE)
    big_int_operations.prepare(prepared, packed)
    return int.from_bytes(prepared, "little")


def execute_program(program: Program, context: bytearray, constants: bytes = TRANSFORM12_BIG_INT_DATA) -> None:
    """Evaluate SSA with the original arithmetic primitives, preserving bytes."""
    if len(context) < program.context_slots * SLOT_BYTES:
        raise ValueError("context is shorter than the declared program buffer")
    if len(constants) < program.constant_slots * SLOT_BYTES:
        raise ValueError("constant table is shorter than the declared program table")
    values: dict[int, bytes] = {}

    def resolve(operand: Operand) -> bytes:
        if operand.kind == "value":
            return values[operand.index]
        buffer = constants if operand.kind == "constant" else context
        offset = operand.index * SLOT_BYTES
        return bytes(buffer[offset : offset + SLOT_BYTES])

    operations = {
        "multiply": big_int_transforms.big_int_multiplication,
        "square": big_int_transforms.big_int_square,
        "add": big_int_transforms.big_int_addition,
        "subtract": big_int_transforms.big_int_subtraction,
    }
    for instruction in program.instructions:
        result = bytearray(SLOT_BYTES)
        operations[instruction.operation](result, *(resolve(operand) for operand in instruction.operands))
        values[instruction.value] = bytes(result)
    # Resolve all outputs before writing, so untouched initial slots also
    # preserve the entry snapshot when used in a sliced program.
    outputs = [(slot, resolve(operand)) for slot, operand in program.outputs]
    for slot, result in outputs:
        context[slot * SLOT_BYTES : (slot + 1) * SLOT_BYTES] = result


def format_program(program: Program, show_constants: bool = False) -> str:
    """Print readable packed-arithmetic equations and final slot bindings."""

    def name(operand: Operand) -> str:
        prefix = {"input": "in", "constant": "K", "value": "v"}[operand.kind]
        return f"{prefix}{operand.index}"

    location = (
        f"Tape words {program.start}..{program.start + program.count - 1}" if program.start >= 0 else "Composed dispatch blocks"
    )
    lines = [
        f"# {location}; {len(program.instructions)} live equations",
        "# Operations use packed BigInt Prepare/Finalize semantics.",
    ]
    for operand in external_operands(program):
        if operand.kind == "input":
            lines.append(f"{name(operand)} = context[{operand.index}] at entry")
        elif show_constants:
            lines.append(f"{name(operand)} = constant[{operand.index}]  # Prepare integer 0x{prepared_constant(operand.index):x}")
    for instruction in program.instructions:
        arguments = ", ".join(name(operand) for operand in instruction.operands)
        suffix = f"  # ignored encoded bits 0x{instruction.ignored_bits:x}" if instruction.ignored_bits else ""
        lines.append(f"v{instruction.value} = {instruction.operation}({arguments}){suffix}")
    lines.extend(f"context[{slot}] at exit = {name(operand)}" for slot, operand in program.outputs)
    return "\n".join(lines)


def catalogue() -> dict[str, object]:
    """Summarize the executed tape, its SSA dependencies, and dispatch bits."""
    used: set[int] = set()
    operation_counts: Counter[str] = Counter()
    summaries = []
    programs = []
    for dispatch in range(len(TRANSFORM7_INDEXES_INTS)):
        program = dispatch_program(dispatch)
        programs.append(program)
        used.update(range(program.start, program.start + program.count))
        operation_counts.update(instruction.operation for instruction in program.instructions)
        live = trace_outputs(program, [slot for slot, _ in program.outputs])
        external = external_operands(live)
        stage, branch = divmod(dispatch, 2)
        phase = "prng2" if stage < 160 else "work_prng1"
        word = (159 - stage) >> 5 if stage < 160 else (stage - 160) >> 5
        bit = (159 - stage) & 31 if stage < 160 else stage & 31
        summaries.append(
            {
                "dispatch": dispatch,
                "stage": stage,
                "branch": branch,
                "bit_source": {"buffer": phase, "word": word, "bit": bit},
                "index": program.start,
                "count": program.count,
                "live_equations": len(live.instructions),
                "input_slots": [operand.index for operand in external if operand.kind == "input"],
                "constant_rows": [operand.index for operand in external if operand.kind == "constant"],
                "output_slots": [slot for slot, _ in program.outputs],
            }
        )
    constants = [prepared_constant(row) for row in range(len(TRANSFORM12_BIG_INT_DATA) // SLOT_BYTES)]
    complete = len(TRANSFORM12_METADATA) // 4
    return {
        "metadata_sha256": hashlib.sha256(TRANSFORM12_METADATA).hexdigest(),
        "constants_sha256": hashlib.sha256(TRANSFORM12_BIG_INT_DATA).hexdigest(),
        "complete_tape_words": complete,
        "trailing_bytes": TRANSFORM12_METADATA[complete * 4 :].hex(),
        "dispatched_instructions": sum(TRANSFORM7_COUNTS_INTS),
        "distinct_used_words": len(used),
        "used_prefix_words": max(used) + 1,
        "dispatches_partition_prefix": used == set(range(max(used) + 1)) and len(used) == sum(TRANSFORM7_COUNTS_INTS),
        "unused_complete_words": complete - len(used),
        "operations": dict(sorted(operation_counts.items())),
        "constant_rows": len(constants),
        "distinct_prepared_constants": len(set(constants)),
        "prepared_zero_rows": sum(value == 0 for value in constants),
        "identical_branch_stages": [
            stage for stage in range(len(programs) // 2) if same_equations(programs[stage * 2], programs[stage * 2 + 1])
        ],
        "programs": summaries,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--catalogue", action="store_true")
    selection.add_argument("--dispatch", type=int)
    selection.add_argument("--phase2", action="store_true")
    parser.add_argument("--output-slot", action="append", type=int)
    parser.add_argument("--constants", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if args.catalogue:
        if args.output_slot or args.constants:
            parser.error("output-slot and constants require a dispatch")
        result = catalogue()
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            result.pop("programs")
            print(json.dumps(result, indent=2))
        return
    program = phase2_program() if args.phase2 else dispatch_program(args.dispatch)
    defaults = [27, 61, 71, 97] if args.phase2 else [slot for slot, _ in program.outputs]
    slots = args.output_slot if args.output_slot is not None else defaults
    program = trace_outputs(program, slots)
    print(json.dumps(asdict(program), indent=2) if args.json else format_program(program, args.constants))


if __name__ == "__main__":
    main()
