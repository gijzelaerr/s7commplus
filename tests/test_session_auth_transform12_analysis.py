"""Byte-level equivalence and dependency checks for the arithmetic decompiler."""

from __future__ import annotations

import random
import struct

import pytest

from s7commplus.session_auth.family0 import big_int_operations, transform12
from tools.decompile_transform12 import (
    CONTEXT_SLOTS,
    Operand,
    build_program,
    catalogue,
    dispatch_program,
    execute_program,
    external_operands,
    phase2_program,
    same_equations,
    trace_outputs,
)


def _context() -> bytearray:
    rng = random.Random(0x1200)
    context = bytearray(transform12.CONTEXT_SIZE)
    for slot in range(CONTEXT_SLOTS):
        big_int_operations.finalize(memoryview(context)[slot * 24 : (slot + 1) * 24], rng.randbytes(20))
    return context


def _word(opcode: int, destination: int, first: int, second: int) -> int:
    return (opcode << 30) | (destination << 22) | (first << 11) | second


def test_all_498_dispatched_programs_match_byte_interpreter() -> None:
    initial = _context()
    for dispatch in range(498):
        program = dispatch_program(dispatch)
        expected = bytearray(initial)
        actual = bytearray(initial)
        transform12.execute(expected, program.start, program.count)
        execute_program(program, actual)
        assert actual == expected, f"dispatch {dispatch}"


def test_ssa_reads_previous_version_before_aliased_writes() -> None:
    tape = struct.pack("<3I", _word(0, 0, 0, 1), _word(2, 0, 0, 1), _word(1, 1, 0, 250))
    program = build_program(0, 3, tape, context_slots=2, constant_slots=0)
    assert program.instructions[0].operands == (Operand("input", 0), Operand("input", 1))
    assert program.instructions[1].operands == (Operand("value", 0), Operand("input", 1))
    assert program.instructions[2].operands == (Operand("value", 1),)
    assert dict(program.outputs) == {0: Operand("value", 1), 1: Operand("value", 2)}


def test_output_slice_matches_selected_exit_bytes_and_keeps_other_inputs() -> None:
    program = dispatch_program(496)
    sliced = trace_outputs(program, [27])
    assert len(sliced.instructions) < len(program.instructions)
    initial = _context()
    full, actual = bytearray(initial), bytearray(initial)
    execute_program(program, full)
    execute_program(sliced, actual)
    assert actual[27 * 24 : 28 * 24] == full[27 * 24 : 28 * 24]
    assert actual[: 27 * 24] == initial[: 27 * 24]
    assert actual[28 * 24 :] == initial[28 * 24 :]
    assert all(operand.kind != "value" for operand in external_operands(sliced))


def test_untouched_output_slot_is_initial_input() -> None:
    program = dispatch_program(0)
    sliced = trace_outputs(program, [97])
    assert not sliced.instructions
    assert sliced.outputs == ((97, Operand("input", 97)),)
    context = _context()
    expected = bytes(context)
    execute_program(sliced, context)
    assert context == expected


def test_catalogue_excludes_suffix_and_recovers_branch_insensitive_phase() -> None:
    result = catalogue()
    assert result["dispatched_instructions"] == result["distinct_used_words"] == 60858
    assert result["dispatches_partition_prefix"] is True
    assert result["unused_complete_words"] == 48
    assert result["trailing_bytes"] == "00"
    assert result["prepared_zero_rows"] == 285
    assert result["identical_branch_stages"] == list(range(160, 249))
    assert same_equations(dispatch_program(496), dispatch_program(497))
    assert not same_equations(dispatch_program(0), dispatch_program(1))


def test_composed_phase2_matches_every_block_with_mixed_branch_choices() -> None:
    expected, actual = _context(), _context()
    for stage in range(160, 249):
        program = dispatch_program(stage * 2 + (stage & 1))
        transform12.execute(expected, program.start, program.count)
    program = phase2_program()
    assert len(program.instructions) == 2000
    execute_program(program, actual)
    assert actual == expected
    sliced = trace_outputs(program, [27, 61, 71, 97])
    assert {operand.index for operand in external_operands(sliced) if operand.kind == "input"} == {5, 87}


def test_encoded_reserved_bits_are_preserved_and_semantically_ignored() -> None:
    tape = struct.pack("<I", _word(0, 0, 0, 1) | 0x200400)
    program = build_program(0, 1, tape, context_slots=2, constant_slots=0)
    assert program.instructions[0].ignored_bits == 0x200400
    assert program.instructions[0].operands == (Operand("input", 0), Operand("input", 1))


@pytest.mark.parametrize("index,count", [(-1, 1), (0, -1), (0, 2), (1, 1)])
def test_invalid_tape_ranges_are_rejected(index: int, count: int) -> None:
    with pytest.raises(ValueError, match="metadata range"):
        build_program(index, count, b"\x00" * 5)


@pytest.mark.parametrize("word", [_word(0, 2, 0, 0), _word(0, 0, 2, 0), _word(0, 0, 256, 0)])
def test_invalid_operand_buffers_are_rejected(word: int) -> None:
    with pytest.raises(ValueError, match="outside"):
        build_program(0, 1, struct.pack("<I", word), context_slots=2, constant_slots=0)
