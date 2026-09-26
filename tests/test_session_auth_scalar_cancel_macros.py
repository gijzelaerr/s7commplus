"""Universal cancellation preserves carries and conditional small lifts."""

import random
from itertools import product
from unittest.mock import patch

import pytest

from tools import scalar_cancel_macros as macros
from tools import transform12_integer_model as exact
from tools.prove_scalar_cancel_macros import prove
from tools.recover_transform12_phase1 import recover as stages
from tools.scalar_shift_macros import P
from tools.scalar_stage_plan import constant
from tools.transform7_reference import tail_program


def test_composed_source_and_actual_predicate_ast_proofs() -> None:
    pytest.importorskip("z3")
    result = prove()
    assert result["full_proof"]
    assert [row["result"] for row in result["obligations"]] == ["unsat", "unsat", "unsat", "sat", "sat"]
    with pytest.raises(ValueError, match="positive"):
        prove(0)


def test_arbitrary_cancellation_corners_carries_and_random_inputs() -> None:
    rng = random.Random(53160)
    values = [0, 1, 2, 45, 46, 47, 48, 94, (1 << 128) - 1, 1 << 128, (1 << 128) + 47, P - 1, P, P + 1, P + 45, P + 46]
    values.extend(rng.randrange(1 << 160) for _ in range(50))
    cases = set(product(values, repeat=2))
    # Addition carry edges need deliberate construction, not random luck.
    for a in values:
        for offset in (0, 1, 46, 47, (1 << 128) - 47, (1 << 128) - 1):
            cases.add((a, ((1 << 160) + offset - a) % (1 << 160)))
    for a, b in cases:
        assert macros.cancel_add(a, b) == exact.subtract(exact.add(a, b), a)
    for a, b in product(values, range(47)):
        assert macros.restore_small_subtract(a, b) == exact.add(exact.subtract(a, b), b)


def test_every_found_pattern_and_small_constant_are_exercised() -> None:
    programs = [*(program for stage in stages() for program in stage.choices), tail_program()]
    all_rows = [row for program in programs for row in macros.recover(program)]
    assert len(all_rows) == 65
    assert sum(row.operation == "cancel_add" for row in all_rows) == 61
    assert sum(row.operation == "restore_small_subtract" for row in all_rows) == 4
    assert sum(len(macros.recover(program)) for program in programs[:-1]) == 1
    values = (0, 1, 45, 46, 47, (1 << 128) + 48, P - 1, P, P + 1, P + 46)
    for program in programs:
        instructions = {instruction.value: instruction for instruction in program.instructions}
        for row in macros.recover(program):
            inner, outer = instructions[row.inner_value], instructions[row.output_value]
            assert row.inner_value < row.output_value
            for raw in values:
                a, b = (constant(operand) if operand.kind == "constant" else raw for operand in row.operands)
                if row.operation == "cancel_add":
                    assert inner.operation == "add" and outer.operation == "subtract"
                    assert macros.cancel_add(a, b) == exact.subtract(exact.add(a, b), a)
                else:
                    assert inner.operation == "subtract" and outer.operation == "add"
                    assert macros.restore_small_subtract(a, b) == exact.add(exact.subtract(a, b), b)


def test_readable_rules_are_not_no_ops_and_call_no_source_arithmetic() -> None:
    with (
        patch.object(exact, "add", side_effect=AssertionError("source add")),
        patch.object(exact, "subtract", side_effect=AssertionError("source subtract")),
    ):
        assert macros.cancel_add(0, P + 1) == P + 1
        assert macros.cancel_add(45, P + 1) == P + 1
        assert macros.cancel_add(46, P + 1) == 1
        assert macros.cancel_add(P - 100, (1 << 128) + 100) == 194
        assert macros.restore_small_subtract(0, 1) == P
        assert macros.restore_small_subtract(1, 1) == 1
        assert macros.restore_small_subtract(P + 1, 0) == P + 1


def test_unproved_and_invalid_domains_are_rejected() -> None:
    for fn in (macros.cancel_add, macros.restore_small_subtract):
        for raw in (True, -1, 1 << 160):
            with pytest.raises(ValueError, match="uint160"):
                fn(raw, 0)
            with pytest.raises(ValueError, match="uint160"):
                fn(0, raw)
    with pytest.raises(ValueError, match="requires b<47"):
        macros.restore_small_subtract(0, 47)
