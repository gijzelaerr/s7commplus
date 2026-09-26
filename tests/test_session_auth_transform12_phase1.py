"""Exact recurrence and structural live-state checks for all first-phase branches."""

import random

import pytest

from s7commplus.session_auth.family0 import transform12
from tools import recover_transform12_phase1 as model
from tools import transform12_integer_model as arithmetic
from tools.decompile_transform12 import dispatch_program


def test_branch_union_liveness_catalogue() -> None:
    catalogue = model.catalogue()
    assert catalogue["initial_slots"] == (46, 48, 70, 94)
    assert catalogue["tail_input_slots"] == (5, 87)
    assert catalogue["maximum_boundary_width"] == 5
    assert catalogue["original_instructions_both_choices"] == 56858
    assert catalogue["live_instructions_both_choices"] == 56497
    assert catalogue["excluded_instructions_both_choices"] == 361
    stages = model.recover()
    assert len(stages) == 160
    assert stages[0].inputs == model.INITIAL_SLOTS
    assert stages[-1].outputs == model.TAIL_INPUT_SLOTS
    for first, second in zip(stages, stages[1:]):
        assert first.outputs == second.inputs
    assert all(len(stage.inputs) == 5 for stage in stages[1:])


def test_slot94_is_never_written_in_any_original_branch() -> None:
    assert not model.catalogue()["slot94_written_in_original_phase"]
    for index in range(320):
        assert all(instruction.destination_slot != 94 for instruction in dispatch_program(index).instructions)
    for stage in model.recover()[:-1]:
        assert 94 in stage.inputs and 94 in stage.outputs


def test_every_branch_matches_original_exit_bytes() -> None:
    rng = random.Random(160320)
    for stage in model.recover():
        state = {slot: rng.getrandbits(160) for slot in stage.inputs}
        for bit in (0, 1):
            context = bytearray(transform12.CONTEXT_SIZE)
            for slot, value in state.items():
                context[slot * 24 : (slot + 1) * 24] = arithmetic.encode(value)
            original = dispatch_program(stage.index * 2 + bit)
            transform12.execute(context, original.start, original.count)
            actual = model.evaluate_stage(stage, state, bit)
            assert set(actual) == set(stage.outputs)
            for slot, value in actual.items():
                assert arithmetic.encode(value) == bytes(context[slot * 24 : (slot + 1) * 24])


def test_complete_phase_with_arbitrary_ignored_slots() -> None:
    rng = random.Random(4160)
    scalars = [0, 1, arithmetic.MASK, 1 << 159, int.from_bytes(b"\x55" * 20, "little")]
    scalars.extend(rng.getrandbits(160) for _ in range(8))
    for scalar in scalars:
        # Non-live initial slots deliberately contain unrelated packed values.
        context = bytearray(b"".join(arithmetic.encode(rng.getrandbits(160)) for _ in range(transform12.CONTEXT_SIZE // 24)))
        initial = tuple(arithmetic.decode(bytes(context[slot * 24 : (slot + 1) * 24])) for slot in model.INITIAL_SLOTS)
        for stage in range(160):
            program = dispatch_program(stage * 2 + ((scalar >> (159 - stage)) & 1))
            transform12.execute(context, program.start, program.count)
        actual = model.execute_state((initial[0], initial[1], initial[2], initial[3]), scalar)
        expected = tuple(arithmetic.decode(bytes(context[slot * 24 : (slot + 1) * 24])) for slot in model.TAIL_INPUT_SLOTS)
        assert actual == expected


@pytest.mark.parametrize("scalar", [-1, arithmetic.LIMIT, arithmetic.LIMIT + 1])
def test_invalid_scalars_rejected(scalar: int) -> None:
    with pytest.raises(ValueError, match="160-bit"):
        model.execute_state((0, 0, 0, 0), scalar)


@pytest.mark.parametrize("bit", [-1, 2])
def test_invalid_stage_branches_rejected(bit: int) -> None:
    stage = model.recover()[0]
    with pytest.raises(ValueError, match="branch"):
        model.evaluate_stage(stage, dict.fromkeys(stage.inputs, 0), bit)
