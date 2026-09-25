"""Raw SSA guard implications, negative controls and complete source checks."""

import random
from dataclasses import replace
from unittest.mock import patch

import pytest

from s7commplus.session_auth.family0._generated.data import TRANSFORM7_DATA
from tools import scalar_stage_plan as compiler
from tools import scalar_first_defect as prefix
from tools import scalar_structural_guards as model
from tools import transform12_integer_model as exact
from tools.decompile_transform12 import Instruction, Operand, Program
from tools.recover_scalar_encodings import scalar_xor_mask
from tools.recover_transform12_phase1 import recover
from tools.trace_scalar_defects import evaluate_stage
from tools.transform7_reference import model as reference, tail_program

P = compiler.P


def toy(parent: str = "add", same_right: bool = True) -> Program:
    u, b, x = (Operand("input", i) for i in range(3))
    instructions = (
        Instruction(0, 0, 3, "subtract", (u, b), 0),
        Instruction(1, 1, 4, parent, (u, x) if parent != "square" else (u,), 0),
        Instruction(2, 2, 5, "subtract", (Operand("value", 1), b if same_right else x), 0),
    )
    return Program(0, 3, 6, 0, instructions, ((3, Operand("value", 0)), (5, Operand("value", 2))))


def test_exact_ssa_identity_and_only_proved_parent_operations() -> None:
    for parent in ("add", "square"):
        assert model.analyze(toy(parent), compiler.constant).dominated == {2: (0,)}
    assert not model.analyze(toy(same_right=False), compiler.constant).dominated
    for parent in ("multiply", "subtract"):
        assert not model.analyze(toy(parent), compiler.constant).dominated


def test_dominance_never_suppresses_a_true_defect() -> None:
    source = toy()
    plan = compiler.compile_plan(source)
    for state in ({0: 1, 1: P + 2, 2: 0}, {0: P + 1, 1: P + 2, 2: 0}):
        old = compiler.evaluate(plan, state)
        new = compiler.evaluate(plan, state, structural_guards=True)
        assert new.outputs == old.outputs and new.defects == old.defects
        assert new.structurally_settled_guards == (0 if state[0] == 1 else 2)
    assert len(compiler.evaluate(plan, {0: 1, 1: P + 2, 2: 0}, structural_guards=True).defects) == 2


def test_direct_cancellation_is_safe_without_modular_monotonicity() -> None:
    source = toy()
    instructions = list(source.instructions)
    instructions[1] = replace(instructions[1], operands=(Operand("input", 1), Operand("input", 2)))
    source = replace(source, instructions=tuple(instructions))
    assert model.analyze(source, compiler.constant).safe == frozenset((2,))
    plan = compiler.compile_plan(source)
    boundaries = (0, 1, 23, 46, 47, (1 << 128) - 1, P - 1, P, P + 23, P + 46)
    for b in boundaries:
        for x in boundaries:
            state = {0: 0, 1: b, 2: x}
            actual = compiler.evaluate(plan, state, structural_guards=True)
            expected = exact.subtract(exact.add(b, x), b)
            assert actual.outputs[5] == expected
            assert actual.structurally_settled_guards == 1


def test_entry_raw_bounds_do_not_confuse_small_residues_and_lifted_inputs() -> None:
    source = toy("multiply")
    source = replace(source, outputs=(*source.outputs, (4, Operand("value", 1))))
    assert 2 not in model.analyze(source, compiler.constant).safe
    facts = model.analyze(source, compiler.constant, input_bounds={0: 47, 2: 1})
    assert 2 in facts.safe and facts.lower_bounds[1] == 47
    # A lifted residue1 is raw-large, not raw-small. Its product's small
    # residue must be lifted too; raw lower bounds settle this without tags.
    plan = compiler.compile_plan(source)
    state = {0: P + 1, 1: P + 2, 2: 1}
    old = compiler.evaluate(plan, state)
    actual = compiler.evaluate(plan, state, structural_guards=True)
    assert actual.outputs == old.outputs and actual.defects == old.defects
    assert actual.structurally_settled_guards == 2 and actual.structurally_settled_lifts == 1
    for invalid in ({0: True}, {False: 1}, {0: -1}, {0: 48}):
        with pytest.raises(ValueError, match="raw bounds"):
            model.analyze(source, compiler.constant, input_bounds=invalid)


def test_saturated_raw_bounds_and_positive_constant_ancestry() -> None:
    u, b = Operand("input", 0), Operand("input", 1)
    for constant, expected_safe, expected_dominated in ((0, False, False), (1, False, True), (47, True, True)):
        instructions = (
            Instruction(0, 0, 2, "subtract", (u, b), 0),
            Instruction(1, 1, 3, "multiply", (u, Operand("constant", 0)), 0),
            Instruction(2, 2, 4, "subtract", (Operand("value", 1), b), 0),
            Instruction(3, 3, 5, "add", (u, Operand("constant", 0)), 0),
            Instruction(4, 4, 6, "subtract", (Operand("value", 3), b), 0),
        )
        source = Program(0, 5, 7, 1, instructions, ())
        facts = model.analyze(source, lambda _: constant)
        assert (4 in facts.safe) == expected_safe
        assert (2 in facts.dominated) == expected_dominated
        assert 4 in facts.dominated


def test_malformed_source_and_constants_are_rejected() -> None:
    source = toy()
    for broken in (
        replace(source.instructions[0], operands=(Operand("value", 1), Operand("input", 1))),
        replace(source.instructions[1], value=0),
        replace(source.instructions[1], operation="divide"),
    ):
        with pytest.raises(ValueError):
            model.analyze(replace(source, instructions=(source.instructions[0], broken)), compiler.constant)
    source = replace(
        source, instructions=(replace(source.instructions[0], operands=(Operand("constant", 0), Operand("input", 1))),)
    )
    for constant in (True, -1, 1 << 160):
        with pytest.raises(ValueError, match="uint160"):
            model.analyze(source, lambda _: constant)


def test_catalogue_counts_are_source_specific_and_not_poly_aliases() -> None:
    static = dynamic = 0
    for source in (*(source for stage in recover() for source in stage.choices), tail_program()):
        facts = model.analyze(source, compiler.constant)
        static += sum(i.value in facts.safe and not compiler.carry_safe(i) for i in source.instructions)
        dynamic += sum(
            i.value in facts.dominated and i.value not in facts.safe and not compiler.carry_safe(i) for i in source.instructions
        )
    assert (static, dynamic) == (369, 154)
    facts = model.analyze(recover()[16].choices[0], compiler.constant)
    assert 9 in facts.dominated[24]


def test_structural_prefix_matches_all_intermediate_source_branches() -> None:
    catalogue = prefix.compile_catalogue(structural_guards=True)
    assert catalogue.summary()["structural_guards"] is True
    assert catalogue.summary()["guard_sites"] < 20007
    rng = random.Random(67419)
    for stage in recover()[1:159]:
        states = [{s: v for s in stage.inputs} for v in (0, 1, 46, P, P + 1, P + 46)]
        states.extend({s: rng.choice((0, 46, 47, P - 1, P, P + 23)) for s in stage.inputs} for _ in range(4))
        states.append({s: rng.randrange(1 << 160) for s in stage.inputs})
        for bit in (0, 1):
            for state in states:
                _, events = evaluate_stage(stage.index, state, bit)
                assert catalogue.first_defect(stage.index, state, bit) == (events[0] if events else None)
    for invalid in (0, 1, "true"):
        with pytest.raises(ValueError, match="Boolean"):
            prefix.compile_catalogue(structural_guards=invalid)


@pytest.mark.parametrize("cap", [2, 8, 64, 256])
def test_all_source_branches_and_prior_defects_match_the_independent_oracle(cap: int) -> None:
    rng = random.Random(34159672)
    for stage in recover():
        samples = [{s: v for s in stage.inputs} for v in (0, 23, P, P + 1, P + 46)]
        samples.append({s: rng.choice((0, 46, 47, P - 1, P, P + 23)) for s in stage.inputs})
        samples.append({s: rng.randrange(1 << 160) for s in stage.inputs})
        for bit, source in enumerate(stage.choices):
            plan = compiler.compile_plan(source, cap, boolean_corrections=True)
            for state in samples:
                expected, events = evaluate_stage(stage.index, state, bit)
                actual = compiler.evaluate(plan, state, stage.index, bit, category_lifts=True, structural_guards=True)
                assert actual.outputs == expected and actual.defects == events
                active = {i.value for i in source.instructions if any(e.tape_index == i.tape_index for e in events)}
                assert not any(a in active and b in active for a, b in model.analyze(source, compiler.constant).exclusive)


@pytest.mark.parametrize("cofactors", [False, True])
def test_complete_bytes_all_boundaries_and_point_changing_control(cofactors: bool) -> None:
    public = tuple(int.from_bytes(TRANSFORM7_DATA[o : o + 20], "little") for o in (0xD8, 0xEC))
    changing = ((1 << 128) + 48, 917984300236617229462155822449362250189314875415)
    for (x, y), scalar in ((public, scalar_xor_mask()), (changing, 0)):
        kwargs = {"boolean_corrections": True, "demand_guards": cofactors, "cofactor_fields": cofactors, "category_lifts": True}
        baseline, old = compiler.full_output(x, y, 0, scalar, **kwargs)
        actual, new = compiler.full_output(x, y, 0, scalar, structural_guards=True, **kwargs)
        expected = reference(bytes(20), scalar.to_bytes(20, "little"), x.to_bytes(20, "little") + y.to_bytes(20, "little"))
        assert actual == baseline == expected.destination
        assert tuple(row.outputs for row in new) == tuple(row.outputs for row in old)
        assert tuple(row.defects for row in new) == tuple(row.defects for row in old)
        assert sum(row.structurally_settled_guards for row in new) > 0


def test_actual_source_lemmas_and_negative_controls() -> None:
    pytest.importorskip("z3")
    from tools.prove_scalar_structural_guards import prove

    report = prove()
    assert report["full_proof"], report
    assert len(report["obligations"]) == 19
    assert sum(row["result"] == "sat" for row in report["obligations"]) == 2


def test_unknown_and_bad_timeout_do_not_count_as_proof() -> None:
    z3 = pytest.importorskip("z3")
    from tools.prove_scalar_structural_guards import prove

    with patch.object(z3.Solver, "check", return_value=z3.unknown):
        assert not prove()["full_proof"]
    for timeout in (0, -1):
        with pytest.raises(ValueError, match="positive"):
            prove(timeout)
