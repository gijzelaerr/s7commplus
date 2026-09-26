"""Canonical-coordinate prefix predicates stop at the exact first correction."""

import random
from unittest.mock import patch

import pytest

from tools import scalar_first_defect as model
from tools import scalar_representative_rules as rules
from tools.recover_transform12_phase1 import recover
from tools.trace_scalar_defects import evaluate_stage

P = model.P


def test_all_intermediate_branches_match_independent_fold_oracle() -> None:
    catalogue = model.compile_catalogue()
    rng = random.Random(946128)
    for stage in recover()[1:159]:
        samples = [{s: value for s in stage.inputs} for value in (0, 1, 23, 46, 47, P, P + 1, P + 46)]
        samples.extend({s: rng.choice((0, 46, 47, P - 1, P, P + 23, (1 << 128) - 1)) for s in stage.inputs} for _ in range(4))
        samples.append({s: rng.randrange(1 << 160) for s in stage.inputs})
        for bit in (0, 1):
            for state in samples:
                _, events = evaluate_stage(stage.index, state, bit)
                assert catalogue.first_defect(stage.index, state, bit) == (events[0] if events else None)


def test_compiled_evaluation_does_not_replay_source_or_python_helpers() -> None:
    catalogue = model.compile_catalogue()
    stage = recover()[1]
    state = {s: P + 1 for s in stage.inputs}
    expected = evaluate_stage(1, state, 0)[1][0]
    with (
        patch.object(model, "stages", side_effect=AssertionError("source replay")),
        patch.object(model, "compile_guard", side_effect=AssertionError("AST recompilation")),
        patch.object(rules, "lazy_addition_defect", side_effect=AssertionError("Python helper")),
        patch.object(rules, "lazy_subtraction_defect", side_effect=AssertionError("Python helper")),
    ):
        assert catalogue.first_defect(1, state, 0) == expected


def test_model_is_explicitly_prefix_only_and_validates_input_scope() -> None:
    catalogue = model.compile_catalogue()
    report = catalogue.summary()
    assert report["branches"] == 316
    assert report["whole_runtime_equivalence"] is False
    for index in (0, 159, 160, True):
        with pytest.raises(ValueError, match="intermediate stage"):
            catalogue.first_defect(index, {}, 0)
    with pytest.raises(ValueError, match="input layout"):
        catalogue.first_defect(1, {}, 0)
    stage = recover()[1]
    for value in (True, -1, 1 << 160):
        with pytest.raises(ValueError, match="unsigned160"):
            catalogue.first_defect(1, {s: value for s in stage.inputs}, 0)


def test_equal_residues_are_not_mistaken_for_equal_raw_representatives() -> None:
    catalogue = model.compile_catalogue()
    slots = recover()[1].inputs
    canonical = {s: 1 for s in slots}
    lifted = {s: P + 1 for s in slots}
    a, b = catalogue.first_defect(1, canonical, 0), catalogue.first_defect(1, lifted, 0)
    assert a != b
    assert b == evaluate_stage(1, lifted, 0)[1][0]
