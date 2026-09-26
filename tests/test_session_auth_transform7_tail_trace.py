"""Reachability observations from synthetic, complete Transform7 executions."""

from unittest.mock import patch

import pytest

from s7commplus.session_auth.family0 import transform7, transform12
from tools import trace_transform7_tail as trace


def test_synthetic_cases_are_deterministic_and_cover_public_sources() -> None:
    cases = trace.cases(1)
    assert cases == trace.cases(1)
    assert len(cases) == 18
    assert {case.name.split("/")[0] for case in cases} == {"base", "s7-1200", "s7-1500"}
    assert len({case.name for case in cases}) == len(cases)
    assert trace.cases(1, seed=42)[5] != cases[5]


@pytest.mark.parametrize("case", trace.cases(0)[::5], ids=lambda case: case.name)
def test_trace_follows_real_prng_dispatches_without_changing_output(case: trace.Case) -> None:
    original = transform12.execute
    observed = trace.observe(case)
    expected = bytearray(transform7.DESTINATION_SIZE)
    transform7.execute(expected, bytearray(case.prng1), bytearray(case.prng2), case.source)
    assert observed.destination == bytes(expected)
    assert transform12.execute is original
    assert len(observed.entry) == len(observed.exit) == transform12.CONTEXT_SIZE
    assert len(observed.dispatches) == 249
    scalar = int.from_bytes(case.prng2, "little")
    blinding = int.from_bytes(case.prng1, "little") | 4
    for stage, dispatch in enumerate(observed.dispatches):
        bit = (scalar >> (159 - stage)) & 1 if stage < 160 else (blinding >> (stage - 160)) & 1
        assert dispatch == stage * 2 + bit


@pytest.mark.parametrize("case", trace.cases(1), ids=lambda case: case.name)
def test_reachable_tail_matches_models_and_full_destination(case: trace.Case) -> None:
    result = trace.analyze(case)
    assert result["entry_below_p"]
    assert result["entry_nonzero"]
    assert result["exact_model_matches"]
    assert result["phase1_model_matches"]
    assert result["shadow_residue_mismatch_slots"] == []
    assert result["shadow_packed_mismatch_slots"] == []
    assert result["first_divergence_value"] is None
    assert result["shadow_final_destination_matches"]


@pytest.mark.parametrize(
    "case",
    [
        trace.Case("short-a", bytes(19), bytes(20), bytes(40)),
        trace.Case("short-b", bytes(20), bytes(19), bytes(40)),
        trace.Case("short-source", bytes(20), bytes(20), bytes(39)),
    ],
)
def test_invalid_cases_rejected(case: trace.Case) -> None:
    with pytest.raises(ValueError, match="20-byte"):
        trace.observe(case)


def test_patch_is_restored_after_failure() -> None:
    original = transform12.execute
    with patch.object(transform7, "execute", side_effect=RuntimeError("synthetic failure")):
        with pytest.raises(RuntimeError, match="synthetic failure"):
            trace.observe(trace.cases(0)[0])
    assert transform12.execute is original


def test_negative_random_count_rejected() -> None:
    with pytest.raises(ValueError, match="negative"):
        trace.cases(-1)


def test_trace_detects_an_incorrect_compact_model() -> None:
    original = trace.compact_outputs

    def incorrect(x: int, y: int) -> dict[int, int]:
        outputs = original(x, y)
        outputs[27] = 0
        return outputs

    with patch.object(trace, "compact_outputs", incorrect):
        result = trace.analyze(trace.cases(0)[0])
    assert result["shadow_residue_mismatch_slots"] == [27]
    assert result["shadow_packed_mismatch_slots"] == [27]
    assert not result["shadow_final_destination_matches"]
    summary = trace.summarize([result])
    assert summary["shadow_final_destination_mismatch_cases"] == ["base/zero"]
    assert summary["shadow_packed_mismatch_cases"] == ["base/zero"]


def test_slot71_changes_are_visible_in_tail_but_unused_by_final_destination() -> None:
    original = trace.compact_outputs

    def change_unused(x: int, y: int) -> dict[int, int]:
        outputs = original(x, y)
        outputs[71] = 0
        return outputs

    with patch.object(trace, "compact_outputs", change_unused):
        result = trace.analyze(trace.cases(0)[0])
    assert result["shadow_packed_mismatch_slots"] == [71]
    assert result["shadow_final_destination_matches"]
