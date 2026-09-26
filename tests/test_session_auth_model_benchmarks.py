"""Validate benchmark scope and correctness without timing thresholds."""

from __future__ import annotations

import pytest

from tools.benchmark_session_auth_models import Implementation, benchmark, measure, validate


def test_benchmark_partial_outputs_never_receive_full_transform_speed_ratio() -> None:
    report = benchmark(
        samples=1, iterations=1, source_count=1, warmups=0, import_repeats=0, names=["monolith7_generated", "monolith7_tail"]
    )
    rows = {row["name"]: row for row in report["results"]}
    assert rows["monolith7_generated"]["complete"]
    assert rows["monolith7_generated"]["generated_over_model_ratio"] == 1
    assert not rows["monolith7_tail"]["complete"]
    assert rows["monolith7_tail"]["generated_over_model_ratio"] is None
    assert rows["monolith7_tail"]["output_words"] == [15, 16, 17]


def test_benchmark_refuses_incorrect_implementation_before_timing() -> None:
    case = Implementation("broken", "tools.monolith11_model", 11, 30, tuple(range(5)))
    with pytest.raises(AssertionError, match="disagrees"):
        validate(case, lambda source: bytes(20), [bytes(120)])


def test_benchmark_rejects_unknown_models_and_empty_timing_configuration() -> None:
    with pytest.raises(ValueError, match="unavailable"):
        benchmark(names=["not_a_model"])
    with pytest.raises(ValueError, match="positive"):
        measure(lambda source: source, [], samples=1, iterations=1, warmups=0)
