"""Individual source equations, pure setup model, and exact carry regressions."""

from __future__ import annotations

import itertools
import json
import random
import struct
import sys
from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest

from s7commplus.session_auth.family0 import big_int_operations, big_int_transforms, transform7, transform12
from s7commplus.session_auth.family0._generated import monolith3, monolith4, monolith5, monolith6
from tools import transform12_integer_model as arithmetic
from tools import transform7_setup_integer as integer
from tools.benchmark_transform7_setup import benchmark
from tools.prove_monolith_carry_save import equations, prove as prove_bits
from tools.prove_transform7_setup_ranges import OutputBit
from tools.prove_transform7_setup_integer import (
    Origin,
    Plain,
    carry_save_dependency,
    prove,
    setup_dependency,
    source_reference,
    verify_topology,
)
from tools.recover_monolith3_span_identity import observe
from tools.recover_monolith4_span_identity import normalized_span
from tools.recover_transform7_setup import SLOTS, capture_setup, targeted_base_point_probe
from tools.trace_transform7_setup_shadows import NAMES
from tools.transform7_setup_merge import decode_payload

FOLDER = Path(__file__).resolve().parents[1] / "tools"


def test_carry_save_integer_identity_exhaustive_small_payloads_and_boundary_bits() -> None:
    for values in itertools.product(range(16), repeat=3):
        spans = tuple(integer.Span(value >> 1, value & 1) for value in values)
        total, carry = integer.carry_save(spans)
        hs = sum(span.boundary for span in spans)
        target = sum(span.payload for span in spans) + integer.H * (hs & 1) + int(hs >= 2)
        assert total + 2 * carry == target
        first, second = integer.pack(spans)
        assert (first + second) % integer.MODULUS == target % integer.MODULUS


def test_exact_monolith5_streams_for_arbitrary_raw_encodings() -> None:
    rng = random.Random(0xC5A5)
    for _ in range(256):
        words = tuple(rng.getrandbits(32) for _ in range(54))
        spans = tuple(integer.Span(*normalized_span(words[i * 18 : (i + 1) * 18])) for i in range(3))
        output = bytearray(48)
        monolith5.execute(output, struct.pack("<54I", *words))
        assert integer.pack(spans) == (decode_payload(bytes(output[:24])), decode_payload(bytes(output[24:])))


def assert_setup(case: tuple[int, int, int]) -> None:
    expected = integer.model(*case)
    count = 0

    def wrap(name, original):
        def execute(*buffers):
            nonlocal count
            step = expected.steps[count]
            number = int(name[8])
            outputs = 1 if number == 4 else 2
            inputs = tuple(
                integer.Span(*normalized_span(struct.unpack("<18I", bytes(buffer[:72]))))
                for buffer in buffers[outputs : outputs + (2 if number in (3, 4) else 3)]
            )
            assert step.number == number and step.inputs == inputs
            if number == 3:
                assert step.plain == int.from_bytes(bytes(buffers[-1][:24]), "little")
            original(*buffers)
            if number == 5:
                assert step.streams == tuple(decode_payload(bytes(buffer[:24])) for buffer in buffers[:outputs])
            else:
                assert step.outputs == tuple(
                    integer.Span(*normalized_span(struct.unpack("<18I", bytes(buffer[:72])))) for buffer in buffers[:outputs]
                )
            count += 1

        return execute

    with ExitStack() as stack:
        for name in NAMES:
            stack.enter_context(patch.object(transform7, name, wrap(name, getattr(transform7, name))))
        actual = capture_setup(*case)
    assert count == 23
    assert expected.slots == actual
    assert expected.slots[3] == case[0]  # Preserve X>=p, not X modulo p.
    assert all(0 <= value < integer.LIMIT for value in expected.slots)


def test_all_decoded_inputs_outputs_streams_and_context_representatives() -> None:
    boundaries = (0, 1, 2, 3, 4, integer.P - 1, integer.P, integer.P + 1, integer.LIMIT - 1, 1 << 128, (1 << 128) - 47)
    cases = [(value, value, value) for value in boundaries]
    cases.append(targeted_base_point_probe())
    rng = random.Random(0xC5A)
    cases.extend(tuple(rng.getrandbits(160) for _ in range(3)) for _ in range(128))
    for case in cases:
        assert_setup(case)


def test_model_executes_no_generated_kernel_or_runtime_arithmetic_helper() -> None:
    with ExitStack() as stack:
        for name in NAMES:
            stack.enter_context(patch.object(transform7, name, side_effect=AssertionError("runtime wrapper called")))
        for module, names in (
            (big_int_transforms, ("big_int_addition", "big_int_subtraction", "big_int_multiplication", "big_int_square")),
            (big_int_operations, ("prepare", "finalize", "rotate_right_30")),
        ):
            for name in names:
                stack.enter_context(patch.object(module, name, side_effect=AssertionError("runtime arithmetic called")))
        for module in (monolith3, monolith4, monolith5, monolith6):
            stack.enter_context(patch.object(module, "execute", side_effect=AssertionError("generated kernel called")))
        assert len(integer.model(1, 2, 3).slots) == 4


def test_exact_input_only_carry_witness_and_noncanonical_x() -> None:
    result = integer.model(*targeted_base_point_probe())
    merges = dict(result.merges)
    assert merges[46].lost_carry and merges[46].result == 94
    assert merges[46].ideal_residue == 1 << 128
    assert not any(value.lost_carry for slot, value in result.merges if slot != 46)
    for x in (integer.P, integer.P + 1, integer.LIMIT - 1):
        assert integer.model(x, 0, 0).slots[3] == x


@pytest.mark.parametrize("scalar", (0, 1, (1 << 160) - 1))
def test_exact_setup_substitution_preserves_complete_transform7_destination(scalar: int) -> None:
    x, y, r = targeted_base_point_probe()
    source = transform7.TRANSFORM7_DATA[0xD8:]
    prng1, prng2 = bytearray(r.to_bytes(20, "little")), bytearray(scalar.to_bytes(20, "little"))
    reference, replaced = bytearray(72), bytearray(72)
    transform7.execute(reference, prng1, prng2, source)
    original = transform12.execute
    calls = 0
    predicted = integer.model(x, y, r).slots

    def substitute(context: bytearray, index: int, count: int) -> None:
        nonlocal calls
        if calls == 0:
            for slot, value in zip(SLOTS, predicted):
                packed = arithmetic.encode(value)
                assert bytes(context[slot * 24 : (slot + 1) * 24]) == packed
                context[slot * 24 : (slot + 1) * 24] = packed
        calls += 1
        original(context, index, count)

    with patch.object(transform12, "execute", substitute):
        transform7.execute(replaced, prng1, prng2, source)
    assert calls == 249 and reference == replaced


def test_invalid_upper_encoding_witness_still_defeats_decoded_only_pair_model() -> None:
    source = transform7.TRANSFORM7_DATA[:144] + bytes(24)
    words = list(struct.unpack("<42I", source))
    words[17] ^= 1 << 9
    before, after = observe(source), observe(struct.pack("<42I", *words))
    spans = tuple(integer.Span(*value) for value in before.encoded_inputs)
    predicted = integer.quarter(spans, 0)
    assert tuple((span.payload, span.boundary) for span in predicted) == before.pair.output_spans
    assert before.encoded_inputs == after.encoded_inputs
    assert tuple((span.payload, span.boundary) for span in predicted) != after.pair.output_spans


def test_individual_bit_record_is_complete_current_and_independently_replayable() -> None:
    carry_save_dependency()
    report = json.loads((FOLDER / "monolith_carry_save_proof.json").read_text())
    assert report["full_proof"] and report["expected_stages"] == 1012
    assert sum(row["conditional"] for row in report["stages"]) == 2
    assert report["translation_controls_per_kernel"] == 8
    assert sum(row["monolith"] == 5 for row in report["stages"]) == 336


def test_source_topology_and_saved_compositional_record_regenerate_exactly() -> None:
    pytest.importorskip("z3")
    expected = json.loads((FOLDER / "transform7_setup_integer_proof.json").read_text())
    assert prove() == expected
    assert expected["full_setup_model_established"] and expected["final_carry_correction_retained"]


def test_symbolic_recipe_detects_wrong_inputs_plain_expression_and_merge_pair() -> None:
    pytest.importorskip("z3")
    original = integer._compose
    for mutation in (lambda x, y, r: original(y, x, r), lambda x, y, r: original(x << 2, y, r)):
        with patch.object(integer, "_compose", mutation):
            with pytest.raises(ValueError):
                verify_topology()

    def wrong_merge(x, y, r):
        result = original(x, y, r)
        slot, streams = result.merges[0]
        return replace(result, merges=((slot, (streams[0], streams[0])), *result.merges[1:]))

    with patch.object(integer, "_compose", wrong_merge):
        with pytest.raises(ValueError, match="exact packed output pair"):
            verify_topology()

    def wrong_encoded_pair(x, y, r):
        quarter = integer.quarter
        with patch.object(integer, "quarter", lambda pair, plain: quarter((pair[1], pair[0]), plain)):
            return original(x, y, r)

    with patch.object(integer, "_compose", wrong_encoded_pair):
        with pytest.raises(ValueError, match="encoded provenance"):
            verify_topology()
    # Provenance checks do not depend on the numerical kernel implementation.
    with patch.object(integer, "carry_save", side_effect=AssertionError("numeric kernel must not be evaluated")):
        assert len(verify_topology()) == 23


@pytest.mark.parametrize("mutation", ("duplicate", "conditional", "sat", "source", "table"))
def test_individual_bit_dependency_rejects_false_or_mismatched_records(mutation: str) -> None:
    report = json.loads((FOLDER / "monolith_carry_save_proof.json").read_text())
    if mutation == "duplicate":
        report["stages"][-1] = report["stages"][0]
    elif mutation == "conditional":
        report["stages"][0]["conditional"] = True
    elif mutation == "sat":
        report["stages"][0]["result"] = "sat"
    elif mutation == "source":
        report["source_sha256"]["monolith3.py"] = "0" * 64
    else:
        report["upper_zero_triples"][0][0] = 0
    with patch("tools.prove_transform7_setup_integer.json.loads", return_value=report):
        with pytest.raises(ValueError):
            carry_save_dependency()


def test_all_1012_individual_source_equations_replay_with_optional_solver() -> None:
    pytest.importorskip("z3")
    assert prove_bits(timeout_ms=10000)["full_proof"]


@pytest.mark.parametrize("values", ((-1, 0), (integer.MODULUS, 0), (0, 2), (False, 0)))
def test_span_values_reject_invalid_payloads_and_boundaries(values: tuple[int, int]) -> None:
    with pytest.raises(ValueError):
        integer.Span(*values)


def test_invalid_primitive_inputs_and_source_references_fail_closed() -> None:
    for value in (-1, integer.LIMIT, False):
        with pytest.raises(ValueError):
            integer.model(value, 0, 0)
    with pytest.raises(ValueError):
        integer.halve((integer.Span(1 << 166), integer.ZERO, integer.ZERO))
    with pytest.raises(ValueError):
        integer.quarter((integer.ZERO, integer.ZERO), 1 << 162)
    with pytest.raises(ValueError):
        integer.carry_save(())
    with pytest.raises(ValueError):
        integer.add(())
    with pytest.raises(ValueError):
        source_reference(())
    with pytest.raises(ValueError):
        Plain("X") | 8
    with pytest.raises(ValueError):
        Plain("X") << 3
    with pytest.raises(ValueError):
        equations(4)
    with pytest.raises(ValueError):
        prove_bits(0)
    bits = tuple(OutputBit(3, 18 + k // 32, k % 32) for k in range(576))
    assert source_reference(bits) == Origin(3, 1)
    with pytest.raises(ValueError):
        source_reference((bits[1], *bits[1:]))


@pytest.mark.parametrize("mutation", ("duplicate", "range", "unproved"))
def test_setup_dependency_rejects_unproved_or_unsound_accounting(mutation: str) -> None:
    pytest.importorskip("z3")
    report = json.loads((FOLDER / "transform7_setup_invariant_proof.json").read_text())
    if mutation == "duplicate":
        report["stages"][-1] = report["stages"][0]
    elif mutation == "range":
        report["stages"][1]["maximum_payload"] = 1 << 166
    else:
        report["stages"][1]["proved"] = False
    with patch("tools.prove_transform7_setup_integer.json.loads", return_value=report):
        with patch(
            "tools.prove_transform7_setup_integer.setup_invariant_dependency", return_value=report["local_invariant_dependency"]
        ):
            with patch(
                "tools.prove_transform7_setup_integer.kernel_dependency",
                side_effect=lambda n: report["kernel_dependencies"][str(n)],
            ):
                with pytest.raises(ValueError, match="accounting"):
                    setup_dependency()


def test_cli_carry_witness_runs_without_runtime_execution(capsys) -> None:
    with patch.object(sys, "argv", ["model", "--carry-witness"]):
        with patch.object(transform7, "execute", side_effect=AssertionError("native setup called")):
            integer.main()
    report = json.loads(capsys.readouterr().out)
    assert report["slots"][0] == 94


@pytest.mark.parametrize("args", (("--x", "-1"), ("--carry-witness", "--r", "0")))
def test_cli_rejects_invalid_or_ambiguous_inputs(args: tuple[str, ...]) -> None:
    with patch.object(sys, "argv", ["model", *args]):
        with pytest.raises(SystemExit) as error:
            integer.main()
    assert error.value.code == 2


def test_setup_benchmark_is_correctness_gated_and_scope_is_explicit() -> None:
    with patch("tools.benchmark_transform7_setup.measure", side_effect=[{"median_us": 2.0}, {"median_us": 1.0}]):
        report = benchmark(samples=1, iterations=1, source_count=2, warmups=0)
    assert report["capture_over_model_ratio"] == 2
    assert "NOT whole Transform7" in report["scope"]
    with patch("tools.benchmark_transform7_setup.capture_setup", return_value=(0, 0, 0, 0)):
        with pytest.raises(AssertionError, match="disagrees"):
            benchmark(samples=1, iterations=1, source_count=1, warmups=0)


@pytest.mark.parametrize("arguments", ({"samples": 0}, {"iterations": 0}, {"source_count": 0}, {"warmups": -1}))
def test_setup_benchmark_rejects_invalid_budget(arguments: dict[str, int]) -> None:
    with pytest.raises(ValueError):
        benchmark(**arguments)
