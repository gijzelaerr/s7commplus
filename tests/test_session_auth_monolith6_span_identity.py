"""Monolith6 local-column controls and limits of decoded-only state."""

from __future__ import annotations

import hashlib
import itertools
import json
import random
import struct
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from s7commplus.session_auth.family0._generated import monolith3, monolith4, monolith6
from tools import prove_monolith6_span_identity as proof
from tools.prove_monolith4_span_identity import boolean_backend, symbolic_source
from tools.recover_monolith4_span_identity import normalized_terms, output_gate_diagram
from tools.recover_monolith6_span_identity import H, high_bit_witness, local_carries, observe, relation
from tools.recover_monolith5_span_decoder import MODULUS, P, local_gate, recover


def test_local_columns_wrap_balance_and_exact_signed_integer_identity() -> None:
    rng = random.Random(0x6DEC)
    wraps = set()
    model = recover()
    offset = sum(term.weight for term in model.terms if term.weight < 0)
    for _ in range(256):
        source = rng.randbytes(216)
        destination = bytearray(144)
        monolith6.execute(destination, source)
        result = relation(source, bytes(destination))
        inputs, outputs = result.input_spans, result.output_spans
        carries = local_carries(inputs)
        hs = sum(h for _, h in inputs)
        counts = [sum((b >> k) & 1 for b, _ in inputs) for k in range(168)]
        assert sum(h for _, h in outputs) == counts[0] + hs % 2 + int(hs >= 2) - 2 * carries[0]
        for k in range(1, 168):
            assert (
                sum((b >> (k - 1)) & 1 for b, _ in outputs)
                == counts[k] + ((H >> k) & 1) * (hs % 2) + carries[k - 1] - 2 * carries[k]
            )
        assert result.wrap_balance == result.local_wrap_balance
        assert -1 <= result.wrap_balance <= 1
        assert result.output_shadow == result.corrected_shadow
        assert result.doubled_output - result.target == MODULUS * result.wrap_balance

        def signed(span: bytes) -> int:
            words = struct.unpack("<18I", span)
            return sum(term.weight * local_gate(term, words) for term in model.terms)

        input_sum = sum(signed(source[i * 72 : (i + 1) * 72]) for i in range(3))
        output_sum = sum(signed(bytes(destination[i * 72 : (i + 1) * 72])) for i in range(2))
        assert 2 * output_sum - input_sum == offset + MODULUS * result.wrap_balance + P * result.boundary_adjustment
        wraps.add(result.wrap_balance)
    assert wraps == {-1, 0, 1}


def test_ignored_source_bit_changes_output_shadow_with_identical_decoded_inputs() -> None:
    before, after = high_bit_witness()
    assert before.input_spans == after.input_spans
    assert before.wrap_balance == 1 and after.wrap_balance == 0
    assert before.output_spans[0][0] - after.output_spans[0][0] == MODULUS // 2
    assert before.output_spans[1] == after.output_spans[1]
    assert (before.output_shadow - after.output_shadow) % P == 6016
    assert (before.output_shadow - H * before.input_shadow) % P == 6016
    assert after.output_shadow == H * after.input_shadow % P


def test_four_bit_column_encoding_cannot_hide_an_integer_mismatch() -> None:
    for left, right in itertools.product(range(3), range(-4, 7)):
        assert ((left - right) % 16 == 0) is (left == right)
    for count in range(6):
        assert count // 2 == (count & 15) >> 1


def test_relation_validates_buffers_exclusivity_and_column_mismatch() -> None:
    for source, destination in ((bytes(215), bytes(144)), (bytes(216), bytes(143))):
        with pytest.raises(ValueError, match="source bytes"):
            relation(source, destination)
    with pytest.raises(ValueError, match="source bytes"):
        observe(bytes(215))
    words = [0] * 36
    words[1] = words[19] = 1
    with pytest.raises(ValueError, match="exclusive"):
        relation(bytes(216), struct.pack("<36I", *words))
    output = bytearray(144)
    monolith6.execute(output, bytes(216))
    words = list(struct.unpack("<36I", output))
    for member in range(3):
        words[member] ^= 2
    with pytest.raises(ValueError, match="differs modulo"):
        relation(bytes(216), struct.pack("<36I", *words))
    for inputs in ((), ((0, 0),) * 2, ((MODULUS, 0),) * 3, ((0, 2),) * 3):
        with pytest.raises(ValueError, match="normalized"):
            local_carries(inputs)


@pytest.mark.parametrize("kwargs", ({"timeout_ms": 0}, {"bits": 0}, {"bits": 169}))
def test_proof_rejects_limits_before_loading_z3(kwargs: dict[str, int]) -> None:
    with pytest.raises(ValueError, match="positive timeout"):
        proof.prove(**kwargs)


def test_shared_source_compiler_rejects_invalid_monoliths_and_outputs_before_solver_load() -> None:
    with pytest.raises(ValueError, match="unsupported"):
        symbolic_source(7)
    with pytest.raises(ValueError, match="positive"):
        boolean_backend(None, 0)
    term = normalized_terms()[0]
    for number, span in ((5, 0), (4, 1), (6, -1), (3, 2)):
        with pytest.raises(ValueError, match="unsupported"):
            output_gate_diagram(term, None, number, span)


def test_demanded_bit_evaluators_keep_separate_versioned_programs_on_one_backend() -> None:
    words = [random.Random(0x6CAC + k).getrandbits(32) for k in range(54)]

    class ConcreteBackend:
        def __init__(self) -> None:
            self.refs = [(word, bit) for word in range(54) for bit in range(32)]
            self.ref_index = {ref: k for k, ref in enumerate(self.refs)}

        def _node(self, variable: int, low: int, high: int) -> int:
            assert (low, high) == (0, 1)
            word, bit = self.refs[variable]
            return (words[word] >> bit) & 1

        @staticmethod
        def invert(value: int) -> int:
            return value ^ 1

        @staticmethod
        def apply(operation: str, left: int, right: int) -> int:
            assert operation in ("xor", "and")
            return left ^ right if operation == "xor" else left & right

    backend = ConcreteBackend()
    boundary, terms = normalized_terms()
    for number in (6, 4, 3, 6, 4):
        module, count = {3: (monolith3, 42), 4: (monolith4, 36), 6: (monolith6, 54)}[number]
        spans = 1 if number == 4 else 2
        destination = bytearray(72 * spans)
        module.execute(destination, struct.pack(f"<{count}I", *words[:count]))
        for span in range(spans):
            expected = struct.unpack("<18I", destination[span * 72 : (span + 1) * 72])
            for term in (boundary, terms[0], terms[79], terms[167]):
                assert output_gate_diagram(term, backend, number, span) == local_gate(term, expected)


@pytest.mark.parametrize(
    "outcomes,bits", ((["unsat"] * 170, 168), (["unsat"] * 25, 24), (["unsat", "unknown"], 168), (["sat"], 168))
)
def test_proof_accounting_distinguishes_complete_partial_and_failed_runs(
    monkeypatch: pytest.MonkeyPatch, outcomes: list[str], bits: int
) -> None:
    answers = iter(outcomes)

    class Solver:
        def set(self, **kwargs: int) -> None:
            pass

        def add(self, root: object) -> None:
            pass

        def check(self) -> str:
            return next(answers)

        def reason_unknown(self) -> str:
            return "test timeout"

    fake = SimpleNamespace(SolverFor=lambda logic: Solver(), unsat="unsat", unknown="unknown", get_version_string=lambda: "test")
    monkeypatch.setattr(proof, "local_equations", lambda: (fake, [(str(k), object()) for k in range(170)]))
    report = proof.prove(bits=bits)
    assert report["full_proof"] is (len(outcomes) == 170)
    assert report["wrap_balance_bound_proved"] is (len(outcomes) == 170)
    assert report["checked_payload_bits"] == min(168, sum(answer == "unsat" for answer in outcomes[1:]))
    if "unknown" in outcomes:
        assert report["stages"][-1]["reason"] == "test timeout"


def test_saved_solver_run_matches_current_source_models_and_all_columns() -> None:
    # Provenance/accounting only: JSON is not an independently checked certificate.
    directory = Path(proof.__file__).parent
    report: dict[str, Any] = json.loads((directory / "monolith6_span_proof.json").read_text(encoding="utf-8"))
    assert report["source_sha256"] == hashlib.sha256(Path(monolith6.__file__).read_bytes()).hexdigest()
    assert set(report["gate_model_sha256"]) == {"monolith5_model.json", "monolith5_gate_model.json"}
    for name, digest in report["gate_model_sha256"].items():
        assert digest == hashlib.sha256((directory / name).read_bytes()).hexdigest()
    assert [row["stage"] for row in report["stages"]] == ["boundary_exclusive", "initial_column"] + [
        f"column_{k}" for k in range(1, 168)
    ] + ["wrap_balance_bound"]
    assert all(row["proved"] and row["result"] == "unsat" for row in report["stages"])
    assert report["full_proof"] is True
    assert report["checked_payload_bits"] == 168
    assert report["wrap_balance_bound_proved"] is True
    assert report["translation_controls"] == 8
