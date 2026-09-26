"""Monolith3 virtual-span controls, carry equations, and quarter-input wraps."""

from __future__ import annotations

import hashlib
import itertools
import json
import random
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

from s7commplus.session_auth.family0._generated import monolith3
from tools import prove_monolith3_span_identity as proof
from tools.prove_monolith6_span_identity import symbolic_pair
from tools.recover_monolith3_span_identity import PLAIN_LIMIT, high_bit_witness, observe, relation
from tools.recover_monolith5_span_decoder import MODULUS, P, local_gate, recover
from tools.recover_monolith6_span_identity import H, local_carries, normalized_relation


def test_virtual_span_columns_exact_integer_and_corrected_field_relations() -> None:
    rng = random.Random(0x3DEC)
    wraps = set()
    model = recover()
    offset = sum(term.weight for term in model.terms if term.weight < 0)

    def signed(span: bytes) -> int:
        words = struct.unpack("<18I", span)
        return sum(term.weight * local_gate(term, words) for term in model.terms)

    for _ in range(256):
        source = rng.randbytes(168)
        destination = bytearray(144)
        monolith3.execute(destination, source)
        result = relation(source, bytes(destination))
        pair = result.pair
        plain = result.plain_effective
        assert 0 <= plain < PLAIN_LIMIT
        assert pair.input_spans[2] == ((plain >> 1) % MODULUS, plain & 1)
        assert -1 <= pair.wrap_balance <= 1
        assert -2 <= result.wrap_balance <= 1
        assert pair.wrap_balance == pair.local_wrap_balance
        assert pair.doubled_output - result.full_target == MODULUS * result.wrap_balance
        assert result.output_shadow == result.corrected_shadow
        assert (
            result.output_shadow
            == (
                H * result.input_shadow
                + H * H * result.plain_original
                + 6016 * result.wrap_balance
                - 12032 * (result.plain_original >> 170)
            )
            % P
        )
        carries = local_carries(pair.input_spans)
        hs = sum(h for _, h in pair.input_spans)
        for k in range(1, 168):
            count = sum((b >> k) & 1 for b, _ in pair.input_spans)
            assert (
                sum((b >> (k - 1)) & 1 for b, _ in pair.output_spans)
                == count + ((H >> k) & 1) * (hs % 2) + carries[k - 1] - 2 * carries[k]
            )
        input_sum = signed(source[:72]) + signed(source[72:144])
        output_sum = signed(bytes(destination[:72])) + signed(bytes(destination[72:]))
        assert (
            2 * output_sum - input_sum - (plain >> 1) - H * (plain & 1)
            == 2 * offset + MODULUS * result.wrap_balance + P * pair.boundary_adjustment
        )
        wraps.add(result.wrap_balance)
    assert wraps == {-2, -1, 0, 1}


def test_encoded_high_bit_changes_pair_shadow_without_changing_decoded_inputs() -> None:
    before, after = high_bit_witness()
    assert before.encoded_inputs == after.encoded_inputs
    assert before.plain_original == after.plain_original == 0
    assert before.wrap_balance == 0 and after.wrap_balance == 1
    assert after.pair.output_spans[0][0] - before.pair.output_spans[0][0] == MODULUS // 2
    assert after.pair.output_spans[1] == before.pair.output_spans[1]
    assert (after.output_shadow - before.output_shadow) % P == 6016


def test_extra_plain_bits_cancel_from_pair_counts_not_necessarily_encoded_bytes() -> None:
    rng = random.Random(0x3170)
    different_encodings = False
    for _ in range(32):
        source = rng.randbytes(168)
        plain = int.from_bytes(source[144:], "little") & (PLAIN_LIMIT - 1)
        cleared = source[:144] + plain.to_bytes(24, "little")
        left, right = bytearray(144), bytearray(144)
        monolith3.execute(left, source)
        monolith3.execute(right, cleared)
        original, zeroed = relation(source, bytes(left)), relation(cleared, bytes(right))
        for k in range(168):
            assert sum((b >> k) & 1 for b, _ in original.pair.output_spans) == sum(
                (b >> k) & 1 for b, _ in zeroed.pair.output_spans
            )
        assert original.output_shadow == zeroed.output_shadow
        assert original.wrap_balance == zeroed.wrap_balance
        different_encodings |= left != right
    assert different_encodings


def test_all_plain_bit_boundaries_and_low_bit_division_choices() -> None:
    zero = observe(bytes(168))
    for bit in range(192):
        words = [0] * 42
        words[36 + bit // 32] = 1 << (bit % 32)
        result = observe(struct.pack("<42I", *words))
        assert result.output_shadow == result.corrected_shadow
        if bit >= 170:
            assert result.plain_effective == 0
            assert result.output_shadow == zero.output_shadow
    for hs, low in itertools.product(range(3), range(4)):
        # Pure arithmetic behind h_plain=L bit0 and B_plain=L>>1.
        assert (H * low) % P == ((low >> 1) + H * (low & 1)) % P
        q = (hs + (low & 1)) % 2
        majority = int(hs + (low & 1) >= 2)
        assert H * hs + (low >> 1) + H * (low & 1) == (low >> 1) + H * q + majority + P * majority


def test_relation_and_virtual_pair_inputs_are_validated() -> None:
    for source, destination in ((bytes(167), bytes(144)), (bytes(168), bytes(143))):
        with pytest.raises(ValueError, match="source bytes"):
            relation(source, destination)
    with pytest.raises(ValueError, match="source bytes"):
        observe(bytes(167))
    for inputs, outputs in (((), ()), (((0, 0),) * 3, ((MODULUS, 0),) * 2), (((0, 2),) * 3, ((0, 0),) * 2)):
        with pytest.raises(ValueError, match="normalized"):
            normalized_relation(inputs, outputs)
    with pytest.raises(ValueError, match="unsupported"):
        symbolic_pair(4)


@pytest.mark.parametrize("kwargs", ({"timeout_ms": 0}, {"bits": 0}, {"bits": 169}))
def test_invalid_proof_limits_do_not_load_optional_solver(kwargs: dict[str, int]) -> None:
    with pytest.raises(ValueError, match="positive timeout"):
        proof.prove(**kwargs)


@pytest.mark.parametrize(
    "outcomes,bits", ((["unsat"] * 171, 168), (["unsat"] * 25, 24), (["unsat"] * 170 + ["unknown"], 168), (["sat"], 168))
)
def test_proof_accounting_distinguishes_truncation_wrap_and_partial_runs(
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
    monkeypatch.setattr(proof, "local_equations", lambda number: (fake, [(str(k), object()) for k in range(171)]))
    report = proof.prove(bits=bits)
    assert report["full_proof"] is (len(outcomes) == 171 and outcomes[-1] == "unsat")
    assert report["plain_truncation_proved"] is report["full_proof"]
    assert report["wrap_balance_bound_proved"] is (len(outcomes) >= 170 and outcomes[169] == "unsat")
    if "unknown" in outcomes:
        assert report["checked_payload_bits"] == 168
        assert report["stages"][-1]["reason"] == "test timeout"


def test_saved_solver_record_pins_current_source_and_all_pair_obligations() -> None:
    directory = Path(proof.__file__).parent
    report = json.loads((directory / "monolith3_span_proof.json").read_text(encoding="utf-8"))
    assert report["source_sha256"] == hashlib.sha256(Path(monolith3.__file__).read_bytes()).hexdigest()
    assert set(report["gate_model_sha256"]) == {"monolith5_model.json", "monolith5_gate_model.json"}
    for name, digest in report["gate_model_sha256"].items():
        assert digest == hashlib.sha256((directory / name).read_bytes()).hexdigest()
    assert [row["stage"] for row in report["stages"]] == ["boundary_exclusive", "initial_column"] + [
        f"column_{k}" for k in range(1, 168)
    ] + ["wrap_balance_bound", "plain_high_bits_pair_invariant"]
    assert all(row["proved"] and row["result"] == "unsat" for row in report["stages"])
    assert report["full_proof"] and report["plain_truncation_proved"] and report["wrap_balance_bound_proved"]
    assert report["checked_payload_bits"] == 168 and report["translation_controls"] == 8
