"""Reachability proof provenance, raw-bit compiler controls, and sound bounds."""

from __future__ import annotations

import inspect
import hashlib
import json
import random
import struct
from pathlib import Path
from unittest.mock import patch

import pytest

from s7commplus.session_auth.family0 import transform7
from s7commplus.session_auth.family0._generated import monolith3, monolith4, monolith5, monolith6
from s7commplus.session_auth.family0._generated.data import TRANSFORM7_DATA
from tools.prove_monolith4_span_identity import symbolic_source
from tools.prove_transform7_setup_ranges import (
    OutputBit,
    SetupDAG,
    combined_maximum,
    kernel_dependency,
    prove,
    span_bound,
    slot94_identity,
    verify_translation,
)
from tools.recover_monolith3_span_identity import observe
from tools.recover_monolith4_span_identity import output_bit_diagram
from tools.recover_transform7_setup import capture_setup


class ConcreteBits:
    """Independent all-concrete backend; no solver dependency."""

    def __init__(self, words: tuple[int, ...]) -> None:
        self.refs = [(word, bit) for word in range(len(words)) for bit in range(32)]
        self.ref_index = {ref: i for i, ref in enumerate(self.refs)}
        self.values = [(words[word] >> bit) & 1 for word, bit in self.refs]

    def _node(self, variable: int, low: int, high: int) -> int:
        assert (low, high) == (0, 1)
        return self.values[variable]

    def invert(self, value: int) -> int:
        return value ^ 1

    def apply(self, operation: str, left: int, right: int) -> int:
        if operation == "and":
            return left & right
        if operation == "xor":
            return left ^ right
        raise ValueError(operation)


@pytest.mark.parametrize("number", (3, 4, 5, 6))
def test_raw_output_bit_compiler_matches_every_generated_word(number: int) -> None:
    module, source_count, output_count = {
        3: (monolith3, 42, 36),
        4: (monolith4, 36, 18),
        5: (monolith5, 54, 12),
        6: (monolith6, 54, 36),
    }[number]
    rng = random.Random(0xB17 + number)
    for _ in range(8):
        words = tuple(rng.getrandbits(32) for _ in range(source_count))
        backend = ConcreteBits(words)
        modeled = tuple(
            sum(output_bit_diagram(word, bit, backend, number) << bit for bit in range(32)) for word in range(output_count)
        )
        output = bytearray(output_count * 4)
        module.execute(output, struct.pack(f"<{source_count}I", *words))
        assert modeled == struct.unpack(f"<{output_count}I", output)


def test_monolith5_independent_fixed_width_source_compiler() -> None:
    pytest.importorskip("z3")
    z3, source, output = symbolic_source(5)
    assert len(source) == 54 and len(output) == 12
    rng = random.Random(0xB175)
    for _ in range(4):
        words = [rng.getrandbits(32) for _ in source]
        bindings = [(variable, z3.BitVecVal(word, 32)) for variable, word in zip(source, words)]
        modeled = [z3.simplify(z3.substitute(value, *bindings)).as_long() for value in output]
        native = bytearray(48)
        monolith5.execute(native, struct.pack("<54I", *words))
        assert modeled == list(struct.unpack("<12I", native))


def test_hidden_bit_witness_also_applies_to_bundled_valid_range_spans() -> None:
    source = TRANSFORM7_DATA[:144] + bytes(24)
    words = list(struct.unpack("<42I", source))
    before = observe(source)
    words[17] ^= 1 << 9
    after = observe(struct.pack("<42I", *words))
    assert before.encoded_inputs == after.encoded_inputs
    assert all(b < 1 << 160 for b, _ in before.encoded_inputs)
    assert before.wrap_balance == 0 and after.wrap_balance == 1
    # Reachable provenance, not a decoded range constraint alone, is necessary.
    assert (after.output_shadow - before.output_shadow) % ((1 << 160) - 47) == 6016


def test_pair_maxima_are_not_accidentally_doubled() -> None:
    first = tuple(OutputBit(0, bit // 32, bit % 32) for bit in range(576))
    second = tuple(OutputBit(0, 18 + bit // 32, bit % 32) for bit in range(576))
    assert span_bound(first, {0: 10}) == (10, (0, 0))
    assert combined_maximum((first, second), {0: 10}, {0: 10}) == 10
    assert combined_maximum((first, first), {0: 10}, {0: 10}) == 20
    assert combined_maximum((first, second, first), {0: 10}, {0: 10}) == 20
    with pytest.raises(ValueError, match="established"):
        span_bound(first, {})
    with pytest.raises(ValueError, match="entire"):
        span_bound(first[:575], {0: 10})
    assert span_bound((0,) * 576, {})[1] is None


@pytest.mark.parametrize("number", (3, 4, 6))
def test_kernel_dependencies_require_complete_pinned_source_theorems(number: int) -> None:
    dependency = kernel_dependency(number)
    assert len(dependency["sha256"]) == 64
    assert dependency["file"].startswith(f"monolith{number}")
    folder = Path(inspect.getfile(kernel_dependency)).parent
    report = json.loads((folder / dependency["file"]).read_text())
    report["full_proof"] = False
    with patch("tools.prove_transform7_setup_ranges.json.loads", return_value=report):
        with pytest.raises(ValueError, match="complete pinned"):
            kernel_dependency(number)


def test_lazy_setup_replays_actual_hidden_high_bits() -> None:
    pytest.importorskip("z3")
    verify_translation(1)


def test_lazy_setup_rejects_changed_initialization() -> None:
    pytest.importorskip("z3")
    source = inspect.getsource(transform7.execute)
    modified = source.replace("[0] | 4", "[0] | 8", 1)
    assert source != modified
    with patch("tools.prove_transform7_setup_ranges.inspect.getsource", return_value=modified):
        with pytest.raises(ValueError, match="initialization"):
            SetupDAG()


@pytest.mark.parametrize("mutation", ("context_reset", "strided_pointer"))
def test_setup_specialization_rejects_unmodeled_state_changes(mutation: str) -> None:
    pytest.importorskip("z3")
    original = inspect.getsource
    source = original(transform7.execute)
    if mutation == "context_reset":
        modified = source.replace(
            "    # -- Transform12 dispatch loop 1",
            "    ctx = bytearray(transform12.CONTEXT_SIZE)\n    # -- Transform12 dispatch loop 1",
            1,
        )
    else:
        modified = source.replace("wv[0xA8:]", "wv[0xA8::2]", 1)
    assert source != modified
    with patch(
        "tools.prove_transform7_setup_ranges.inspect.getsource",
        side_effect=lambda obj: modified if obj is transform7.execute else original(obj),
    ):
        with pytest.raises(ValueError, match="unsupported setup"):
            SetupDAG()


def test_proof_budget_and_raw_output_indices_fail_closed() -> None:
    with pytest.raises(ValueError, match="positive"):
        prove(0)
    with pytest.raises(ValueError, match="positive"):
        verify_translation(0)
    for word, bit, number in ((12, 0, 5), (-1, 0, 4), (0, 32, 6), (0, 0, 7)):
        with pytest.raises(ValueError, match="unsupported"):
            output_bit_diagram(word, bit, None, number)


def test_lazy_ancestry_keeps_unrelated_carry_networks_out_of_queries() -> None:
    pytest.importorskip("z3")
    dag = SetupDAG()
    assert dag.ancestors(6) == {0, 2, 3}
    assert dag.ancestors(10) == {0, 1, 2, 3, 6, 9}
    assert dag.ancestors(12) == {0, 2, 11}
    assert dag.ancestors(21) == set()
    assert dag.ancestors(22) == {21}


def test_slot94_integer_identity_has_independent_source_queries() -> None:
    pytest.importorskip("z3")
    dag = SetupDAG()
    count = 0
    for name, query in dag.queries():
        if int(name.split("_")[1]) not in (21, 22):
            continue
        solver = dag.z3.Tactic("sat").solver()
        solver.set(timeout=10000)
        solver.add(query())
        assert solver.check() == dag.z3.unsat
        count += 1
    assert count == 3
    assert slot94_identity(dag, {21, 22})
    assert not slot94_identity(dag, {21})


def test_slot94_preserves_noncanonical_input_representatives() -> None:
    p = (1 << 160) - 47
    rng = random.Random(94)
    for x in (0, 1, p - 1, p, p + 1, (1 << 160) - 1):
        assert capture_setup(x, rng.getrandbits(160), rng.getrandbits(160))[3] == x


def test_saved_reachable_range_proof_provenance_and_accounting() -> None:
    folder = Path(inspect.getfile(kernel_dependency)).parent
    report = json.loads((folder / "transform7_setup_range_proof.json").read_text())
    family = Path(transform7.__file__).parent
    for name, digest in report["source_sha256"].items():
        path = family / ("_generated" if name in {f"monolith{i}.py" for i in (3, 4, 5, 6)} else "") / name
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
    assert hashlib.sha256(TRANSFORM7_DATA).hexdigest() == report["data_sha256"]
    assert report["translation_controls"] == 8
    for number, dependency in report["kernel_dependencies"].items():
        assert dependency == kernel_dependency(int(number))
    rows = report["stages"]
    assert report["full_proof"] == (len(rows) == 29 and all(row["proved"] for row in rows))
    assert report["zero_wrap_calls"] == sorted({int(row["stage"].split("_")[1]) for row in rows if row.get("zero_wrap_derived")})
    for row in rows:
        assert row["proved"] == (row["result"] in ("unsat", "derived"))
        if row["result"] == "derived":
            assert int(row["stage"].split("_")[1]) in {4, 7, 9, 11, 13, 15, 17, 19}
        if row.get("zero_wrap_derived"):
            assert type(row["maximum_payload"]) is int
            assert 0 <= row["maximum_payload"] < 1 << 166
    assert report["slot94_exact_input_identity_proved"]
    assert {46, 94} <= set(report["completed_premerge_slots"])
