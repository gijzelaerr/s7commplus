"""Independent full-output oracle, representation boundaries and negative controls."""

from __future__ import annotations

import random
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

import pytest

from s7commplus.session_auth.family0 import big_int_operations, big_int_transforms, transform7, transform12
from s7commplus.session_auth.family0._generated import monolith3, monolith4, monolith5, monolith6, monolith7
from tools import monolith_encoded_reference as encoded
from tools import transform12_integer_model as arithmetic
from tools import transform7_reference as reference
from tools.recover_transform7_setup import targeted_base_point_probe
from tools.prove_transform7_reference_topology import verify as verify_topology
from tools.trace_transform7_tail import Case, cases, observe

FIXTURES = Path(__file__).resolve().parents[1] / "tests/fixtures/family0/monoliths"


@pytest.mark.parametrize("number,layout", [(4, (72, 72)), (6, (72, 72, 72)), (7, (24, 72))])
def test_encoded_references_match_upstream_vectors_and_arbitrary_raw_bytes(number, layout) -> None:
    source = (FIXTURES / f"monolith{number}-src.bin").read_bytes()
    spans, offset = [], 0
    for size in layout:
        spans.append(source[offset : offset + size])
        offset += size
    assert b"".join(encoded.execute(number, *spans)) == (FIXTURES / f"monolith{number}-dst.bin").read_bytes()
    rng = random.Random(0xE0C0 + number)
    kernel = {4: monolith4, 6: monolith6, 7: monolith7}[number]
    for _ in range(64):
        spans = [rng.randbytes(size) for size in layout]
        expected = bytearray(72 if number == 4 else 144)
        kernel.execute(expected, b"".join(spans))
        assert b"".join(encoded.execute(number, *spans)) == expected


@pytest.mark.parametrize("case", cases(2), ids=lambda case: case.name)
def test_full_reference_matches_all_checkpoints_and_destination(case: Case) -> None:
    result = reference.model(case.prng1, case.prng2, case.source)
    actual = observe(case)
    assert result.initial == tuple(
        arithmetic.decode(actual.phase1_entry[slot * 24 : (slot + 1) * 24]) for slot in (46, 48, 70, 94)
    )
    assert result.tail_inputs == tuple(arithmetic.decode(actual.entry[slot * 24 : (slot + 1) * 24]) for slot in (5, 87))
    assert dict(result.tail_outputs) == {
        slot: arithmetic.decode(actual.exit[slot * 24 : (slot + 1) * 24]) for slot in (27, 61, 71, 97)
    }
    assert result.destination == actual.destination
    assert len(result.destination) == 72


@pytest.mark.parametrize("scalar", [0, 1, arithmetic.MASK])
def test_legal_setup_carry_exception_is_preserved_through_full_output(scalar: int) -> None:
    x, y, r = targeted_base_point_probe()
    case = Case(
        "legal-carry",
        r.to_bytes(20, "little"),
        scalar.to_bytes(20, "little"),
        x.to_bytes(20, "little") + y.to_bytes(20, "little"),
    )
    result = reference.model(case.prng1, case.prng2, case.source)
    assert result.initial[0] == 94
    assert result.destination == observe(case).destination


@pytest.mark.parametrize("x", [arithmetic.CANDIDATE_MODULUS, arithmetic.MASK])
def test_noncanonical_source_representatives_are_not_reduced(x: int) -> None:
    case = Case("noncanonical", bytes(20), b"\xff" * 20, x.to_bytes(20, "little") + bytes(20))
    result = reference.model(case.prng1, case.prng2, case.source)
    assert result.initial[3] == x
    assert result.destination == observe(case).destination


def test_reference_calls_no_runtime_entry_points_and_mutates_no_inputs() -> None:
    case = cases(0)[0]
    expected = reference.model(case.prng1, case.prng2, case.source)
    a, b, source = bytearray(case.prng1), bytearray(case.prng2), bytearray(case.source)
    with ExitStack() as stack:
        for module, names in (
            (transform7, ["execute"]),
            (transform12, ["execute"]),
            (big_int_operations, ["prepare", "finalize", "prepare_finalize", "rotate_right_30"]),
            (big_int_transforms, ["big_int_addition", "big_int_subtraction", "big_int_multiplication", "big_int_square"]),
            *((module, ["execute"]) for module in (monolith3, monolith4, monolith5, monolith6, monolith7)),
        ):
            for name in names:
                stack.enter_context(patch.object(module, name, side_effect=AssertionError("runtime entry point used")))
        assert reference.model(a, b, source) == expected
    assert (bytes(a), bytes(b), bytes(source)) == (case.prng1, case.prng2, case.source)


def test_prepare_finalize_is_identity_on_reference_canonical_packing() -> None:
    rng = random.Random(0xF1A1)
    values = [0, 1, arithmetic.CANDIDATE_MODULUS - 1, arithmetic.CANDIDATE_MODULUS, arithmetic.MASK]
    values.extend(rng.getrandbits(160) for _ in range(128))
    for value in values:
        packed = arithmetic.encode(value)
        buffer = bytearray(packed)
        big_int_operations.prepare_finalize(buffer)
        assert buffer == packed


def test_dead_tail_slot_does_not_affect_destination_but_live_slot_does() -> None:
    outputs = dict(reference.model(*((case := cases(0)[0]).prng1, case.prng2, case.source)).tail_outputs)
    expected = reference.finalize(outputs)
    outputs[71] ^= 1
    assert reference.finalize(outputs) == expected
    outputs[27] ^= 1
    assert reference.finalize(outputs) != expected


@pytest.mark.parametrize(
    "a,b,source", [(bytes(19), bytes(20), bytes(40)), (bytes(20), bytes(21), bytes(40)), (bytes(20), bytes(20), bytes(39))]
)
def test_incomplete_or_ambiguous_inputs_rejected(a, b, source) -> None:
    with pytest.raises(ValueError, match="20-byte"):
        reference.model(a, b, source)


@pytest.mark.parametrize(
    "number,spans", [(3, ()), (4, (bytes(71), bytes(72))), (6, (bytes(72), bytes(72))), (7, (bytes(24), bytes(73)))]
)
def test_wrong_encoded_layout_rejected(number, spans) -> None:
    with pytest.raises(ValueError, match="layout"):
        encoded.execute(number, *spans)


def test_integer_graph_versions_self_assignments_and_logical_shifts() -> None:
    source = """def execute(destination, source):
    src_dwords = _to_uints(source)
    dst_dwords = _to_uints(destination)
    uVar0 = src_dwords[0]
    uVar1 = _shr(~uVar0, 1)
    uVar0 = ((uVar0 << 1) ^ uVar1) & 0xFFFFFFFF
    dst_dwords[0] = uVar0
    dst_dwords[1] = uVar0
    destination[:] = _from_uints(dst_dwords)
"""
    program = encoded.compile_source(source, 2)
    assert program.outputs[0] == program.outputs[1]
    for value in (0, 1, 0xFFFFFFFF, 0xAAAAAAAA):
        expected = ((value << 1) ^ ((~value & 0xFFFFFFFF) >> 1)) & 0xFFFFFFFF
        assert encoded.evaluate(program, (value,)) == (expected, expected)


@pytest.mark.parametrize(
    "statement",
    ["return", "uVar0 = unknown(src_dwords[0])", "uVar0 = src_dwords[0] + 1", "uVar0 = src_dwords[0] << src_dwords[1]"],
)
def test_graph_rejects_unsupported_source_instead_of_silently_skipping(statement) -> None:
    source = f"""def execute(destination, source):
    src_dwords = _to_uints(source)
    dst_dwords = _to_uints(destination)
    {statement}
    dst_dwords[0] = src_dwords[0]
    destination[:] = _from_uints(dst_dwords)
"""
    with pytest.raises(ValueError, match="unsupported|nonconstant"):
        encoded.compile_source(source, 1)


def test_final_chain_symbolic_source_provenance_and_dead_branch() -> None:
    report = verify_topology()
    assert report["recipe_matches"]
    assert report["source_calls"] == 12
    assert report["destination_live_calls"] == 11
    assert report["dead_context_input"] == 71
    assert report["whole_pipeline_solver_proof"] is False


@pytest.mark.parametrize(
    "old,new",
    [
        ("cv[0x5B8:], wv[0x2A0:]", "cv[0x6A8:], wv[0x2A0:]"),
        ("wv[0x330:], wv[0xA8:], wv[0x60:]", "wv[0x330:], wv[0xA8:], wv[0xA8:]"),
        ("destination, wv[0x378:], wv[0x408:]", "destination, wv[0x408:], wv[0x378:]"),
        ("prepare_finalize(cv[0x918:])", "prepare_finalize(cv[0x900:])"),
    ],
)
def test_source_topology_rejects_wrong_slot_mate_order_or_finalization(old, new) -> None:
    source = Path(transform7.__file__).read_text(encoding="utf-8")
    assert old in source
    with pytest.raises(ValueError, match="provenance|layout"):
        verify_topology(source.replace(old, new))
