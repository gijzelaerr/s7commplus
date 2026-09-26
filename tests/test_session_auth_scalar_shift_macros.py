"""Exact macros explain why apparent tail shift no-ops cannot be deleted."""

import random
from unittest.mock import patch

import pytest

from tools import scalar_shift_macros as macros
from tools import transform12_integer_model as exact
from tools.prove_scalar_shift_macros import prove
from tools.recover_transform12_phase1 import recover
from tools.transform7_reference import tail_program

P = macros.P


def test_composed_actual_source_ast_proof_and_negative_controls() -> None:
    pytest.importorskip("z3")
    result = prove()
    assert result["full_proof"]
    assert [r["result"] for r in result["obligations"]] == ["unsat", "unsat", "unsat", "unsat", "sat", "sat"]
    with pytest.raises(ValueError, match="positive"):
        prove(0)


def test_all_42_large_shift_patterns_are_in_the_fixed_tail() -> None:
    assert all(not macros.recover(source) for row in recover() for source in row.choices)
    rows = macros.recover(tail_program())
    assert len(rows) == 42
    assert sum(r.operation == "canonical_shift" for r in rows) == 38
    assert sum(r.operation == "lifted_shift" for r in rows) == 4
    assert all(macros.lift_independent_constant(r.constant) for r in rows)


def test_compact_macros_match_source_at_carries_lifts_and_all_found_constants() -> None:
    rng = random.Random(42160)
    constants = {r.constant for r in macros.recover(tail_program())}
    constants.update((47, 48, (1 << 128) - 47, 1 << 128, (1 << 128) + 47, P - 1))
    for c in constants:
        cases = set((0, 1, 46, 47, c - 1, c, c + 1, P - 1, P, P + 1, P + 46))
        cases.update(rng.randrange(1 << 160) for _ in range(100))
        # Exact low-word carry boundaries, both direct macro and closed
        # after-subtraction predicate, not merely random unlikely carries.
        for residue in (0, 1, 46, 47, (1 << 128) - 47, (1 << 128) - 1):
            cases.add(((1 << 160) + residue - c) % (1 << 160))
            cases.add(((1 << 160) + (1 << 128) - 47 + residue - c) % (1 << 160))
            cases.add((1 << 128) + residue)
        for raw in cases:
            if not 0 <= raw < 1 << 160:
                continue
            assert macros.canonical_shift(raw, c) == exact.subtract(exact.add(raw, c), c)
            assert macros.lifted_shift(raw, c) == exact.add(exact.subtract(raw, c), c)
            if macros.lift_independent_constant(c):
                assert macros.canonical_residue_shift(raw % P, c) == macros.canonical_shift(raw, c)


def test_macros_do_not_call_source_primitives_and_are_not_no_ops() -> None:
    with (
        patch.object(exact, "add", side_effect=AssertionError("source add")),
        patch.object(exact, "subtract", side_effect=AssertionError("source subtract")),
    ):
        assert macros.canonical_shift(P + 1, 47) == 1
        assert macros.lifted_shift(1, 47) == P + 1
        assert macros.lifted_shift(0, 47) == P
    # Field-changing carries are preserved, not erased by the naming.
    raw, c = (1 << 128) + 100, P - 100
    assert macros.canonical_carry(raw, c)
    assert macros.canonical_shift(raw, c) != raw % P


def test_macro_domain_is_explicit_and_rejects_unproved_constants() -> None:
    for fn in (macros.canonical_shift, macros.lifted_shift):
        for raw in (True, -1, 1 << 160):
            with pytest.raises(ValueError, match="uint160"):
                fn(raw, 47)
        for c in (True, 0, 46, P, P + 1, 1 << 160):
            with pytest.raises(ValueError, match="constant"):
                fn(0, c)
    for mu, c in ((P, 47), (0, (1 << 128) + 47)):
        with pytest.raises(ValueError, match="lift-independent"):
            macros.canonical_residue_shift(mu, c)
