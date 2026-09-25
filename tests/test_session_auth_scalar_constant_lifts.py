"""Constant-factor cuts, callback demand and independent fold controls."""

from collections.abc import Callable
from unittest.mock import patch

import pytest

from tools import scalar_constant_lifts as rules
from tools import transform12_residue_defects as arithmetic

P = arithmetic.P


def wrong_cutoff(a: int, cutoff: int, lift_a: Callable[[], bool]) -> bool:
    return a >= cutoff + 1 or lift_a()


def test_positive_threshold_partition_and_bad_values() -> None:
    for c in range(1, 47):
        k = rules.threshold(c)
        assert (k - 1) * c <= 46 < k * c
    for c in (47, 48, P - 1, P, P + 46):
        assert rules.threshold(c) == 1
    for c in (False, 0, -1, 1 << 160):
        with pytest.raises(ValueError, match="positive uint160"):
            rules.threshold(c)


def test_actual_fold_oracle_at_all_small_classes_and_large_constants() -> None:
    inputs = list(range(47)) + list(range(P, P + 47)) + [47, P - 1, (1 << 128) - 1]
    constants = list(range(1, 48)) + [P - 46, P - 1, P, P + 1, P + 46]
    ambiguous = 0
    for c in constants:
        for raw in inputs:
            result = arithmetic.multiply(raw, c)
            if result.residue <= 46:
                ambiguous += 1
                actual = rules.lift(raw % P, rules.threshold(c), lambda: raw >= P)
                assert result.representative == result.residue + P * actual
    assert ambiguous > 500


def test_constant_cut_queries_a_lift_only_below_the_threshold() -> None:
    def unexpected() -> bool:
        raise AssertionError("unnecessary dependency")

    for cutoff in range(1, 48):
        assert rules.lift(cutoff, cutoff, unexpected)
        assert rules.lift(cutoff - 1, cutoff, lambda: True)
        assert not rules.lift(cutoff - 1, cutoff, lambda: False)


def test_all_actual_ast_obligations_and_mutated_cutoff() -> None:
    pytest.importorskip("z3")
    from tools.prove_scalar_constant_lifts import prove

    actual = prove()
    assert actual["full_proof"], actual
    assert len(actual["obligations"]) == 96
    with patch.object(rules, "lift", wrong_cutoff):
        wrong = prove()
    assert not wrong["full_proof"]
    assert any(row["result"] == "sat" for row in wrong["obligations"])


def test_unknown_and_bad_timeout_cannot_be_proof() -> None:
    z3 = pytest.importorskip("z3")
    from tools.prove_scalar_constant_lifts import prove

    with patch.object(z3.Solver, "check", return_value=z3.unknown):
        assert not prove()["full_proof"]
    for timeout in (0, -1):
        with pytest.raises(ValueError, match="positive"):
            prove(timeout)
