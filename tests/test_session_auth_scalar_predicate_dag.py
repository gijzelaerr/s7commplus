"""Typed predicate sharing preserves actual helper AST semantics."""

import itertools
from unittest.mock import patch
from types import FunctionType

import pytest

from tools import scalar_representative_rules as rules
from tools.prove_scalar_predicate_guards import compile_guard
from tools.scalar_predicate_dag import Backend, P


@pytest.mark.parametrize(
    "name",
    ["lazy_addition_defect", "lazy_subtraction_defect", "nonzero_product_lift", "subtraction_lift", "small_nonzero_product_lift"],
)
def test_actual_helper_ast_matches_boundaries_and_all_input_lifts(name: str) -> None:
    backend = Backend()
    a, b, ta, tb = backend.field(0), backend.field(1), backend.lift(0), backend.lift(1)
    inputs = {"a": a, "b": b, "lift_a": ta, "lift_b": tb}
    if name == "subtraction_lift":
        inputs["defective"] = backend.lift(2)
    root = compile_guard(backend, name, inputs, module=rules).index
    boundaries = [0, 1, 23, 46, 47, 48, 92, 93, (1 << 128) - 47, 1 << 128, P - 47, P - 1]
    for x, y, ax, by, defective in itertools.product(boundaries, boundaries, (False, True), (False, True), (False, True)):
        args = (x, y, defective, lambda: ax, lambda: by) if name == "subtraction_lift" else (x, y, lambda: ax, lambda: by)
        expected = getattr(rules, name)(*args)
        assert backend.evaluate(root, (x, y).__getitem__, (ax, by, defective), {}) is expected


def test_sum_lift_ast_uses_shared_numeric_equation() -> None:
    backend = Backend()
    a, b = backend.field(0), backend.field(1)
    first = a + b
    assert first.index == (b + a).index
    root = compile_guard(backend, "addition_lift", {"s": first, "lift_a": backend.lift(0), "lift_b": backend.lift(1)}, rules)
    for x, y, ta, tb in itertools.product((0, 23, 47, P - 1), repeat=4):
        actual = backend.evaluate(root.index, (x, y).__getitem__, (bool(ta), bool(tb)), {})
        assert actual is rules.addition_lift(x + y, lambda: bool(ta), lambda: bool(tb))


def test_boolean_identities_and_interval_folding_are_exact() -> None:
    backend = Backend()
    a, t = backend.field(0), backend.lift(0)
    assert backend.And(t, t).index == t.index
    assert backend.Not(backend.Not(t)).index == t.index
    assert backend.nodes[backend.And(t, backend.Not(t)).index].arguments == (0,)
    assert backend.nodes[backend.Or(t, backend.Not(t)).index].arguments == (1,)
    assert backend.nodes[(a < 0).index].arguments == (0,)
    assert backend.nodes[(a <= P - 1).index].arguments == (1,)
    assert backend.nodes[(a == a).index].arguments == (1,)
    with pytest.raises(TypeError, match="no Python truth"):
        bool(t)


def test_wrong_sorts_backends_and_noncanonical_field_leaves_fail() -> None:
    backend = Backend()
    with pytest.raises(ValueError, match="sort or backend mismatch"):
        backend.And(backend.field(0))
    with pytest.raises(ValueError, match="sort or backend mismatch"):
        backend.And(Backend().lift(0))
    with pytest.raises(ValueError, match="bit mask"):
        backend.field(0) & backend.field(1)
    for value in (-1, P, True):
        with pytest.raises(ValueError, match="canonical residue"):
            backend.evaluate(backend.field(0).index, lambda _: value, (), {})


def test_short_circuit_never_queries_an_unneeded_field() -> None:
    backend = Backend()
    first, second = backend.field(0) <= 46, backend.field(1) <= 46
    root = backend.And(first, second)

    def field(index: int) -> int:
        assert index == 0
        return 47

    assert backend.evaluate(root.index, field, (), {}) is False


def test_all_nine_frontend_obligations_prove_and_detect_bad_folding() -> None:
    pytest.importorskip("z3")
    from tools.prove_scalar_predicate_dag import prove

    report = prove()
    assert report["full_proof"], report["obligations"]
    assert len(report["obligations"]) == 9
    with patch.object(Backend, "And", lambda backend, *args: backend.expression(False, "boolean")):
        wrong = prove()
    assert not wrong["full_proof"] and any(row["result"] == "sat" for row in wrong["obligations"])


def test_integer_complements_share_category_comparisons() -> None:
    backend = Backend()
    a = backend.field(0)
    assert backend.Not(a >= 47).index == (a <= 46).index
    assert (a == 0).index == (a < 1).index
    assert backend.Not(a >= 7).index == (a <= 6).index


def test_frontend_unknown_or_invalid_timeout_fails_closed() -> None:
    z3 = pytest.importorskip("z3")
    from tools.prove_scalar_predicate_dag import prove

    with patch.object(z3.Solver, "check", return_value=z3.unknown):
        assert not prove()["full_proof"]
    for timeout in (0, -1):
        with pytest.raises(ValueError, match="positive solver timeout"):
            prove(timeout)


def test_loaded_function_constants_must_match_the_inspected_ast() -> None:
    function = rules.square_lift
    original = function.__code__.co_consts

    def tamper(value: object) -> object:
        if type(value) is int:
            return value + 1
        if isinstance(value, str):
            return value + " "
        return value

    constants = tuple(tamper(value) for value in original)
    # CPython 3.14+ loads small integer literals via LOAD_SMALL_INT, which never
    # touches co_consts; square_lift's only always-present constant is its
    # docstring, so tampering must not rely on an int literal surviving there.
    assert constants != original, "no co_consts entry available to tamper with"
    stale = FunctionType(function.__code__.replace(co_consts=constants), function.__globals__, function.__name__)
    backend = Backend()
    with patch.object(rules, "square_lift", stale), pytest.raises(ValueError, match="source/runtime mismatch"):
        compile_guard(backend, "square_lift", {"a": backend.field(0), "lift_a": backend.lift(0)}, rules)
