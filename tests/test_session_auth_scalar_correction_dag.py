"""Coefficient specialization and bounded two-value decision certificates."""

import itertools
import random
from dataclasses import replace
from unittest.mock import patch

import pytest

from s7commplus.session_auth.family0._generated.data import TRANSFORM7_DATA
from tools import scalar_correction_dag as dag
from tools import scalar_stage_plan as compiler
from tools.recover_scalar_encodings import scalar_xor_mask
from tools.recover_transform12_phase1 import recover
from tools.trace_scalar_defects import evaluate_stage

P = dag.P


def plain(poly: compiler.Polynomial, values: dict[int, int]) -> int:
    result = 0
    for monomial, coefficient in poly.items():
        for variable, exponent in monomial:
            coefficient = coefficient * pow(values[variable], exponent, P) % P
        result += coefficient
    return result % P


def test_taken_error_branch_cancels_another_dependency() -> None:
    poly = {((0, 1), (1, 1)): 1, ((1, 1),): P - 47}
    graph = dag.build(poly, {0: 47, 1: 47})
    assert dag.verify(graph, poly, {0: 47, 1: 47}).decisions == 2
    queries = []

    def lookup(variable: int) -> int:
        queries.append(variable)
        if variable == 0:
            return 47
        raise AssertionError("canceled second error")

    assert dag.evaluate(graph, lookup) == 0 and queries == [0]


def test_numeric_input_cancellation_drops_an_error_without_querying_it() -> None:
    poly = {((0, 1), (2, 1)): 1, ((1, 1), (2, 1)): P - 1}
    assigned = {0: 9, 1: 9}
    reduced = dag.specialize(poly, assigned)
    dag.verify_specialization(poly, reduced, assigned)
    assert reduced == {}
    graph = dag.build(reduced, {2: 47})
    dag.verify(graph, reduced, {2: 47})

    def unexpected(variable: int) -> int:
        raise AssertionError("zero coefficient's error")

    assert dag.evaluate(graph, unexpected) == 0


def test_nonunit_and_zero_weights_do_not_require_division() -> None:
    # P happens to be irrelevant: weight0 already forces an error to vanish.
    for weight in (0, 47):
        poly = {((0, 2),): 1, ((0, 1),): (-weight) % P} if weight else {((0, 1),): 1}
        graph = dag.build(poly, {0: weight})
        dag.verify(graph, poly, {0: weight})
        assert dag.evaluate(graph, lambda _: weight) == 0


@pytest.mark.parametrize("budget", [0, 1, 8, 64])
def test_bounded_graph_preserves_every_error_assignment(budget: int) -> None:
    rng = random.Random(86447)
    weights = {0: 47, 1: (94 - (1 << 128)) % P, 2: 47}
    poly: compiler.Polynomial = {}
    for _ in range(30):
        monomial = tuple((v, exponent) for v in range(5) if (exponent := rng.randrange(4)))
        poly[monomial] = rng.randrange(1, P)
    graph = dag.build(poly, weights, max_decisions=budget)
    dag.verify(graph, poly, weights)
    assert len(graph.nodes) <= 2 * budget + 1
    for bits in itertools.product((False, True), repeat=3):
        values = {v: c * bits[v] for v, c in weights.items()} | {3: 3, 4: 5}
        assert dag.evaluate(graph, values.__getitem__) == plain(poly, values)
    fallback = dag.build(poly, weights, max_work=0)
    assert isinstance(fallback.nodes[fallback.root], dag.Leaf)
    dag.verify(fallback, poly, weights)


def test_dropping_a_branch_or_mutating_a_domain_fails_the_certificate() -> None:
    poly = {((0, 1),): 1}
    graph = dag.build(poly, {0: 47})
    root = graph.nodes[graph.root]
    assert isinstance(root, dag.Decision)
    nodes = graph.nodes[:-1] + (replace(root, high=root.low),)
    with pytest.raises(ValueError, match="cofactor.*identity failed"):
        dag.verify(replace(graph, nodes=nodes), poly, {0: 47})
    with pytest.raises(ValueError, match="domain mismatch"):
        dag.verify(replace(graph, domains=((0, 1),)), poly, {0: 47})
    with pytest.raises(ValueError, match="forward or cyclic"):
        dag.verify(replace(graph, nodes=graph.nodes[:-1] + (replace(root, high=graph.root),)), poly, {0: 47})
    with pytest.raises(ValueError, match="outside the certified"):
        dag.evaluate(graph, lambda _: 1)


def test_corrupt_specialization_fails_exact_coefficient_checking() -> None:
    poly = {((0, 1), (1, 1)): 1}
    with pytest.raises(ValueError, match="specialized coefficient identity"):
        dag.verify_specialization(poly, {((1, 1),): 8}, {0: 9})


def test_cofactor_verifier_never_calls_builder_or_specializer() -> None:
    poly = {((0, 1),): 1, ((1, 1),): 1}
    graph = dag.build(poly, {0: 47})
    reduced = dag.specialize(poly, {1: 9})
    with (
        patch.object(dag, "build", side_effect=AssertionError("builder")),
        patch.object(dag, "specialize", side_effect=AssertionError("specializer")),
    ):
        dag.verify(graph, poly, {0: 47})
        dag.verify_specialization(poly, reduced, {1: 9})


@pytest.mark.parametrize("budget", [-1, True])
def test_invalid_budgets_fail_closed(budget: int) -> None:
    with pytest.raises(ValueError, match="nonnegative integer"):
        dag.build({}, {}, max_decisions=budget)


def test_excessive_exponents_fail_closed() -> None:
    with pytest.raises(ValueError, match="exponent budget"):
        dag.build({((0, 1 << 4096),): 1}, {0: 47})


def test_all_scalar_branches_match_source_under_cofactor_evaluation() -> None:
    rng = random.Random(6131)
    for stage in recover():
        for bit, source in enumerate(stage.choices):
            plan = compiler.compile_plan(source, boolean_corrections=True)
            for value in (0, 1, P + 1, None):
                state = {s: rng.getrandbits(160) if value is None else value for s in plan.input_slots}
                result = compiler.evaluate(plan, state, stage.index, bit, demand_guards=True, cofactor_fields=True)
                expected, events = evaluate_stage(stage.index, state, bit)
                assert result.outputs == expected and all(event in events for event in result.defects)


@pytest.mark.parametrize("cap", [2, 8, 64, 256])
def test_full_boundaries_and_bytes_match_before_factoring(cap: int) -> None:
    x, y = (int.from_bytes(TRANSFORM7_DATA[o : o + 20], "little") for o in (0xD8, 0xEC))
    cases = [(x, y, 0, scalar_xor_mask()), ((1 << 128) + 48, 917984300236617229462155822449362250189314875415, 0, 0)]
    for x, y, prng1, scalar in cases:
        expected, previous = compiler.full_output(x, y, prng1, scalar, cap, boolean_corrections=True, demand_guards=True)
        actual, factored = compiler.full_output(
            x, y, prng1, scalar, cap, boolean_corrections=True, demand_guards=True, cofactor_fields=True, verify_algebra=True
        )
        assert actual == expected and [r.outputs for r in factored] == [r.outputs for r in previous]


def test_cofactor_mode_requires_both_domain_and_demand_flags() -> None:
    source = recover()[1].choices[0]
    plan = compiler.compile_plan(source)
    state = {s: 1 for s in plan.input_slots}
    with pytest.raises(ValueError, match="require Boolean corrections and demand"):
        compiler.evaluate(plan, state, cofactor_fields=True, demand_guards=True)
    constrained = compiler.compile_plan(source, boolean_corrections=True)
    with pytest.raises(ValueError, match="require Boolean corrections and demand"):
        compiler.evaluate(constrained, state, cofactor_fields=True)
