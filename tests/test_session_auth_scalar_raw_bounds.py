"""Finite-semiring bounds, exact normalization and first-defect controls."""

import itertools
import random
from unittest.mock import patch

import pytest

from tools import scalar_first_defect as prefix
from tools import scalar_raw_bound_polynomials as algebra
from tools import scalar_structural_guards as structural
from tools.scalar_predicate_dag import Backend
from tools.scalar_raw_bound_dag import Graph
from tools.scalar_stage_plan import constant
from tools.recover_transform12_phase1 import recover
from tools.trace_scalar_defects import evaluate_stage

P = prefix.P


def test_exhaustive_saturated_semiring_laws() -> None:
    def add(a: int, b: int) -> int:
        return min(a + b, 47)

    def mul(a: int, b: int) -> int:
        return min(a * b, 47)

    for a, b, c in itertools.product(range(48), repeat=3):
        assert add(add(a, b), c) == add(a, add(b, c))
        assert mul(mul(a, b), c) == mul(a, mul(b, c))
        assert mul(a, add(b, c)) == add(mul(a, b), mul(a, c))
    for x in range(48):
        assert min(x**6, 47) == min(x**7, 47)
        for c in range(1, 48):
            cutoff = 1
            while c * 2**cutoff < 47:
                cutoff += 1
            assert min(c * x**cutoff, 47) == min(c * x ** (cutoff + 1), 47)


def test_normalization_keeps_zero_and_one_and_removes_only_dominated_terms() -> None:
    terms = {(9, 0): 2, (0, 8): 30, (1, 1): 47, (6, 6): 1, (5, 1): 3}
    actual = algebra.normalize(terms)
    assert actual == (((0, 1), 30), ((1, 1), 47), ((5, 0), 2))
    for a, b in itertools.product(range(48), repeat=2):
        expected = min(sum(c * a ** powers[0] * b ** powers[1] for powers, c in terms.items()), 47)
        got = min(sum(c * a ** powers[0] * b ** powers[1] for powers, c in actual), 47)
        assert got == expected
    for terms in ({(1,): -1}, {(True,): 1}, {(1,): True}, {(1,): 1, (0, 1): 1}):
        with pytest.raises(ValueError, match="nonnegative"):
            algebra.normalize(terms)


def test_graph_folds_are_exhaustively_equal_to_transfer_functions() -> None:
    graph = Graph()
    a, b = graph.input(0), graph.input(1)
    roots = {op: graph.combine(op, a, b) for op in ("add", "multiply", "subtract")}
    for first, last in itertools.product(range(48), repeat=2):
        for op, root in roots.items():
            assert graph.evaluate(root, (first, last), {}) == graph.transfer(op, first, last)
            folded = graph.combine(op, graph.literal(first), graph.literal(last))
            assert graph.evaluate(folded, (), {}) == graph.transfer(op, first, last)
    for c in range(48):
        for op in ("add", "multiply", "subtract"):
            root = graph.combine(op, a, graph.literal(c))
            for x in range(48):
                assert graph.evaluate(root, (x,), {}) == graph.transfer(op, x, c)


def test_all_316_branches_have_compact_positive_bound_polynomials() -> None:
    graph = Graph()
    records = []
    for stage in recover()[1:159]:
        slots = tuple(sorted(s for s in stage.inputs if s != 94)) + (94,)
        for source in stage.choices:
            records.append((source, slots, graph.compile(source, slots, constant)))
    catalogue = algebra.Catalogue(graph)
    assert len(graph.nodes) == 12793
    assert len(catalogue.polynomials) == 7001
    assert sum(map(len, catalogue.polynomials)) == 16439
    assert max(map(len, catalogue.polynomials)) == 12
    rng = random.Random(576349)
    samples = [(v,) * 5 for v in (0, 1, 2, 6, 7, 23, 46, 47, P, P + 1)]
    samples.extend(tuple(rng.randrange(48) for _ in range(5)) for _ in range(20))
    for raw in samples:
        cache = {}
        for node, root in enumerate(catalogue.roots):
            assert catalogue.evaluate(root, raw) == graph.evaluate(node, raw, cache)
    for source, slots, values in records:
        raw = tuple(rng.choice((0, 1, 7, 47, P, P + 1)) for _ in slots)
        facts = structural.analyze(source, constant, input_bounds={s: min(v, 47) for s, v in zip(slots, raw)})
        for value, node in values.items():
            assert catalogue.evaluate(catalogue.roots[node], raw) == facts.lower_bounds[value]


def test_entry_bounds_first_defect_matches_all_intermediate_branches() -> None:
    catalogue = prefix.compile_catalogue(structural_guards=True, entry_bounds=True)
    summary = catalogue.summary()
    assert summary["entry_raw_bounds"] is True and summary["raw_bound_polynomials"] == 7001
    rng = random.Random(914725)
    for stage in recover()[1:159]:
        states = [{s: v for s in stage.inputs} for v in (0, 1, 7, 23, 46, P, P + 1, P + 46)]
        states.extend({s: rng.choice((0, 1, 7, 47, P, P + 23)) for s in stage.inputs} for _ in range(4))
        states.append({s: rng.randrange(1 << 160) for s in stage.inputs})
        for bit in (0, 1):
            for state in states:
                _, events = evaluate_stage(stage.index, state, bit)
                assert catalogue.first_defect(stage.index, state, bit) == (events[0] if events else None)


def test_compiled_prefix_does_not_replay_source_or_bound_instructions() -> None:
    catalogue = prefix.compile_catalogue(structural_guards=True, entry_bounds=True)
    stage = recover()[1]
    state = {s: P + 1 for s in stage.inputs}
    expected = evaluate_stage(stage.index, state, 0)[1][0]
    with (
        patch.object(prefix, "stages", side_effect=AssertionError("source replay")),
        patch.object(prefix, "analyze", side_effect=AssertionError("source bounds replay")),
        patch.object(Graph, "evaluate", side_effect=AssertionError("bound instructions replay")),
        patch.object(algebra, "normalize", side_effect=AssertionError("runtime compilation")),
    ):
        assert catalogue.first_defect(stage.index, state, 0) == expected


def test_bad_bound_graph_and_polynomial_inputs_are_rejected() -> None:
    graph = Graph()
    root = graph.input(0)
    for raw in (True, -1, 1 << 160):
        with pytest.raises(ValueError, match="uint160"):
            graph.evaluate(root, (raw,), {})
    future = graph.node("add", (root, len(graph.nodes)))
    with pytest.raises(ValueError, match="future"):
        graph.evaluate(future, (1,), {})
    with pytest.raises(ValueError, match="acyclic"):
        algebra.Catalogue(graph)
    graph = Graph()
    root = graph.combine("subtract", graph.input(0), graph.literal(1))
    with pytest.raises(ValueError, match="positive-semiring"):
        algebra.Catalogue(graph)
    graph = Graph()
    graph.input(0)
    catalogue = algebra.Catalogue(graph, input_count=1)
    for raw in ((), (True,), (-1,), (1 << 160,), (0, 1)):
        with pytest.raises(ValueError, match="uint160"):
            catalogue.evaluate(0, raw)
    with pytest.raises(ValueError, match="require structural"):
        prefix.compile_catalogue(entry_bounds=True)
    with pytest.raises(ValueError, match="Boolean"):
        prefix.compile_catalogue(structural_guards=True, entry_bounds=1)


def test_predicate_override_is_lazy_and_requires_a_boolean_equation_and_result() -> None:
    backend = Backend()
    root = backend.lift(0).index
    assert backend.evaluate(root, lambda _: 0, (), {}, override_lookup=lambda _: True) is True
    with pytest.raises(ValueError, match="Boolean"):
        backend.evaluate(root, lambda _: 0, (), {}, override_lookup=lambda _: 1)
    with pytest.raises(ValueError, match="Boolean"):
        backend.evaluate(backend.field(0).index, lambda _: 0, (), {}, override_lookup=lambda _: True)
    short = backend.Or(True, backend.lift(0))
    assert backend.evaluate(short.index, lambda _: 0, (), {}, override_lookup=lambda _: None) is True
