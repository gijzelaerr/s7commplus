"""Exact factored coefficient data, without source or compiler trust."""

import random
from dataclasses import replace
from unittest.mock import patch

import pytest

from tools import scalar_field_circuit as model
from tools import verify_scalar_field_circuit as checker
from tools.scalar_compiled_stage import compile_stage
from tools.recover_transform12_phase1 import recover
from tools.transform7_reference import tail_program

P = model.P


def numerical(terms: model.Terms, values: dict[int, int]) -> int:
    total = 0
    for monomial, coefficient in terms:
        term = coefficient
        for variable, exponent in monomial:
            term = term * pow(values[variable], exponent, P) % P
        total = (total + term) % P
    return total


def test_unit_scaling_and_common_monomials_share_circuits() -> None:
    builder = model.Builder()
    first = ((((0, 2), (1, 1)), 3), (((0, 3), (2, 2)), 6))
    scaled = tuple((m, c * 7 % P) for m, c in first)
    roots = builder.compile(first), builder.compile(scaled)
    circuit = builder.freeze()
    assert circuit.nodes[roots[0]].operation == circuit.nodes[roots[1]].operation == "multiply"
    assert set(circuit.nodes[roots[0]].arguments) & set(circuit.nodes[roots[1]].arguments)
    assert checker.verify(circuit, roots, (first, scaled)).identities == 2
    for values in ({0: 0, 1: 1, 2: 23}, {0: 1, 1: P - 1, 2: 47}, {0: P - 1, 1: 2, 2: 3}):
        cache: dict[int, int] = {}
        assert tuple(model.evaluate(circuit, r, values.__getitem__, cache) for r in roots) == tuple(
            numerical(t, values) for t in (first, scaled)
        )


def test_random_polynomials_are_verified_as_formal_coefficients_not_samples() -> None:
    rng = random.Random(561278)
    builder = model.Builder()
    fields = []
    for _ in range(100):
        poly = {}
        for _ in range(rng.randrange(1, 30)):
            powers = tuple((v, e) for v in range(5) if (e := rng.randrange(4)))
            poly[powers] = rng.randrange(1, P)
        fields.append(tuple(sorted(poly.items())))
    roots = tuple(builder.compile(t) for t in fields)
    circuit = builder.freeze()
    assert checker.verify(circuit, roots, tuple(fields), max_terms=30).identities == 100
    values = {v: rng.randrange(P) for v in range(5)}
    cache: dict[int, int] = {}
    for root, terms in zip(roots, fields):
        assert model.evaluate(circuit, root, values.__getitem__, cache) == numerical(terms, values)


@pytest.mark.parametrize("cap", [2, 256])
def test_all_321_stage_field_pools_have_independently_verified_circuits(cap: int) -> None:
    builder = model.Builder()
    rng = random.Random(517262)
    identities = 0
    for source in (*(p for row in recover() for p in row.choices), tail_program()):
        stage = compile_stage(source, cap, exclusive_corrections=True)
        roots = tuple(builder.compile(t) for t in stage.fields)
        circuit = builder.freeze()
        identities += checker.verify(circuit, roots, stage.fields, max_terms=cap).identities
        # Completely arbitrary bindings include simultaneous error values, not
        # just legal correction domains. Factorization preserves the full ring.
        values = {v: rng.randrange(P) for v in range(len(stage.variables))}
        cache: dict[int, int] = {}
        for root, terms in zip(roots, stage.fields):
            assert model.evaluate(circuit, root, values.__getitem__, cache) == numerical(terms, values)
    assert identities > 58_486
    if cap == 256:
        assert len(builder.nodes) < 500_000


def test_verifier_is_independent_of_builder_and_numerical_evaluator() -> None:
    terms = ((((0, 1),), 7), (((1, 2),), 11))
    builder = model.Builder()
    root = builder.compile(terms)
    circuit = builder.freeze()
    with (
        patch.object(model.Builder, "compile", side_effect=AssertionError("builder")),
        patch.object(model.Builder, "_compile", side_effect=AssertionError("builder")),
        patch.object(model, "evaluate", side_effect=AssertionError("sample evaluator")),
    ):
        assert checker.verify(circuit, (root,), (terms,)).identities == 1


def test_mutated_coefficients_roots_powers_and_edges_are_rejected() -> None:
    terms = ((((0, 2),), 7), (((1, 1),), 11))
    builder = model.Builder()
    root = builder.compile(terms)
    circuit = builder.freeze()
    nodes = list(circuit.nodes)
    constant = next(i for i, n in enumerate(nodes) if n.operation == "constant" and n.arguments == (7,))
    nodes[constant] = model.Node("constant", (8,))
    with pytest.raises(ValueError, match="identity"):
        checker.verify(replace(circuit, nodes=tuple(nodes)), (root,), (terms,))
    with pytest.raises(ValueError, match="identity"):
        checker.verify(circuit, (builder.one,), (terms,))
    nodes = list(circuit.nodes)
    power = next(i for i, n in enumerate(nodes) if n.operation == "power")
    nodes[power] = model.Node("power", (nodes[power].arguments[0], 3))
    with pytest.raises(ValueError, match="identity"):
        checker.verify(replace(circuit, nodes=tuple(nodes)), (root,), (terms,))
    nodes = list(circuit.nodes)
    nodes[root] = model.Node("add", (root, builder.zero))
    with pytest.raises(ValueError, match="future|cyclic"):
        checker.verify(replace(circuit, nodes=tuple(nodes)), (root,), (terms,))


def test_zero_annihilation_does_not_request_unneeded_binding() -> None:
    circuit = model.Circuit((model.Node("constant", (0,)), model.Node("variable", (0,)), model.Node("multiply", (0, 1))))
    # This generic zero circuit contains a cancelled extra input. Its ring
    # identity is valid, but it is not a dependency-preserving stage lowering.
    assert not checker.verify(circuit, (2,), ((),), strict_dependencies=False).dependencies_checked
    with patch.object(model.Builder, "compile", side_effect=AssertionError("builder")):
        assert model.evaluate(circuit, 2, lambda v: pytest.fail("unnecessary variable demand"), {}) == 0


def test_zero_cancelled_extra_bindings_do_not_receive_a_causal_stage_certificate() -> None:
    # Operand ordering asks for the unavailable input before discovering zero.
    circuit = model.Circuit((model.Node("variable", (999,)), model.Node("constant", (0,)), model.Node("multiply", (0, 1))))
    assert checker.verify(circuit, (2,), ((),), strict_dependencies=False).identities == 1
    with pytest.raises(ValueError, match="extraneous binding"):
        checker.verify(circuit, (2,), ((),))
    with pytest.raises(KeyError):
        model.evaluate(circuit, 2, {}.__getitem__, {})


def test_missing_binding_can_resume_with_the_same_numeric_cache() -> None:
    builder = model.Builder()
    terms = ((((0, 1), (1, 1)), 1),)
    root = builder.compile(terms)
    circuit = builder.freeze()
    values = {0: 23}
    cache: dict[int, int] = {}
    with pytest.raises(KeyError):
        model.evaluate(circuit, root, values.__getitem__, cache)
    values[1] = 47
    assert model.evaluate(circuit, root, values.__getitem__, cache) == 23 * 47


def test_deep_circuit_evaluation_and_expansion_are_iterative() -> None:
    nodes = [model.Node("constant", (1,))]
    for i in range(1, 2500):
        nodes.append(model.Node("add", (0, i - 1)))
    circuit = model.Circuit(tuple(nodes))
    terms = (((), 2500),)
    assert checker.verify(circuit, (2499,), (terms,), max_terms=1).identities == 1
    assert model.evaluate(circuit, 2499, lambda v: pytest.fail("constant circuit"), {}) == 2500


def test_budget_exhaustion_and_malformed_inputs_are_not_partial_successes() -> None:
    builder = model.Builder(2)
    with pytest.raises(ValueError, match="budget"):
        builder.compile(((((0, 1),), 1),))
    for terms in ((((), 0),), (((), True),), ((((0, 0),), 1),), ((((0, 1 << 16),), 1),)):
        with pytest.raises(ValueError):
            model.Builder().compile(terms)
    with pytest.raises(ValueError, match="canonical residue"):
        builder = model.Builder()
        root = builder.compile(((((0, 1),), 1),))
        model.evaluate(builder.freeze(), root, lambda v: True, {})
    with pytest.raises(ValueError, match="inventory"):
        checker.verify(model.Circuit(()), (0,), ((),))
