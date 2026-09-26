"""Dependency-free controls for proof accounting and generalized cone safety."""

from __future__ import annotations

import itertools
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tools.prove_monolith4_carry_stages import abstract_cone, proof_progress, prove
from tools import prove_monolith4_carry_stages as carry_proof


class Node:
    def __init__(self, factory: Factory, operation: str, name: str, args: tuple[Node, ...], identifier: int) -> None:
        self.factory, self.operation, self.name, self.args, self.identifier = factory, operation, name, args, identifier

    def get_id(self) -> int:
        return self.identifier

    def children(self) -> tuple[Node, ...]:
        return self.args

    def decl(self) -> Any:
        return lambda *args: self.factory.make(self.operation, self.name, args)

    def evaluate(self, values: dict[str, bool]) -> bool:
        if self.operation == "var":
            return values[self.name]
        if self.operation == "const":
            return self.name == "1"
        args = [arg.evaluate(values) for arg in self.args]
        if self.operation == "and":
            return all(args)
        if self.operation == "xor":
            return sum(args) % 2 == 1
        if self.operation == "not":
            return not args[0]
        raise AssertionError("unknown test operation")


class Factory:
    def __init__(self) -> None:
        self.nodes: dict[tuple[str, str, tuple[Node, ...]], Node] = {}

    def make(self, operation: str, name: str = "", args: tuple[Node, ...] = ()) -> Node:
        key = operation, name, args
        if key not in self.nodes:
            self.nodes[key] = Node(self, operation, name, args, len(self.nodes))
        return self.nodes[key]

    def Bool(self, name: str) -> Node:
        return self.make("var", name)

    @staticmethod
    def is_true(node: Node) -> bool:
        return node.operation == "const" and node.name == "1"

    @staticmethod
    def is_false(node: Node) -> bool:
        return node.operation == "const" and node.name == "0"


def specialize(cuts: dict[int, Node], assignment: dict[str, bool]) -> dict[str, bool]:
    return {**assignment, **{f"cut_{identifier}": node.evaluate(assignment) for identifier, node in cuts.items()}}


def test_shared_cuts_and_refinement_preserve_every_original_assignment() -> None:
    factory = Factory()
    a, b, c = [factory.Bool(name) for name in ("a", "b", "c")]
    shared = factory.make("and", args=(b, c))
    root = factory.make("xor", args=(factory.make("and", args=(a, shared)), shared))
    local = frozenset({a.get_id()})
    generalized, cuts = abstract_cone(factory, root, local)
    assert set(cuts) == {shared.get_id()}
    expanded = frozenset(cuts)
    refined, refined_cuts = abstract_cone(factory, root, local, expanded)
    assert set(refined_cuts) == {b.get_id(), c.get_id()}
    exact, exact_cuts = abstract_cone(factory, root, local, expanded | refined_cuts.keys())
    assert exact is root and not exact_cuts
    for bits in itertools.product((False, True), repeat=3):
        assignment = dict(zip(("a", "b", "c"), bits))
        assert generalized.evaluate(specialize(cuts, assignment)) == root.evaluate(assignment)
        assert refined.evaluate(specialize(refined_cuts, assignment)) == root.evaluate(assignment)


def test_generalized_sat_can_be_spurious_and_constants_are_not_cut() -> None:
    factory = Factory()
    a, b = factory.Bool("a"), factory.Bool("b")
    double_not = factory.make("not", args=(factory.make("not", args=(b,)),))
    root = factory.make("xor", args=(factory.make("and", args=(a, b)), factory.make("and", args=(a, double_not))))
    generalized, cuts = abstract_cone(factory, root, frozenset({a.get_id()}))
    assert len(cuts) == 2
    assert all(not root.evaluate(dict(zip(("a", "b"), bits))) for bits in itertools.product((False, True), repeat=2))
    assert generalized.evaluate({"a": True, f"cut_{b.get_id()}": True, f"cut_{double_not.get_id()}": False})
    for value in ("0", "1"):
        constant = factory.make("const", value)
        result, constant_cuts = abstract_cone(factory, constant, frozenset())
        assert result is constant and not constant_cuts


def test_progress_never_counts_beyond_a_gap_or_completes_a_partial_run() -> None:
    assert proof_progress([], 0, 169) == (0, False)
    assert proof_progress([{"proved": True}] * 2, 0, 169) == (1, False)
    rows = [{"proved": True}] * 31 + [{"proved": False}, {"proved": True}]
    assert proof_progress(rows, 0, 169) == (30, False)
    assert proof_progress([{"proved": True}] * 169, 0, 169) == (168, True)
    assert proof_progress([{"proved": True}] * 168, 0, 168) == (167, False)
    assert proof_progress([{"proved": True}] * 5, 10, 15) == (0, False)


@pytest.mark.parametrize(
    "kwargs", ({"timeout_ms": 0}, {"refinements": -1}, {"start": -1}, {"stop": 170}, {"start": 5, "stop": 5})
)
def test_prover_rejects_invalid_limits_before_loading_optional_solver(kwargs: dict[str, int]) -> None:
    with pytest.raises(ValueError, match="positive timeout"):
        prove(**kwargs)


@pytest.mark.parametrize("failure", (None, "sat", "unknown"))
def test_source_solver_keeps_dag_and_counts_only_completed_stages(monkeypatch: pytest.MonkeyPatch, failure: str | None) -> None:
    outcomes = iter(["unsat"] * (169 if failure is None else 3) + ([] if failure is None else [failure]))
    roots = [object() for _ in range(169)]
    submitted: list[object] = []
    tactics: list[str] = []

    class Solver:
        def set(self, *, timeout: int) -> None:
            assert 0 < timeout <= 1000

        def add(self, root: object) -> None:
            submitted.append(root)

        def check(self) -> str:
            return next(outcomes)

        def reason_unknown(self) -> str:
            return "test timeout"

    def tactic(name: str) -> SimpleNamespace:
        tactics.append(name)
        return SimpleNamespace(solver=Solver)

    # No simplify method: an eager source-DAG rewrite fails this control.
    fake_z3 = SimpleNamespace(Tactic=tactic, sat="sat", unsat="unsat", unknown="unknown", get_version_string=lambda: "test")
    stages = [(f"stage_{index}", root, frozenset()) for index, root in enumerate(roots)]
    monkeypatch.setattr(carry_proof, "equations", lambda: (fake_z3, None, stages))
    observed: list[dict[str, Any]] = []

    def progress(row: dict[str, Any]) -> None:
        observed.append(row.copy())
        row["proved"] = False  # Observers must not mutate proof accounting.

    report = prove(progress=progress)
    count = 169 if failure is None else 4
    assert submitted == roots[:count]
    assert tactics == ["sat"] * (count + 1)
    assert observed == report["stages"]
    assert all(row["elapsed_seconds"] >= 0 for row in observed)
    assert report["full_proof"] is (failure is None)
    assert report["proved_payload_prefix_bits"] == (168 if failure is None else 2)
    if failure == "unknown":
        assert report["stages"][-1]["reason"] == "test timeout"
    elif failure == "sat":
        assert "reason" not in report["stages"][-1]


def test_recorded_full_run_has_current_source_and_models_and_all_obligations() -> None:
    # This checks a recorded solver run's provenance and bookkeeping, not a
    # proof certificate. Replaying the proof requires the optional Z3 extra.
    directory = Path(carry_proof.__file__).parent
    report = json.loads((directory / "monolith4_carry_proof.json").read_text(encoding="utf-8"))
    assert report["source_sha256"] == hashlib.sha256(Path(carry_proof.monolith4.__file__).read_bytes()).hexdigest()
    for name, digest in report["gate_model_sha256"].items():
        assert digest == hashlib.sha256((directory / name).read_bytes()).hexdigest()
    assert set(report["gate_model_sha256"]) == {"monolith5_model.json", "monolith5_gate_model.json"}
    assert report["stage_range"] == [0, 169]
    assert report["abstraction"] is False
    assert report["retain_lemmas"] is False
    assert report["translation_controls"] == 8
    assert [row["stage"] for row in report["stages"]] == ["boundary", "initial_carry"] + [
        f"carry_{bit}_to_{bit + 1}" for bit in range(167)
    ]
    assert all(row["result"] == "unsat" and row["proved"] and row["independent_cut_signals"] == 0 for row in report["stages"])
    assert proof_progress(report["stages"], *report["stage_range"]) == (168, True)
    assert report["proved_payload_prefix_bits"] == 168
    assert report["full_proof"] is True
