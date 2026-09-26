"""Translation validation of complete compiled scalar-stage equation data.

Reconstructs field/anchor/correction bindings for the independent coefficient
checker, and checks actual Boolean roots against source primitive contracts.
Never calls the stage compiler or its algebra/constant-exclusion helpers.
Trusts the separately proved helper contracts, typed predicate frontend and
source integer-model bridge. NOT packed-kernel/whole-pipeline SMT or human review.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import ModuleType

from tools import scalar_constant_lifts as constants
from tools import scalar_lift_categories as categories
from tools import scalar_representative_rules as rules
from tools import verify_scalar_stage_algebra as checker
from tools.decompile_transform12 import Operand, Program
from tools.prove_scalar_predicate_guards import compile_guard
from tools.scalar_compiled_stage import Stage, Terms
from tools.scalar_predicate_dag import Backend, Expr
from tools.scalar_stage_plan import Binding, Guard, Plan, Polynomial

P = (1 << 160) - 47


@dataclass(frozen=True)
class Verification:
    coefficients: checker.Certificate
    carry_contracts: int
    lift_contracts: int
    outputs: int


def verify(stage: Stage, source: Program) -> Verification:
    """Check actual equation data and references, not a compiler-side digest."""
    if type(stage.field_kernel_required) is not bool or stage.field_kernel_required:
        raise ValueError("original coefficient data required for source translation validation")
    if tuple(s.value for s in stage.sites) != tuple(i.value for i in source.instructions):
        raise ValueError("compiled field/tag site inventory mismatch")
    if type(stage.max_terms) is not int or stage.max_terms < 2:
        raise ValueError("compiled term bound required")
    for terms in stage.fields:
        if tuple(sorted(terms)) != terms or len(dict(terms)) != len(terms) or len(terms) > stage.max_terms:
            raise ValueError("noncanonical compiled field terms")
    sites = {s.value: s for s in stage.sites}
    unsafe = tuple(i for i in source.instructions if not checker._safe(i))
    if tuple(g.value for g in stage.guards) != tuple(i.value for i in unsafe):
        raise ValueError("compiled carry inventory mismatch")
    for actual, instruction in zip(stage.guards, unsafe):
        correction = 94 - (1 << 128) if instruction.operation == "add" else 47
        if (actual.operation, actual.tape_index, actual.correction) != (
            instruction.operation,
            instruction.tape_index,
            correction,
        ):
            raise ValueError("compiled carry provenance or weight mismatch")

    def field(index: int) -> Polynomial:
        if type(index) is not int or not 0 <= index < len(stage.fields):
            raise ValueError("undefined compiled field reference")
        return dict(stage.fields[index])

    bindings: list[Binding] = []
    anchors: list[Polynomial] = []
    frontiers: list[int] = []
    input_variables: dict[int, int] = {}
    for ordinal, variable in enumerate(stage.variables):
        if type(variable.index) is not int or variable.index < 0:
            raise ValueError("invalid compiled variable reference")
        if variable.kind == "input":
            if variable.index >= len(stage.input_slots):
                raise ValueError("compiled input ordinal outside layout")
            slot = stage.input_slots[variable.index]
            bindings.append(Binding("input", slot))
            input_variables[slot] = ordinal
            frontiers.append(-1)
        elif variable.kind == "correction":
            if variable.index >= len(stage.guards):
                raise ValueError("compiled correction ordinal outside layout")
            value = stage.guards[variable.index].value
            bindings.append(Binding("correction", value))
            frontiers.append(value)
        elif variable.kind == "anchor":
            poly = field(variable.index)
            if any(not 0 <= v < ordinal for m in poly for v, _ in m):
                raise ValueError("compiled anchor reads a future or cyclic variable")
            bindings.append(Binding("anchor", len(anchors)))
            anchors.append(poly)
            frontiers.append(max((frontiers[v] for m in poly for v, _ in m), default=-1))
        else:
            raise ValueError("unsupported compiled variable")
    for terms in stage.fields:
        for monomial, coefficient in terms:
            if type(coefficient) is not int or not 0 < coefficient < P:
                raise ValueError("noncanonical compiled coefficient")
            if tuple(sorted(monomial)) != monomial or len(dict(monomial)) != len(monomial):
                raise ValueError("noncanonical compiled powers")
            if any(type(v) is not int or not 0 <= v < len(bindings) or type(e) is not int or e < 1 for v, e in monomial):
                raise ValueError("invalid compiled formula variable or exponent")
    pool = {terms: index for index, terms in enumerate(stage.fields)}
    if len(pool) != len(stage.fields):
        raise ValueError("duplicate compiled field identities")

    def operand(operand: Operand) -> tuple[int, int | None]:
        key: Terms
        if operand.kind == "value":
            site = sites[operand.index]
            return site.field, site.tag
        if operand.kind == "input":
            key = ((((input_variables[operand.index], 1),), 1),)
        else:
            raw = checker._constant(operand) % P
            key = (((), raw),) if raw else ()
        if key not in pool:
            raise ValueError("compiled input/constant field identity is missing")
        return pool[key], None

    guard_polys: list[Guard] = []
    for actual, instruction in zip(stage.guards, unsafe):
        expected = tuple(operand(o)[0] for o in instruction.operands)
        if actual.fields != expected:
            raise ValueError("compiled carry operands mismatch")
        poly_a, poly_b = (field(f) for f in actual.fields)
        before = dict(poly_a)
        for monomial, coefficient in poly_b.items():
            before[monomial] = (before.get(monomial, 0) + coefficient * (1 if instruction.operation == "add" else -1)) % P
        before = {m: c for m, c in before.items() if c}
        guard_polys.append(Guard(instruction, before, (poly_a, poly_b)))
    # Guard contracts use original operand fields, not compiler-chosen anchors;
    # their sum may need twice the stage's storage budget.
    plan = Plan(
        source,
        {i.value: i for i in source.instructions},
        stage.input_slots,
        {s.value: field(s.field) for s in stage.sites},
        tuple(guard_polys),
        tuple(bindings),
        tuple(anchors),
        tuple(frontiers),
        sum(i.operation in ("add", "subtract") for i in source.instructions) - len(unsafe),
        2 * stage.max_terms,
        stage.boolean_corrections,
        stage.exclusive_corrections,
    )
    coefficient_certificate = checker.verify(
        plan, source, boolean_corrections=stage.boolean_corrections, exclusive_corrections=stage.exclusive_corrections
    )

    # Rebuild typed canonical nodes rather than trusting compiler-supplied
    # interval metadata during contract comparison.
    backend = Backend()
    for index, node in enumerate(stage.predicates.nodes):
        op, args = node.operation, node.arguments
        if op in ("integer", "boolean", "field", "lift"):
            if len(args) != 1 or type(args[0]) is not int:
                raise ValueError("invalid compiled predicate leaf")
            if op == "integer":
                root = backend.expression(args[0], "number")
            elif op == "boolean":
                if args[0] not in (0, 1):
                    raise ValueError("invalid compiled Boolean literal")
                root = backend.expression(bool(args[0]), "boolean")
            elif op == "field":
                field(args[0])
                root = backend.field(args[0])
            else:
                if not 0 <= args[0] < len(stage.input_slots):
                    raise ValueError("compiled lift leaf outside entry layout")
                root = backend.lift(args[0])
        else:
            if any(type(child) is not int or not 0 <= child < index for child in args):
                raise ValueError("compiled predicate reads a future or cyclic node")
            children = tuple(Expr(backend, child) for child in args)
            if op in ("and", "or"):
                root = backend.logic(op, children)
            elif op == "not" and len(children) == 1:
                root = backend.Not(children[0])
            elif op in ("add", "multiply", "subtract", "mask") and len(children) == 2:
                root = backend.number(op, *children)
            elif op in ("lt", "le", "ge", "eq") and len(children) == 2:
                root = backend.compare(op, *children)
            else:
                raise ValueError("unsupported compiled predicate equation")
        if root.index != index:
            raise ValueError("noncanonical compiled predicate equation")
    if backend.sorts != stage.predicates.sorts or backend.bounds != stage.predicates.bounds:
        raise ValueError("compiled predicate type/interval metadata mismatch")

    def expression(index: int) -> Expr:
        terms = stage.fields[index]
        if not terms or all(not m for m, _ in terms):
            return backend.expression(sum(c for _, c in terms) % P, "number")
        return backend.field(index)

    def tag(root: int) -> Expr:
        if type(root) is not int or not 0 <= root < len(stage.predicates.nodes) or backend.sorts[root] != "boolean":
            raise ValueError("undefined or non-Boolean compiled root")
        return Expr(backend, root)

    def resolve(o: Operand) -> tuple[int, Expr]:
        mu, tau = operand(o)
        if tau is not None:
            return mu, tag(tau)
        if o.kind == "input":
            return mu, backend.lift(stage.input_slots.index(o.index))
        return mu, backend.expression(checker._constant(o) >= P, "boolean")

    def contract(name: str, symbols: dict[str, Expr], module: ModuleType = rules) -> Expr:
        return compile_guard(backend, name, symbols, module=module)  # type: ignore[no-any-return]

    guards = {g.value: g for g in stage.guards}
    for instruction in source.instructions:
        first, last = instruction.operands[0], instruction.operands[-1]
        fa, ta = resolve(first)
        fb, tb = resolve(last)
        a, b = expression(fa), expression(fb)
        output = expression(sites[instruction.value].field)
        symbols = {"a": a, "b": b, "lift_a": ta, "lift_b": tb}
        defective = backend.expression(False, "boolean")
        if instruction.value in guards:
            name = "lazy_addition_defect" if instruction.operation == "add" else "lazy_subtraction_defect"
            defective = contract(name, symbols)
            actual = guards[instruction.value]
            if actual.predicate != defective.index or actual.tags != (ta.index, tb.index):
                raise ValueError("compiled carry contract mismatch")
        if instruction.operation in ("add", "subtract"):
            name = "small_addition_lift" if instruction.operation == "add" else "small_subtraction_lift"
            expected_tag = contract(name, symbols | {"defective": defective}, categories)
        elif first.kind == "constant" or last.kind == "constant":
            raw_constant = checker._constant(first if first.kind == "constant" else last)
            other, other_tag = (b, tb) if first.kind == "constant" else (a, ta)
            expected_tag = (
                contract(
                    "lift",
                    {"a": other, "cutoff": backend.expression(46 // raw_constant + 1, "number"), "lift_a": other_tag},
                    constants,
                )
                if raw_constant
                else backend.expression(False, "boolean")
            )
        elif first == last:
            expected_tag = contract("square_lift", {"a": a, "lift_a": ta})
        else:
            positive = backend.And(backend.Or(backend.Not(a == 0), ta), backend.Or(backend.Not(b == 0), tb))
            nonzero = contract("small_nonzero_product_lift", symbols)
            expected_tag = backend.Or(backend.And(output == 0, positive), backend.And(backend.Not(output == 0), nonzero))
        expected_tag = backend.And(output <= 46, expected_tag)
        if expected_tag.index != sites[instruction.value].tag:
            raise ValueError("compiled lift contract mismatch")
    expected_outputs = tuple((slot, mu, tau.index) for slot, o in source.outputs for mu, tau in (resolve(o),))
    if stage.outputs != expected_outputs:
        raise ValueError("compiled output references mismatch")
    return Verification(coefficient_certificate, len(stage.guards), len(stage.sites), len(stage.outputs))
