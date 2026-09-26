"""Compile source-specific scalar stages into bounded field/carry formulas.

Explicit correction variables preserve nonlinear interactions. Polynomial
anchors bound expansion at compile time. Runtime visits carry guards and lazy
lift dependencies, not arithmetic instructions or repair traversals. This is
still a source-specific research plan, NOT an independent compact curve ladder.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass, replace
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tools.scalar_correction_dag import Graph

from s7commplus.session_auth.family0._generated.data import TRANSFORM7_DATA, TRANSFORM12_BIG_INT_DATA
from tools import scalar_representative_rules as rules
from tools import scalar_lift_categories as categories
from tools import scalar_constant_lifts as constant_lifts
from tools import transform12_integer_model as packing
from tools.decompile_transform12 import Instruction, Operand, Program, external_operands
from tools.predict_scalar_defects import addition_possible, subtraction_possible
from tools.recover_scalar_encodings import scalar_xor_mask
from tools.recover_transform12_phase1 import recover as stages
from tools.trace_scalar_defects import Defect
from tools.transform7_reference import finalize, tail_program
from tools.transform7_setup_integer import model as setup

P = rules.MODULUS
Monomial = tuple[tuple[int, int], ...]  # Sparse (variable ID, exponent) pairs.
Polynomial = dict[Monomial, int]


@dataclass(frozen=True)
class Binding:
    kind: str  # input, correction, or anchor
    index: int


@dataclass(frozen=True)
class Guard:
    instruction: Instruction
    before: Polynomial
    operands: tuple[Polynomial, Polynomial]


@dataclass(frozen=True)
class Plan:
    program: Program
    tag_sources: dict[int, Instruction]
    input_slots: tuple[int, ...]
    fields: dict[int, Polynomial]
    guards: tuple[Guard, ...]
    bindings: tuple[Binding, ...]
    anchors: tuple[Polynomial, ...]
    frontiers: tuple[int, ...]
    excluded_guards: int
    max_terms: int
    boolean_corrections: bool = False
    exclusive_corrections: bool = False


@dataclass(frozen=True)
class Evaluation:
    outputs: dict[int, int]
    defects: tuple[Defect, ...]
    defect_values: tuple[int, ...]
    guards: int
    potential_guards: int
    anchors_evaluated: int
    fields_evaluated: int
    tag_rules: int
    nonzero_product_rules: int
    product_lift_queries: int
    subtraction_rules: int
    subtraction_lift_queries: int
    addition_rules: int
    addition_lift_queries: int
    guard_lift_queries: int
    settled_potential_guards: int
    skipped_guards: int
    cofactor_nodes: int
    scheduler_retries: int
    square_rules: int = 0
    square_lift_queries: int = 0
    structurally_settled_guards: int = 0
    structurally_settled_lifts: int = 0
    constant_product_rules: int = 0


def constant(operand: Operand) -> int:
    offset = operand.index * 24
    return packing.decode(TRANSFORM12_BIG_INT_DATA[offset : offset + 24])


def fixed(value: int) -> Polynomial:
    value %= P
    return {(): value} if value else {}


def variable(index: int) -> Polynomial:
    return {((index, 1),): 1}


def combine(a: Polynomial, b: Polynomial, sign: int = 1) -> Polynomial:
    result = dict(a)
    for monomial, coefficient in b.items():
        value = (result.get(monomial, 0) + sign * coefficient) % P
        if value:
            result[monomial] = value
        else:
            result.pop(monomial, None)
    return result


def product(
    a: Polynomial,
    b: Polynomial,
    max_terms: int,
    correction_weights: dict[int, int] | None = None,
    correction_exclusions: set[tuple[int, int]] | None = None,
) -> Polynomial:
    if len(a) * len(b) > max_terms * 16:
        raise ValueError("polynomial work bound exceeded")
    exclusions: dict[int, set[int]] = {}
    for excluded_first, excluded_second in correction_exclusions or ():
        exclusions.setdefault(excluded_first, set()).add(excluded_second)
    result: Polynomial = {}
    for first, ac in a.items():
        for second, bc in b.items():
            powers = dict(first)
            for index, exponent in second:
                powers[index] = powers.get(index, 0) + exponent
            if exclusions and any(not powers.keys().isdisjoint(exclusions[i]) for i in powers.keys() & exclusions.keys()):
                continue
            coefficient = ac * bc
            if correction_weights:
                for index, exponent in tuple(powers.items()):
                    if index in correction_weights and exponent > 1:
                        coefficient = coefficient * pow(correction_weights[index], exponent - 1, P) % P
                        powers[index] = 1
            monomial = tuple(sorted(powers.items()))
            value = (result.get(monomial, 0) + coefficient) % P
            if value:
                result[monomial] = value
            else:
                result.pop(monomial, None)
            if len(result) > max_terms:
                raise ValueError("polynomial term bound exceeded")
    return result


def operation(
    name: str,
    a: Polynomial,
    b: Polynomial,
    max_terms: int,
    correction_weights: dict[int, int] | None = None,
    correction_exclusions: set[tuple[int, int]] | None = None,
) -> Polynomial:
    if name in ("add", "subtract"):
        result = combine(a, b, -1 if name == "subtract" else 1)
    elif name in ("multiply", "square"):
        result = product(a, b, max_terms, correction_weights, correction_exclusions)
    else:
        raise ValueError("unsupported source operation")
    if len(result) > max_terms:
        raise ValueError("polynomial term bound exceeded")
    return result


def carry_safe(instruction: Instruction) -> bool:
    if instruction.operation not in ("add", "subtract"):
        return True
    a, b = instruction.operands[0], instruction.operands[-1]
    if instruction.operation == "add":
        return any(o.kind == "constant" and rules.addition_constant_safe(constant(o)) for o in (a, b))
    return (
        b.kind == "constant"
        and rules.subtraction_right_constant_safe(constant(b))
        or a.kind == "constant"
        and rules.subtraction_left_constant_safe(constant(a))
    )


@lru_cache(maxsize=4, typed=True)
def compile_plan(
    program: Program, max_terms: int = 256, *, boolean_corrections: bool = False, exclusive_corrections: bool = False
) -> Plan:
    if type(max_terms) is not int or max_terms < 2:
        raise ValueError("polynomial term bound must be at least two")
    if type(boolean_corrections) is not bool:
        raise ValueError("Boolean correction mode required")
    if type(exclusive_corrections) is not bool or exclusive_corrections and not boolean_corrections:
        raise ValueError("exclusive corrections require Boolean correction mode")
    slots = tuple(o.index for o in external_operands(program) if o.kind == "input")
    bindings = [Binding("input", s) for s in slots]
    frontiers = [-1 for _ in slots]
    fields: dict[int, Polynomial] = {}
    guards = []
    anchors: list[Polynomial] = []
    anchor_keys: dict[tuple[tuple[Monomial, int], ...], int] = {}
    input_variables = {s: variable(i) for i, s in enumerate(slots)}
    excluded = 0
    correction_weights: dict[int, int] = {}
    correction_exclusions: set[tuple[int, int]] = set()
    error_variables: dict[int, int] = {}
    source_exclusions: frozenset[tuple[int, int]] = frozenset()
    if exclusive_corrections:
        from tools.scalar_structural_guards import analyze

        source_exclusions = analyze(program, constant).exclusive

    def resolve(operand: Operand) -> Polynomial:
        if operand.kind == "value":
            return fields[operand.index]
        if operand.kind == "input":
            return input_variables[operand.index]
        return fixed(constant(operand))

    def frontier(poly: Polynomial) -> int:
        return max((frontiers[v] for m in poly for v, _ in m), default=-1)

    def anchor(poly: Polynomial) -> Polynomial:
        if not poly or len(poly) == 1 and next(iter(poly)) == ():
            return poly
        key = tuple(sorted(poly.items()))
        if key not in anchor_keys:
            index = len(bindings)
            anchor_keys[key] = index
            bindings.append(Binding("anchor", len(anchors)))
            frontiers.append(frontier(poly))
            anchors.append(poly)
        return variable(anchor_keys[key])

    for instruction in program.instructions:
        a, b = resolve(instruction.operands[0]), resolve(instruction.operands[-1])
        if max(frontier(a), frontier(b)) >= instruction.value:
            raise ValueError("source SSA is not in acyclic correction order")
        try:
            before = operation(instruction.operation, a, b, max_terms, correction_weights, correction_exclusions)
        except ValueError as error:
            if instruction.operation not in ("add", "subtract", "multiply", "square"):
                raise error
            a, b = anchor(a), anchor(b)
            before = operation(instruction.operation, a, b, max_terms, correction_weights, correction_exclusions)
        if carry_safe(instruction):
            fields[instruction.value] = before
            excluded += instruction.operation in ("add", "subtract")
        else:
            if len(before) == max_terms:
                before = anchor(before)
            guards.append(Guard(instruction, before, (a, b)))
            index = len(bindings)
            bindings.append(Binding("correction", instruction.value))
            error_variables[instruction.value] = index
            correction_exclusions.update(
                (error_variables[first], index)
                for first, last in source_exclusions
                if last == instruction.value and first in error_variables
            )
            frontiers.append(instruction.value)
            if boolean_corrections:
                correction_weights[index] = (94 - (1 << 128) if instruction.operation == "add" else 47) % P
            fields[instruction.value] = combine(before, variable(index))
    plan = Plan(
        program,
        {i.value: i for i in program.instructions},
        slots,
        fields,
        tuple(guards),
        tuple(bindings),
        tuple(anchors),
        tuple(frontiers),
        excluded,
        max_terms,
        boolean_corrections,
        exclusive_corrections,
    )
    validate_order(plan)
    if boolean_corrections:
        # Normalizing before expansion can change anchor placement adversely.
        # Keep a post-normalized candidate with the original anchors too.
        post = reduce_correction_powers(
            compile_plan(program, max_terms, boolean_corrections=exclusive_corrections),
            exclusive_corrections=exclusive_corrections,
        )
        if formula_size(post) < formula_size(plan):
            plan = post
    return plan


def formula_size(plan: Plan) -> tuple[int, int]:
    """Stored monomial count and anchor count, not runtime work or speed."""
    polys = (*plan.fields.values(), *plan.anchors, *(p for g in plan.guards for p in (g.before, *g.operands)))
    return sum(map(len, polys)), len(plan.anchors)


def reduce_correction_powers(plan: Plan, *, exclusive_corrections: bool = False) -> Plan:
    """Normalize a fixed anchor layout using each error's two-value domain."""
    if type(exclusive_corrections) is not bool or plan.exclusive_corrections and not exclusive_corrections:
        raise ValueError("exclusive correction domains cannot be erased")
    weights = {
        v: arithmetic_correction(plan.tag_sources[b.index].operation) % P
        for v, b in enumerate(plan.bindings)
        if b.kind == "correction"
    }
    exclusions: set[tuple[int, int]] = set()
    if exclusive_corrections:
        from tools.scalar_structural_guards import analyze

        variables = {b.index: v for v, b in enumerate(plan.bindings) if b.kind == "correction"}
        exclusions = {
            (variables[a], variables[b])
            for a, b in analyze(plan.program, constant).exclusive
            if a in variables and b in variables
        }
    exclusion_neighbors: dict[int, set[int]] = {}
    for a, b in exclusions:
        exclusion_neighbors.setdefault(a, set()).add(b)

    def normalize(poly: Polynomial) -> Polynomial:
        result: Polynomial = {}
        for monomial, coefficient in poly.items():
            support = {v for v, _ in monomial}
            if exclusion_neighbors and any(
                not support.isdisjoint(exclusion_neighbors[v]) for v in support & exclusion_neighbors.keys()
            ):
                continue
            reduced = []
            for variable_id, exponent in monomial:
                if variable_id in weights:
                    coefficient = coefficient * pow(weights[variable_id], exponent - 1, P) % P
                    exponent = 1
                reduced.append((variable_id, exponent))
            key = tuple(reduced)
            result[key] = (result.get(key, 0) + coefficient) % P
        return {m: c for m, c in result.items() if c}

    anchors = tuple(normalize(poly) for poly in plan.anchors)
    frontiers: list[int] = []
    for binding in plan.bindings:
        if binding.kind == "input":
            frontiers.append(-1)
        elif binding.kind == "correction":
            frontiers.append(binding.index)
        else:
            frontiers.append(max((frontiers[v] for m in anchors[binding.index] for v, _ in m), default=-1))
    reduced = replace(
        plan,
        fields={v: normalize(poly) for v, poly in plan.fields.items()},
        guards=tuple(
            Guard(g.instruction, normalize(g.before), (normalize(g.operands[0]), normalize(g.operands[1]))) for g in plan.guards
        ),
        anchors=anchors,
        frontiers=tuple(frontiers),
        boolean_corrections=True,
        exclusive_corrections=exclusive_corrections,
    )
    validate_order(reduced)
    return reduced


def validate_order(plan: Plan) -> None:
    """Independent structural check, not an algebraic-equivalence certificate.

    Every anchor refers backward; every guard refers only to finalized earlier
    corrections. This is the invariant that makes runtime caches repair-free.
    """
    if type(plan.boolean_corrections) is not bool:
        raise ValueError("Boolean correction mode required")
    if type(plan.exclusive_corrections) is not bool or plan.exclusive_corrections and not plan.boolean_corrections:
        raise ValueError("exclusive corrections require Boolean correction mode")
    frontiers: list[int] = []

    def frontier(poly: Polynomial, available: int) -> int:
        if len(poly) > plan.max_terms:
            raise ValueError("formula exceeds its declared term bound")
        result = -1
        for monomial, coefficient in poly.items():
            if type(coefficient) is not int or not 0 < coefficient < P or tuple(sorted(monomial)) != monomial:
                raise ValueError("noncanonical formula")
            seen = set()
            for variable_id, exponent in monomial:
                if type(variable_id) is not int or not 0 <= variable_id < available:
                    raise ValueError("formula contains a forward variable reference")
                if type(exponent) is not int or exponent <= 0 or variable_id in seen:
                    raise ValueError("noncanonical formula monomial")
                seen.add(variable_id)
                result = max(result, frontiers[variable_id])
        return result

    expected_guards = tuple(i for i in plan.program.instructions if not carry_safe(i))
    if tuple(g.instruction for g in plan.guards) != expected_guards:
        raise ValueError("carry guard inventory mismatch")
    if plan.tag_sources != {i.value: i for i in plan.program.instructions} or set(plan.fields) != set(plan.tag_sources):
        raise ValueError("source field/tag inventory mismatch")
    inputs: list[int] = []
    corrections: list[int] = []
    anchors: list[int] = []
    for variable_id, binding in enumerate(plan.bindings):
        if binding.kind == "input":
            inputs.append(binding.index)
            frontiers.append(-1)
        elif binding.kind == "correction":
            corrections.append(binding.index)
            frontiers.append(binding.index)
        elif binding.kind == "anchor":
            if binding.index != len(anchors) or binding.index >= len(plan.anchors):
                raise ValueError("anchor inventory mismatch")
            anchors.append(binding.index)
            frontiers.append(frontier(plan.anchors[binding.index], variable_id))
        else:
            raise ValueError("unsupported formula binding")
    if tuple(inputs) != plan.input_slots or tuple(corrections) != tuple(i.value for i in expected_guards):
        raise ValueError("formula input/correction inventory mismatch")
    if len(anchors) != len(plan.anchors) or tuple(frontiers) != plan.frontiers:
        raise ValueError("formula frontier inventory mismatch")
    for guard in plan.guards:
        if max(frontier(p, len(frontiers)) for p in (guard.before, *guard.operands)) >= guard.instruction.value:
            raise ValueError("guard depends on an unresolved correction")
    for value, poly in plan.fields.items():
        if frontier(poly, len(frontiers)) > value:
            raise ValueError("source field depends on a future correction")


def evaluate(
    plan: Plan,
    state: dict[int, int],
    index: int = 160,
    bit: int = 0,
    *,
    lazy_guards: bool = True,
    demand_guards: bool = False,
    cofactor_fields: bool = False,
    square_shortcuts: bool = False,
    small_product_shortcuts: bool = False,
    category_lifts: bool = False,
    structural_guards: bool = False,
) -> Evaluation:
    if bit not in (0, 1) or set(state) != set(plan.input_slots):
        raise ValueError("stage input layout or branch mismatch")
    if cofactor_fields and not (plan.boolean_corrections and demand_guards):
        raise ValueError("cofactor fields require Boolean corrections and demand guards")
    if cofactor_fields:
        validate_order(plan)
    state = dict(state)  # Freeze entry values for all partial-evaluation facts.
    inputs = {s: rules.Representative.from_integer(v) for s, v in state.items()}
    instructions = plan.tag_sources
    corrections: dict[int, int] = {}
    anchors: dict[int, int] = {}
    fields: dict[int, int] = {}
    representatives: dict[int, int] = {}
    tags = 0
    product_rules = 0
    product_queries = 0
    constant_rules = 0
    square_rules = 0
    square_queries = 0
    sub_rules = 0
    sub_queries = 0
    add_rules = 0
    add_queries = 0
    guard_queries = 0
    settled_guards = 0
    guard_map = {g.instruction.value: g for g in plan.guards}
    active_guards: list[int] = []
    structural = None
    structurally_settled: set[int] = set()
    structurally_lifted: set[int] = set()
    if structural_guards:
        from tools.scalar_structural_guards import analyze

        structural = analyze(plan.program, constant, input_bounds={slot: min(value, 47) for slot, value in state.items()})
    graphs: dict[tuple[tuple[Monomial, int], ...], Graph] = {}
    current_request: tuple[str, int] | None = None
    retries = 0

    class NeedBinding(Exception):
        def __init__(self, request: tuple[str, int]) -> None:
            self.request = request

    weights = {
        v: arithmetic_correction(plan.tag_sources[b.index].operation) % P
        for v, b in enumerate(plan.bindings)
        if b.kind == "correction"
    }

    def binding_value(variable_id: int) -> int:
        binding = plan.bindings[variable_id]
        if binding.kind == "input":
            return inputs[binding.index].residue
        if binding.kind == "correction":
            if binding.index not in corrections:
                if demand_guards:
                    raise NeedBinding(("correction", binding.index))
                if not demand_guards:
                    raise ValueError("formula reads an unresolved correction")
                decide_guard(binding.index)
            return corrections[binding.index] % P
        if binding.kind == "anchor":
            if binding.index not in anchors:
                if demand_guards:
                    raise NeedBinding(("anchor", binding.index))
                anchors[binding.index] = field(plan.anchors[binding.index])
            return anchors[binding.index]
        raise ValueError("unsupported formula binding")

    def field(poly: Polynomial) -> int:
        if cofactor_fields:
            from tools import scalar_correction_dag as cofactor

            key = tuple(sorted(poly.items()))
            if key not in graphs:
                assigned = {}
                for v, b in enumerate(plan.bindings):
                    if b.kind == "input":
                        assigned[v] = inputs[b.index].residue
                    elif b.kind == "correction" and b.index in corrections:
                        assigned[v] = corrections[b.index] % P
                    elif b.kind == "anchor" and b.index in anchors:
                        assigned[v] = anchors[b.index]
                specialized = cofactor.specialize(poly, assigned)
                cofactor.verify_specialization(poly, specialized, assigned)
                graph = cofactor.build(specialized, weights, max_decisions=8)
                cofactor.verify(graph, specialized, weights)
                graphs[key] = graph
            # Known values used by the certificate are finalized and immutable.
            # A resumed attempt must not grow a fresh graph for each new fact.
            return cofactor.evaluate(graphs[key], binding_value)
        total = 0
        for monomial, coefficient in poly.items():
            term = coefficient
            for variable_id, exponent in monomial:
                value = binding_value(variable_id)
                term = term * pow(value, exponent, P) % P
                if demand_guards and term == 0:
                    # Annihilated monomials need no later correction values.
                    # Their skipped diagnostic carry events are intentional.
                    break
            total += term
        return total % P

    def residue(operand: Operand) -> int:
        if operand.kind == "input":
            return inputs[operand.index].residue
        if operand.kind == "constant":
            return constant(operand) % P
        if operand.index not in fields:
            if demand_guards:
                raise NeedBinding(("field", operand.index))
            fields[operand.index] = field(plan.fields[operand.index])
        return fields[operand.index]

    def representative(operand: Operand) -> int:
        nonlocal tags, product_rules, sub_rules, add_rules, square_rules, constant_rules
        if operand.kind == "input":
            return state[operand.index]
        if operand.kind == "constant":
            return constant(operand)
        if operand.index not in representatives:
            if demand_guards and current_request != ("representative", operand.index):
                raise NeedBinding(("representative", operand.index))
            value = residue(operand)
            if value > 46:
                representatives[operand.index] = value
            elif structural is not None and structural.lower_bounds[operand.index] >= 47:
                # Small residue plus raw value>=47 uniquely forces a p lift.
                representatives[operand.index] = value + P
                structurally_lifted.add(operand.index)
            else:
                instruction = instructions[operand.index]
                first, last = instruction.operands[0], instruction.operands[-1]
                if structural_guards and instruction.operation == "multiply" and any(o.kind == "constant" for o in (first, last)):
                    const, other = (first, last) if first.kind == "constant" else (last, first)
                    raw_constant = constant(const)

                    def constant_lift() -> bool:
                        nonlocal product_queries
                        product_queries += 1
                        return representative(other) >= P

                    lifted = raw_constant != 0 and constant_lifts.lift(
                        residue(other), constant_lifts.threshold(raw_constant), constant_lift
                    )
                    representatives[operand.index] = value + (P if lifted else 0)
                    constant_rules += 1
                elif instruction.operation == "subtract":

                    def sub_lift(o: Operand) -> bool:
                        nonlocal sub_queries
                        sub_queries += 1
                        return representative(o) >= P

                    subtraction_lift = categories.small_subtraction_lift if category_lifts else rules.subtraction_lift
                    lifted = first != last and subtraction_lift(
                        residue(first),
                        residue(last),
                        corrections.get(operand.index, 0) != 0,
                        lambda: sub_lift(first),
                        lambda: sub_lift(last),
                    )
                    representatives[operand.index] = value + (P if lifted else 0)
                    sub_rules += 1
                elif instruction.operation == "add":

                    def add_lift(o: Operand) -> bool:
                        nonlocal add_queries
                        add_queries += 1
                        return representative(o) >= P

                    if category_lifts:
                        lifted = categories.small_addition_lift(
                            residue(first),
                            residue(last),
                            corrections.get(operand.index, 0) != 0,
                            lambda: add_lift(first),
                            lambda: add_lift(last),
                        )
                    else:
                        lifted = rules.addition_lift(
                            residue(first) + residue(last),
                            lambda: add_lift(first),
                            lambda: add_lift(last),
                        )
                    representatives[operand.index] = value + (P if lifted else 0)
                    add_rules += 1
                elif (
                    instruction.operation == "square"
                    and (square_shortcuts or category_lifts)
                    or (structural_guards and instruction.operation == "multiply" and first == last)
                ):

                    def square_lift() -> bool:
                        nonlocal square_queries
                        square_queries += 1
                        return representative(first) >= P

                    lifted = rules.square_lift(residue(first), square_lift)
                    representatives[operand.index] = value + (P if lifted else 0)
                    square_rules += 1
                elif value == 0:

                    def positive(o: Operand) -> bool:
                        return residue(o) != 0 or representative(o) != 0

                    if instruction.operation in ("multiply", "square"):
                        lifted = positive(first) and positive(last)
                    else:
                        raise ValueError("unsupported zero-lift instruction")
                    representatives[operand.index] = P if lifted else 0
                elif instruction.operation in ("multiply", "square"):

                    def lift(o: Operand) -> bool:
                        nonlocal product_queries
                        product_queries += 1
                        return representative(o) >= P

                    product_lift = (
                        rules.small_nonzero_product_lift
                        if small_product_shortcuts or category_lifts
                        else rules.nonzero_product_lift
                    )
                    lifted = product_lift(residue(first), residue(last), lambda: lift(first), lambda: lift(last))
                    representatives[operand.index] = value + (P if lifted else 0)
                    product_rules += 1
                else:
                    raise ValueError("unsupported lift instruction")
                tags += 1
        return representatives[operand.index]

    events: list[Defect] = []
    event_values: list[int] = []
    potentials = 0

    def compute_guard(value_id: int) -> None:
        nonlocal potentials, settled_guards
        if value_id in corrections:
            return
        if value_id not in guard_map:
            raise ValueError("formula reads an undefined correction")
        guard = guard_map[value_id]
        instruction = guard.instruction
        if structural is not None and (
            value_id in structural.safe
            or any(
                previous not in guard_map or corrections.get(previous) == 0 for previous in structural.dominated.get(value_id, ())
            )
        ):
            # Only already resolved facts: never introduce a new dependency.
            # Keep the formal error variable and coefficient certificate intact.
            corrections[value_id] = 0
            structurally_settled.add(value_id)
            return
        if instruction.operation == "add":
            possible = addition_possible(field(guard.before))
        else:
            possible = subtraction_possible(field(guard.operands[0]), field(guard.operands[1]))
        correction = 0
        if possible:
            potentials += 1

            def guard_lift(o: Operand) -> bool:
                nonlocal guard_queries
                guard_queries += 1
                return representative(o) >= P

            first, last = instruction.operands
            queries_before = guard_queries
            if lazy_guards:
                defective = (rules.lazy_addition_defect if instruction.operation == "add" else rules.lazy_subtraction_defect)(
                    residue(first), residue(last), lambda: guard_lift(first), lambda: guard_lift(last)
                )
                settled_guards += guard_queries == queries_before
            else:
                # Comparison mode retains the previous eager guard demand.
                defective = True
            if defective:
                a, b = (representative(o) for o in instruction.operands)
                result, correction = (rules.add if instruction.operation == "add" else rules.subtract)(
                    rules.Representative.from_integer(a), rules.Representative.from_integer(b)
                )
                if lazy_guards and not correction:
                    raise ValueError("lazy guard disagrees with exact correction")
            if correction:
                events.append(
                    Defect(index, bit, instruction.tape_index, instruction.operation, (a, b), result.integer(), correction)
                )
                event_values.append(instruction.value)
        corrections[instruction.value] = correction

    def decide_guard(value_id: int) -> None:
        if active_guards and value_id >= active_guards[-1]:
            raise ValueError("formula reads an unresolved correction")
        active_guards.append(value_id)
        try:
            compute_guard(value_id)
        finally:
            active_guards.pop()

    def resolve(request: tuple[str, int]) -> None:
        nonlocal current_request, retries, potentials, guard_queries, settled_guards
        nonlocal tags, product_rules, product_queries, sub_rules, sub_queries, add_rules, add_queries
        nonlocal square_rules, square_queries
        pending = [request]
        active = {request}
        while pending:
            current_request = pending[-1]
            kind, index_id = current_request
            # Paused attempts are not completed rule executions. Keep retry
            # probes separate from logical queries and completed tag counts.
            snapshot = (
                potentials,
                guard_queries,
                settled_guards,
                tags,
                product_rules,
                product_queries,
                sub_rules,
                sub_queries,
                add_rules,
                add_queries,
                square_rules,
                square_queries,
            )
            try:
                if kind == "correction":
                    decide_guard(index_id)
                elif kind == "anchor":
                    anchors[index_id] = field(plan.anchors[index_id])
                elif kind == "field":
                    fields[index_id] = field(plan.fields[index_id])
                elif kind == "representative":
                    representative(Operand("value", index_id))
                else:
                    raise ValueError("unsupported demand binding")
            except NeedBinding as needed:
                (
                    potentials,
                    guard_queries,
                    settled_guards,
                    tags,
                    product_rules,
                    product_queries,
                    sub_rules,
                    sub_queries,
                    add_rules,
                    add_queries,
                    square_rules,
                    square_queries,
                ) = snapshot
                retries += 1
                if needed.request[0] == "correction" and any(k == "correction" and needed.request[1] >= i for k, i in pending):
                    raise ValueError("formula reads an unresolved correction") from needed
                if needed.request in active:
                    raise ValueError("formula reads an unresolved correction or cyclic binding") from needed
                active.add(needed.request)
                pending.append(needed.request)
            else:
                active.remove(pending.pop())
        current_request = None

    if not demand_guards:
        for guard in plan.guards:
            decide_guard(guard.instruction.value)
    else:
        for _, operand in plan.program.outputs:
            if operand.kind == "value":
                resolve(("representative", operand.index))
    outputs = {s: representative(o) for s, o in plan.program.outputs}
    ordered_events = sorted(zip(event_values, events))
    return Evaluation(
        outputs,
        tuple(e for _, e in ordered_events),
        tuple(v for v, _ in ordered_events),
        len(corrections),
        potentials,
        len(anchors),
        len(fields),
        tags,
        product_rules,
        product_queries,
        sub_rules,
        sub_queries,
        add_rules,
        add_queries,
        guard_queries,
        settled_guards,
        len(plan.guards) - len(corrections),
        sum(len(g.nodes) for g in graphs.values()),
        retries,
        square_rules,
        square_queries,
        len(structurally_settled),
        len(structurally_lifted),
        constant_rules,
    )


def full_output(
    x: int,
    y: int,
    prng1: int,
    scalar: int,
    max_terms: int = 256,
    *,
    verify_algebra: bool = False,
    lazy_guards: bool = True,
    boolean_corrections: bool = False,
    exclusive_corrections: bool = False,
    demand_guards: bool = False,
    cofactor_fields: bool = False,
    square_shortcuts: bool = False,
    small_product_shortcuts: bool = False,
    category_lifts: bool = False,
    structural_guards: bool = False,
) -> tuple[bytes, tuple[Evaluation, ...]]:
    def plan_for(source: Program) -> Plan:
        plan = compile_plan(
            source, max_terms, boolean_corrections=boolean_corrections, exclusive_corrections=exclusive_corrections
        )
        if verify_algebra:
            from tools.verify_scalar_stage_algebra import verify

            verify(plan, source, boolean_corrections=boolean_corrections, exclusive_corrections=exclusive_corrections)
        return plan

    for value in (x, y, prng1, scalar):
        rules.Representative.from_integer(value)
    state = dict(zip(stages()[0].inputs, setup(x, y, prng1).slots))
    rows = []
    for stage in stages():
        bit = scalar >> (159 - stage.index) & 1
        row = evaluate(
            plan_for(stage.choices[bit]),
            state,
            stage.index,
            bit,
            lazy_guards=lazy_guards,
            demand_guards=demand_guards,
            cofactor_fields=cofactor_fields,
            square_shortcuts=square_shortcuts,
            small_product_shortcuts=small_product_shortcuts,
            category_lifts=category_lifts,
            structural_guards=structural_guards,
        )
        state = row.outputs
        rows.append(row)
    tail = evaluate(
        plan_for(tail_program()),
        state,
        lazy_guards=lazy_guards,
        demand_guards=demand_guards,
        cofactor_fields=cofactor_fields,
        square_shortcuts=square_shortcuts,
        small_product_shortcuts=small_product_shortcuts,
        category_lifts=category_lifts,
        structural_guards=structural_guards,
    )
    return finalize(tail.outputs), tuple(rows) + (tail,)


def describe(plan: Plan) -> dict[str, object]:
    """Readable output equations and error provenance, without input material."""
    validate_order(plan)
    names = tuple({"input": "s", "correction": "e", "anchor": "f"}[b.kind] + str(b.index) for b in plan.bindings)

    def render(poly: Polynomial) -> str:
        terms = []
        for monomial, coefficient in sorted(poly.items()):
            coefficient = coefficient if coefficient <= P // 2 else coefficient - P
            factors = [names[v] + (f"**{exponent}" if exponent != 1 else "") for v, exponent in monomial]
            if coefficient != 1 or not factors:
                factors.insert(0, str(coefficient))
            terms.append("*".join(factors))
        return "(" + " + ".join(terms or ["0"]) + ") % p"

    def error_dependencies(poly: Polynomial) -> tuple[int, ...]:
        errors = set()
        for monomial in poly:
            for v, _ in monomial:
                binding = plan.bindings[v]
                if binding.kind == "correction":
                    errors.add(binding.index)
                elif binding.kind == "anchor":
                    errors.update(anchor_errors(binding.index))
        return tuple(sorted(errors))

    @lru_cache(maxsize=None)
    def anchor_errors(index: int) -> tuple[int, ...]:
        return error_dependencies(plan.anchors[index])

    def operand_field(operand: Operand) -> Polynomial:
        if operand.kind == "value":
            return plan.fields[operand.index]
        if operand.kind == "constant":
            return fixed(constant(operand))
        variable_id = plan.bindings.index(Binding("input", operand.index))
        return variable(variable_id)

    return {
        "scope": "source-specific field equations, explicit carry provenance; representative lift rules remain separate; NOT compact curve algorithm",
        "modulus": P,
        "symbol_legend": "s<slot>: input residue; e<SSA>: carry correction modulo p; f<index>: bounded formula anchor",
        "source_instructions": len(plan.program.instructions),
        "excluded_constant_carry_sites": plan.excluded_guards,
        "max_terms": plan.max_terms,
        "boolean_corrections": plan.boolean_corrections,
        "exclusive_corrections": plan.exclusive_corrections,
        "anchors": {f"f{i}": render(poly) for i, poly in enumerate(plan.anchors)},
        "carry_sites": [
            {
                "symbol": f"e{g.instruction.value}",
                "tape_index": g.instruction.tape_index,
                "operation": g.instruction.operation,
                "possible_corrections": (0, arithmetic_correction(g.instruction.operation)),
            }
            for g in plan.guards
        ],
        "outputs": {
            str(slot): {
                "field_formula": render(operand_field(operand)),
                "carry_dependencies": error_dependencies(operand_field(operand)),
                "lift_dependency": (operand.kind, operand.index),
                "representative_rule": "r is unique above46; otherwise retain the source-dependent p-lift bit",
            }
            for slot, operand in plan.program.outputs
        },
    }


def arithmetic_correction(operation: str) -> int:
    return 94 - (1 << 128) if operation == "add" else 47


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--effective-scalar", type=lambda value: int(value, 0), default=0)
    parser.add_argument("--prng1", type=lambda value: int(value, 0), default=0)
    parser.add_argument("--max-terms", type=int, default=256)
    parser.add_argument("--verify-algebra", action="store_true", help="independently check each field/guard plan before use")
    parser.add_argument("--eager-guards", action="store_true", help="retain old eager carry decisions for comparison")
    parser.add_argument("--square-shortcuts", action="store_true", help="use the proved conditional a>=7 square-lift rule")
    parser.add_argument("--category-lifts", action="store_true", help="use the unified seven-state output-conditioned lift rules")
    parser.add_argument("--structural-guards", action="store_true", help="use proved raw-bound and subtraction-dominance facts")
    parser.add_argument(
        "--small-product-shortcuts", action="store_true", help="eliminate small nonzero-output product thresholds"
    )
    parser.add_argument(
        "--cofactor-fields", action="store_true", help="certify numeric specialization and bounded correction cofactors"
    )
    parser.add_argument(
        "--demand-guards", action="store_true", help="resolve only output-needed guards; NOT a complete carry trace"
    )
    parser.add_argument(
        "--boolean-corrections", action="store_true", help="reduce correction powers using their two-value domains"
    )
    parser.add_argument("--exclusive-corrections", action="store_true", help="drop proved mutually exclusive error products")
    parser.add_argument(
        "--stage", type=int, choices=range(160), help="describe one stage instead of evaluating a synthetic input"
    )
    parser.add_argument("--branch", type=int, choices=(0, 1), default=0)
    args = parser.parse_args()
    if args.cofactor_fields and not (args.boolean_corrections and args.demand_guards):
        parser.error("--cofactor-fields requires --boolean-corrections and --demand-guards")
    if args.exclusive_corrections and not args.boolean_corrections:
        parser.error("--exclusive-corrections requires --boolean-corrections")
    if not 0 <= args.effective_scalar < 1 << 160 or not 0 <= args.prng1 < 1 << 160 or args.max_terms < 2:
        parser.error("unsigned160 synthetic inputs and a term bound of at least two required")
    if args.stage is not None:
        source = stages()[args.stage].choices[args.branch]
        plan = compile_plan(
            source, args.max_terms, boolean_corrections=args.boolean_corrections, exclusive_corrections=args.exclusive_corrections
        )
        description = describe(plan)
        if args.verify_algebra:
            from tools.verify_scalar_stage_algebra import verify

            description["algebra_certificate"] = asdict(
                verify(
                    plan, source, boolean_corrections=args.boolean_corrections, exclusive_corrections=args.exclusive_corrections
                )
            )
        print(json.dumps(description, indent=2))
        return
    x, y = (int.from_bytes(TRANSFORM7_DATA[o : o + 20], "little") for o in (0xD8, 0xEC))
    output, rows = full_output(
        x,
        y,
        args.prng1,
        args.effective_scalar ^ scalar_xor_mask(),
        args.max_terms,
        verify_algebra=args.verify_algebra,
        lazy_guards=not args.eager_guards,
        boolean_corrections=args.boolean_corrections,
        exclusive_corrections=args.exclusive_corrections,
        demand_guards=args.demand_guards,
        cofactor_fields=args.cofactor_fields,
        square_shortcuts=args.square_shortcuts,
        small_product_shortcuts=args.small_product_shortcuts,
        category_lifts=args.category_lifts,
        structural_guards=args.structural_guards,
    )
    from tools.predict_scalar_defects import source_hashes

    hashes = source_hashes()
    hashes["tools/scalar_stage_plan.py"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    print(
        json.dumps(
            {
                "scope": "source-specific bounded carry/tag/output formulas; NOT independent compact ladder or whole-pipeline SMT proof",
                "destination_hex": output.hex(),
                "defects": [e.__dict__ for row in rows for e in row.defects],
                "full_numeric_instruction_replay": False,
                "polynomial_repairs": 0,
                "algebra_verified_plans": len(rows) if args.verify_algebra else 0,
                "guard_formulas": sum(row.guards for row in rows),
                "potential_guards": sum(row.potential_guards for row in rows),
                "anchors_evaluated": sum(row.anchors_evaluated for row in rows),
                "fields_evaluated": sum(row.fields_evaluated for row in rows),
                "tag_rules": sum(row.tag_rules for row in rows),
                "nonzero_product_rules": sum(row.nonzero_product_rules for row in rows),
                "product_lift_queries": sum(row.product_lift_queries for row in rows),
                "subtraction_rules": sum(row.subtraction_rules for row in rows),
                "subtraction_lift_queries": sum(row.subtraction_lift_queries for row in rows),
                "addition_rules": sum(row.addition_rules for row in rows),
                "addition_lift_queries": sum(row.addition_lift_queries for row in rows),
                "guard_lift_queries": sum(row.guard_lift_queries for row in rows),
                "settled_potential_guards": sum(row.settled_potential_guards for row in rows),
                "lazy_guards": not args.eager_guards,
                "boolean_corrections": args.boolean_corrections,
                "exclusive_corrections": args.exclusive_corrections,
                "demand_guards": args.demand_guards,
                "complete_guard_trace": not args.demand_guards,
                "skipped_guards": sum(row.skipped_guards for row in rows),
                "cofactor_fields": args.cofactor_fields,
                "cofactor_nodes": sum(row.cofactor_nodes for row in rows),
                "scheduler_retries": sum(row.scheduler_retries for row in rows),
                "square_shortcuts": args.square_shortcuts,
                "small_product_shortcuts": args.small_product_shortcuts,
                "category_lifts": args.category_lifts,
                "structural_guards": args.structural_guards,
                "structurally_settled_guards": sum(row.structurally_settled_guards for row in rows),
                "structurally_settled_lifts": sum(row.structurally_settled_lifts for row in rows),
                "constant_product_rules": sum(row.constant_product_rules for row in rows),
                "square_rules": sum(row.square_rules for row in rows),
                "square_lift_queries": sum(row.square_lift_queries for row in rows),
                "max_terms": args.max_terms,
                "source_sha256": hashes,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
