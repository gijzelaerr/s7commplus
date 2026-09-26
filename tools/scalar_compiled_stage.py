"""Complete scalar-stage field/carry/lift equations, without source replay.

Research only. Compile recovered SSA once into immutable field polynomials and
actual helper-AST Boolean equations. Evaluation receives no Program, Instruction,
constant table or arithmetic helper. Includes post-defect interactions, not
just a first-defect prefix. Still source-specific formula DATA, not a recovered
compact curve ladder, generated-kernel SMT proof or runtime replacement.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from functools import lru_cache
from types import ModuleType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tools.scalar_field_circuit import Kernel
    from tools.verify_scalar_compiled_stage import Verification

from tools import scalar_constant_lifts as constants
from tools import scalar_lift_categories as categories
from tools import scalar_representative_rules as rules
from tools import scalar_stage_plan as compiler
from tools.decompile_transform12 import Operand, Program
from tools.prove_scalar_predicate_guards import compile_guard
from tools.scalar_predicate_dag import Backend, Expr
from tools.trace_scalar_defects import Defect
from tools.verify_scalar_stage_algebra import Certificate, verify

P = rules.MODULUS
Terms = tuple[tuple[compiler.Monomial, int], ...]


@dataclass(frozen=True)
class Variable:
    kind: str  # input ordinal, correction ordinal, anchor field ordinal
    index: int


@dataclass(frozen=True)
class Guard:
    value: int
    tape_index: int
    operation: str
    correction: int
    fields: tuple[int, int]
    tags: tuple[int, int]
    predicate: int


@dataclass(frozen=True)
class Site:
    value: int
    field: int
    tag: int


@dataclass(frozen=True)
class Stage:
    input_slots: tuple[int, ...]
    variables: tuple[Variable, ...]
    fields: tuple[Terms, ...]
    predicates: Backend
    guards: tuple[Guard, ...]
    outputs: tuple[tuple[int, int, int], ...]  # slot, field ordinal, tag root
    certificate: Certificate | None
    boolean_corrections: bool
    exclusive_corrections: bool
    sites: tuple[Site, ...]
    max_terms: int
    field_kernel_required: bool = False


@dataclass(frozen=True)
class Evaluation:
    outputs: dict[int, int]
    defects: tuple[Defect, ...]
    fields_evaluated: int
    anchors_evaluated: int
    predicate_nodes_evaluated: int


@dataclass(frozen=True)
class Catalogue:
    choices: tuple[tuple[Stage, Stage], ...]
    tail: Stage
    verifications: tuple[Verification, ...] = ()


@lru_cache(maxsize=4, typed=True)
def compile_stage(
    source: Program,
    max_terms: int = 256,
    *,
    boolean_corrections: bool = True,
    exclusive_corrections: bool = False,
    verify_algebra: bool = False,
) -> Stage:
    if type(verify_algebra) is not bool:
        raise ValueError("Boolean algebra-verification mode required")
    plan = compiler.compile_plan(
        source, max_terms, boolean_corrections=boolean_corrections, exclusive_corrections=exclusive_corrections
    )
    certificate = (
        verify(plan, source, boolean_corrections=boolean_corrections, exclusive_corrections=exclusive_corrections)
        if verify_algebra
        else None
    )
    backend = Backend()
    fields: list[Terms] = []
    interned: dict[Terms, int] = {}

    def field_id(poly: compiler.Polynomial) -> int:
        key = tuple(sorted(poly.items()))
        if key not in interned:
            interned[key] = len(fields)
            fields.append(key)
        return interned[key]

    def expression(index: int) -> Expr:
        poly = fields[index]
        if not poly or all(not powers for powers, _ in poly):
            return backend.expression(sum(c for _, c in poly) % P, "number")
        return backend.field(index)

    inputs = {slot: i for i, slot in enumerate(plan.input_slots)}
    input_fields = {b.index: field_id(compiler.variable(i)) for i, b in enumerate(plan.bindings) if b.kind == "input"}
    value_fields = {value: field_id(poly) for value, poly in plan.fields.items()}
    value_tags: dict[int, Expr] = {}
    guard_values = {g.instruction.value for g in plan.guards}
    guards: list[Guard] = []

    def resolve(operand: Operand) -> tuple[int, Expr]:
        if operand.kind == "value":
            return value_fields[operand.index], value_tags[operand.index]
        if operand.kind == "input":
            return input_fields[operand.index], backend.lift(inputs[operand.index])
        raw = compiler.constant(operand)
        return field_id(compiler.fixed(raw)), backend.expression(raw >= P, "boolean")

    def predicate(name: str, symbols: dict[str, Expr], module: ModuleType = rules) -> Expr:
        result = compile_guard(backend, name, symbols, module=module)
        if not backend.is_bool(result):
            raise ValueError("compiled lift/carry predicate must be Boolean")
        return result  # type: ignore[no-any-return]

    for instruction in source.instructions:
        first, last = instruction.operands[0], instruction.operands[-1]
        fa, ta = resolve(first)
        fb, tb = resolve(last)
        a, b = expression(fa), expression(fb)
        output = expression(value_fields[instruction.value])
        symbols = {"a": a, "b": b, "lift_a": ta, "lift_b": tb}
        defective = backend.expression(False, "boolean")
        if instruction.value in guard_values:
            name = "lazy_addition_defect" if instruction.operation == "add" else "lazy_subtraction_defect"
            defective = predicate(name, symbols)
            guards.append(
                Guard(
                    instruction.value,
                    instruction.tape_index,
                    instruction.operation,
                    compiler.arithmetic_correction(instruction.operation),
                    (fa, fb),
                    (ta.index, tb.index),
                    defective.index,
                )
            )
        if instruction.operation in ("add", "subtract"):
            name = "small_addition_lift" if instruction.operation == "add" else "small_subtraction_lift"
            tag = predicate(name, symbols | {"defective": defective}, categories)
        elif instruction.operation in ("multiply", "square"):
            if first.kind == "constant" or last.kind == "constant":
                raw_constant = compiler.constant(first if first.kind == "constant" else last)
                other, other_tag = (b, tb) if first.kind == "constant" else (a, ta)
                tag = (
                    predicate(
                        "lift",
                        {
                            "a": other,
                            "cutoff": backend.expression(constants.threshold(raw_constant), "number"),
                            "lift_a": other_tag,
                        },
                        constants,
                    )
                    if raw_constant
                    else backend.expression(False, "boolean")
                )
            elif first == last:
                tag = predicate("square_lift", {"a": a, "lift_a": ta})
            else:
                positive = backend.And(backend.Or(backend.Not(a == 0), ta), backend.Or(backend.Not(b == 0), tb))
                nonzero = predicate("small_nonzero_product_lift", symbols)
                tag = backend.Or(backend.And(output == 0, positive), backend.And(backend.Not(output == 0), nonzero))
        else:
            raise ValueError("unsupported source arithmetic")
        value_tags[instruction.value] = backend.And(output <= 46, tag)

    guard_ordinals = {g.value: i for i, g in enumerate(guards)}
    variables = tuple(
        Variable(
            b.kind,
            inputs[b.index]
            if b.kind == "input"
            else guard_ordinals[b.index]
            if b.kind == "correction"
            else field_id(plan.anchors[b.index]),
        )
        for b in plan.bindings
    )
    outputs = tuple((slot, field, tag.index) for slot, operand in source.outputs for field, tag in (resolve(operand),))
    return Stage(
        plan.input_slots,
        variables,
        tuple(fields),
        backend,
        tuple(guards),
        outputs,
        certificate,
        boolean_corrections,
        exclusive_corrections,
        tuple(Site(i.value, value_fields[i.value], value_tags[i.value].index) for i in source.instructions),
        max_terms,
    )


def evaluate(
    stage: Stage, state: dict[int, int], index: int = 160, bit: int = 0, *, field_kernel: Kernel | None = None
) -> Evaluation:
    """Full correction trace and exact raw outputs, using equations only.

    Guards are finalized in source causal order. A field/anchor may read only
    earlier finalized corrections; no polynomial repairs or tag callbacks.
    Anchor scheduling and Boolean evaluation are iterative, including cap2 tail.
    A separately coefficient-verified field kernel can replace polynomial data.
    """
    if type(bit) is not int or bit not in (0, 1) or set(state) != set(stage.input_slots):
        raise ValueError("stage input layout or branch mismatch")
    if type(stage.field_kernel_required) is not bool or stage.field_kernel_required and field_kernel is None:
        raise ValueError("externally stored field equations require their field kernel")
    raw = tuple(state[slot] for slot in stage.input_slots)
    if any(type(v) is not int or not 0 <= v < 1 << 160 for v in raw):
        raise ValueError("uint160 raw entry values required")
    inputs = tuple(v % P for v in raw)
    lifts = tuple(v >= P for v in raw)
    corrections: list[int] = []
    variable_cache: dict[int, int] = {}
    field_cache: dict[int, int] = {}
    predicate_cache: dict[int, int | bool] = {}
    circuit_cache: dict[int, int] = {}
    anchors = 0
    if field_kernel is not None and len(field_kernel.roots) != len(stage.fields):
        raise ValueError("field kernel root inventory mismatch")

    class NeedVariable(Exception):
        def __init__(self, ordinal: int) -> None:
            self.ordinal = ordinal

    def formula(ordinal: int) -> int:
        if field_kernel is not None:
            from tools.scalar_field_circuit import evaluate as circuit_evaluate

            def binding(variable: int) -> int:
                if variable not in variable_cache:
                    raise NeedVariable(variable)
                return variable_cache[variable]

            return circuit_evaluate(field_kernel.circuit, field_kernel.roots[ordinal], binding, circuit_cache)
        total = 0
        for monomial, coefficient in stage.fields[ordinal]:
            term = coefficient
            for variable, power in monomial:
                if variable not in variable_cache:
                    raise NeedVariable(variable)
                term = term * pow(variable_cache[variable], power, P) % P
                if term == 0:
                    break
            total += term
        return total % P

    def variable_value(root: int) -> None:
        nonlocal anchors
        pending = [root]
        while pending:
            ordinal = pending[-1]
            if ordinal in variable_cache:
                pending.pop()
                continue
            variable = stage.variables[ordinal]
            if variable.kind == "input":
                value = inputs[variable.index]
            elif variable.kind == "correction":
                if variable.index >= len(corrections):
                    raise ValueError("equation reads an unresolved correction")
                value = corrections[variable.index] % P
            elif variable.kind == "anchor":
                try:
                    value = formula(variable.index)
                except NeedVariable as needed:
                    if needed.ordinal >= ordinal:
                        raise ValueError("anchor equation reads a future or cyclic variable") from None
                    pending.append(needed.ordinal)
                    continue
                anchors += 1
            else:
                raise ValueError("unsupported compiled variable")
            variable_cache[ordinal] = value

    def field(ordinal: int) -> int:
        if ordinal not in field_cache:
            while True:
                try:
                    field_cache[ordinal] = formula(ordinal)
                    break
                except NeedVariable as needed:
                    variable_value(needed.ordinal)
        return field_cache[ordinal]

    def boolean(root: int) -> bool:
        value = stage.predicates.evaluate(root, field, lifts, predicate_cache)
        if type(value) is not bool:
            raise ValueError("compiled carry/lift equation returned a non-Boolean")
        return value

    events = []
    for guard in stage.guards:
        correction = guard.correction if boolean(guard.predicate) else 0
        if correction:
            a, b = (field(f) for f in guard.fields)
            ta, tb = (boolean(t) for t in guard.tags)
            operands = a + P * ta, b + P * tb
            result = (a + b + correction) % P if guard.operation == "add" else (a - b + correction) % P + P
            events.append(Defect(index, bit, guard.tape_index, guard.operation, operands, result, correction))
        corrections.append(correction)
    outputs = {slot: field(f) + P * boolean(tag) for slot, f, tag in stage.outputs}
    return Evaluation(outputs, tuple(events), len(field_cache), anchors, len(predicate_cache))


def compile_catalogue(
    max_terms: int = 256, *, boolean_corrections: bool = True, exclusive_corrections: bool = False, verify_data: bool = False
) -> Catalogue:
    """Offline/source compilation; the returned catalogue contains no SSA."""
    from tools.recover_transform12_phase1 import recover
    from tools.transform7_reference import tail_program

    if type(verify_data) is not bool:
        raise ValueError("Boolean data-verification mode required")
    certificates = []

    def compiled(source: Program) -> Stage:
        stage = compile_stage(
            source, max_terms, boolean_corrections=boolean_corrections, exclusive_corrections=exclusive_corrections
        )
        if verify_data:
            from tools.verify_scalar_compiled_stage import verify

            certificates.append(verify(stage, source))
        return stage

    choices = tuple((compiled(row.choices[0]), compiled(row.choices[1])) for row in recover())
    return Catalogue(choices, compiled(tail_program()), tuple(certificates))


def full_output(catalogue: Catalogue, x: int, y: int, prng1: int, scalar: int) -> tuple[bytes, tuple[Evaluation, ...]]:
    """Exact full-output research model after offline stage compilation."""
    from tools.transform7_setup_integer import model as setup
    from tools.transform7_reference import finalize

    if any(type(v) is not int or not 0 <= v < 1 << 160 for v in (x, y, prng1, scalar)):
        raise ValueError("four uint160 synthetic/public inputs required")
    if len(catalogue.choices) != 160 or catalogue.choices[0][0].input_slots != (46, 48, 70, 94):
        raise ValueError("complete pinned scalar-stage catalogue required")
    state = dict(zip(catalogue.choices[0][0].input_slots, setup(x, y, prng1).slots))
    rows = []
    for index, choices in enumerate(catalogue.choices):
        bit = scalar >> (159 - index) & 1
        row = evaluate(choices[bit], state, index, bit)
        state = row.outputs
        rows.append(row)
    tail = evaluate(catalogue.tail, state)
    return finalize(tail.outputs), tuple(rows) + (tail,)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-terms", type=int, default=256)
    parser.add_argument("--effective-scalar", type=lambda v: int(v, 0), default=0)
    parser.add_argument("--prng1", type=lambda v: int(v, 0), default=0)
    parser.add_argument("--verify-data", action="store_true", help="independently validate all actual compiled equation data")
    parser.add_argument("--exclusive-corrections", action="store_true", help="use source-proved joint correction domains")
    args = parser.parse_args()
    if args.max_terms < 2 or not 0 <= args.effective_scalar < 1 << 160 or not 0 <= args.prng1 < 1 << 160:
        parser.error("unsigned160 synthetic parameters and term bound>=2 required")
    from s7commplus.session_auth.family0._generated.data import TRANSFORM7_DATA
    from tools.recover_scalar_encodings import scalar_xor_mask

    catalogue = compile_catalogue(args.max_terms, exclusive_corrections=args.exclusive_corrections, verify_data=args.verify_data)
    x, y = (int.from_bytes(TRANSFORM7_DATA[o : o + 20], "little") for o in (0xD8, 0xEC))
    output, rows = full_output(catalogue, x, y, args.prng1, args.effective_scalar ^ scalar_xor_mask())
    print(
        json.dumps(
            {
                "scope": "complete source-specific compiled field/carry/lift equations; public synthetic case; NOT compact independent curve algorithm or packed-kernel/whole-pipeline SMT proof",
                "source_instruction_replay": False,
                "runtime_arithmetic_or_tag_callbacks": False,
                "runtime_source_constant_lookup": False,
                "complete_guard_trace": True,
                "destination_hex": output.hex(),
                "boundaries": len(rows),
                "defects": len([e for row in rows for e in row.defects]),
                "verified_programs": len(catalogue.verifications),
                "field_identities": sum(v.coefficients.field_identities for v in catalogue.verifications),
                "carry_contracts": sum(v.carry_contracts for v in catalogue.verifications),
                "lift_contracts": sum(v.lift_contracts for v in catalogue.verifications),
                "fields_evaluated": sum(r.fields_evaluated for r in rows),
                "anchors_evaluated": sum(r.anchors_evaluated for r in rows),
                "predicate_nodes_evaluated": sum(r.predicate_nodes_evaluated for r in rows),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
