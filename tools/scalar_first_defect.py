"""Shared exact first-defect predicates in canonical point coordinates.

Research only. Covers intermediate stages1..158, both branches, arbitrary
uint160 entry states. Coefficient expansions are UNREDUCED by the differential
curve relation. Tag predicates are valid until the first correction, where
evaluation MUST stop. This is not a complete compact scalar algorithm.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field as dataclass_field
from functools import lru_cache
from types import ModuleType

from s7commplus.session_auth.family0._generated.data import TRANSFORM12_BIG_INT_DATA
from tools import scalar_representative_rules as rules
from tools import scalar_lift_categories as categories
from tools import scalar_constant_lifts as constant_lifts
from tools.decompile_transform12 import Operand
from tools.prove_scalar_predicate_guards import compile_guard
from tools.recover_scalar_encodings import recover_all
from tools.recover_scalar_shadow import Polynomial, add, evaluate, multiply
from tools.recover_transform12_phase1 import recover as stages
from tools.scalar_predicate_dag import Backend, Expr
from tools.scalar_raw_bound_dag import Graph as RawBoundGraph
from tools.scalar_raw_bound_polynomials import Catalogue as RawBoundCatalogue
from tools.scalar_stage_plan import carry_safe, constant
from tools.scalar_structural_guards import analyze
from tools.trace_scalar_defects import Defect
from tools.transform12_integer_model import LIMIT, decode
from tools.transform12_residue_defects import ADD_DEFECT, P

Coefficients = tuple[tuple[tuple[int, ...], int], ...]


@dataclass(frozen=True)
class Guard:
    tape_index: int
    operation: str
    fields: tuple[int, int]
    tags: tuple[int, int]
    predicate: int
    raw_bound: int | None = None


@dataclass(frozen=True)
class Layout:
    slots: tuple[int, ...]
    decoder: tuple[Coefficients, ...]
    encoded_inputs: tuple[int, ...]


@dataclass
class Catalogue:
    fields: tuple[Coefficients, ...]
    backend: Backend
    layouts: dict[int, Layout]
    guards: dict[tuple[int, int], tuple[Guard, ...]]
    structural_guards: bool = False
    bounds: RawBoundCatalogue | None = None
    tag_bounds: dict[tuple[int, int], dict[int, tuple[int, int]]] = dataclass_field(default_factory=dict)

    def summary(self) -> dict[str, object]:
        entries = [g for branch in self.guards.values() for g in branch]
        field_pairs = {(g.operation, g.fields if g.operation == "subtract" else tuple(sorted(g.fields))) for g in entries}
        predicates = {g.predicate for g in entries}
        return {
            "scope": "exact FIRST defect only; intermediate stages1..158; arbitrary entry states; no curve assumption",
            "branches": len(self.guards),
            "guard_sites": len(entries),
            "distinct_field_pairs": len(field_pairs),
            "distinct_complete_predicates": len(predicates),
            "predicate_equations": len(self.backend.nodes),
            "field_polynomials": len(self.fields),
            "constant_false_sites": sum(
                self.backend.nodes[g.predicate].operation == "boolean" and self.backend.nodes[g.predicate].arguments == (0,)
                for g in entries
            ),
            "whole_runtime_equivalence": False,
            "structural_guards": self.structural_guards,
            "entry_raw_bounds": self.bounds is not None,
            "raw_bound_polynomials": len(self.bounds.polynomials) if self.bounds is not None else 0,
            "raw_bound_monomials": sum(map(len, self.bounds.polynomials)) if self.bounds is not None else 0,
        }

    def first_defect(self, index: int, state: dict[int, int], bit: int) -> Defect | None:
        if type(index) is not int or index not in self.layouts or type(bit) is not int or bit not in (0, 1):
            raise ValueError("intermediate stage1..158 and branch0/1 required")
        layout = self.layouts[index]
        if set(state) != set(layout.slots) | {94}:
            raise ValueError("stage input layout mismatch")
        if any(type(v) is not int or not 0 <= v < LIMIT for v in state.values()):
            raise ValueError("unsigned160 entry values required")
        state = dict(state)  # Freeze the entry used by decoder and raw-bound facts.
        incoming = tuple(state[s] % P for s in layout.slots)
        point: tuple[int, ...]
        if index == 1:
            a, b, c, d = incoming
            point = (b, (a - d * d) % P, (c - d) % P, d, state[94] % P)
        else:
            point = tuple(evaluate(dict(poly), incoming) for poly in layout.decoder) + (state[94] % P,)
        values: dict[int, int] = {}

        def field(variable: int) -> int:
            if variable not in values:
                values[variable] = evaluate(dict(self.fields[variable]), point)
            return values[variable]

        if any(field(f) != r for f, r in zip(layout.encoded_inputs, incoming + (state[94] % P,))):
            raise ValueError("entry decoder/encoder composition failed")
        lifts = tuple(state[s] >= P for s in layout.slots + (94,))
        cache: dict[int, int | bool] = {}
        bound_cache: dict[int, bool] = {}

        def raw_large(root: int) -> bool:
            if self.bounds is None:
                raise ValueError("raw-bound catalogue required")
            if root not in bound_cache:
                bound_cache[root] = self.bounds.evaluate(root, tuple(state[s] for s in layout.slots + (94,))) >= 47
            return bound_cache[root]

        tag_bounds = self.tag_bounds.get((index, bit), {})

        def override(node: int) -> bool | None:
            if node in tag_bounds:
                bound, output_field = tag_bounds[node]
                if raw_large(bound):
                    return field(output_field) <= 46
            return None

        for guard in self.guards[index, bit]:
            if guard.raw_bound is not None and raw_large(guard.raw_bound):
                continue
            if not self.backend.evaluate(guard.predicate, field, lifts, cache, override_lookup=override):
                continue
            a, b = (field(f) for f in guard.fields)
            ta, tb = (bool(self.backend.evaluate(t, field, lifts, cache, override_lookup=override)) for t in guard.tags)
            raw = a + P * ta, b + P * tb
            if guard.operation == "add":
                correction = ADD_DEFECT
                representative = (a + b + correction) % P
            else:
                correction = 47
                representative = (a - b + correction) % P + P
            return Defect(index, bit, guard.tape_index, guard.operation, raw, representative, correction)
        return None


@lru_cache(maxsize=3, typed=True)
def compile_catalogue(*, structural_guards: bool = False, entry_bounds: bool = False) -> Catalogue:
    if type(structural_guards) is not bool or type(entry_bounds) is not bool:
        raise ValueError("Boolean structural guard mode required")
    if entry_bounds and not structural_guards:
        raise ValueError("entry bounds require structural guard mode")
    backend = Backend()
    fields: list[Coefficients] = []
    interned: dict[Coefficients, int] = {}
    layouts: dict[int, Layout] = {}
    guards: dict[tuple[int, int], tuple[Guard, ...]] = {}
    tag_bounds: dict[tuple[int, int], dict[int, tuple[int, int]]] = {}
    encodings = recover_all()
    bound_graph = RawBoundGraph()
    bound_values: dict[tuple[int, int], dict[int, int]] = {}
    if entry_bounds:
        for row in encodings:
            stage = stages()[row.stage]
            slots = tuple(sorted(s for s in stage.inputs if s != 94)) + (94,)
            for bit, program in enumerate(stage.choices):
                bound_values[row.stage, bit] = bound_graph.compile(program, slots, constant)
    bounds = RawBoundCatalogue(bound_graph) if entry_bounds else None

    def field_id(poly: Polynomial) -> int:
        # Equality compares complete canonical coefficients, NOT only a hash.
        key = tuple(sorted(poly.items()))
        if key not in interned:
            interned[key] = len(fields)
            fields.append(key)
        return interned[key]

    def expression(poly: Polynomial) -> Expr:
        if not poly or all(not any(powers) for powers in poly):
            return backend.expression(sum(poly.values()) % P, "number")
        return backend.field(field_id(poly))

    def predicate(name: str, inputs: dict[str, Expr], module: ModuleType = rules) -> Expr:
        result = compile_guard(backend, name, inputs, module=module)
        if not backend.is_bool(result):
            raise ValueError("source predicate did not compile as Boolean")
        return result  # type: ignore[no-any-return]

    for row in encodings:
        stage = stages()[row.stage]
        slots = tuple(sorted(s for s in stage.inputs if s != 94))
        decoder = () if row.stage == 1 else tuple(tuple(sorted(poly.items())) for poly in encodings[row.stage - 2].decoder)
        layouts[row.stage] = Layout(slots, decoder, tuple(field_id(row.inputs[s]) for s in slots + (94,)))
        for bit, program in enumerate(stage.choices):
            structural = analyze(program, constant) if structural_guards else None
            values: dict[int, Polynomial] = {}
            tags: dict[int, Expr] = {}
            entries: list[Guard] = []

            def raw_bound(operand: Operand) -> int | None:
                if bounds is None:
                    return None
                if operand.kind == "value":
                    node = bound_values[row.stage, bit][operand.index]
                elif operand.kind == "input":
                    node = bound_graph.input((slots + (94,)).index(operand.index))
                else:
                    return None
                root = bounds.roots[node]
                polynomial = bounds.polynomials[root]
                if not polynomial or all(not any(powers) for powers, _ in polynomial):
                    return None
                return root

            def resolve(operand: Operand) -> tuple[Polynomial, Expr]:
                if operand.kind == "value":
                    return values[operand.index], tags[operand.index]
                if operand.kind == "input":
                    return row.inputs[operand.index], backend.lift((slots + (94,)).index(operand.index))
                raw = decode(TRANSFORM12_BIG_INT_DATA[operand.index * 24 : operand.index * 24 + 24])
                return ({(0,) * 5: raw % P} if raw % P else {}), backend.expression(raw >= P, "boolean")

            for instruction in program.instructions:
                pa, ta = resolve(instruction.operands[0])
                pb, tb = resolve(instruction.operands[-1])
                a, b = expression(pa), expression(pb)
                inputs = {"a": a, "b": b, "lift_a": ta, "lift_b": tb}
                op = instruction.operation
                if op in ("add", "subtract"):
                    poly = add(pa, pb, -1 if op == "subtract" else 1)
                    if not carry_safe(instruction) and not (
                        structural is not None
                        and (instruction.value in structural.safe or instruction.value in structural.dominated)
                    ):
                        delta = predicate(f"lazy_{'addition' if op == 'add' else 'subtraction'}_defect", inputs)
                        entries.append(
                            Guard(
                                instruction.tape_index,
                                op,
                                (field_id(pa), field_id(pb)),
                                (ta.index, tb.index),
                                delta.index,
                                raw_bound(instruction.operands[0]) if op == "subtract" else None,
                            )
                        )
                    if structural is not None and structural.lower_bounds[instruction.value] >= 47:
                        tag = expression(poly) <= 46
                    else:
                        tag = backend.And(
                            expression(poly) <= 46,
                            predicate(
                                f"small_{'addition' if op == 'add' else 'subtraction'}_lift",
                                inputs | {"defective": backend.expression(False, "boolean")},
                                categories,
                            ),
                        )
                elif op in ("multiply", "square"):
                    poly = multiply(pa, pb, 16384)
                    output = expression(poly)
                    if structural is not None and structural.lower_bounds[instruction.value] >= 47:
                        tag = output <= 46
                    elif structural is not None and op == "multiply" and any(o.kind == "constant" for o in instruction.operands):
                        const, other_a, other_tag = (
                            (instruction.operands[0], b, tb)
                            if instruction.operands[0].kind == "constant"
                            else (instruction.operands[-1], a, ta)
                        )
                        raw_constant = constant(const)
                        tag = (
                            backend.And(
                                output <= 46,
                                predicate(
                                    "lift",
                                    {
                                        "a": other_a,
                                        "cutoff": backend.expression(constant_lifts.threshold(raw_constant), "number"),
                                        "lift_a": other_tag,
                                    },
                                    constant_lifts,
                                ),
                            )
                            if raw_constant
                            else backend.expression(False, "boolean")
                        )
                    elif op == "square" or structural is not None and instruction.operands[0] == instruction.operands[-1]:
                        tag = backend.And(output <= 46, predicate("square_lift", {"a": a, "lift_a": ta}))
                    else:
                        positive_a = backend.Or(backend.Not(a == 0), ta)
                        positive_b = backend.Or(backend.Not(b == 0), tb)
                        nonzero_tag = predicate("small_nonzero_product_lift", inputs)
                        # With zero residue a positive raw product is a
                        # positive multiple of p, hence already crosses p.
                        zero_tag = backend.And(positive_a, positive_b)
                        tag = backend.And(
                            output <= 46,
                            backend.Or(backend.And(output == 0, zero_tag), backend.And(backend.Not(output == 0), nonzero_tag)),
                        )
                else:
                    raise ValueError("unsupported source operation")
                bound = raw_bound(Operand("value", instruction.value))
                if bound is not None and backend.nodes[tag.index].operation != "boolean":
                    # Facts belong to this source branch, even when the tag
                    # formula is shared globally. Never transfer raw bounds
                    # from another stage's encoding through an equal tag root.
                    tag_bounds.setdefault((row.stage, bit), {}).setdefault(tag.index, (bound, field_id(poly)))
                values[instruction.value], tags[instruction.value] = poly, tag
            guards[row.stage, bit] = tuple(entries)
    return Catalogue(tuple(fields), backend, layouts, guards, structural_guards, bounds, tag_bounds)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--structural-guards", action="store_true", help="exclude guards that cannot be the first defect")
    parser.add_argument("--entry-bounds", action="store_true", help="use shared saturated raw-bound polynomials")
    args = parser.parse_args()
    if args.entry_bounds and not args.structural_guards:
        parser.error("--entry-bounds requires --structural-guards")
    print(
        json.dumps(
            compile_catalogue(structural_guards=args.structural_guards, entry_bounds=args.entry_bounds).summary(), indent=2
        )
    )


if __name__ == "__main__":
    main()
