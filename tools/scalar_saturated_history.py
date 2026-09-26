"""Exact scalar carry history in a 48-state saturated raw semiring.

Write mu=raw mod p and s=min(raw,47). The lift is exactly mu<=46 and s=47.
Unlike raw lower bounds, these saturation equations are exact. Addition and
multiplication become saturated + and *; only subtraction needs field cuts.
Numerical evaluation retains no source program, Boolean lift DAG or helpers.
Research only: the field plane and subtraction cuts remain stage-specific.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass

from tools import scalar_compiled_stage as compiled
from tools import scalar_stage_plan as compiler
from tools.decompile_transform12 import Operand, Program
from tools.scalar_representative_rules import MODULUS as P
from tools.trace_scalar_defects import Defect

LOW = 1 << 128


def addition_carry(a: int, b: int, wide_a: Callable[[], bool], wide_b: Callable[[], bool]) -> bool:
    """Canonical residues; callbacks observe exact raw saturation47."""
    return (
        a + b >= P + 47
        and (a + b) % LOW >= LOW - 47
        or 47 <= a + b <= 92
        and a <= 46
        and b <= 46
        and wide_a()
        and wide_b()
        or a + b >= LOW
        and (a + b) % LOW < 47
        and (a <= 46 and wide_a() or b <= 46 and wide_b())
    )


def subtraction_carry(a: int, b: int, wide_a: Callable[[], bool], wide_b: Callable[[], bool]) -> bool:
    """The left operand must be raw-small, the right p-lifted-small."""
    return a < b <= 46 and not wide_a() and wide_b()


def subtraction_small_lift(a: int, b: int, sa: int, sb: int) -> bool:
    """Conditional on the corrected subtraction residue being at most46."""
    return a <= 46 and b <= 46 and (sa == 47 and sb < 47 or a < b and sa < 47 and sb == 47)


def product(factors: tuple[int, ...]) -> int:
    """Collapse any multiplication/square tree to one exact raw product.

    Source-AST primitive saturation/residue identities plus associativity in
    the two rings prove the induction. No huge unfurled integer, prime, source
    arithmetic or representation-history tree is needed. Empty product is1.
    """
    if any(type(v) is not int or not 0 <= v < 1 << 160 for v in factors):
        raise ValueError("uint160 raw factors required")
    residue, saturated = 1, 1
    for raw in factors:
        residue = residue * (raw % P) % P
        saturated = min(saturated * min(raw, 47), 47)
    return residue + P * (residue <= 46 and saturated == 47)


@dataclass(frozen=True)
class Node:
    operation: str
    arguments: tuple[int, ...]


class Builder:
    def __init__(self) -> None:
        self.nodes: list[Node] = []
        self.interned: dict[Node, int] = {}

    def node(self, op: str, args: tuple[int, ...]) -> int:
        key = Node(op, args)
        if key not in self.interned:
            self.interned[key] = len(self.nodes)
            self.nodes.append(key)
        return self.interned[key]

    def literal(self, value: int) -> int:
        return self.node("literal", (min(value, 47),))

    def combine(self, op: str, a: int, b: int) -> int:
        an, bn = self.nodes[a], self.nodes[b]
        ac = an.arguments[0] if an.operation == "literal" else None
        bc = bn.arguments[0] if bn.operation == "literal" else None
        if ac is not None and bc is not None:
            return self.literal(ac + bc if op == "add" else ac * bc)
        if op == "add":
            if 47 in (ac, bc):
                return self.literal(47)
            if ac == 0 or bc == 0:
                return b if ac == 0 else a
        else:
            if 0 in (ac, bc):
                return self.literal(0)
            if ac == 1 or bc == 1:
                return b if ac == 1 else a
        return self.node(op, tuple(sorted((a, b))))


@dataclass(frozen=True)
class Guard:
    value: int
    tape_index: int
    operation: str
    correction: int
    fields: tuple[int, int]
    saturations: tuple[int, int]


@dataclass(frozen=True)
class Stage:
    input_slots: tuple[int, ...]
    variables: tuple[compiled.Variable, ...]
    fields: tuple[compiled.Terms, ...]
    nodes: tuple[Node, ...]
    guards: tuple[Guard, ...]
    outputs: tuple[tuple[int, int, int], ...]
    site_saturations: tuple[int, ...]  # actual-data verification inventory


def lower(source: Program, original: compiled.Stage, builder: Builder | None = None) -> Stage:
    """Compile saturation equations; source/old Boolean data are not retained."""
    if original.field_kernel_required or tuple(s.value for s in original.sites) != tuple(i.value for i in source.instructions):
        raise ValueError("complete original field-plane witness required")
    graph = Builder() if builder is None else builder
    inputs = {slot: graph.node("input", (i,)) for i, slot in enumerate(original.input_slots)}
    field_ids = {site.value: site.field for site in original.sites}
    values: dict[int, int] = {}
    fields = {poly: i for i, poly in enumerate(original.fields)}

    def saturation(operand: Operand) -> int:
        if operand.kind == "input":
            return inputs[operand.index]
        if operand.kind == "value":
            return values[operand.index]
        return graph.literal(compiler.constant(operand))

    def field(operand: Operand) -> int:
        if operand.kind == "value":
            return field_ids[operand.index]
        if operand.kind == "constant":
            poly = compiler.fixed(compiler.constant(operand))
        else:
            ordinal = next(
                i
                for i, binding in enumerate(original.variables)
                if binding.kind == "input" and original.input_slots[binding.index] == operand.index
            )
            poly = compiler.variable(ordinal)
        return fields[tuple(sorted(poly.items()))]

    for instruction in source.instructions:
        first, last = instruction.operands[0], instruction.operands[-1]
        a, b = saturation(first), saturation(last)
        if instruction.operation == "subtract":
            an, bn = graph.nodes[a], graph.nodes[b]
            ac = an.arguments[0] if an.operation == "literal" else None
            bc = bn.arguments[0] if bn.operation == "literal" else None
            if first == last:
                root = graph.literal(0)
            elif bc == 0:
                root = a
            elif ac is not None and bc is not None and ac < 47 and bc < 47:
                root = graph.literal(ac - bc if ac >= bc else 47)
            elif a == b:
                root = graph.node("field", (field_ids[instruction.value],))
            elif any(o.kind == "constant" and 47 <= compiler.constant(o) < P for o in (first, last)):
                root = graph.node("field", (field_ids[instruction.value],))
            else:
                root = graph.node("subtract", (field_ids[instruction.value], field(first), field(last), a, b))
        elif instruction.operation in ("add", "multiply", "square"):
            root = graph.combine("add" if instruction.operation == "add" else "multiply", a, b)
        else:
            raise ValueError("unsupported source operation")
        values[instruction.value] = root
    instructions = {i.value: i for i in source.instructions}
    guards = tuple(
        Guard(
            g.value,
            g.tape_index,
            g.operation,
            g.correction,
            g.fields,
            tuple(saturation(o) for o in instructions[g.value].operands),  # type: ignore[arg-type]
        )
        for g in original.guards
    )
    original_fields = {slot: f for slot, f, _ in original.outputs}
    return Stage(
        original.input_slots,
        original.variables,
        original.fields,
        tuple(graph.nodes),
        guards,
        tuple((slot, original_fields[slot], saturation(operand)) for slot, operand in source.outputs),
        tuple(values[i.value] for i in source.instructions),
    )


def saturation_value(
    nodes: tuple[Node, ...], root: int, raw: tuple[int, ...], field: Callable[[int], int], cache: dict[int, int]
) -> int:
    """Iterative exact 0..47 evaluation; field cuts short-circuit when large."""
    pending = [root]
    while pending:
        index = pending[-1]
        if index in cache:
            pending.pop()
            continue
        node = nodes[index]
        op, args = node.operation, node.arguments
        if op == "literal":
            cache[index] = args[0]
        elif op == "input":
            cache[index] = min(raw[args[0]], 47)
        elif op == "field":
            cache[index] = min(field(args[0]), 47)
        elif op == "subtract":
            out, fa, fb, sa, sb = args
            residue = field(out)
            if residue >= 47:
                cache[index] = 47
                continue
            a, b = field(fa), field(fb)
            if a >= 47 or b >= 47:
                cache[index] = residue
                continue
            missing = next((c for c in (sa, sb) if c not in cache), None)
            if missing is not None:
                pending.append(missing)
            else:
                # Actual formula is also independently source-AST checked.
                lifted = subtraction_small_lift(a, b, cache[sa], cache[sb])
                cache[index] = 47 if lifted else residue
        elif op in ("add", "multiply"):
            a, b = args
            settled = 47 if op == "add" else 0
            if cache.get(a) == settled or cache.get(b) == settled:
                cache[index] = settled
                continue
            missing = next((c for c in args if c not in cache), None)
            if missing is not None:
                pending.append(missing)
            else:
                cache[index] = min(cache[a] + cache[b] if op == "add" else cache[a] * cache[b], 47)
        else:
            raise ValueError("unsupported saturation equation")
    return cache[root]


@dataclass(frozen=True)
class Evaluation:
    outputs: dict[int, int]
    defects: tuple[Defect, ...]
    fields_evaluated: int
    anchors_evaluated: int
    saturation_nodes_evaluated: int


def evaluate(stage: Stage, state: dict[int, int], index: int = 160, bit: int = 0) -> Evaluation:
    if type(bit) is not int or bit not in (0, 1) or set(state) != set(stage.input_slots):
        raise ValueError("stage input layout or branch mismatch")
    raw = tuple(state[s] for s in stage.input_slots)
    if any(type(v) is not int or not 0 <= v < 1 << 160 for v in raw):
        raise ValueError("uint160 raw entry values required")
    inputs = tuple(v % P for v in raw)
    corrections: list[int] = []
    variable_cache: dict[int, int] = {}
    field_cache: dict[int, int] = {}
    saturation_cache: dict[int, int] = {}
    anchors = 0

    class NeedVariable(Exception):
        def __init__(self, ordinal: int) -> None:
            self.ordinal = ordinal

    def formula(ordinal: int) -> int:
        result = 0
        for monomial, coefficient in stage.fields[ordinal]:
            term = coefficient
            for variable, power in monomial:
                if variable not in variable_cache:
                    raise NeedVariable(variable)
                term = term * pow(variable_cache[variable], power, P) % P
                if not term:
                    break
            result += term
        return result % P

    def variable_value(root: int) -> None:
        nonlocal anchors
        pending = [root]
        while pending:
            ordinal = pending[-1]
            if ordinal in variable_cache:
                pending.pop()
                continue
            binding = stage.variables[ordinal]
            if binding.kind == "input":
                value = inputs[binding.index]
            elif binding.kind == "correction":
                if binding.index >= len(corrections):
                    raise ValueError("equation reads an unresolved correction")
                value = corrections[binding.index] % P
            elif binding.kind == "anchor":
                try:
                    value = formula(binding.index)
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

    def sat(root: int) -> int:
        return saturation_value(stage.nodes, root, raw, field, saturation_cache)

    events = []
    for guard in stage.guards:
        a, b = (field(f) for f in guard.fields)
        sa, sb = guard.saturations
        if guard.operation == "subtract":
            defective = subtraction_carry(a, b, lambda: sat(sa) == 47, lambda: sat(sb) == 47)
        else:
            defective = addition_carry(a, b, lambda: sat(sa) == 47, lambda: sat(sb) == 47)
        correction = guard.correction if defective else 0
        if correction:
            operands = a + P * (a <= 46 and sat(sa) == 47), b + P * (b <= 46 and sat(sb) == 47)
            result = (a + b + correction) % P if guard.operation == "add" else (a - b + correction) % P + P
            events.append(Defect(index, bit, guard.tape_index, guard.operation, operands, result, correction))
        corrections.append(correction)
    outputs = {}
    for slot, ordinal, root in stage.outputs:
        residue = field(ordinal)
        outputs[slot] = residue + P * (residue <= 46 and sat(root) == 47)
    return Evaluation(outputs, tuple(events), len(field_cache), anchors, len(saturation_cache))


@dataclass(frozen=True)
class Certificate:
    source_values: int
    node_sha256: str


def verify(stage: Stage, source: Program, original: compiled.Stage) -> Certificate:
    """Check actual saturation DATA separately from the builder.

    The supplied field-plane witness is first independently checked against
    source. Source primitive identities justify the saturation transfer rules;
    the walk below checks their application and causal operand binding.
    """
    from tools.verify_scalar_compiled_stage import verify as verify_original

    verify_original(original, source)
    if (stage.input_slots, stage.variables, stage.fields) != (original.input_slots, original.variables, original.fields):
        raise ValueError("saturation field plane differs from verified witness")
    if len(stage.site_saturations) != len(source.instructions):
        raise ValueError("saturation source inventory mismatch")
    if len(stage.guards) != len(original.guards):
        raise ValueError("saturation carry inventory mismatch")
    nodes = stage.nodes
    lookup: dict[Node, int] = {}
    for index, node in enumerate(nodes):
        op, args = node.operation, node.arguments
        if any(type(a) is not int or a < 0 for a in args):
            raise ValueError("invalid saturation node arguments")
        children = args if op in ("add", "multiply") else args[3:] if op == "subtract" else ()
        if any(c >= index for c in children):
            raise ValueError("future or cyclic saturation edge")
        if (
            op == "literal"
            and (len(args) != 1 or args[0] > 47)
            or op == "input"
            and len(args) != 1
            or op == "field"
            and len(args) != 1
            or op == "subtract"
            and len(args) != 5
            or op in ("add", "multiply")
            and (len(args) != 2 or args != tuple(sorted(args)))
            or op not in ("literal", "input", "field", "subtract", "add", "multiply")
            or node in lookup
        ):
            raise ValueError("invalid or duplicate saturation node")
        lookup[node] = index

    # Shared field ordinals bind to each stage's own field plane. Templates
    # from other stages can have larger ordinals; validate this stage's layout
    # only at reachable leaves and cuts. All edges are checked above.
    pending = list(stage.site_saturations) + [r for g in stage.guards for r in g.saturations] + [r for _, _, r in stage.outputs]
    reachable: set[int] = set()
    while pending:
        root = pending.pop()
        if type(root) is not int or not 0 <= root < len(nodes):
            raise ValueError("undefined saturation root")
        if root in reachable:
            continue
        reachable.add(root)
        node = nodes[root]
        if node.operation in ("add", "multiply"):
            pending.extend(node.arguments)
        elif node.operation == "subtract":
            if any(f >= len(stage.fields) for f in node.arguments[:3]):
                raise ValueError("saturation subtraction field outside stage layout")
            pending.extend(node.arguments[3:])
        elif node.operation == "field" and node.arguments[0] >= len(stage.fields):
            raise ValueError("saturation field outside stage layout")
        elif node.operation == "input" and node.arguments[0] >= len(stage.input_slots):
            raise ValueError("saturation input outside stage layout")

    def find(op: str, args: tuple[int, ...]) -> int:
        if Node(op, args) not in lookup:
            raise ValueError("missing expected saturation equation")
        return lookup[Node(op, args)]

    def constant(o: Operand) -> int:
        # Independent constant decoder, not the saturation compiler helper.
        from s7commplus.session_auth.family0._generated.data import TRANSFORM12_BIG_INT_DATA
        from tools.transform12_integer_model import decode

        return decode(TRANSFORM12_BIG_INT_DATA[o.index * 24 : (o.index + 1) * 24])

    fields = {s.value: s.field for s in original.sites}
    values: dict[int, int] = {}
    slots = {slot: ordinal for ordinal, slot in enumerate(original.input_slots)}

    def resolve(o: Operand) -> int:
        if o.kind == "value":
            return values[o.index]
        return find("input", (slots[o.index],)) if o.kind == "input" else find("literal", (min(constant(o), 47),))

    def operand_field(o: Operand) -> int:
        if o.kind == "value":
            return fields[o.index]
        if o.kind == "constant":
            c = constant(o) % P
            terms: compiled.Terms = (((), c),) if c else ()
        else:
            ordinal = next(i for i, v in enumerate(original.variables) if v.kind == "input" and v.index == slots[o.index])
            terms = ((((ordinal, 1),), 1),)
        return original.fields.index(terms)

    def combine(op: str, left: int, right: int) -> int:
        # Independent local identity checker: only exact literal arithmetic,
        # absorbing values, units and commutativity. No builder/interner calls.
        a, b = nodes[left], nodes[right]
        ac = a.arguments[0] if a.operation == "literal" else None
        bc = b.arguments[0] if b.operation == "literal" else None
        if ac is not None and bc is not None:
            result = ac + bc if op == "add" else ac * bc
            return find("literal", (min(result, 47),))
        if op == "add" and (ac == 47 or bc == 47):
            return find("literal", (47,))
        if op == "multiply" and (ac == 0 or bc == 0):
            return find("literal", (0,))
        unit = 0 if op == "add" else 1
        if ac == unit:
            return right
        if bc == unit:
            return left
        return find(op, tuple(sorted((left, right))))

    for instruction, actual in zip(source.instructions, stage.site_saturations):
        first, last = instruction.operands[0], instruction.operands[-1]
        a, b = resolve(first), resolve(last)
        if instruction.operation == "subtract":
            left, right = nodes[a], nodes[b]
            ac = left.arguments[0] if left.operation == "literal" else None
            bc = right.arguments[0] if right.operation == "literal" else None
            if first == last:
                expected = find("literal", (0,))
            elif bc == 0:
                expected = a
            elif ac is not None and bc is not None and max(ac, bc) < 47:
                expected = find("literal", (ac - bc if ac >= bc else 47,))
            elif a == b:
                expected = find("field", (fields[instruction.value],))
            elif any(o.kind == "constant" and 47 <= constant(o) < P for o in (first, last)):
                expected = find("field", (fields[instruction.value],))
            else:
                expected = find("subtract", (fields[instruction.value], operand_field(first), operand_field(last), a, b))
        else:
            expected = combine("add" if instruction.operation == "add" else "multiply", a, b)
        if type(actual) is not int or actual != expected:
            raise ValueError("actual saturation equation differs from source transfer")
        values[instruction.value] = actual
    instructions = {i.value: i for i in source.instructions}
    for guard, witness in zip(stage.guards, original.guards):
        if (guard.value, guard.tape_index, guard.operation, guard.correction, guard.fields) != (
            witness.value,
            witness.tape_index,
            witness.operation,
            witness.correction,
            witness.fields,
        ) or guard.saturations != tuple(resolve(o) for o in instructions[witness.value].operands):
            raise ValueError("saturation carry binding mismatch")
    expected_outputs = tuple((slot, operand_field(o), resolve(o)) for slot, o in source.outputs)
    if stage.outputs != expected_outputs:
        raise ValueError("saturation output binding mismatch")
    payload = repr(
        (tuple((i, nodes[i]) for i in sorted(reachable)), stage.site_saturations, stage.guards, stage.outputs)
    ).encode()
    return Certificate(len(values), hashlib.sha256(payload).hexdigest())


@dataclass(frozen=True)
class Catalogue:
    choices: tuple[tuple[Stage, Stage], ...]
    tail: Stage
    certificates: tuple[Certificate, ...]


def catalogue(max_terms: int = 2, *, verify_data: bool = True) -> Catalogue:
    from dataclasses import replace
    from tools.recover_transform12_phase1 import recover
    from tools.transform7_reference import tail_program

    if type(verify_data) is not bool:
        raise ValueError("Boolean verification mode required")
    graph = Builder()
    certificates = []

    def compile_one(source: Program) -> Stage:
        original = compiled.compile_stage(source, max_terms)
        stage = lower(source, original, graph)
        if verify_data:
            certificates.append(verify(stage, source, original))
        return stage

    rows = tuple((compile_one(row.choices[0]), compile_one(row.choices[1])) for row in recover())
    tail = compile_one(tail_program())
    nodes = tuple(graph.nodes)
    return Catalogue(
        tuple((replace(a, nodes=nodes), replace(b, nodes=nodes)) for a, b in rows),
        replace(tail, nodes=nodes),
        tuple(certificates),
    )


def full_output(data: Catalogue, x: int, y: int, prng1: int, scalar: int) -> tuple[bytes, tuple[Evaluation, ...]]:
    from tools.transform7_setup_integer import model as setup
    from tools.transform7_reference import finalize

    if any(type(v) is not int or not 0 <= v < 1 << 160 for v in (x, y, prng1, scalar)):
        raise ValueError("four uint160 synthetic/public inputs required")
    if len(data.choices) != 160 or data.choices[0][0].input_slots != (46, 48, 70, 94):
        raise ValueError("complete scalar-stage catalogue required")
    state = dict(zip(data.choices[0][0].input_slots, setup(x, y, prng1).slots))
    rows = []
    for index, pair in enumerate(data.choices):
        bit = scalar >> (159 - index) & 1
        row = evaluate(pair[bit], state, index, bit)
        state = row.outputs
        rows.append(row)
    row = evaluate(data.tail, state)
    return finalize(row.outputs), tuple(rows) + (row,)


def main() -> None:
    from s7commplus.session_auth.family0._generated.data import TRANSFORM7_DATA
    from tools.recover_scalar_encodings import scalar_xor_mask

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-terms", type=int, default=2)
    args = parser.parse_args()
    data = catalogue(args.max_terms)
    x, y = (int.from_bytes(TRANSFORM7_DATA[o : o + 20], "little") for o in (0xD8, 0xEC))
    output, rows = full_output(data, x, y, 0, scalar_xor_mask())
    print(
        json.dumps(
            {
                "scope": "exact field/saturated-history research model; subtraction cuts remain stage-specific; NOT compact curve replacement",
                "verified_programs": len(data.certificates),
                "source_values_checked": sum(c.source_values for c in data.certificates),
                "shared_saturation_nodes": len(data.tail.nodes),
                "retained_boolean_lift_nodes": 0,
                "boundaries": len(rows),
                "defects": sum(len(r.defects) for r in rows),
                "destination_hex": output.hex(),
                "saturation_nodes_evaluated": sum(r.saturation_nodes_evaluated for r in rows),
                "fields_evaluated": sum(r.fields_evaluated for r in rows),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
