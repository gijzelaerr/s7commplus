"""Independent local ring-identity checker for source-specific stage plans.

Checks exact coefficients, not sampled inputs or SMT queries. Polynomial
differences are reduced through acyclic anchor definitions. The checker does
not call compiler algebra, constant decoding, carry exclusion, or structural
validation helpers. It trusts the recovered SSA and existing canonical packing
decoder. This is NOT independent human review, a generated-kernel certificate,
or a proof of runtime guard/lift evaluation, setup, selection, or finalization.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path

from s7commplus.session_auth.family0._generated.data import TRANSFORM12_BIG_INT_DATA
from tools.decompile_transform12 import Instruction, Operand, Program
from tools.scalar_stage_plan import Plan, Polynomial, compile_plan
from tools.transform12_integer_model import decode

MODULUS = (1 << 160) - 47
LOW_LIMIT = 1 << 128
Support = frozenset[tuple[int, int]]
Ring = dict[Support, int]
TERM_LIMIT = 131072  # Enough for each local product of two256-term operands.
WORK_LIMIT = 1048576


@dataclass(frozen=True)
class Certificate:
    source_instructions: int
    field_identities: int
    guard_identities: int
    anchors: int
    excluded_carry_sites: int
    source_sha256: str
    plan_sha256: str
    constant_table_sha256: str
    correction_domains: tuple[tuple[int, int], ...] = ()
    exclusive_correction_pairs: tuple[tuple[int, int], ...] = ()


def _add(a: Ring, b: Ring, sign: int = 1) -> Ring:
    coefficients = defaultdict(int, a)
    for support, value in b.items():
        coefficients[support] += sign * value
    result = {support: value % MODULUS for support, value in coefficients.items() if value % MODULUS}
    if len(result) > TERM_LIMIT:
        raise ValueError("local identity exceeds the checker term budget")
    return result


def _multiply(a: Ring, b: Ring) -> Ring:
    if len(a) * len(b) > WORK_LIMIT:
        raise ValueError("local identity exceeds the checker work budget")
    coefficients: dict[Support, int] = defaultdict(int)
    for first, left in a.items():
        for second, right in b.items():
            powers = Counter(dict(first))
            powers.update(dict(second))
            coefficients[frozenset(powers.items())] += left * right
            if len(coefficients) > TERM_LIMIT:
                raise ValueError("local identity exceeds the checker term budget")
    return {support: value % MODULUS for support, value in coefficients.items() if value % MODULUS}


def _power(a: Ring, exponent: int) -> Ring:
    if exponent.bit_length() > 4096:
        raise ValueError("local identity exceeds the checker exponent budget")
    result: Ring = {frozenset(): 1}
    while exponent:
        if exponent & 1:
            result = _multiply(result, a)
        exponent >>= 1
        if exponent:
            a = _multiply(a, a)
    return result


def _constant(operand: Operand) -> int:
    if type(operand.index) is not int or not 0 <= operand.index < len(TRANSFORM12_BIG_INT_DATA) // 24:
        raise ValueError("constant index outside the trusted source table")
    start = operand.index * 24
    return decode(TRANSFORM12_BIG_INT_DATA[start : start + 24])


def _safe(instruction: Instruction) -> bool:
    if instruction.operation not in ("add", "subtract"):
        return True
    a, b = instruction.operands
    if instruction.operation == "add":
        return any(o.kind == "constant" and _constant(o) <= LOW_LIMIT - 47 for o in (a, b))
    return b.kind == "constant" and _constant(b) <= MODULUS or a.kind == "constant" and _constant(a) >= 47


def _exclusive(source: Program) -> frozenset[tuple[int, int]]:
    """Reconstruct raw low-ancestor implications without compiler helpers.

    A nonzero arithmetic correction has raw output>=47. A defective later
    subtraction has raw left<=46, hence all these ancestors are raw-small.
    The separately source-AST-proved primitive lemmas justify both facts.
    """
    values: dict[int, tuple[int, frozenset[Operand]]] = {}
    errors: set[int] = set()
    pairs: set[tuple[int, int]] = set()

    def facts(o: Operand) -> tuple[int, frozenset[Operand]]:
        if o.kind == "value":
            return values[o.index]
        return min(_constant(o), 47) if o.kind == "constant" else 0, frozenset((o,))

    for i in source.instructions:
        first, last = i.operands[0], i.operands[-1]
        a, aa = facts(first)
        b, bb = facts(last)
        inherited: frozenset[Operand] = frozenset()
        if i.operation == "add":
            lower, inherited = min(a + b, 47), aa | bb
        elif i.operation in ("multiply", "square"):
            lower = min(a * b, 47)
            if first == last:
                inherited = aa
            else:
                if b:
                    inherited |= aa
                if a:
                    inherited |= bb
        else:
            lower = max(a - _constant(last), 0) if last.kind == "constant" else 0
            if last.kind == "constant" and _constant(last) == 0:
                inherited = aa
            if not _safe(i):
                pairs.update((o.index, i.value) for o in aa if o.kind == "value" and o.index in errors)
        values[i.value] = lower, inherited | frozenset((Operand("value", i.value),))
        if not _safe(i):
            errors.add(i.value)
    return frozenset(pairs)


def verify(plan: Plan, source: Program, *, boolean_corrections: bool = False, exclusive_corrections: bool = False) -> Certificate:
    """Validate field and guard equations against separately supplied SSA.

    Resource exhaustion fails closed; no random-check or execution fallback.
    Constant exclusions rely on the separately source-AST-proved primitive
    lemmas. Anchor ordering and all correction frontiers are rederived here.
    Optional two-value correction domains must be explicitly requested;
    their quotient-ring identities are not arbitrary-error identities.
    """
    if plan.program != source:
        raise ValueError("plan does not match the supplied source program")
    if type(boolean_corrections) is not bool or type(plan.boolean_corrections) is not bool:
        raise ValueError("Boolean correction proof mode required")
    if plan.boolean_corrections != boolean_corrections:
        raise ValueError("correction proof mode does not match the plan")
    if (
        type(exclusive_corrections) is not bool
        or type(plan.exclusive_corrections) is not bool
        or exclusive_corrections
        and not boolean_corrections
        or plan.exclusive_corrections != exclusive_corrections
    ):
        raise ValueError("exclusive correction proof mode does not match the plan")
    if type(plan.max_terms) is not int or plan.max_terms < 2:
        raise ValueError("invalid plan term bound")
    instructions = {i.value: i for i in source.instructions}
    if len(instructions) != len(source.instructions) or plan.tag_sources != instructions or set(plan.fields) != set(instructions):
        raise ValueError("source field/tag inventory mismatch")
    defined = set()
    previous = -1
    inputs = set()
    for instruction in source.instructions:
        arity = 1 if instruction.operation == "square" else 2
        if instruction.operation not in ("add", "subtract", "multiply", "square") or len(instruction.operands) != arity:
            raise ValueError("unsupported source instruction")
        if type(instruction.value) is not int or instruction.value <= previous:
            raise ValueError("source is not in unique ascending SSA order")
        for operand in instruction.operands:
            if operand.kind == "input":
                inputs.add(operand.index)
            elif operand.kind == "value":
                if operand.index not in defined:
                    raise ValueError("source contains a forward SSA reference")
            elif operand.kind == "constant":
                _constant(operand)
            else:
                raise ValueError("unsupported source operand")
        defined.add(instruction.value)
        previous = instruction.value
    for _, operand in source.outputs:
        if operand.kind == "input":
            inputs.add(operand.index)
        elif operand.kind == "value" and operand.index not in defined:
            raise ValueError("source output is undefined")
        elif operand.kind == "constant":
            _constant(operand)
        elif operand.kind not in ("input", "value"):
            raise ValueError("unsupported source output operand")
    if plan.input_slots != tuple(sorted(inputs)):
        raise ValueError("source input inventory mismatch")
    unsafe = tuple(i for i in source.instructions if not _safe(i))
    unsafe_values = {i.value for i in unsafe}
    if tuple(g.instruction for g in plan.guards) != unsafe:
        raise ValueError("source carry guard inventory mismatch")
    if any(len(g.operands) != 2 for g in plan.guards):
        raise ValueError("carry guard must have exactly two operand equations")
    excluded = sum(i.operation in ("add", "subtract") for i in source.instructions) - len(unsafe)
    if plan.excluded_guards != excluded:
        raise ValueError("constant carry exclusion count mismatch")

    frontiers: list[int] = []
    correction_weights: dict[int, int] = {}
    source_exclusions = _exclusive(source) if exclusive_corrections else frozenset()
    error_variables: dict[int, int] = {}
    correction_exclusions: set[tuple[int, int]] = set()
    exclusion_neighbors: dict[int, set[int]] = {}

    def reduce_domain(poly: Ring) -> Ring:
        # Work in the quotient by E_i^2-c_i*E_i. On E_i in {0,c_i},
        # E_i^n=c_i^(n-1)*E_i for every n>=1, including nonunit c_i.
        # Weights are rederived from source operation types, not the compiler.
        if not correction_weights:
            return poly
        coefficients: dict[Support, int] = defaultdict(int)
        for support, coefficient in poly.items():
            powers = dict(support)
            if exclusion_neighbors and any(
                not powers.keys().isdisjoint(exclusion_neighbors[v]) for v in powers.keys() & exclusion_neighbors.keys()
            ):
                continue
            for variable_id in powers.keys() & correction_weights.keys():
                exponent = powers[variable_id]
                if exponent.bit_length() > 4096:
                    raise ValueError("correction reduction exceeds the checker exponent budget")
                coefficient *= pow(correction_weights[variable_id], exponent - 1, MODULUS)
                powers[variable_id] = 1
            coefficients[frozenset(powers.items())] += coefficient
        return {m: c % MODULUS for m, c in coefficients.items() if c % MODULUS}

    def ring_add(a: Ring, b: Ring, sign: int = 1) -> Ring:
        return reduce_domain(_add(a, b, sign))

    def ring_multiply(a: Ring, b: Ring) -> Ring:
        return reduce_domain(_multiply(a, b))

    def ring_power(a: Ring, exponent: int) -> Ring:
        if not correction_weights:
            return _power(a, exponent)
        if exponent.bit_length() > 4096:
            raise ValueError("local identity exceeds the checker exponent budget")
        result: Ring = {frozenset(): 1}
        while exponent:
            if exponent & 1:
                result = ring_multiply(result, a)
            exponent >>= 1
            if exponent:
                a = ring_multiply(a, a)
        return result

    def read(poly: Polynomial, available: int) -> Ring:
        if len(poly) > plan.max_terms:
            raise ValueError("formula exceeds the declared plan term bound")
        result: Ring = {}
        for monomial, coefficient in poly.items():
            if type(coefficient) is not int or not 0 < coefficient < MODULUS:
                raise ValueError("noncanonical polynomial coefficient")
            last = -1
            for variable_id, exponent in monomial:
                if type(variable_id) is not int or not last < variable_id < available:
                    raise ValueError("noncanonical or forward formula variable")
                if type(exponent) is not int or exponent <= 0:
                    raise ValueError("noncanonical polynomial exponent")
                if variable_id in correction_weights and exponent != 1:
                    # Do not hide unresolved reads by canceling noncanonical
                    # error powers only in the proof but not at execution.
                    raise ValueError("correction-domain formulas must be multilinear in explicit errors")
                last = variable_id
            support = {v for v, _ in monomial}
            if exclusion_neighbors and any(
                not support.isdisjoint(exclusion_neighbors[v]) for v in support & exclusion_neighbors.keys()
            ):
                raise ValueError("exclusive correction formulas contain an excluded error product")
            result[frozenset(monomial)] = coefficient
        return reduce_domain(result)

    def frontier(poly: Ring) -> int:
        return max((frontiers[v] for support in poly for v, _ in support), default=-1)

    input_variables: dict[int, int] = {}
    anchor_variables: dict[int, Ring] = {}
    anchor_count = 0
    for variable_id, binding in enumerate(plan.bindings):
        if type(binding.index) is not int:
            raise ValueError("invalid binding index")
        if binding.kind == "input":
            if binding.index not in inputs or binding.index in input_variables:
                raise ValueError("formula input binding mismatch")
            input_variables[binding.index] = variable_id
            frontiers.append(-1)
        elif binding.kind == "correction":
            if binding.index not in unsafe_values or binding.index in error_variables:
                raise ValueError("formula correction binding mismatch")
            error_variables[binding.index] = variable_id
            correction_exclusions.update(
                (error_variables[a], variable_id) for a, b in source_exclusions if b == binding.index and a in error_variables
            )
            for excluded_first, excluded_second in correction_exclusions:
                exclusion_neighbors.setdefault(excluded_first, set()).add(excluded_second)
            if boolean_corrections:
                correction_weights[variable_id] = (
                    94 - LOW_LIMIT if instructions[binding.index].operation == "add" else 47
                ) % MODULUS
            frontiers.append(binding.index)
        elif binding.kind == "anchor":
            if binding.index != anchor_count or binding.index >= len(plan.anchors):
                raise ValueError("formula anchor inventory mismatch")
            poly = read(plan.anchors[binding.index], variable_id)
            anchor_variables[variable_id] = poly
            frontiers.append(frontier(poly))
            anchor_count += 1
        else:
            raise ValueError("unsupported formula binding")
    if set(input_variables) != inputs or tuple(error_variables) != tuple(i.value for i in unsafe):
        raise ValueError("formula input/correction inventory mismatch")
    if anchor_count != len(plan.anchors) or tuple(frontiers) != plan.frontiers:
        raise ValueError("anchor/correction frontier mismatch")
    fields = {value: read(poly, len(frontiers)) for value, poly in plan.fields.items()}

    def symbolic(variable_id: int) -> Ring:
        return {frozenset(((variable_id, 1),)): 1}

    def operand_field(operand: Operand) -> Ring:
        if operand.kind == "input":
            return symbolic(input_variables[operand.index])
        if operand.kind == "value":
            return fields[operand.index]
        value = _constant(operand) % MODULUS
        return {frozenset(): value} if value else {}

    guards = {g.instruction.value: g for g in plan.guards}
    guard_identities = 0
    for instruction in source.instructions:
        a = operand_field(instruction.operands[0])
        b = operand_field(instruction.operands[-1])
        if max(frontier(a), frontier(b)) >= instruction.value or frontier(fields[instruction.value]) > instruction.value:
            raise ValueError("field equation reads a future correction")

        def contract(poly: Ring) -> Ring:
            # Replacing a WHOLE polynomial by an anchor with exactly that
            # definition is itself a coefficient identity. This avoids
            # expanding an old alias used inside another operand.
            for variable_id, definition in anchor_variables.items():
                if definition == poly:
                    return symbolic(variable_id)
            return poly

        def identical(first: Ring, second: Ring) -> bool:
            # Cancel before substitution. Merely treating all operand
            # anchors as independent fails when the compiler reuses an
            # old anchor whose definition is another current operand.
            difference = ring_add(first, second, -1)
            basis = {v for support in second for v, _ in support}
            while difference:
                candidates = {v for support in difference for v, _ in support if v in anchor_variables and v not in basis}
                if not candidates:
                    return False
                chosen = max(candidates)
                powers: dict[int, Ring] = {}
                coefficients: dict[Support, int] = defaultdict(int)
                work = 0
                for support, coefficient in difference.items():
                    exponent = dict(support).get(chosen, 0)
                    if exponent == 0:
                        term = {support: coefficient}
                    else:
                        if exponent not in powers:
                            powers[exponent] = ring_power(anchor_variables[chosen], exponent)
                        rest = frozenset((v, e) for v, e in support if v != chosen)
                        term = ring_multiply({rest: coefficient}, powers[exponent])
                    work += len(term)
                    if work > WORK_LIMIT:
                        raise ValueError(f"anchor substitution exceeds the checker work budget at SSA {instruction.value}")
                    for monomial, value in term.items():
                        coefficients[monomial] += value
                    if len(coefficients) > TERM_LIMIT:
                        raise ValueError(f"anchor substitution exceeds the checker term budget at SSA {instruction.value}")
                difference = reduce_domain({m: c % MODULUS for m, c in coefficients.items() if c % MODULUS})
            return True

        def operation(left: Ring, right: Ring) -> Ring:
            if instruction.operation in ("add", "subtract"):
                return ring_add(left, right, -1 if instruction.operation == "subtract" else 1)
            return ring_multiply(left, right)

        before = operation(a, b)
        contracted_before = operation(contract(a), contract(b))

        def equivalent(actual: Ring, *alternatives: Ring) -> bool:
            # Every alternative is constructed by exact whole-polynomial
            # substitutions, never inferred from sampled evaluations.
            candidates = [candidate for poly in alternatives for candidate in (poly, contract(poly))]
            if any(actual == candidate for candidate in candidates):
                return True
            return any(identical(actual, candidate) for candidate in candidates)

        expected = before
        alternatives: tuple[Ring, ...] = (expected, contracted_before)
        if instruction.value in guards:
            guard = guards[instruction.value]
            guard_polys = [read(poly, len(frontiers)) for poly in (guard.before, *guard.operands)]
            if any(frontier(poly) >= instruction.value for poly in guard_polys):
                raise ValueError("guard equation reads an unresolved correction")
            if not all(
                equivalent(actual, expected, alternative)
                for actual, expected, alternative in zip(guard_polys, (before, a, b), (contracted_before, a, b))
            ):
                raise ValueError(f"guard polynomial identity failed at SSA {instruction.value}")
            guard_identities += 3
            error = symbolic(error_variables[instruction.value])
            alternatives = tuple(
                ring_add(poly, error) for poly in (before, contract(before), contracted_before, contract(contracted_before))
            )
        if not equivalent(fields[instruction.value], *alternatives):
            raise ValueError(f"field polynomial identity failed at SSA {instruction.value}")
    source_json = json.dumps(asdict(source), sort_keys=True, separators=(",", ":"))
    plan_json = repr(
        (
            plan.bindings,
            plan.frontiers,
            tuple(tuple(sorted(poly.items())) for poly in plan.anchors),
            tuple((value, tuple(sorted(poly.items()))) for value, poly in sorted(plan.fields.items())),
            tuple(
                (g.instruction.value, tuple(sorted(g.before.items())), tuple(tuple(sorted(p.items())) for p in g.operands))
                for g in plan.guards
            ),
            plan.max_terms,
            plan.excluded_guards,
            boolean_corrections,
            exclusive_corrections,
        )
    )
    return Certificate(
        len(source.instructions),
        len(fields),
        guard_identities,
        len(plan.anchors),
        excluded,
        hashlib.sha256(source_json.encode()).hexdigest(),
        hashlib.sha256(plan_json.encode()).hexdigest(),
        hashlib.sha256(TRANSFORM12_BIG_INT_DATA).hexdigest(),
        tuple((ssa, correction_weights[v]) for ssa, v in error_variables.items()) if boolean_corrections else (),
        tuple(sorted(source_exclusions)),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-terms", type=int, default=256)
    parser.add_argument("--stage", type=int, choices=range(160))
    parser.add_argument("--branch", type=int, choices=(0, 1), default=0)
    parser.add_argument(
        "--boolean-corrections", action="store_true", help="check identities modulo explicit two-value correction domains"
    )
    parser.add_argument("--exclusive-corrections", action="store_true", help="check source-derived joint correction domains")
    args = parser.parse_args()
    if args.exclusive_corrections and not args.boolean_corrections:
        parser.error("--exclusive-corrections requires --boolean-corrections")
    from tools.recover_transform12_phase1 import recover
    from tools.transform7_reference import tail_program

    programs = (
        [recover()[args.stage].choices[args.branch]]
        if args.stage is not None
        else [p for s in recover() for p in s.choices] + [tail_program()]
    )
    certificates = [
        verify(
            compile_plan(
                source,
                args.max_terms,
                boolean_corrections=args.boolean_corrections,
                exclusive_corrections=args.exclusive_corrections,
            ),
            source,
            boolean_corrections=args.boolean_corrections,
            exclusive_corrections=args.exclusive_corrections,
        )
        for source in programs
    ]
    print(
        json.dumps(
            {
                "scope": "independent coefficient-identity validation of compiled field/guard formulas against recovered SSA; NOT whole-pipeline SMT or independent human review",
                "programs": len(certificates),
                "field_identities": sum(c.field_identities for c in certificates),
                "guard_identities": sum(c.guard_identities for c in certificates),
                "max_terms": args.max_terms,
                "boolean_corrections": args.boolean_corrections,
                "exclusive_corrections": args.exclusive_corrections,
                "exclusive_correction_pairs": sum(len(c.exclusive_correction_pairs) for c in certificates),
                "certificates": [asdict(c) for c in certificates],
                "source_sha256": {
                    name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                    for name in (
                        "verify_scalar_stage_algebra.py",
                        "scalar_stage_plan.py",
                        "decompile_transform12.py",
                        "transform12_integer_model.py",
                        "scalar_structural_guards.py",
                        "prove_scalar_structural_guards.py",
                    )
                },
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
