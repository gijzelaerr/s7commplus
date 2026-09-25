"""Exact source-free scalar research evaluation with factored field DATA.

Independently check coefficient identities before dropping the polynomials and
SSA site inventory. All correction/lift equations, guard provenance and anchors
are retained. NOT a compact stage-independent curve algorithm or runtime rewrite.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass, replace

from tools import scalar_compiled_stage as equations
from tools.scalar_field_circuit import Builder, Kernel
from tools.scalar_predicate_dag import Backend, Node
from tools.verify_scalar_field_circuit import Certificate, verify as verify_coefficients


@dataclass(frozen=True)
class PredicateCertificate:
    nodes: int
    data_sha256: str


@dataclass(frozen=True)
class Stage:
    equations: equations.Stage
    kernel: Kernel
    certificate: Certificate
    predicates: PredicateCertificate


@dataclass(frozen=True)
class Catalogue:
    choices: tuple[tuple[Stage, Stage], ...]
    tail: Stage


def _share(original: Backend, shared: Backend) -> tuple[int, ...]:
    """Copy abstract field/lift templates; numerical values never cross stages."""
    mapping: list[int] = []
    for index, node in enumerate(original.nodes):
        args = node.arguments
        if node.operation not in ("field", "integer", "boolean", "lift"):
            args = tuple(mapping[child] for child in args)
            if node.operation in ("and", "or", "eq", "add", "multiply"):
                args = tuple(sorted(args))
        root = shared.node(node.operation, args, original.sorts[index], original.bounds[index]).index
        if (shared.sorts[root], shared.bounds[root]) != (original.sorts[index], original.bounds[index]):
            raise ValueError("shared predicate metadata conflict")
        mapping.append(root)
    return tuple(mapping)


def _verify_projection(original: Backend, actual: Backend) -> tuple[tuple[int, ...], PredicateCertificate]:
    """Independent DAG substitution check; no sharing builder/frontend calls.

    Preserve every leaf and operation, allowing only explicitly commutative
    argument reordering. Check actual nodes and metadata, not interning tables.
    """
    if len(actual.nodes) != len(actual.sorts) or len(actual.nodes) != len(actual.bounds):
        raise ValueError("shared predicate metadata inventory mismatch")
    lookup = {node: index for index, node in enumerate(actual.nodes)}
    if len(lookup) != len(actual.nodes):
        raise ValueError("duplicate shared predicate node")
    mapped: list[int] = []
    for index, old in enumerate(original.nodes):
        if old.operation in ("field", "integer", "boolean", "lift"):
            arguments = old.arguments
        else:
            if any(type(child) is not int or not 0 <= child < index for child in old.arguments):
                raise ValueError("original predicate reads a future or cyclic node")
            arguments = tuple(mapped[child] for child in old.arguments)
            if old.operation in ("and", "or", "eq", "add", "multiply"):
                arguments = tuple(sorted(arguments))
        target = lookup.get(Node(old.operation, arguments))
        if target is None:
            raise ValueError("shared predicate projection identity failed")
        if old.operation not in ("field", "integer", "boolean", "lift") and any(child >= target for child in arguments):
            raise ValueError("shared predicate reads a future or cyclic node")
        if (actual.sorts[target], actual.bounds[target]) != (original.sorts[index], original.bounds[index]):
            raise ValueError("shared predicate type/interval metadata mismatch")
        mapped.append(target)
    data = tuple((i, actual.nodes[i], actual.sorts[i], actual.bounds[i]) for i in mapped)
    certificate = PredicateCertificate(len(mapped), hashlib.sha256(repr(data).encode()).hexdigest())
    return tuple(mapped), certificate


def _remap(stage: equations.Stage, shared: Backend, mapping: tuple[int, ...]) -> equations.Stage:
    return replace(
        stage,
        predicates=shared,
        guards=tuple(
            replace(g, tags=(mapping[g.tags[0]], mapping[g.tags[1]]), predicate=mapping[g.predicate]) for g in stage.guards
        ),
        outputs=tuple((slot, field, mapping[tag]) for slot, field, tag in stage.outputs),
    )


def _lower(original: equations.Stage, builder: Builder) -> tuple[equations.Stage, tuple[int, ...], Certificate]:
    roots = tuple(builder.compile(terms) for terms in original.fields)
    certificate = verify_coefficients(builder.freeze(), roots, original.fields, max_terms=original.max_terms)
    # Field ordinals remain unchanged. Empty placeholders have no coefficients;
    # the numerical evaluator reads only the independently checked kernel.
    stripped = replace(original, fields=((),) * len(roots), sites=(), certificate=None, field_kernel_required=True)
    return stripped, roots, certificate


def factor_stage(original: equations.Stage, max_nodes: int = 1_000_000) -> Stage:
    builder = Builder(max_nodes)
    stripped, roots, certificate = _lower(original, builder)
    shared = Backend()
    mapping = _share(stripped.predicates, shared)
    checked, predicates = _verify_projection(stripped.predicates, shared)
    if mapping != checked:
        raise ValueError("predicate remapping mismatch")
    result = Stage(_remap(stripped, shared, mapping), Kernel(builder.freeze(), roots), certificate, predicates)
    shared.interned.clear()  # Compilation lookup table is not numerical data.
    return result


def factor_catalogue(original: equations.Catalogue, max_nodes: int = 1_000_000) -> Catalogue:
    """One globally shared circuit, with distinct per-stage variable bindings."""
    builder = Builder(max_nodes)
    lowered = [_lower(stage, builder) for pair in original.choices for stage in pair]
    tail = _lower(original.tail, builder)
    circuit = builder.freeze()
    shared = Backend()

    def stage(data: tuple[equations.Stage, tuple[int, ...], Certificate]) -> Stage:
        stripped, roots, certificate = data
        mapping = _share(stripped.predicates, shared)
        checked, predicates = _verify_projection(stripped.predicates, shared)
        if mapping != checked:
            raise ValueError("predicate remapping mismatch")
        return Stage(_remap(stripped, shared, mapping), Kernel(circuit, roots), certificate, predicates)

    choices = tuple((stage(lowered[i]), stage(lowered[i + 1])) for i in range(0, len(lowered), 2))
    result = Catalogue(choices, stage(tail))
    shared.interned.clear()
    return result


def verify(actual: Stage, original: equations.Stage) -> Certificate:
    """Validate retained references and the actual factored coefficient data.

    The original equations need their own translation validation; factoring
    adds an independent formal-ring identity, not a source semantics theorem.
    """
    mapping, predicates = _verify_projection(original.predicates, actual.equations.predicates)
    expected = _remap(
        replace(original, fields=((),) * len(original.fields), sites=(), certificate=None, field_kernel_required=True),
        actual.equations.predicates,
        mapping,
    )
    if actual.equations != expected or len(actual.kernel.roots) != len(original.fields):
        raise ValueError("factored stage retained equation metadata mismatch")
    certificate = verify_coefficients(actual.kernel.circuit, actual.kernel.roots, original.fields, max_terms=original.max_terms)
    if certificate != actual.certificate:
        raise ValueError("factored stage coefficient certificate mismatch")
    if predicates != actual.predicates:
        raise ValueError("factored stage predicate certificate mismatch")
    return certificate


def evaluate(stage: Stage, state: dict[int, int], index: int = 160, bit: int = 0) -> equations.Evaluation:
    return equations.evaluate(stage.equations, state, index, bit, field_kernel=stage.kernel)


def full_output(catalogue: Catalogue, x: int, y: int, prng1: int, scalar: int) -> tuple[bytes, tuple[equations.Evaluation, ...]]:
    from tools.transform7_reference import finalize
    from tools.transform7_setup_integer import model as setup

    if any(type(v) is not int or not 0 <= v < 1 << 160 for v in (x, y, prng1, scalar)):
        raise ValueError("four uint160 synthetic/public inputs required")
    if len(catalogue.choices) != 160 or catalogue.choices[0][0].equations.input_slots != (46, 48, 70, 94):
        raise ValueError("complete pinned factored scalar catalogue required")
    state = dict(zip(catalogue.choices[0][0].equations.input_slots, setup(x, y, prng1).slots))
    rows = []
    for index, pair in enumerate(catalogue.choices):
        bit = scalar >> (159 - index) & 1
        row = evaluate(pair[bit], state, index, bit)
        state = row.outputs
        rows.append(row)
    tail = evaluate(catalogue.tail, state)
    return finalize(tail.outputs), tuple(rows) + (tail,)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-nodes", type=int, default=1_000_000)
    parser.add_argument("--max-terms", type=int, default=256)
    args = parser.parse_args()
    if args.max_nodes < 2 or args.max_terms < 2:
        parser.error("integer node and term budgets>=2 required")
    from s7commplus.session_auth.family0._generated.data import TRANSFORM7_DATA
    from tools.recover_scalar_encodings import scalar_xor_mask

    original = equations.compile_catalogue(args.max_terms, exclusive_corrections=True, verify_data=True)
    catalogue = factor_catalogue(original, args.max_nodes)
    field_words = sum(1 + 2 * len(m) for pair in original.choices for stage in pair for terms in stage.fields for m, _ in terms)
    field_words += sum(1 + 2 * len(m) for terms in original.tail.fields for m, _ in terms)
    predicate_words = sum(1 + len(n.arguments) for pair in original.choices for stage in pair for n in stage.predicates.nodes)
    predicate_words += sum(1 + len(n.arguments) for n in original.tail.predicates.nodes)
    verified_source_programs = len(original.verifications)
    del original
    x, y = (int.from_bytes(TRANSFORM7_DATA[o : o + 20], "little") for o in (0xD8, 0xEC))
    output, rows = full_output(catalogue, x, y, 0, scalar_xor_mask())
    stages = tuple(stage for pair in catalogue.choices for stage in pair) + (catalogue.tail,)
    circuit = catalogue.tail.kernel.circuit
    print(
        json.dumps(
            {
                "scope": "exact source-specific factored field/carry/lift research evaluator; NOT compact independent curve algorithm",
                "verified_source_programs": verified_source_programs,
                "term_budget": args.max_terms,
                "verified_factored_field_identities": sum(s.certificate.identities for s in stages),
                "field_polynomial_terms_retained": sum(len(t) for s in stages for t in s.equations.fields),
                "source_site_inventory_retained": sum(len(s.equations.sites) for s in stages),
                "field_coefficient_data_integer_words_before": field_words,
                "field_circuit_integer_words_including_roots": sum(1 + len(n.arguments) for n in circuit.nodes)
                + sum(len(s.kernel.roots) for s in stages),
                "word_metric_note": "integer items, not byte size, memory, speed or work",
                "globally_shared_circuit_nodes": len(circuit.nodes),
                "predicate_integer_words_before": predicate_words,
                "globally_shared_predicate_nodes": len(catalogue.tail.equations.predicates.nodes),
                "shared_predicate_integer_words": sum(1 + len(n.arguments) for n in catalogue.tail.equations.predicates.nodes),
                "boundaries": len(rows),
                "defects": sum(len(r.defects) for r in rows),
                "destination_hex": output.hex(),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
