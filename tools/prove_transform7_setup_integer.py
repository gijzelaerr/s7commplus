"""Check the input-only exact setup model against pinned source theorems.

The recipe is interpreted with distinct provenance tokens, not numeric probes:
every encoded input, plain input expression, call order, and merge slot must
match the strict actual-source SetupDAG. Single-threaded analysis only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest.mock import patch

from s7commplus.session_auth.family0 import big_int_transforms, transform7
from tools import transform7_setup_integer as integer
from tools import transform12_integer_model as arithmetic
from tools import recover_monolith5_span_decoder as decoder
from tools.prove_monolith_setup_invariant import UPPER_ZERO_TRIPLES
from tools.prove_transform7_setup_ranges import OutputBit, SetupDAG, kernel_dependency, setup_invariant_dependency, span_bound
from tools.recover_monolith4_span_identity import normalized_span
from tools.transform7_setup_merge import SETUP_ADD_SLOTS


@dataclass(frozen=True)
class Origin:
    call: int
    span: int


@dataclass(frozen=True)
class Plain:
    name: str
    force: int = 0
    shift: int = 0

    def __or__(self, mask: int) -> Plain:
        if type(mask) is not int or mask != 4 or self.shift:
            raise ValueError("unsupported model plain mask")
        return Plain(self.name, self.force | mask)

    def __lshift__(self, count: int) -> Plain:
        if type(count) is not int or count != 2 or self.shift:
            raise ValueError("unsupported model plain shift")
        return Plain(self.name, self.force, count)


def carry_save_dependency() -> dict[str, str]:
    folder = Path(__file__).parent
    path = folder / "monolith_carry_save_proof.json"
    report = json.loads(path.read_text(encoding="utf-8"))
    expected = {(5, f"stream_{span}_bit_{k}", False) for span in range(2) for k in range(168)}
    for number in (3, 6):
        expected.update((number, f"span_0_bit_{k}", False) for k in range(167))
        expected.update((number, f"span_1_bit_{k}", False) for k in range(168))
        expected.update(
            {
                (number, "boundary_0", False),
                (number, "boundary_1_zero", False),
                (number, "span_0_bit_167_zero_under_setup_invariant", True),
            }
        )
    rows = report["stages"]
    if (
        not report["full_proof"]
        or len(rows) != 1012
        or {(row["monolith"], row["stage"], row["conditional"]) for row in rows} != expected
        or not all(row["proved"] and row["result"] == "unsat" for row in rows)
        or report["upper_zero_triples"] != [list(values) for values in UPPER_ZERO_TRIPLES]
    ):
        raise ValueError("complete pinned individual carry-save source proof is required")
    sources = Path(transform7.__file__).parent / "_generated"
    if set(report["source_sha256"]) != {f"monolith{number}.py" for number in (3, 5, 6)}:
        raise ValueError("incomplete carry-save source provenance")
    if set(report["gate_model_sha256"]) != {"monolith5_model.json", "monolith5_gate_model.json"}:
        raise ValueError("incomplete carry-save decoder provenance")
    for pins, directory in ((report["source_sha256"], sources), (report["gate_model_sha256"], folder)):
        if any(hashlib.sha256((directory / name).read_bytes()).hexdigest() != digest for name, digest in pins.items()):
            raise ValueError("carry-save source or decoder changed")
    return {
        "file": path.name,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "scope": "all 1012 individual source obligations; solver-run record, not a certificate",
    }


def setup_dependency() -> dict[str, str]:
    folder = Path(__file__).parent
    path = folder / "transform7_setup_invariant_proof.json"
    report = json.loads(path.read_text(encoding="utf-8"))
    if (
        not report["full_proof"]
        or report["zero_wrap_calls"] != list(range(23))
        or report["local_invariant_dependency"] != setup_invariant_dependency()
        or report["kernel_dependencies"] != {str(number): kernel_dependency(number) for number in (3, 4, 6)}
    ):
        raise ValueError("complete pinned legal-setup invariant proof is required")
    stages = report["stages"]
    expected_stages = {name for name, _ in SetupDAG().queries()}
    if (
        len(stages) != 29
        or {row["stage"] for row in stages} != expected_stages
        or not all(row["proved"] and row["result"] == "derived" for row in stages)
        or {int(row["stage"].split("_")[1]) for row in stages if row.get("zero_wrap_derived")} != set(range(23))
        or any(
            type(row["maximum_payload"]) is not int or not 0 <= row["maximum_payload"] < 1 << 166
            for row in stages
            if row.get("zero_wrap_derived")
        )
    ):
        raise ValueError("incomplete setup range deduction accounting")
    family = Path(transform7.__file__).parent
    expected_sources = {
        "transform7.py",
        "big_int_operations.py",
        "monolith_wrappers.py",
        *(f"monolith{number}.py" for number in (3, 4, 5, 6)),
    }
    if set(report["source_sha256"]) != expected_sources:
        raise ValueError("incomplete setup source provenance")
    for name, digest in report["source_sha256"].items():
        directory = family / "_generated" if name.startswith("monolith") and name != "monolith_wrappers.py" else family
        if hashlib.sha256((directory / name).read_bytes()).hexdigest() != digest:
            raise ValueError("setup source changed")
    if report["data_sha256"] != hashlib.sha256(transform7.TRANSFORM7_DATA).hexdigest():
        raise ValueError("setup data changed")
    return {
        "file": path.name,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "scope": "all 23 calls satisfy the upper encoding/range premises",
    }


def source_reference(bits: tuple[Any, ...]) -> integer.Span | Origin:
    if len(bits) != 576:
        raise ValueError("expected entire source encoded span")
    if all(type(bit) is int and bit in (0, 1) for bit in bits):
        words = tuple(sum(bits[word * 32 + bit] << bit for bit in range(32)) for word in range(18))
        return integer.Span(*normalized_span(words))
    first = bits[0]
    if not isinstance(first, OutputBit):
        raise ValueError("unsupported encoded source provenance")
    _, origin = span_bound(bits, {first.call: 0})
    if origin is None:
        raise ValueError("expected prior encoded output provenance")
    return Origin(*origin)


def verify_topology() -> list[dict[str, Any]]:
    """Compare uninterpreted recipe inputs with exact actual-source snapshots."""
    dag = SetupDAG()
    calls: list[tuple[int, tuple[Any, ...], Plain | None]] = []

    def operation(number: int, inputs: tuple[Any, ...], plain: Plain | None = None) -> Any:
        index = len(calls)
        calls.append((number, tuple(inputs), plain))
        return Origin(index, 0) if number == 4 else (Origin(index, 0), Origin(index, 1))

    with ExitStack() as stack:
        stack.enter_context(patch.object(integer, "quarter", lambda pair, plain: operation(3, pair, plain)))
        stack.enter_context(patch.object(integer, "add", lambda pair: operation(4, pair)))
        stack.enter_context(patch.object(integer, "halve", lambda spans: operation(6, spans)))
        stack.enter_context(patch.object(integer, "pack", lambda spans: operation(5, spans)))
        stack.enter_context(patch.object(integer, "merge", lambda first, second: (first, second)))
        recipe = integer._compose(Plain("X"), Plain("Y"), Plain("R"))
    if len(calls) != len(dag.calls) or len(recipe.steps) != len(calls):
        raise ValueError("model call count differs from actual setup")
    if tuple(slot for slot, _ in recipe.merges) != SETUP_ADD_SLOTS:
        raise ValueError("model merge order differs from actual setup")
    packed_calls = [index for index, (number, _, _) in enumerate(calls) if number == 5]
    if [streams for _, streams in recipe.merges] != [(Origin(index, 0), Origin(index, 1)) for index in packed_calls]:
        raise ValueError("model merge does not consume its exact packed output pair")
    rows = []
    for index, ((number, inputs, plain), (actual_number, _, actual_inputs)) in enumerate(zip(calls, dag.calls)):
        count = 2 if number == 3 else len(inputs)
        if number != actual_number or tuple(source_reference(bits) for bits in actual_inputs[:count]) != inputs:
            raise ValueError(f"model encoded provenance differs at call {index}")
        if number == 3:
            if not isinstance(plain, Plain):
                raise ValueError("model plain input lost symbolic provenance")
            expected = [dag.z3.Bool(f"{plain.name}_{bit}") if bit < 160 else 0 for bit in range(192)]
            for bit in range(160):
                if plain.force >> bit & 1:
                    expected[bit] = 1
            expected = ([0] * plain.shift + expected)[:192]
            if any(not dag.boolean(a).eq(dag.boolean(b)) for a, b in zip(actual_inputs[2], expected)):
                raise ValueError(f"model plain expression differs at call {index}")
        rows.append(
            {"call": index, "monolith": number, "encoded_provenance_checked": True, "plain_expression_checked": number == 3}
        )
    return rows


def prove() -> dict[str, Any]:
    carry = carry_save_dependency()
    setup = setup_dependency()
    rows = verify_topology()
    # The inherited range/encoding premises make the pair top-bit obligations
    # applicable. All other individual bit equations are unconditional. The
    # complete Monolith4 addition theorem covers the remaining operation.
    return {
        "scope": "input-only exact representatives of setup slots 46/48/70/94 for every legal unsigned-160-bit X/Y/R; runtime unchanged",
        "dependencies": {"carry_save": carry, "setup_invariant": setup, "decoded_addition": kernel_dependency(4)},
        "source_sha256": {
            name: hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()
            for name, module in (
                ("integer_model", integer),
                ("merge_wrapper", big_int_transforms),
                ("span_decoder", decoder),
                ("shared_integer_model", arithmetic),
            )
        },
        "merge_model_sha256": hashlib.sha256(Path(__file__).with_name("transform7_setup_merge.py").read_bytes()).hexdigest(),
        "method": "individual generated-source bit theorems, inherited reachable premises, symbolic recipe provenance, and source-derived exact prepare/merge equations",
        "final_carry_correction_retained": True,
        "slot94_exact_representative": "X",
        "full_setup_model_established": len(rows) == 23,
        "topology_checks": rows,
        "limits": "solver-run/compositional accounting, not an independently checked certificate, whole Transform7 rewrite, or new hardware validation",
    }


def main() -> None:
    argparse.ArgumentParser(description=__doc__).parse_args()
    print(json.dumps(prove(), indent=2))


if __name__ == "__main__":
    main()
