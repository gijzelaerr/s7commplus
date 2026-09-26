"""Prove reachable setup payload bounds using lazy generated-source bit DAGs.

Development-only Z3; no runtime substitution. Each query expands the actual
preceding setup calls, not an assumed invariant on arbitrary encoded inputs.
Initializers and rotation must match the small, explicitly modeled source AST.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import inspect
import json
import random
import sys
import time
from dataclasses import dataclass
from collections.abc import Iterator
from pathlib import Path
from typing import Any, TypeAlias
from contextlib import ExitStack
from unittest.mock import patch
from collections.abc import Callable

from s7commplus.session_auth.family0 import big_int_operations, transform7, transform12
from tools.prove_monolith4_span_identity import symbolic_source
from tools.prove_monolith_setup_invariant import UPPER_ZERO_TRIPLES
from tools.recover_transform7_setup import capture_setup
from tools.recover_monolith4_span_identity import _gate, normalized_span, normalized_terms, output_bit_diagram
from tools.recover_monolith5_span_decoder import MODULUS, P
from tools.trace_transform7_setup_shadows import NAMES, _pointer, compose

INITIALIZATION = """
data = TRANSFORM7_DATA
prng1_dwords = list(struct.unpack("<5I", bytes(prng1[:20])))
prng2_dwords = list(struct.unpack("<5I", bytes(prng2[:20])))
src_dwords = struct.unpack(f"<{len(source) // 4}I", bytes(source[: (len(source) // 4) * 4]))
w = bytearray(_WORK_SIZE)
wv = memoryview(w)
for i in range(5):
    struct.pack_into("<I", w, (0xC + i) * 4, prng1_dwords[i])
struct.pack_into("<I", w, 0xC * 4, struct.unpack_from("<I", w, 0xC * 4)[0] | 4)
for i in range(5):
    struct.pack_into("<I", w, i * 4, src_dwords[i])
for i in range(5):
    struct.pack_into("<I", w, (0x12 + i) * 4, src_dwords[5 + i])
struct.pack_into("<I", w, 0x12 * 4, struct.unpack_from("<I", w, 0x12 * 4)[0] | 4)
"""
ROTATION = """
ds = _to_uints(buffer, 6)
ds[5] = (ds[4] >> 0x1E) & _U32
for i in range(4, 0, -1):
    ds[i] = ((ds[i - 1] >> 0x1E) | ((ds[i] << 2) & _U32)) & _U32
ds[0] = (ds[0] << 2) & _U32
_write_uints(buffer, ds)
"""


def _same_statements(actual: list[ast.stmt], expected: str) -> bool:
    return [ast.dump(node) for node in actual] == [ast.dump(node) for node in ast.parse(expected).body]


@dataclass(frozen=True)
class OutputBit:
    call: int
    word: int
    bit: int


Bit: TypeAlias = Any  # Constant 0/1, lazy OutputBit, or a Z3 Boolean expression.


class SetupDAG:
    """Snapshots preserve aliased wrapper reads; output bits expand on demand."""

    def __init__(self, concrete: tuple[int, int, int] | None = None) -> None:
        try:
            import z3
        except ImportError as error:
            raise RuntimeError("install the development-only analysis extra to run this proof") from error
        self.z3 = z3
        self.concrete = concrete is not None
        self._outputs: dict[OutputBit, Any] = {}
        self.calls: list[tuple[int, Any, tuple[tuple[Bit, ...], ...]]] = []
        self.banks: dict[str, list[Bit]] = {
            "wv": [0] * (transform7._WORK_SIZE * 8),
            "cv": [0] * (transform12.CONTEXT_SIZE * 8),
            "data": [(byte >> bit) & 1 for byte in transform7.TRANSFORM7_DATA for bit in range(8)],
        }
        for offset, name, coordinate in ((0, "X", 0), (48, "R", 2), (72, "Y", 1)):
            self.banks["wv"][offset * 8 : offset * 8 + 160] = [
                z3.Bool(f"{name}_{bit}") if concrete is None else (concrete[coordinate] >> bit) & 1 for bit in range(160)
            ]
        for offset in (48, 72):
            self.banks["wv"][offset * 8 + 2] = 1
        function = ast.parse(inspect.getsource(transform7.execute)).body[0]
        if not isinstance(function, ast.FunctionDef) or transform7._WORK_SIZE != 2400:
            raise ValueError("unexpected setup function or work size")
        prefix = ast.parse(INITIALIZATION).body
        if not _same_statements(function.body[: len(prefix)], INITIALIZATION):
            raise ValueError("unsupported setup initialization")
        rotation = ast.parse(inspect.getsource(big_int_operations.rotate_right_30)).body[0]
        if not isinstance(rotation, ast.FunctionDef) or not _same_statements(rotation.body[1:], ROTATION):
            raise ValueError("unsupported setup rotation")
        # This also checks exact merge operands and the 23-call topology.
        compose(corrected=True)
        context_created = context_view = rotated = False
        for statement in function.body[len(prefix) :]:
            if isinstance(statement, ast.For):
                break
            if isinstance(statement, ast.Assign):
                if (
                    _same_statements([statement], "ctx = bytearray(transform12.CONTEXT_SIZE)")
                    and len(self.calls) == 5
                    and not context_created
                ):
                    context_created = True
                elif (
                    _same_statements([statement], "cv = memoryview(ctx)")
                    and len(self.calls) == 5
                    and context_created
                    and not context_view
                ):
                    context_view = True
                else:
                    raise ValueError("unsupported setup assignment")
                continue
            if not isinstance(statement, ast.Expr) or not isinstance(statement.value, ast.Call):
                raise ValueError("unsupported setup statement")
            call = statement.value
            if isinstance(call.func, ast.Attribute) and ast.dump(call) == ast.dump(
                ast.parse("big_int_operations.rotate_right_30(w)", mode="eval").body
            ):
                if rotated or len(self.calls) != 21 or big_int_operations._U32 != 0xFFFFFFFF:
                    raise ValueError("unexpected setup rotation position or mask")
                rotated = True
                self.banks["wv"][:192] = [0, 0] + self.banks["wv"][:160] + [0] * 30
                continue
            if isinstance(call.func, ast.Name) and call.func.id == "big_int_addition":
                # These context outputs never feed a later setup wrapper. Do
                # not leave their old packed values available accidentally.
                bank, offset = _pointer(call.args[0])
                self.banks[bank][offset * 8 : offset * 8 + 192] = [z3.Bool(f"merge_{offset}_{bit}") for bit in range(192)]
                continue
            if not isinstance(call.func, ast.Name) or call.func.id not in NAMES:
                raise ValueError("unsupported setup call")
            number = int(call.func.id[8])
            if call.keywords or len(call.args) != (3 if number == 4 else 5):
                raise ValueError("unsupported setup wrapper signature")
            pointers = [_pointer(node) for node in call.args]
            count = 1 if number == 4 else 2
            inputs = tuple(
                tuple(self.banks[bank][offset * 8 : offset * 8 + (192 if number == 3 and i == 2 else 576)])
                for i, (bank, offset) in enumerate(pointers[count:])
            )
            backend = self.backend(tuple(bit for span in inputs for bit in span))
            index = len(self.calls)
            self.calls.append((number, backend, inputs))
            size = 192 if number == 5 else 576
            for span, (bank, offset) in enumerate(pointers[:count]):
                self.banks[bank][offset * 8 : offset * 8 + size] = [
                    OutputBit(index, span * (size // 32) + bit // 32, bit % 32) for bit in range(size)
                ]
        if len(self.calls) != 23 or not (context_created and context_view and rotated):
            raise ValueError("unexpected setup wrapper count")

    def boolean(self, bit: Bit) -> Any:
        if isinstance(bit, OutputBit):
            return self.output(bit)
        if self.concrete and type(bit) is int:
            return bit
        return self.z3.BoolVal(bool(bit)) if type(bit) is int else bit

    def output(self, bit: OutputBit) -> Any:
        if bit in self._outputs:
            return self._outputs[bit]
        number, backend, _ = self.calls[bit.call]
        value = self.boolean(output_bit_diagram(bit.word, bit.bit, backend, number))
        self._outputs[bit] = value
        return value

    def backend(self, bits: tuple[Bit, ...]) -> Any:
        owner = self
        z3 = self.z3

        class Backend:
            ref_index = {(word, bit): word * 32 + bit for word in range(len(bits) // 32) for bit in range(32)}

            def _node(self, variable: int, low: int, high: int) -> Any:
                if (low, high) != (0, 1):
                    raise ValueError("unsupported source bit branches")
                return owner.boolean(bits[variable])

            def invert(self, value: Bit) -> Any:
                bit = owner.boolean(value)
                if owner.concrete:
                    return bit ^ 1
                if z3.is_true(bit) or z3.is_false(bit):
                    return z3.BoolVal(z3.is_false(bit))
                return bit.arg(0) if z3.is_not(bit) else z3.Not(bit)

            def apply(self, operation: str, left: Bit, right: Bit) -> Any:
                a, b = owner.boolean(left), owner.boolean(right)
                if owner.concrete:
                    if operation == "and":
                        return a & b
                    if operation == "xor":
                        return a ^ b
                    raise ValueError("unsupported Boolean operation")
                if operation == "and":
                    if z3.is_false(a) or z3.is_false(b):
                        return z3.BoolVal(False)
                    if z3.is_true(a) or a.eq(b):
                        return b
                    return a if z3.is_true(b) else z3.And(a, b)
                if operation == "xor":
                    if a.eq(b):
                        return z3.BoolVal(False)
                    if z3.is_false(a):
                        return b
                    if z3.is_false(b):
                        return a
                    if z3.is_true(a):
                        return self.invert(b)
                    return self.invert(a) if z3.is_true(b) else z3.Xor(a, b)
                raise ValueError("unsupported Boolean operation")

        return Backend()

    def normalized(self, bits: tuple[Bit, ...], k: int) -> Any:
        _, terms = normalized_terms()
        term = terms[k]
        backend = self.backend(bits)
        value = _gate(backend, term, [self.boolean(bits[(term.chunk * 3 + member) * 32 + term.bit]) for member in range(3)])
        return backend.invert(value) if term.weight < 0 else self.boolean(value)

    def range_query(self, index: int, width: int) -> Any:
        number = self.calls[index][0]
        count = 1 if number == 4 else 2
        return self.z3.Or(
            *[
                self.normalized(tuple(OutputBit(index, span * 18 + bit // 32, bit % 32) for bit in range(576)), k)
                for span in range(count)
                for k in range(width, 168)
            ]
        )

    def packed_top_query(self, index: int) -> Any:
        return self.z3.Or(*(self.output(OutputBit(index, span * 6 + 5, 29)) for span in range(2)))

    def ancestors(self, index: int) -> set[int]:
        result = set()
        pending = [index]
        while pending:
            current = pending.pop()
            for span in self.calls[current][2]:
                for bit in span:
                    if isinstance(bit, OutputBit) and bit.call not in result:
                        if bit.call >= current:
                            raise ValueError("cyclic setup input provenance")
                        result.add(bit.call)
                        pending.append(bit.call)
        return result

    def queries(self) -> Iterator[tuple[str, Callable[[], Any]]]:
        for index, (number, _, inputs) in enumerate(self.calls):
            if number == 3:
                yield (
                    f"call_{index}_plain_below_2_162",
                    lambda bits=inputs[2][162:]: self.z3.Or(*(self.boolean(bit) for bit in bits)),
                )
            if number == 5:
                # Both streams below 2^167 imply their integer sum is <2^168.
                yield f"call_{index}_packed_streams_below_2_167", lambda index=index: self.packed_top_query(index)
            else:
                if number == 4:
                    yield f"call_{index}_decoded_addition_bound", lambda: self.z3.BoolVal(False)
                else:
                    yield f"call_{index}_top_payload_bit_zero", lambda index=index: self.range_query(index, 167)


def kernel_dependency(number: int = 4) -> dict[str, Any]:
    """Pin the earlier complete decoded-addition proof, not a sampled lemma."""
    folder = Path(__file__).parent
    name, count = {
        3: ("monolith3_span_proof.json", 171),
        4: ("monolith4_carry_proof.json", 169),
        6: ("monolith6_span_proof.json", 170),
    }[number]
    path = folder / name
    report = json.loads(path.read_text(encoding="utf-8"))
    source = Path(transform7.__file__).parent / "_generated" / f"monolith{number}.py"
    if (
        not report["full_proof"]
        or len(report["stages"]) != count
        or not all(row["proved"] and row["result"] == "unsat" for row in report["stages"])
        or report["source_sha256"] != hashlib.sha256(source.read_bytes()).hexdigest()
    ):
        raise ValueError(f"complete pinned Monolith{number} source proof is required")
    for name, digest in report["gate_model_sha256"].items():
        if hashlib.sha256((folder / name).read_bytes()).hexdigest() != digest:
            raise ValueError(f"Monolith{number} gate model changed")
    return {
        "file": path.name,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "scope": "complete decoded local-carry kernel theorem; solver-run record, not a certificate",
    }


def span_bound(bits: tuple[Bit, ...], bounds: dict[int, int]) -> tuple[int, tuple[int, int] | None]:
    """Read only concrete spans or complete outputs with already proved bounds."""
    if len(bits) != 576:
        raise ValueError("expected an entire encoded span")
    if all(type(bit) is int and bit in (0, 1) for bit in bits):
        words = [sum(bits[word * 32 + k] << k for k in range(32)) for word in range(18)]
        return normalized_span(words)[0], None
    first = bits[0]
    if (
        isinstance(first, OutputBit)
        and first.call in bounds
        and first.bit == 0
        and first.word in (0, 18)
        and bits == tuple(OutputBit(first.call, first.word + bit // 32, bit % 32) for bit in range(576))
    ):
        return bounds[first.call], (first.call, first.word // 18)
    raise ValueError("span does not have an established reachable bound")


def combined_maximum(inputs: tuple[tuple[Bit, ...], ...], maxima: dict[int, int], pair_maxima: dict[int, int]) -> int:
    spans = [span_bound(bits, maxima) for bits in inputs]
    total = sum(value for value, _ in spans)
    for index, maximum in pair_maxima.items():
        if {origin for _, origin in spans}.issuperset({(index, 0), (index, 1)}):
            total += maximum - 2 * maxima[index]
    return total


def verify_translation(controls: int = 8, progress: bool = False) -> None:
    """Replay lazy high-bit snapshots against real setup before solver queries."""
    if controls <= 0:
        raise ValueError("expected positive translation control count")
    for number in (3, 4, 5, 6):
        # Independently validate helpers, prologues, uint32 expressions, and
        # every generated word writeback, including Monolith5's new support.
        symbolic_source(number)
    rng = random.Random(0x716A)
    for control in range(controls):
        case = tuple(rng.getrandbits(160) for _ in range(3))
        observed: list[tuple[int, tuple[bytes, ...]]] = []

        def wrap(name: str, original: Callable[..., None]) -> Callable[..., None]:
            def execute(*buffers: memoryview | bytes) -> None:
                original(*buffers)
                number = int(name[8])
                count = 1 if number == 4 else 2
                observed.append((number, tuple(bytes(buffer[: 24 if number == 5 else 72]) for buffer in buffers[:count])))

            return execute

        with ExitStack() as stack:
            for name in NAMES:
                stack.enter_context(patch.object(transform7, name, wrap(name, getattr(transform7, name))))
            capture_setup(*case)
        dag = SetupDAG(case)
        if len(observed) != len(dag.calls):
            raise AssertionError("lazy call graph differs from actual setup")
        for index, (number, outputs) in enumerate(observed):
            if number != dag.calls[index][0]:
                raise AssertionError("lazy wrapper order differs from actual setup")
            for span, output in enumerate(outputs):
                words = [int.from_bytes(output[i : i + 4], "little") for i in range(0, len(output), 4)]
                selected = (
                    [(word, bit) for word in (5,) for bit in range(24, 32)]
                    if number == 5
                    else [(word, bit) for word in (15, 16, 17) for bit in range(7, 11)]
                )
                for word, bit in selected:
                    value = dag.output(OutputBit(index, span * len(words) + word, bit))
                    if type(value) is not int or value not in (0, 1) or value != words[word] >> bit & 1:
                        raise AssertionError("lazy generated-source snapshot differs from runtime")
        if progress:
            print(json.dumps({"translation_control": control + 1, "passed": True}), file=sys.stderr, flush=True)


def slot94_identity(dag: SetupDAG, zero_wraps: set[int]) -> bool:
    """Discharge the integer premises for slot94=X, not just equality modulo p."""
    if not {21, 22} <= zero_wraps:
        return False
    n3, _, inputs3 = dag.calls[21]
    n5, _, inputs5 = dag.calls[22]
    if n3 != 3 or n5 != 5:
        raise ValueError("unexpected slot94 wrapper chain")
    for bits in (*inputs3[:2], inputs5[0]):
        if not all(type(bit) is int and bit in (0, 1) for bit in bits):
            raise ValueError("slot94 zero span is not concrete")
        words = [sum(bits[word * 32 + bit] << bit for bit in range(32)) for word in range(18)]
        if normalized_span(words) != (0, 0):
            raise ValueError("slot94 input is not the encoded zero")
    expected_plain = [0, 0] + [dag.z3.Bool(f"X_{bit}") for bit in range(160)] + [0] * 30
    if any(not dag.boolean(a).eq(dag.boolean(b)) for a, b in zip(inputs3[2], expected_plain)):
        raise ValueError("slot94 plain input is not exactly 4*X")
    for span, bits in enumerate(inputs5[1:]):
        if bits != tuple(OutputBit(21, span * 18 + bit // 32, bit % 32) for bit in range(576)):
            raise ValueError("slot94 packing does not consume its source pair")
    # N=4*X gives T3=2*X. m3=0 and exclusive output boundaries imply
    # 2*(B0+B1)+h0+h1=2*X, hence h0=h1=0 and B0+B1=X. Thus T5=X.
    # m5=0 makes A+B=X as integers. Each stream <=X<2^160, so Prepare
    # is the identity and the final merge has no carry: exact representative X.
    return True


def setup_invariant_dependency() -> dict[str, Any]:
    """Require every local preservation obligation, with exact source pins."""
    folder = Path(__file__).parent
    path = folder / "monolith_setup_invariant_proof.json"
    report = json.loads(path.read_text(encoding="utf-8"))
    stages = {"payload_bit_167_zero", *(f"upper_bit_{k}_zero" for k in range(168, 191))}
    expected = {(number, stage) for number in (3, 4, 6) for stage in stages}
    expected.add((5, "packed_streams_below_2_167"))
    rows = report["stages"]
    if (
        not report["full_proof"]
        or len(rows) != 73
        or {(row["monolith"], row["stage"]) for row in rows} != expected
        or not all(row["proved"] and row["result"] == "unsat" for row in rows)
        or report["upper_zero_triples"] != [list(values) for values in UPPER_ZERO_TRIPLES]
    ):
        raise ValueError("complete pinned local setup invariant proof is required")
    source = Path(transform7.__file__).parent / "_generated"
    expected_sources = {f"monolith{number}.py" for number in (3, 4, 5, 6)}
    expected_models = {"monolith5_model.json", "monolith5_gate_model.json"}
    if set(report["source_sha256"]) != expected_sources or set(report["gate_model_sha256"]) != expected_models:
        raise ValueError("incomplete local invariant provenance")
    for pins, directory in ((report["source_sha256"], source), (report["gate_model_sha256"], folder)):
        if any(hashlib.sha256((directory / name).read_bytes()).hexdigest() != digest for name, digest in pins.items()):
            raise ValueError("local invariant source or decoder changed")
    return {
        "file": path.name,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "scope": "all 73 local source obligations; solver-run record, not a certificate",
    }


def require_upper_zero(bits: tuple[Bit, ...], origin: tuple[int, int] | None, established: set[int]) -> None:
    """Validate constants directly, or inherit only from a proved output span."""
    if origin is not None:
        if origin[0] not in established:
            raise ValueError("input upper encoding invariant has not been established")
        if span_bound(bits, {origin[0]: 0})[1] != origin:
            raise ValueError("upper encoding provenance does not match the entire output span")
        return
    if len(bits) != 576 or not all(type(bit) is int and bit in (0, 1) for bit in bits):
        raise ValueError("upper encoding input is not a concrete complete span")
    for bit, allowed in enumerate(UPPER_ZERO_TRIPLES, 9):
        code = sum(bits[(15 + member) * 32 + bit] << member for member in range(3))
        if code not in allowed:
            raise ValueError("concrete span violates the upper encoding invariant")


def prove_compositional(progress: bool = False, *, translation_controls: int = 8) -> dict[str, Any]:
    """Induct through actual setup using local theorems, not sampled bounds."""
    dependency = setup_invariant_dependency()
    dependencies = {number: kernel_dependency(number) for number in (3, 4, 6)}
    verify_translation(translation_controls, progress)
    dag = SetupDAG()
    maxima: dict[int, int] = {}
    pair_maxima: dict[int, int] = {}
    upper_zero: set[int] = set()
    zero_wraps: set[int] = set()
    rows = []
    for name, _ in dag.queries():
        index = int(name.split("_")[1])
        number, _, inputs = dag.calls[index]
        row: dict[str, Any] = {"stage": name, "result": "derived", "proved": True}
        if "plain" in name:
            if any(type(bit) is not int or bit != 0 for bit in inputs[2][162:]):
                raise ValueError("plain input does not have its structural 162-bit bound")
            row["method"] = "exact setup initialization/rotation: all plain bits 162..191 are zero"
        else:
            encoded = inputs[:2] if number == 3 else inputs
            for bits in encoded:
                maximum, origin = span_bound(bits, maxima)
                if maximum >= 1 << 166:
                    raise ValueError("local theorem requires input B<2^166")
                require_upper_zero(bits, origin, upper_zero)
            combined = combined_maximum(encoded, maxima, pair_maxima)
            if number == 4:
                maximum = combined + 1
                row["method"] = "complete decoded addition theorem plus local upper-zero preservation"
            else:
                target = combined + (P + 1) // 2 + 1
                if number == 3:
                    plain = inputs[2]
                    if any(isinstance(bit, OutputBit) for bit in plain):
                        raise ValueError("unexpected encoded output in plain setup input")
                    plain_maximum = sum(1 << k for k, bit in enumerate(plain) if type(bit) is not int or bit != 0)
                    if plain_maximum >= 1 << 162:
                        raise ValueError("plain range does not establish zero truncation/top carry")
                    target += plain_maximum >> 1
                if number in (3, 6):
                    # Inputs B<2^166 imply r167=0. The local theorem gives
                    # both output top bits zero, hence m=top_count-r167=0.
                    maximum = target // 2
                    pair_maxima[index] = maximum
                    row["method"] = "local top-bit/upper-zero theorem plus complete doubled-pair carry identity"
                else:
                    # Local theorem bounds each packed stream below 2^167.
                    # Their sum and target are <2^168, lifting the exact
                    # combined-payload congruence to an integer equality.
                    if target >= MODULUS:
                        raise ValueError("packed target may wrap")
                    maximum = target
                    row["method"] = "local packed-stream top-bit theorem plus exact Monolith5 combined congruence"
            if maximum >= 1 << 166:
                raise ValueError("derived bound does not close setup induction")
            maxima[index] = maximum
            zero_wraps.add(index)
            if number != 5:
                upper_zero.add(index)
            row.update(maximum_payload=maximum, zero_wrap_derived=True, upper_zero_inherited=number != 5)
        rows.append(row)
        if progress:
            print(json.dumps(row), file=sys.stderr, flush=True)
    paths = [
        Path(transform7.__file__),
        Path(big_int_operations.__file__),
        Path(transform7.__file__).with_name("monolith_wrappers.py"),
    ]
    paths.extend(Path(transform7.__file__).parent / "_generated" / f"monolith{number}.py" for number in (3, 4, 5, 6))
    completed = [
        slot
        for slot, expression in compose(corrected=True).items()
        if all(int(name[1:]) in zero_wraps for name, _ in expression.terms if name.startswith("c"))
    ]
    return {
        "scope": "all legal unsigned-160-bit setup inputs: zero wrapper corrections and affine PREMERGE residues; NOT final merge or whole-runtime equivalence",
        "source_sha256": {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths},
        "data_sha256": hashlib.sha256(transform7.TRANSFORM7_DATA).hexdigest(),
        "z3_version": dag.z3.get_version_string(),
        "translation_controls": translation_controls,
        "expected_stages": 29,
        "full_proof": len(rows) == 29 and zero_wraps == set(range(23)),
        "kernel_dependencies": dependencies,
        "local_invariant_dependency": dependency,
        "zero_wrap_calls": sorted(zero_wraps),
        "completed_premerge_slots": sorted(completed),
        "slot94_exact_input_identity_proved": slot94_identity(dag, zero_wraps),
        "stages": rows,
    }


def prove(timeout_ms: int = 10000, progress: bool = False, *, stop_on_failure: bool = False) -> dict[str, Any]:
    if timeout_ms <= 0:
        raise ValueError("expected positive solver timeout")
    verify_translation(progress=progress)
    dag = SetupDAG()
    dependencies = {number: kernel_dependency(number) for number in (3, 4, 6)}
    rows = []
    proved: list[tuple[int, Any]] = []
    maxima: dict[int, int] = {}
    pair_maxima: dict[int, int] = {}
    for name, query in dag.queries():
        index = int(name.split("_")[1])
        number, _, inputs = dag.calls[index]
        if "plain" not in name:
            encoded = inputs[:2] if number == 3 else inputs
            try:
                combined_maximum(encoded, maxima, pair_maxima)
            except ValueError as error:
                row = {"stage": name, "result": "skipped_unproved_dependency", "proved": False, "reason": str(error)}
                rows.append(row)
                if progress:
                    print(json.dumps(row), file=sys.stderr, flush=True)
                if stop_on_failure:
                    break
                continue
        mismatch = query()
        solver = dag.z3.Tactic("sat").solver()
        solver.set(timeout=timeout_ms)
        ancestors = dag.ancestors(index) | {index}
        solver.add(*(fact for call, fact in proved if call in ancestors))
        solver.add(mismatch)
        start = time.monotonic()
        inferred = number == 4
        if inferred:
            maximum = combined_maximum(inputs, maxima, pair_maxima) + 1
            if maximum >= MODULUS:
                raise ValueError("Monolith4 input bounds do not establish output bound")
            result = dag.z3.unsat
        else:
            result = solver.check()
        row = {
            "stage": name,
            "result": "derived" if inferred else str(result),
            "proved": result == dag.z3.unsat,
            "elapsed_seconds": round(time.monotonic() - start, 6),
            "method": "integer bound via complete Monolith4 decoded-addition theorem"
            if inferred
            else "generated-source SAT query",
        }
        if inferred:
            row["maximum_payload"] = maximum
        if result == dag.z3.unknown:
            row["reason"] = solver.reason_unknown()
        rows.append(row)
        if progress:
            print(json.dumps(row), file=sys.stderr, flush=True)
        if result != dag.z3.unsat:
            if stop_on_failure:
                break
            continue
        proved.append((index, dag.z3.Not(mismatch)))
        if "plain" in name:
            continue
        if number in (3, 6):
            encoded = inputs[:2] if number == 3 else inputs
            # Local carries at column 167 are zero: both top input payload
            # bits are zero and H has no bit there. With both output top bits
            # proved zero, the complete source column theorem gives m=0.
            if any(span_bound(bits, maxima)[0] >= 1 << 166 for bits in encoded):
                raise ValueError("input range does not establish zero top carry")
            target_maximum = combined_maximum(encoded, maxima, pair_maxima) + (P + 1) // 2 + 1
            if number == 3:
                if any(isinstance(bit, OutputBit) for bit in inputs[2]):
                    raise ValueError("plain input unexpectedly contains encoded output")
                plain_maximum = sum(1 << k for k, bit in enumerate(inputs[2]) if type(bit) is not int or bit != 0)
                if plain_maximum >= 1 << 162:
                    raise ValueError("plain input does not have its proved range")
                target_maximum += plain_maximum >> 1
            maximum = target_maximum // 2
            pair_maxima[index] = maximum
        elif number == 5:
            target_maximum = combined_maximum(inputs, maxima, pair_maxima) + (P + 1) // 2 + 1
            if target_maximum >= MODULUS:
                raise ValueError("Monolith5 target can wrap despite packed stream bounds")
            maximum = target_maximum
        if maximum >= 1 << 166:
            raise ValueError("derived payload range does not close induction")
        maxima[index] = maximum
        row["maximum_payload"] = maximum
        row["zero_wrap_derived"] = True
        if number != 5:
            # A weaker proved bound avoids dragging irrelevant low carry
            # networks into the next SAT query. The integer maxima remain
            # available independently for later algebraic deductions.
            proved.append((index, dag.z3.Not(dag.range_query(index, max(162, maximum.bit_length())))))
    paths = [
        Path(transform7.__file__),
        Path(big_int_operations.__file__),
        Path(transform7.__file__).with_name("monolith_wrappers.py"),
    ]
    paths.extend(Path(transform7.__file__).parent / "_generated" / f"monolith{number}.py" for number in (3, 4, 5, 6))
    zero_wraps = {int(row["stage"].split("_")[1]) for row in rows if row.get("zero_wrap_derived")}
    completed_slots = [
        slot
        for slot, expression in compose(corrected=True).items()
        if all(int(name[1:]) in zero_wraps for name, _ in expression.terms if name.startswith("c"))
    ]
    return {
        "scope": "reachable setup ranges from generated-source bit DAGs; NOT whole encoded runtime equivalence",
        "source_sha256": {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths},
        "data_sha256": hashlib.sha256(transform7.TRANSFORM7_DATA).hexdigest(),
        "z3_version": dag.z3.get_version_string(),
        "translation_controls": 8,
        "solver_budget_per_stage_ms": timeout_ms,
        "expected_stages": 29,
        "retained_lemmas": "earlier UNSAT queries and integer consequences of the pinned Monolith3/4/6 kernel theorems; only ancestor-call facts; no sampled invariant is assumed",
        "kernel_dependencies": dependencies,
        "full_proof": len(rows) == 29 and all(row["proved"] for row in rows),
        "zero_wrap_calls": sorted(zero_wraps),
        "completed_premerge_slots": sorted(completed_slots),
        "slot94_exact_input_identity_proved": slot94_identity(dag, zero_wraps),
        "stages": rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout-ms", type=int, default=10000)
    parser.add_argument("--progress", action="store_true")
    parser.add_argument("--stop-on-failure", action="store_true")
    parser.add_argument(
        "--compositional",
        action="store_true",
        help="use the complete local encoding invariant instead of expanding preceding calls",
    )
    args = parser.parse_args()
    report = (
        prove_compositional(args.progress)
        if args.compositional
        else prove(args.timeout_ms, args.progress, stop_on_failure=args.stop_on_failure)
    )
    print(json.dumps(report, indent=2))
    if not report["full_proof"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
