"""Trace candidate span semantics and compose them through the real setup AST.

The default composition omits the source-derived wrapper corrections and is
therefore conditional on their vanishing. The corrected composition retains
every wrap/truncation and final-merge term. Neither is an input-only encoded
replacement. Single-threaded patching only; never supply live secrets.
"""

from __future__ import annotations

import ast
import inspect
import json
import random
import struct
from collections.abc import Callable, Mapping
from contextlib import ExitStack
from dataclasses import asdict, dataclass
from fractions import Fraction
from unittest.mock import patch

from s7commplus.session_auth.family0 import transform7
from s7commplus.session_auth.family0._generated.data import TRANSFORM7_DATA
from tools.recover_monolith5_span_decoder import P, local_gate, recover
from tools.recover_transform7_setup import Candidate, capture_setup, targeted_base_point_probe
from tools.transform7_setup_merge import decode_payload

NAMES = tuple(f"monolith{i}_with_copy" for i in (3, 4, 5, 6))


def span_shadow(span: bytes) -> int:
    """Candidate residue of the SIGNED gate sum, not decode_span(span) % p."""
    if len(span) != 72:
        raise ValueError("span must contain exactly 72 bytes")
    words = struct.unpack("<18I", span)
    model = recover()
    return (sum(term.weight * local_gate(term, words) for term in model.terms) + model.constant * pow(3, -1, P)) % P


@dataclass(frozen=True)
class Observation:
    operation: str
    actual: int
    expected: int


def trace(x: int, y: int, r: int) -> tuple[Observation, ...]:
    """Observe every setup wrapper; copy inputs before possible aliased writes."""
    observations = []

    def wrap(name: str, original: Callable[..., None]) -> Callable[..., None]:
        def execute(*buffers: memoryview | bytes) -> None:
            outputs = 1 if name == NAMES[1] else 2
            inputs = [bytes(buffer[:72]) for buffer in buffers[outputs:]]
            values = [span_shadow(value) for value in inputs[:2]]
            if name == NAMES[0]:
                expected = (sum(values) * pow(2, -1, P) + int.from_bytes(inputs[2][:24], "little") * pow(4, -1, P)) % P
            elif name == NAMES[1]:
                expected = sum(values) % P
            else:
                expected = (sum(values) + span_shadow(inputs[2])) % P
                if name == NAMES[3]:
                    expected = expected * pow(2, -1, P) % P
            original(*buffers)
            if name == NAMES[2]:
                actual = sum(decode_payload(bytes(buffer[:24])) for buffer in buffers[:2]) % P
            else:
                actual = sum(span_shadow(bytes(buffer[:72])) for buffer in buffers[:outputs]) % P
            observations.append(Observation(name, actual, expected))

        return execute

    with ExitStack() as stack:
        for name in NAMES:
            stack.enter_context(patch.object(transform7, name, wrap(name, getattr(transform7, name))))
        capture_setup(x, y, r)
    return tuple(observations)


@dataclass(frozen=True)
class Expression:
    terms: tuple[tuple[str, Fraction], ...]

    @classmethod
    def variable(cls, name: str) -> Expression:
        return cls(((name, Fraction(1)),))

    def __add__(self, other: Expression) -> Expression:
        values = dict(self.terms)
        for name, coefficient in other.terms:
            values[name] = values.get(name, Fraction(0)) + coefficient
        return Expression(tuple(sorted((name, value) for name, value in values.items() if value)))

    def scale(self, factor: Fraction | int) -> Expression:
        return Expression(tuple((name, value * factor) for name, value in self.terms if value * factor))

    def evaluate(self, values: Mapping[str, int]) -> int:
        """Evaluate over Z/pZ using unit denominators, not a primality assumption."""
        return (
            sum(coefficient.numerator * pow(coefficient.denominator, -1, P) * values[name] for name, coefficient in self.terms)
            % P
        )


Pointer = tuple[str, int]


def _pointer(node: ast.expr) -> Pointer:
    if isinstance(node, ast.Name) and node.id in {"wv", "cv", "data"}:
        return node.id, 0
    if (
        isinstance(node, ast.Subscript)
        and isinstance(node.slice, ast.Slice)
        and node.slice.upper is None
        and node.slice.step is None
    ):
        bank, offset = _pointer(node.value)
        lower = node.slice.lower
        if isinstance(lower, ast.Constant) and type(lower.value) is int:
            return bank, offset + lower.value
    raise ValueError("unsupported setup pointer")


def _copied_payload(node: ast.expr) -> Pointer:
    """Validate bytes(ctx/w[offset:offset+24]) instead of assuming merge inputs."""

    def integer(value: ast.expr | None) -> int:
        if isinstance(value, ast.Constant) and type(value.value) is int:
            return value.value
        if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Add):
            return integer(value.left) + integer(value.right)
        raise ValueError("unsupported setup copy offset")

    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "bytes"
        and len(node.args) == 1
        and not node.keywords
    ):
        source = node.args[0]
        if (
            isinstance(source, ast.Subscript)
            and isinstance(source.value, ast.Name)
            and source.value.id in {"ctx", "w"}
            and isinstance(source.slice, ast.Slice)
            and source.slice.step is None
        ):
            offset = integer(source.slice.lower)
            if integer(source.slice.upper) == offset + 24:
                return ("cv" if source.value.id == "ctx" else "wv"), offset
    raise ValueError("unsupported setup payload copy")


def compose(*, corrected: bool = False) -> dict[int, Expression]:
    """Compose span identities through source calls, retaining unknown pair splits.

    Pair members are NOT assumed to have individually affine semantics. Fresh
    nuisance variables represent their unknown split and must cancel at exits.
    With corrections, c0..c22 denote additive wrapper residue corrections in
    source-call order; merge<slot> denotes that slot's final carry correction.
    """
    zero = Expression(())
    encoded = {("data", 0): zero, ("data", 72): Expression.variable("d")}
    plain = {("wv", 0): Expression.variable("X"), ("wv", 72): Expression.variable("Y"), ("wv", 48): Expression.variable("R")}
    result = {}
    packed_pairs = {}
    count = 0
    merges = set()
    body = ast.parse(inspect.getsource(transform7.execute)).body[0]
    if not isinstance(body, ast.FunctionDef):
        raise ValueError("expected Transform7 function")
    for statement in body.body:
        if isinstance(statement, ast.For) and any(
            isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "execute"
            for node in ast.walk(statement)
        ):
            break
        if not isinstance(statement, ast.Expr) or not isinstance(statement.value, ast.Call):
            continue
        call = statement.value
        if isinstance(call.func, ast.Attribute) and call.func.attr == "rotate_right_30":
            plain["wv", 0] = plain["wv", 0].scale(4)
            continue
        if isinstance(call.func, ast.Name) and call.func.id == "big_int_addition":
            if len(call.args) != 3 or call.keywords:
                raise ValueError("unexpected setup merge signature")
            bank, offset = _pointer(call.args[0])
            slot = offset // 24
            if bank != "cv" or offset % 24 or slot not in result or slot in merges:
                raise ValueError("unexpected setup merge destination")
            if tuple(_copied_payload(node) for node in call.args[1:]) != packed_pairs[slot]:
                raise ValueError("setup merge does not consume its Monolith5 output pair")
            if corrected:
                result[slot] = result[slot] + Expression.variable(f"merge{slot}")
            merges.add(slot)
            continue
        if not isinstance(call.func, ast.Name) or call.func.id not in NAMES:
            continue
        name = call.func.id
        pointers = [_pointer(arg) for arg in call.args]
        outputs = 1 if name == NAMES[1] else 2
        inputs = pointers[outputs:]
        value = encoded[inputs[0]] + encoded[inputs[1]]
        if name == NAMES[0]:
            value = value.scale(Fraction(1, 2)) + plain[inputs[2]].scale(Fraction(1, 4))
        elif name in (NAMES[2], NAMES[3]):
            value = value + encoded[inputs[2]]
            if name == NAMES[3]:
                value = value.scale(Fraction(1, 2))
        if corrected:
            value = value + Expression.variable(f"c{count}")
        if name == NAMES[2]:
            bank, offset = pointers[0]
            if bank != "cv" or offset % 24:
                raise ValueError("unexpected setup context destination")
            result[offset // 24] = value
            packed_pairs[offset // 24] = tuple(pointers[:2])
        elif outputs == 1:
            encoded[pointers[0]] = value
        else:
            split = Expression.variable(f"split{count}")
            encoded[pointers[0]] = split
            encoded[pointers[1]] = value + split.scale(-1)
        count += 1
    if count != 23 or set(result) != {46, 48, 70, 94} or merges != set(result):
        raise ValueError("unexpected setup call graph")
    if any(name.startswith("split") for expression in result.values() for name, _ in expression.terms):
        raise ValueError("unknown output-pair split survives setup composition")
    return result


def conditional_candidate() -> Candidate:
    """Read offsets from bundled data and source composition, not recovery probes."""
    if span_shadow(TRANSFORM7_DATA[:72]) != 0:
        raise ValueError("bundled zero span changed")
    d = span_shadow(TRANSFORM7_DATA[72:144])
    expressions = compose()

    def residue(value: Fraction) -> int:
        return value.numerator * pow(value.denominator, -1, P) % P

    offsets = tuple(residue(dict(expressions[slot].terms).get("d", Fraction(0))) * d % P for slot in (46, 48, 70))
    matrix = tuple(
        tuple(residue(dict(expressions[slot].terms).get(name, Fraction(0))) for name in ("X", "Y", "R")) for slot in (46, 48, 70)
    )
    return Candidate(offsets, matrix)


def main() -> None:
    rng = random.Random(0x7346)
    cases = [(0, 0, 0), (1, 1, 1), ((1 << 160) - 1,) * 3, targeted_base_point_probe()]
    cases.extend(tuple(rng.getrandbits(160) for _ in range(3)) for _ in range(128))
    observations = [observation for case in cases for observation in trace(*case)]
    print(
        json.dumps(
            {
                "scope": "sampled zero-correction wrappers; exact source composition CONDITIONAL on corrections vanishing",
                "cases": len(cases),
                "wrapper_observations": len(observations),
                "mismatches": [asdict(value) for value in observations if value.actual != value.expected],
                "composition": {
                    slot: {name: str(value) for name, value in expression.terms} for slot, expression in compose().items()
                },
                "candidate": asdict(conditional_candidate()),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
