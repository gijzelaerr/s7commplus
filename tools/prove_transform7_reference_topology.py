"""Check the independent final-chain recipe against actual Transform7 source.

Symbolic provenance/backward liveness only, not arithmetic or solver proof.
Distinct output-origin tokens detect alias/mate mistakes without numeric probes.
"""

from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch

from s7commplus.session_auth.family0 import transform7
from s7commplus.session_auth.family0._generated.data import TRANSFORM7_DATA
from tools import transform7_reference as reference
from tools.recover_monolith5 import _literal


@dataclass(frozen=True)
class Input:
    slot: int


@dataclass(frozen=True)
class Origin:
    call: int
    span: int


def verify(source: str | None = None) -> dict[str, object]:
    source = Path(transform7.__file__).read_text(encoding="utf-8") if source is None else source
    function = next(node for node in ast.parse(source).body if isinstance(node, ast.FunctionDef) and node.name == "execute")
    calls = [
        statement.value
        for statement in function.body
        if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call)
    ]
    prepares = [
        call
        for call in calls
        if isinstance(call.func, ast.Attribute)
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id == "big_int_operations"
        and call.func.attr == "prepare_finalize"
    ]
    expected_prepares = [ast.dump(ast.parse(f"cv[{offset}:]", mode="eval").body) for offset in (0x918, 0x6A8, 0x5B8, 0x288)]
    if (
        len(prepares) != 4
        or any(call.keywords or len(call.args) != 1 for call in prepares)
        or [ast.dump(call.args[0]) for call in prepares] != expected_prepares
    ):
        raise ValueError("finalization input layout changed")
    first = next(
        index
        for index, statement in enumerate(function.body)
        if isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Call)
        and isinstance(statement.value.func, ast.Name)
        and statement.value.func.id == "monolith7_with_copy"
    )
    records: list[tuple[int, tuple[object, ...]]] = []
    buffers: dict[tuple[str, int], object] = {("cv", slot * 24): Input(slot) for slot in (27, 61, 71, 97)}

    def address(node: ast.expr) -> tuple[str, int]:
        if isinstance(node, ast.Name) and node.id == "destination":
            return "destination", 0
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Name)
            and node.value.id in {"wv", "cv", "data"}
            and isinstance(node.slice, ast.Slice)
            and node.slice.upper is None
            and node.slice.step is None
        ):
            return node.value.id, 0 if node.slice.lower is None else _literal(node.slice.lower)
        raise ValueError("unsupported final-chain buffer expression")

    for statement in function.body[first:]:
        if not isinstance(statement, ast.Expr) or not isinstance(statement.value, ast.Call):
            raise ValueError("unsupported final-chain statement")
        call = statement.value
        names = {"monolith4_with_copy": 4, "monolith6_with_copy": 6, "monolith7_with_copy": 7}
        if not isinstance(call.func, ast.Name) or call.func.id not in names or call.keywords:
            raise ValueError("unsupported final-chain wrapper")
        number = names[call.func.id]
        outputs = 1 if number == 4 else 2
        if len(call.args) != {4: 3, 6: 5, 7: 4}[number]:
            raise ValueError("final-chain wrapper arity changed")
        inputs = []
        for node in call.args[outputs:]:
            name, offset = address(node)
            if name == "data":
                inputs.append(bytes(TRANSFORM7_DATA[offset : offset + 72]))
            elif (name, offset) in buffers:
                inputs.append(buffers[name, offset])
            else:
                raise ValueError("final-chain reads an unknown encoded origin")
        index = len(records)
        records.append((number, tuple(inputs)))
        for span, node in enumerate(call.args[:outputs]):
            name, offset = address(node)
            if name not in {"wv", "destination"}:
                raise ValueError("final-chain output buffer changed")
            buffers[name, offset] = Origin(index, span)
    destination = buffers.get(("destination", 0))
    if destination is None:
        raise ValueError("final-chain destination is missing")
    live = set()

    def normalize(value: object, recipe: list[tuple[int, tuple[object, ...]]], collect: bool = False) -> object:
        if not isinstance(value, Origin):
            return value
        if collect:
            live.add(value.call)
        number, inputs = recipe[value.call]
        return number, value.span, tuple(normalize(operand, recipe, collect) for operand in inputs)

    expected = normalize(destination, records, True)
    model_records: list[tuple[int, tuple[object, ...]]] = []

    def encoded(number: int, *inputs: object) -> tuple[Origin, ...]:
        index = len(model_records)
        model_records.append((number, inputs))
        return tuple(Origin(index, span) for span in range(1 if number == 4 else 2))

    with patch.object(reference, "encoded", encoded), patch.object(reference.arithmetic, "encode", side_effect=Input):
        actual = reference.finalize({slot: slot for slot in (27, 61, 71, 97)})
    source_live = [
        (number, tuple(normalize(operand, records) for operand in inputs))
        for index, (number, inputs) in enumerate(records)
        if index in live
    ]
    model_live = [(number, tuple(normalize(operand, model_records) for operand in inputs)) for number, inputs in model_records]
    if expected != normalize(actual, model_records) or source_live != model_live:
        raise ValueError("independent final-chain recipe differs from actual source provenance")
    dead = [index for index in range(len(records)) if index not in live]
    if len(records) != 12 or len(live) != 11 or dead != [7] or records[7][0] != 7 or records[7][1][0] != Input(71):
        raise ValueError("final-chain dead-output accounting changed")
    return {
        "scope": "symbolic final-chain provenance and liveness, not arithmetic proof",
        "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "source_calls": len(records),
        "destination_live_calls": len(live),
        "omitted_dead_calls": dead,
        "dead_context_input": 71,
        "recipe_matches": True,
        "whole_pipeline_solver_proof": False,
    }


if __name__ == "__main__":
    print(json.dumps(verify(), indent=2))
