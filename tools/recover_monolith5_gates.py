"""Recover the shared span gate and symmetric combine behind every Monolith5 LUT.

Search every three-input gate with g(000)=0. For each of the 512 inputs,
require the LUT to depend only on the three span gate results. This finds an
exact disjoint functional decomposition, then recognizes choose/majority
under permutation and inversion using the Boolean decomposition machinery.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import TypedDict

from tools.decompose_boolean_polynomial import CORE_FORMULAS, _recognized_kernel


class Gate(TypedDict):
    gate: str
    order: list[int]
    inversions: int
    combine: str


class Model(TypedDict):
    version: int
    functions: list[Gate]


COMBINES = {0x96: "xor3", 0xE8: "majority", 0xFE: "or3", 0x7E: "not_all_equal"}


def truth_to_anf(table: int, inputs: int = 3) -> frozenset[int]:
    """Convert a complete truth table into its unique Boolean polynomial."""
    coefficients = [(table >> index) & 1 for index in range(1 << inputs)]
    for variable in range(inputs):
        for index in range(1 << inputs):
            if index & (1 << variable):
                coefficients[index] ^= coefficients[index ^ (1 << variable)]
    return frozenset(index for index, value in enumerate(coefficients) if value)


def recover_model(path: Path | None = None) -> Model:
    """Prove all LUT decompositions exhaustively; reject ambiguous/unrecognized data."""
    path = path or Path(__file__).with_name("monolith5_model.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    functions: list[Gate] = []
    for encoded in data["luts"]:
        table = int(encoded, 16)
        matches: list[tuple[int, int]] = []
        for gate in range(0, 256, 2):
            outputs: dict[int, int] = {}
            for assignment in range(512):
                selected = sum(((gate >> ((assignment >> (3 * span)) & 7)) & 1) << span for span in range(3))
                value = (table >> assignment) & 1
                if selected in outputs and outputs[selected] != value:
                    break
                outputs[selected] = value
            else:
                if len(outputs) == 8:
                    matches.append((gate, sum(value << selected for selected, value in outputs.items())))
        if len(matches) != 1:
            raise ValueError("Monolith5 LUT requires a unique complete span decomposition")
        gate, combine = matches[0]
        order, core, inversions = _recognized_kernel(3, truth_to_anf(gate))
        known = CORE_FORMULAS.get((3, core))
        if known is None or known[0] not in {"choose", "majority"} or combine not in COMBINES:
            raise ValueError("Monolith5 LUT has an unrecognized gate or combine")
        functions.append({"gate": known[0], "order": list(order), "inversions": inversions, "combine": COMBINES[combine]})
    if len(functions) != 32:
        raise ValueError("Monolith5 requires 32 lane functions")
    return {"version": 1, "functions": functions}


def format_formula(model: Model, function_id: int) -> str:
    """Show one LUT as three identical span gates followed by a named combine."""
    if not 0 <= function_id < len(model["functions"]):
        raise ValueError("Monolith5 function ID must be 0..31")
    function = model["functions"][function_id]
    lines = ["choose(a, b, c) = b XOR ((a XOR b) AND c)", "majority(a, b, c) = (a AND b) XOR (a AND c) XOR (b AND c)"]
    lines.extend(
        [
            "xor3(a, b, c) = a XOR b XOR c",
            "or3(a, b, c) = a OR b OR c",
            "not_all_equal(a, b, c) = xor3(a, b, c) XOR majority(a, b, c)",
        ]
    )
    for span in range(3):
        arguments = [
            f"NOT x{span * 3 + source}" if function["inversions"] & (1 << position) else f"x{span * 3 + source}"
            for position, source in enumerate(function["order"])
        ]
        lines.append(f"s{span} = {function['gate']}({', '.join(arguments)})")
    lines.append(f"F{function_id}(x0, ..., x8) = {function['combine']}(s0, s1, s2)")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--json", action="store_true")
    mode.add_argument("--verify", type=Path)
    mode.add_argument("--formula", type=int)
    args = parser.parse_args()
    model = recover_model()
    if args.formula is not None:
        print(format_formula(model, args.formula))
    elif args.verify is not None:
        if model != json.loads(args.verify.read_text(encoding="utf-8")):
            raise SystemExit("Monolith5 gate model differs from recovered LUTs")
        print("All 32 Monolith5 gate decompositions exactly match all 512 LUT rows")
    elif args.json:
        print(json.dumps(model, separators=(",", ":")))
    else:
        print("Recovered 32 LUTs as shared three-input span gates and symmetric combines")


if __name__ == "__main__":
    main()
