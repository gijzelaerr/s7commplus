"""Seven-state exact lift transitions, GIVEN the actual corrected residue.

States0/1: zero canonical/lifted;2/3: residues1..6 canonical/lifted;
4/5: residues7..46 canonical/lifted;6: residues>=47, uniquely canonical.
No curve, tape or source-stage data. The residue and addition/subtraction
defect MUST be exact; these rules do not compute either of them.
"""

from __future__ import annotations

from collections.abc import Callable

P = (1 << 160) - 47


def classify(raw: int) -> int:
    if type(raw) is not int or not 0 <= raw < 1 << 160:
        raise ValueError("unsigned160 representative required")
    residue, lifted = raw % P, int(raw >= P)
    return (0 if residue == 0 else 2 if residue <= 6 else 4 if residue <= 46 else 6) + lifted


def addition_lift(a: int, b: int, defective: bool) -> bool:
    """Output0..46 excludes addition defects; identical to nonzero product."""
    return a == 6 or b == 6 or a % 2 == 1 or b % 2 == 1


def subtraction_lift(a: int, b: int, defective: bool) -> bool:
    """Actual corrected output residue must be0..46."""
    return defective or a % 2 == 1 and b < 6 and b % 2 == 0


def nonzero_product_lift(a: int, b: int) -> bool:
    """Actual product output residue must be1..46."""
    return a == 6 or b == 6 or a % 2 == 1 or b % 2 == 1


def zero_product_lift(a: int, b: int) -> bool:
    """Actual product output residue must be zero."""
    return not a == 0 and not b == 0


def square_lift(a: int) -> bool:
    """Actual square output residue must be0..46."""
    return a >= 4 or a % 2 == 1


def transition(operation: str, output_residue: int, a: int, b: int, defective: bool = False) -> bool:
    """Pure finite-state reference; infeasible combinations are not certified."""
    if operation not in ("add", "subtract", "multiply", "square"):
        raise ValueError("unknown lift transition")
    if type(a) is not int or type(b) is not int or not 0 <= a <= 6 or not 0 <= b <= 6:
        raise ValueError("input lift states must be0..6")
    if type(output_residue) is not int or not 0 <= output_residue < P or type(defective) is not bool:
        raise ValueError("canonical output residue and Boolean defect required")
    if operation in ("multiply", "square") and defective:
        raise ValueError("products have no residue defect")
    if defective and (operation == "add" and output_residue < 94 or operation == "subtract" and not 1 <= output_residue <= 46):
        raise ValueError("defect and corrected output category are inconsistent")
    if output_residue > 46:
        return False
    if operation == "add":
        return addition_lift(a, b, defective)
    if operation == "subtract":
        return subtraction_lift(a, b, defective)
    if operation == "square":
        return square_lift(a)
    return nonzero_product_lift(a, b) if output_residue else zero_product_lift(a, b)


def small_addition_lift(a: int, b: int, defective: bool, lift_a: Callable[[], bool], lift_b: Callable[[], bool]) -> bool:
    """Output0..46 excludes defects; no sum or defect query is needed."""
    return a >= 47 or b >= 47 or lift_a() or lift_b()


def small_subtraction_lift(a: int, b: int, defective: bool, lift_a: Callable[[], bool], lift_b: Callable[[], bool]) -> bool:
    """Lazy state rule; a,b are canonical residues, output must be0..46."""
    return defective or a <= 46 and b <= 46 and lift_a() and not lift_b()
