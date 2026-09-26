"""Standalone exact uint160 arithmetic using field residues and one lift bit.

Research only: no source SSA, tape, curve assumptions, or runtime changes.
A lift bit is legal only for residues 0..46. The three-fold product oracle
remains independent; this model uses a modular product and a Boolean lift.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from tools import transform12_residue_defects as arithmetic

MODULUS = arithmetic.P


def addition_constant_safe(c: int) -> bool:
    """Either uint160 operand is this constant: a defect is impossible."""
    return c <= arithmetic.LOW_LIMIT - 47


def subtraction_right_constant_safe(c: int) -> bool:
    """Subtracting a constant at most p cannot require a second wrap."""
    return c <= MODULUS


def subtraction_left_constant_safe(c: int) -> bool:
    """A constant first operand at least47 prevents a second wrap."""
    return c >= 47


def addition_defect(s: int, k: int) -> bool:
    """s is the residue sum; k is the number of lifted operands."""
    return (
        k == 0
        and s >= MODULUS + 47
        and s % arithmetic.LOW_LIMIT >= arithmetic.LOW_LIMIT - 47
        or k == 1
        and s >= 47
        and s % arithmetic.LOW_LIMIT < 47
        or k == 2
        and s >= 47
    )


def addition_tag(s: int, k: int, defective: bool) -> bool:
    """A defective sum is never p-lifted; the remaining cases are intervals."""
    return not defective and (k == 0 and MODULUS <= s < MODULUS + 47 or k == 1 and (s < 47 or s >= MODULUS) or k == 2 and s < 47)


def subtraction_defect(a: int, b: int, ta: bool, tb: bool) -> bool:
    """Exactly the canonical-small minus larger p-lifted-small case."""
    return not ta and tb and a < b


def subtraction_tag(a: int, b: int, ta: bool, tb: bool) -> bool:
    """Positive p-lifted difference, or the exceptional second wrap."""
    return ta and not tb and a >= b or not ta and tb and a < b


def nonzero_product_lift(a: int, b: int, lift_a: Callable[[], bool], lift_b: Callable[[], bool]) -> bool:
    """Output residue must be1..46; a,b are its canonical input residues.

    A nonzero product residue implies a,b are positive. Crossing p settles
    the output lift; otherwise only ambiguous operand lifts can matter.
    Keep callbacks lazy: a settled output must not walk their dependencies.
    Zero outputs require the separate positivity rule and must not use this.
    """
    return a * b >= MODULUS or a <= 46 and lift_a() or b <= 46 and lift_b()


def square_lift(a: int, lift_a: Callable[[], bool]) -> bool:
    """Exact square lift, conditional on its output residue being0..46.

    A canonical square below p with a>=7 would have residue at least49,
    contradicting the precondition. Smaller inputs need only their lift.
    Includes zero outputs and does not assume p is prime.
    """
    return a >= 7 or lift_a()


def small_nonzero_product_lift(a: int, b: int, lift_a: Callable[[], bool], lift_b: Callable[[], bool]) -> bool:
    """Output residue must be1..46. Eliminate the integer product threshold.

    A large positive factor gives canonical product at least47. Its small
    residue therefore forces a wrap. Two small factors cannot cross p;
    only an operand lift can. Zero outputs require the positivity rule.
    """
    return a >= 47 or b >= 47 or lift_a() or lift_b()


def subtraction_lift(a: int, b: int, defective: bool, lift_a: Callable[[], bool], lift_b: Callable[[], bool]) -> bool:
    """Canonical input residues, legal lifts and an already decided defect.

    A defect settles the lift. Otherwise only b<=a<=46 can be lifted;
    query the left lift first and query the right only if it is true.
    This exact tag rule includes zero outputs, unlike the product shortcut.
    """
    return defective or b <= a <= 46 and lift_a() and not lift_b()


def addition_lift(s: int, lift_a: Callable[[], bool], lift_b: Callable[[], bool]) -> bool:
    """Canonical residue sum and legal lifts; no defect decision needed.

    Defective sums cannot be in either permitted interval. The wrap
    interval settles the lift as true; only a sum at most46 needs operand
    lifts, queried with lazy OR. This exact tag rule includes zero outputs.
    """
    return MODULUS <= s < MODULUS + 47 or s <= 46 and (lift_a() or lift_b())


def lazy_addition_defect(a: int, b: int, lift_a: Callable[[], bool], lift_b: Callable[[], bool]) -> bool:
    """Exact defect on canonical residues and legal lazy operand lifts.

    A large sum permits no input lifts. Sums47..92 need two lifts; low-word
    wrap sums need one. Tests separately establish Python callback demand.
    """
    return (
        a + b >= MODULUS + 47
        and (a + b) % arithmetic.LOW_LIMIT >= arithmetic.LOW_LIMIT - 47
        or 47 <= a + b <= 92
        and a <= 46
        and b <= 46
        and lift_a()
        and lift_b()
        or a + b >= arithmetic.LOW_LIMIT
        and (a + b) % arithmetic.LOW_LIMIT < 47
        and (a <= 46 and lift_a() or b <= 46 and lift_b())
    )


def lazy_subtraction_defect(a: int, b: int, lift_a: Callable[[], bool], lift_b: Callable[[], bool]) -> bool:
    """Exact second-wrap decision; a true left lift settles it as false."""
    return a < b <= 46 and not lift_a() and lift_b()


@dataclass(frozen=True)
class Representative:
    residue: int
    lifted: bool = False

    def __post_init__(self) -> None:
        if type(self.residue) is not int or not 0 <= self.residue < MODULUS:
            raise ValueError("canonical residue required")
        if type(self.lifted) is not bool or self.lifted and self.residue > 46:
            raise ValueError("a Boolean lift is permitted only for residues 0..46")

    @classmethod
    def from_integer(cls, value: int) -> Representative:
        arithmetic.validate(value, 0)
        return cls(value % MODULUS, value >= MODULUS)

    def integer(self) -> int:
        return self.residue + MODULUS * self.lifted


def add(a: Representative, b: Representative) -> tuple[Representative, int]:
    s, k = a.residue + b.residue, int(a.lifted) + int(b.lifted)
    defective = addition_defect(s, k)
    correction = arithmetic.ADD_DEFECT if defective else 0
    return Representative((s + correction) % MODULUS, addition_tag(s, k, defective)), correction


def subtract(a: Representative, b: Representative) -> tuple[Representative, int]:
    correction = 47 if subtraction_defect(a.residue, b.residue, a.lifted, b.lifted) else 0
    return Representative(
        (a.residue - b.residue + correction) % MODULUS,
        subtraction_tag(a.residue, b.residue, a.lifted, b.lifted),
    ), correction


def multiply(a: Representative, b: Representative) -> Representative:
    product = a.residue * b.residue
    residue = product % MODULUS
    positive_a, positive_b = a.residue != 0 or a.lifted, b.residue != 0 or b.lifted
    lifted = residue <= 46 and positive_a and positive_b and (a.lifted or b.lifted or product >= MODULUS)
    return Representative(residue, lifted)
