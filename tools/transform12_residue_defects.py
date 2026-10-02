"""Exact compatibility representatives lifted to residues with explicit defects.

Addition has one exceptional low-128 carry predicate and a fixed residue
correction. Subtraction has one exceptional negative-wrap predicate.
Multiplication's folds preserve residues throughout the uint160 domain.
These observations do not authorize a compact production curve replacement.
"""

from __future__ import annotations

from dataclasses import dataclass

from tools import transform12_integer_model as exact

P = exact.CANDIDATE_MODULUS
LOW_LIMIT = 1 << 128
ADD_DEFECT = 2 * exact.FOLD - LOW_LIMIT


@dataclass(frozen=True)
class Result:
    representative: int
    residue: int
    correction: int


def validate(a: int, b: int) -> None:
    if any(type(value) is not int or not 0 <= value < exact.LIMIT for value in (a, b)):
        raise ValueError("unsigned 160-bit representatives required")


def add(a: int, b: int) -> Result:
    """One overflow fold, with a fixed correction when its upper carry is lost."""
    validate(a, b)
    total = a + b
    exceptional = total >= exact.LIMIT and total % LOW_LIMIT >= LOW_LIMIT - exact.FOLD
    correction = ADD_DEFECT if exceptional else 0
    representative = total if total < exact.LIMIT else total - P + correction
    return Result(representative, (total + correction) % P, correction)


def subtract(a: int, b: int) -> Result:
    """The second negative wrap adds LIMIT, hence a residue defect of 47."""
    validate(a, b)
    difference = a - b
    representative = difference if difference >= 0 else difference + P
    exceptional = representative < 0
    if exceptional:
        representative += exact.LIMIT
    correction = exact.FOLD if exceptional else 0
    return Result(representative, (difference + correction) % P, correction)


def multiply(a: int, b: int) -> Result:
    """Three ordinary high-160 folds; third fold cannot overflow its low word."""
    validate(a, b)
    value = a * b
    for _ in range(3):
        if value >= exact.LIMIT:
            value = value % exact.LIMIT + (value // exact.LIMIT) * exact.FOLD
    if not 0 <= value < exact.LIMIT:
        raise AssertionError("three-fold uint160 product bound failed")
    return Result(value, a * b % P, 0)
