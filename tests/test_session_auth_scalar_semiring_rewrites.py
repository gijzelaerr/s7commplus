"""Compositional exact rewrite laws from the proved field/saturation quotient.

These numerical controls are not an additional all-domain solver proof. The
laws follow algebraically from the existing all-domain primitive contracts.
"""

from itertools import product
from math import gcd

from tools import transform12_integer_model as source
from tools.scalar_cancel_macros import cancellation_carry as carry
from tools.scalar_shift_macros import CORRECTION, LOW, P

VALUES = (0, 1, 2, 45, 46, 47, 48, 94, LOW - 1, LOW, LOW + 47, LOW + 100, P - 100, P - 1, P, P + 1, P + 46)


def test_finite_saturation_semiring_associativity_and_distributivity() -> None:
    for a, b, c in product(range(48), repeat=3):
        assert min(min(a + b, 47) + c, 47) == min(a + min(b + c, 47), 47)
        assert min(min(a * b, 47) * c, 47) == min(a * min(b * c, 47), 47)
        assert min(a * min(b + c, 47), 47) == min(min(a * b, 47) + min(a * c, 47), 47)


def test_raw_add_associativity_iff_actual_carry_counts_balance() -> None:
    assert gcd(CORRECTION, P) == 1
    for a, b, c in product(VALUES, repeat=3):
        ab, bc = source.add(a, b), source.add(b, c)
        left, right = source.add(ab, c), source.add(a, bc)
        left_carries = int(carry(a, b)) + int(carry(ab, c))
        right_carries = int(carry(b, c)) + int(carry(a, bc))
        assert (left == right) == (left_carries == right_carries)
    assert source.add(source.add(1, LOW - 1), P) != source.add(1, source.add(LOW - 1, P))


def test_raw_distributivity_iff_the_weighted_carry_defects_balance() -> None:
    for a, b, c in product(VALUES, repeat=3):
        ab, ac = source.multiply(a, b), source.multiply(a, c)
        left, right = source.multiply(a, source.add(b, c)), source.add(ab, ac)
        weighted_left = a % P * int(carry(b, c)) % P
        weighted_right = int(carry(ab, ac))
        assert (left == right) == (weighted_left == weighted_right)
    # Defects need not be absent, and equal unweighted carry counts do NOT
    # suffice under multiplication. This is why ordinary factoring can fail.
    b, c = P - 100, LOW + 100
    assert carry(b, c)
    for a in (P, 1, P + 1):
        assert source.multiply(a, source.add(b, c)) == source.add(source.multiply(a, b), source.multiply(a, c))
    assert carry(source.multiply(2, b), source.multiply(2, c))
    assert source.multiply(2, source.add(b, c)) != source.add(source.multiply(2, b), source.multiply(2, c))


def test_raw_multiplication_is_associative_without_discarding_lifts() -> None:
    for a, b, c in product(VALUES, repeat=3):
        assert source.multiply(source.multiply(a, b), c) == source.multiply(a, source.multiply(b, c))
    assert source.multiply(P - 1, P - 1) == P + 1
    assert source.multiply(P, 1) == P
    assert source.multiply(P, 0) == 0
