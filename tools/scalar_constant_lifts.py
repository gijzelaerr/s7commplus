"""Exact small-output lift rule for a positive raw constant multiplier.

If the corrected product residue is0..46, its lift equals raw_product>=47.
For a positive raw constant c this needs only a>=floor(46/c)+1 or the
variable operand's lift. Includes zero residues and c>=p, without primality.
Zero multipliers must be handled separately and never queried here.
"""

from __future__ import annotations

from collections.abc import Callable


def threshold(constant: int) -> int:
    if type(constant) is not int or not 1 <= constant < 1 << 160:
        raise ValueError("positive uint160 raw multiplier required")
    return 46 // constant + 1


def lift(a: int, cutoff: int, lift_a: Callable[[], bool]) -> bool:
    """Output residue0..46 and cutoff=threshold(positive raw multiplier)."""
    return a >= cutoff or lift_a()
