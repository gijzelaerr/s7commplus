"""Input-only carry-save model of every Family0 Transform7 setup wrapper.

Checkout analysis only. Pair formulas require the proved reachable upper-zero
invariant; they are NOT valid for arbitrary raw encodings with the same B/h.
No generated kernel or runtime arithmetic helper is executed by this model.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass

from tools.recover_monolith5_span_decoder import MODULUS, P
from tools.transform7_setup_merge import Merge, merge

H = (P + 1) // 2
MASK = MODULUS - 1
LIMIT = 1 << 160
D = 479351431067838523670377406553314858552643643568


@dataclass(frozen=True)
class Span:
    payload: int
    boundary: int = 0

    def __post_init__(self) -> None:
        if type(self.payload) is not int or not 0 <= self.payload < MODULUS:
            raise ValueError("expected unsigned 168-bit decoded payload")
        if type(self.boundary) is not int or self.boundary not in (0, 1):
            raise ValueError("expected a boundary bit")


Pair = tuple[Span, Span]
ZERO = Span(0)


def carry_save(spans: tuple[Span, Span, Span]) -> tuple[int, int]:
    """Return S,C with S+2*C=sum(B)+H*parity(h)+majority(h) exactly."""
    if len(spans) != 3:
        raise ValueError("expected three decoded spans")
    a, b, c = (span.payload for span in spans)
    boundaries = sum(span.boundary for span in spans)
    u = a ^ b ^ c
    v = H * (boundaries & 1)
    majority = (a & b) | (a & c) | (b & c)
    w = (majority << 1) | int(boundaries >= 2)
    return u ^ v ^ w, (u & v) | (u & w) | (v & w)


def halve(spans: tuple[Span, Span, Span]) -> Pair:
    """Decoded Monolith6 on reachable setup spans, including individual split."""
    if any(span.payload >= 1 << 166 for span in spans):
        raise ValueError("setup pair theorem requires B<2^166 and valid upper encoding")
    total, carry = carry_save(spans)
    return Span(total >> 1, total & 1), Span(carry)


def quarter(pair: Pair, plain: int) -> Pair:
    """Decoded Monolith3: a plain N becomes the virtual span (N>>1,N&1)."""
    if len(pair) != 2 or type(plain) is not int or not 0 <= plain < 1 << 162:
        raise ValueError("expected two spans and unsigned 162-bit setup plain input")
    return halve((*pair, Span(plain >> 1, plain & 1)))


def add(pair: Pair) -> Span:
    """Decoded Monolith4; reject overflow instead of silently dropping its wrap."""
    if len(pair) != 2:
        raise ValueError("expected two decoded spans")
    a, b = pair
    return Span(a.payload + b.payload + a.boundary * b.boundary, a.boundary ^ b.boundary)


def pack(spans: tuple[Span, Span, Span]) -> tuple[int, int]:
    """Both Monolith5 168-bit streams, valid for every decoded B/h input."""
    total, carry = carry_save(spans)
    return total & MASK, (carry << 1) & MASK


@dataclass(frozen=True)
class Step:
    number: int
    inputs: tuple[Span, ...]
    plain: int | None
    outputs: tuple[Span, ...] = ()
    streams: tuple[int, int] | None = None


@dataclass(frozen=True)
class Setup:
    steps: tuple[Step, ...]
    merges: tuple[tuple[int, Merge], ...]

    @property
    def slots(self) -> tuple[int, ...]:
        values = {slot: value.result for slot, value in self.merges}
        return tuple(values[slot] for slot in (46, 48, 70, 94))


def model(x: int, y: int, r: int) -> Setup:
    """Exact representatives of setup slots 46/48/70/94 from public synthetic inputs.

    This models the pinned setup call topology. The separate source proof and
    differential tests establish its correspondence; runtime is unchanged.
    """
    if any(type(value) is not int or not 0 <= value < LIMIT for value in (x, y, r)):
        raise ValueError("expected unsigned 160-bit setup inputs")
    return _compose(x, y, r)


def _compose(x: int, y: int, r: int) -> Setup:
    """Shared recipe; the source checker also runs it with provenance tokens."""
    y, r = y | 4, r | 4
    steps: list[Step] = []
    merges: list[tuple[int, Merge]] = []

    def m3(pair: Pair, plain: int) -> Pair:
        output = quarter(pair, plain)
        steps.append(Step(3, pair, plain, output))
        return output

    def m4(pair: Pair) -> Span:
        output = add(pair)
        steps.append(Step(4, pair, None, (output,)))
        return output

    def m6(single: Span, pair: Pair) -> Pair:
        inputs = (single, *pair)
        output = halve(inputs)
        steps.append(Step(6, inputs, None, output))
        return output

    def m5(slot: int, single: Span, pair: Pair) -> None:
        inputs = (single, *pair)
        streams = pack(inputs)
        steps.append(Step(5, inputs, None, streams=streams))
        merges.append((slot, merge(*streams)))

    bundled = (ZERO, Span(D))
    pair0 = m3(bundled, r)
    pair1 = m3(bundled, y)
    pair2 = m3(pair0, x)
    pair3 = m3(pair2, y)
    m5(46, m4(pair3), pair3)
    pair6 = m3(pair3, r)
    m6(m4(bundled), pair0)  # Calls 7/8 are dead for these four setup slots.
    pair10 = m6(m4(pair6), pair1)
    pair12 = m6(m4(pair0), pair2)
    pair14 = m6(m4(pair12), pair1)
    m5(70, m4(pair14), pair14)
    pair18 = m6(m4(pair10), pair14)
    m5(48, m4(pair18), pair18)
    pair21 = m3((ZERO, ZERO), x << 2)
    m5(94, ZERO, pair21)
    if len(steps) != 23:
        raise AssertionError("setup model topology changed")
    return Setup(tuple(steps), tuple(merges))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("x", "y", "r"):
        parser.add_argument(f"--{name}", type=lambda value: int(value, 0))
    parser.add_argument(
        "--carry-witness", action="store_true", help="use the public synthetic regression without running the original setup"
    )
    args = parser.parse_args()
    values = (args.x, args.y, args.r)
    if args.carry_witness:
        if any(value is not None for value in values):
            parser.error("--carry-witness cannot be combined with --x/--y/--r")
        from s7commplus.session_auth.family0._generated.data import TRANSFORM7_DATA

        source = TRANSFORM7_DATA[0xD8:]
        values = (
            int.from_bytes(source[:20], "little"),
            int.from_bytes(source[20:40], "little"),
            1456322070154714087054275448276265639382807574476,
        )
    try:
        result = model(*(0 if value is None else value for value in values))
    except ValueError as error:
        parser.error(str(error))
    print(
        json.dumps(
            {
                "scope": "input-only exact integer setup, checkout analysis; source proof is separate",
                "slots": result.slots,
                "merges": [{"slot": slot, **asdict(value)} for slot, value in result.merges],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
