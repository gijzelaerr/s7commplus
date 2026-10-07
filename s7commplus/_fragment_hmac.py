"""Verify legacy S7-1500 V3 fragments without discarding integrity checks.

A multi-fragment V3 response chains its fragments with HMAC-SHA256, but the
PLCs do not agree on the continuation dialect. Real S7-1200/1500 firmware
finalize, then reuse, both SHA-256 states of HMAC for each fragment
(*state-resume*); finalization mutates the chaining state but does not
increase the message byte count, and hashlib deliberately cannot resume a
finalized digest, so the small SHA-256 continuation below handles that wire
compatibility case. PLCSIM Advanced clears the HMAC key each time instead and
chains *feed-forward*: each later fragment's digest is a fresh HMAC over the
previous fragment's digest followed by this fragment's data,
``HMAC(key, digest_{n-1} || fragment_n)``. A response may also carry plain,
independent per-fragment HMACs. The dialect is fixed for the whole response
and is detected from the second fragment; a mismatch afterwards is rejected.

Each verifier is scoped to exactly one reassembled response.

This module is private, and is used only by the opt-in legacy S7-1500
compatibility path. Ordinary frames continue to use hashlib/hmac.

References:
- FIPS 180-4, sections 4.2.2 and 6.2: SHA-256 constants and compression.
- Biham et al., Rogue7 (2019), section 3.1: finalize/update continuation.
  https://i.blackhat.com/USA-19/Thursday/us-19-Bitan-Rogue7-Rogue-Engineering-Station-Attacks-On-S7-Simatic-PLCs-wp.pdf
"""

import hashlib
import hmac
import struct

from typing import Literal

from .error import S7IntegrityError

_SHA256_ROUND_CONSTANTS = (
    0x428A2F98,
    0x71374491,
    0xB5C0FBCF,
    0xE9B5DBA5,
    0x3956C25B,
    0x59F111F1,
    0x923F82A4,
    0xAB1C5ED5,
    0xD807AA98,
    0x12835B01,
    0x243185BE,
    0x550C7DC3,
    0x72BE5D74,
    0x80DEB1FE,
    0x9BDC06A7,
    0xC19BF174,
    0xE49B69C1,
    0xEFBE4786,
    0x0FC19DC6,
    0x240CA1CC,
    0x2DE92C6F,
    0x4A7484AA,
    0x5CB0A9DC,
    0x76F988DA,
    0x983E5152,
    0xA831C66D,
    0xB00327C8,
    0xBF597FC7,
    0xC6E00BF3,
    0xD5A79147,
    0x06CA6351,
    0x14292967,
    0x27B70A85,
    0x2E1B2138,
    0x4D2C6DFC,
    0x53380D13,
    0x650A7354,
    0x766A0ABB,
    0x81C2C92E,
    0x92722C85,
    0xA2BFE8A1,
    0xA81A664B,
    0xC24B8B70,
    0xC76C51A3,
    0xD192E819,
    0xD6990624,
    0xF40E3585,
    0x106AA070,
    0x19A4C116,
    0x1E376C08,
    0x2748774C,
    0x34B0BCB5,
    0x391C0CB3,
    0x4ED8AA4A,
    0x5B9CCA4F,
    0x682E6FF3,
    0x748F82EE,
    0x78A5636F,
    0x84C87814,
    0x8CC70208,
    0x90BEFFFA,
    0xA4506CEB,
    0xBEF9A3F7,
    0xC67178F2,
)


def _rotate_right(v: int, n: int) -> int:
    return ((v >> n) | (v << (32 - n))) & 0xFFFFFFFF


def _continue_sha256(digest: bytes, data: bytes, total: int) -> bytes:
    """Resume a finalized SHA-256 state and finalize after ``data``.

    ``digest`` is the previous final chaining state. ``total`` counts all
    message bytes including the original 64-byte HMAC pad, but excludes
    finalization padding. The previous partial block has already been
    compressed, so this call pads according to len(data), not total.
    This is intentionally not a general-purpose SHA-256 interface.
    """
    h = list(struct.unpack(">8I", digest))
    raw = data + b"\x80" + bytes((55 - len(data)) % 64) + (total * 8).to_bytes(8, "big")
    for off in range(0, len(raw), 64):
        w = list(struct.unpack(">16I", raw[off : off + 64]))
        for j in range(16, 64):
            a, b = w[j - 15], w[j - 2]
            w.append(
                (
                    w[j - 16]
                    + (_rotate_right(a, 7) ^ _rotate_right(a, 18) ^ (a >> 3))
                    + w[j - 7]
                    + (_rotate_right(b, 17) ^ _rotate_right(b, 19) ^ (b >> 10))
                )
                & 0xFFFFFFFF
            )
        a, b, c, d, e, f, g, z = h
        for j in range(64):
            t1 = (
                z
                + (_rotate_right(e, 6) ^ _rotate_right(e, 11) ^ _rotate_right(e, 25))
                + ((e & f) ^ ((~e) & g))
                + _SHA256_ROUND_CONSTANTS[j]
                + w[j]
            ) & 0xFFFFFFFF
            t2 = (
                (_rotate_right(a, 2) ^ _rotate_right(a, 13) ^ _rotate_right(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))
            ) & 0xFFFFFFFF
            a, b, c, d, e, f, g, z = (t1 + t2) & 0xFFFFFFFF, a, b, c, (d + t1) & 0xFFFFFFFF, e, f, g
        h = [(x + y) & 0xFFFFFFFF for x, y in zip(h, (a, b, c, d, e, f, g, z))]
    return struct.pack(">8I", *h)


class FragmentHMACVerifier:
    """Authenticate fragments belonging to one V3 response.

    The first fragment must always carry a standard HMAC. The second picks the
    continuation dialect among independent fragments, the state-resume
    continuation, and the feed-forward chain, and the choice is then fixed for
    the rest of the response. Return application data only after comparing the
    full digest in constant time.

    Construct a fresh verifier per response; never share it between sessions.
    """

    def __init__(self, session_key: bytes) -> None:
        if len(session_key) < 24:
            raise ValueError("A V3 SessionKey must contain at least 24 bytes")
        self._key = session_key[:24]
        self._inner: bytes | None = None
        self._outer: bytes | None = None
        self._inner_count = 64
        self._outer_count = 64
        # The previous fragment's received digest, for the feed-forward dialect.
        self._last = b""
        self._mode: Literal["independent", "legacy", "feed-forward"] | None = None

    def verify(self, protected: bytes) -> bytes:
        if not protected or protected[0] != 32 or len(protected) < 33:
            raise S7IntegrityError("Invalid V3 HMAC prefix")
        received = protected[1:33]
        data = protected[33:]

        if self._inner is None:
            independent = hmac.new(self._key, data, hashlib.sha256).digest()
            if not hmac.compare_digest(received, independent):
                raise S7IntegrityError("Invalid V3 HMAC")
            ipad = bytes(value ^ 0x36 for value in self._key.ljust(64, b"\0"))
            self._inner = hashlib.sha256(ipad + data).digest()
            self._outer = independent
            self._inner_count += len(data)
            self._outer_count += 32
            self._last = received
            return data

        if self._mode == "independent":
            independent = hmac.new(self._key, data, hashlib.sha256).digest()
            if not hmac.compare_digest(received, independent):
                raise S7IntegrityError("Invalid V3 continuation HMAC")
            self._last = received
            return data

        if self._mode == "feed-forward":
            expected = hmac.new(self._key, self._last + data, hashlib.sha256).digest()
            if not hmac.compare_digest(received, expected):
                raise S7IntegrityError("Invalid V3 continuation HMAC")
            self._last = received
            return data

        assert self._outer is not None
        inner_count = self._inner_count + len(data)
        outer_count = self._outer_count + 32
        inner = _continue_sha256(self._inner, data, inner_count)
        outer = _continue_sha256(self._outer, inner, outer_count)

        if self._mode == "legacy":
            if not hmac.compare_digest(received, outer):
                raise S7IntegrityError("Invalid V3 continuation HMAC")
            self._inner, self._outer = inner, outer
            self._inner_count, self._outer_count = inner_count, outer_count
            self._last = received
            return data

        # Second fragment: detect the dialect and fix it for the rest of the response.
        independent = hmac.new(self._key, data, hashlib.sha256).digest()
        feed_forward = hmac.new(self._key, self._last + data, hashlib.sha256).digest()
        if hmac.compare_digest(received, independent):
            self._mode = "independent"
        elif hmac.compare_digest(received, outer):
            self._mode = "legacy"
            self._inner, self._outer = inner, outer
            self._inner_count, self._outer_count = inner_count, outer_count
        elif hmac.compare_digest(received, feed_forward):
            self._mode = "feed-forward"
        else:
            raise S7IntegrityError("Invalid V3 continuation HMAC")
        self._last = received
        return data
