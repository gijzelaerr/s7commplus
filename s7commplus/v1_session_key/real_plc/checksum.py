"""GF(2^128) multiplication for the blob's GHASH-style checksum.

The authenticator folds each ciphertext block into the checksum as
``c = multiply(c ^ block, H)``. Products are taken in GF(2)[x] modulo
``POLYNOMIAL`` (x^128 + x^32 + x^15 + x^2 + 1, irreducible), with 16-byte
values read little endian and bit i as the coefficient of x^i. That is not the
AES-GCM field or bit order.

HarpoS7's ``ChecksumTransform`` and ``LutGenerator`` compute the same product
with a 4 KB table; their ports are kept in ``old/family0`` in the repository.
"""

from __future__ import annotations

POLYNOMIAL = (1 << 128) | (1 << 32) | (1 << 15) | (1 << 2) | 1


def multiply(a: int, b: int) -> int:
    """``a * b`` in GF(2)[x] modulo ``POLYNOMIAL``, for 128-bit ``a`` and ``b``."""
    product = 0
    while b:
        if b & 1:
            product ^= a
        b >>= 1
        a <<= 1
        if a >> 128:
            a ^= POLYNOMIAL
    return product
