"""The SessionKey blob algorithm for real S7-1200 and S7-1500 PLCs.

HarpoS7 calls this algorithm "Family 0". It serves both real-PLC key
families, 00 (S7-1500) and 01 (S7-1200); PLCSIM's family 03 has its own
algorithm in ``v1_session_key.plcsim``.

- ``authenticator``: builds the 180-byte SecurityKeyEncryptedKey blob.
- ``seed``: the encrypted seed and the blob's three keys, from key1 and the
  PLC public key (HarpoS7's PreSeed, Seed, Transform13 and KeyDerivation
  transforms).
- ``curve``: the 160-bit elliptic curve behind the seed's ECDH.
- ``present``: the PRESENT-80 variant behind the seed and the keys.
- ``checksum``: the GF(2^128) multiply for the blob's checksum.
- ``fingerprint``: the challenge fingerprint for the session key, a fixed-key
  SPN on AES's inverse S-box.

HarpoS7's transpiled originals, their vendored tables and the ports these
modules replace are not part of this package; the tests check each module
against answers recorded from them (``tests/fixtures/family0``).
"""
