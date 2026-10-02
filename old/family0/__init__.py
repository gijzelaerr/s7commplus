"""Retired Family-0 transforms, the generated monoliths they call, and their tables.

- ``_generated/``: Monolith1-11 as mechanically transpiled from HarpoS7 (do
  not edit; see ``tools/transpile_harpo_monolith.py``) and, in ``data/``, the
  vendored HarpoS7 tables;
- ``transform7``, ``transform12``, ``transform13``, ``big_int_operations``,
  ``big_int_transforms`` and ``monolith_wrappers``: the manual HarpoS7 ports
  that call them;
- ``transform7_compact``, ``transform12_compact`` and ``monolith5_compact``:
  the proven integer models of Transform7/Transform12 that replaced them
  before SeedTransform became the ECDH in ``s7commplus/.../family0/curve.py``;
- ``pre_seed_transform``, ``key_derivation_transform`` and ``seed_transform``:
  the encoded HarpoS7 ports of ``s7commplus/.../family0/seed.py``;
- ``encoding`` and ``monolith11_compact``: decoders for the encoded values
  those ports exchange;
- ``checksum_transform`` and ``lut_generator``: the table-driven checksum;
- ``fingerprint``: the direct HarpoFingerprint port and its gate network, from which
  ``tools/recover_fingerprint.py`` recovers the runtime cipher.

The proof reports under ``tools/`` pin the SHA-256 of the monoliths,
Transform7 and the BigInt helpers, so those files are byte-identical to their
last runtime versions.
"""
