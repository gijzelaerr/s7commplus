# SessionKey maintainer guide

How to change the V1 SessionKey code safely. It does not claim to reconstruct
Siemens' original source. Preserve `LICENSE-HarpoS7` and attribution when
reusing HarpoS7-derived code.

Recovery identified every primitive the Family-0 runtime executes, so it runs
no transpiled code:

- `real_plc/seed.py`: HarpoS7's PreSeed, Seed, Transform13 and KeyDerivation
  transforms, on plain 160-bit integers.
- `real_plc/present.py`: Monolith9/Monolith10, a PRESENT-80 variant.
- `real_plc/curve.py`: SeedTransform's Transform7/Monolith1/Monolith2 chain,
  an x-only ECDH on a 160-bit prime-order curve. The ladder differs from the
  original only where Transform7's arithmetic is not modular, which needs
  structured inputs (see `curve.py`).
- `real_plc/checksum.py`: the blob checksum's GF(2^128) multiply.
- `real_plc/fingerprint.py`: the challenge fingerprint, a fixed-key 13-round SPN
  on AES's inverse S-box recovered from HarpoS7's white-boxed gate network.

HarpoS7's transpiled monoliths, their tables and the ports the runtime was
checked against are not part of this repository. Their answers are recorded in
`tests/fixtures/family0/reference_vectors.json`.

## Start at the handwritten boundary

`connection.py` owns negotiation, sequencing and network frames; it calls
`handshake.authenticate_session_key(challenge, public_key, family)`. For
families 00/01 that is `authenticate_real_plc`, which returns the **180-byte
blob and 24-byte SessionKey**; family 03 (PLCSIM) goes to `authenticate_plcsim`
and returns a 216-byte blob (emulator-tested only, see `ARCHITECTURE.md`).

The synchronous path is `connect` → CreateObject attributes →
`_try_session_key_auth` / `_setup_session` → `_session_activate` →
`_post_auth_legitimation`. SetupSession uses V2 framing even after V1
negotiation; successful SessionKey data frames use V3/HMAC. Legitimation runs
even with an empty password. The async client's legacy support is not the
same as the synchronous path: consult `docs/connections.rst` instead of
assuming parity from shared arithmetic helpers.

| Handwritten interface | Responsibility | First evidence to inspect |
| --- | --- | --- |
| `keys.parse_fingerprint`, `get_public_key`, `fingerprints_for_family` | Family/key lookup; unknown-key errors | `tests/test_v1_session_key.py`; the 25 keys in `tests/fixtures/family0/public_keys.json` |
| `handshake.authenticate_real_plc` | Blob construction + SessionKey return boundary | `tests/test_v1_session_key_handshake.py` (both complete upstream vectors) and the recorded authentications in `tests/test_v1_session_key_seed.py` |
| `real_plc.authenticator.RealPlcAuthenticator` | Metadata, seed, challenge/key2 encryption, checksum | Deterministic entropy sequence in the complete blob vectors |
| `key_derivation.derive_session_key` | HMAC(key2[:24], fingerprint(challenge) + challenge[2:18])[:24] | Complete SessionKey vectors and fingerprint regressions |
| `legitimation` | Post-setup challenge solution, distinct from initial key derivation | `tests/test_v1_session_key_legitimation.py`; connection's 303/1846 exchange |
| `real_plc.curve`, `real_plc.seed` | Seed and blob keys: x-only ECDH and PRESENT-80 | `tests/test_v1_session_key_curve.py`: domain parameters, the ladder against Transform7's recorded values on every catalogue key, upstream Transform7 vectors, recorded seeds and carry cases; `tests/test_v1_session_key_seed.py`: PRESENT-80 vectors and the encoded ports' recorded answers |
| `real_plc.fingerprint` | Challenge fingerprint | `tests/test_v1_session_key_fingerprint.py`: 164 recorded gate-network answers |

For a new key within
an existing supported family, verify its upstream bytes/identifier and add it
to `tests/fixtures/family0/public_keys.json`. A genuinely new family needs its own
authenticator, blob/metadata rules and independently sourced vectors before
connection negotiation routes to it. Increasing a length constant or bypassing
a family guard is not an implementation.

## Classify a file before changing it

- `v1_session_key/`: handwritten library code. `keys.py` also holds the
  vendored HarpoS7 public keys, and `fingerprint.py`, `curve.py` and `seed.py`
  hold recovered constants: change those only with evidence from the original
  code, never to make a test pass.
- `tests/fixtures/family0/provenance.json` and `transforms/*.bin`: immutable
  upstream HarpoS7 known-answer data, **not** hardware captures, with the two
  upstream Transform7 vectors embedded as hex.
- `tests/fixtures/family0/public_keys.json`: the upstream file, size and hash
  of every embedded public key.
- `tests/fixtures/family0/reference_vectors.json`: answers recorded from the
  retired reference code. Re-recording them needs that code, so treat a change
  as a change to the algorithm.

## Verification

From a source checkout, no PLC or download is required:

```bash
python -m tools.verify_v1_session_key
python -m tools.verify_v1_session_key --upstream-root /path/to/HarpoS7
```

The first checks the 25 embedded public keys and the upstream fixtures against
their recorded sizes, hashes and source files, using only the standard library
and without importing the package. The second also compares their bytes with a
local HarpoS7 checkout at the pinned revision. CI and the pre-commit hook run
the first. The runtime behaviour itself is covered by the test suite.

## Diagnose the boundary

Record package version/commit, CPU order number/firmware, negotiated protocol,
whether TLS is active, public fingerprint/family, challenge **length only**,
SetupSession return status/function/sequence, SystemEvent code, and which
boundary failed. Do not record passwords, keys, challenges or decrypted blobs.
Current raw frame/debug logging can include authentication material; do not
publish those logs without deliberate redaction, including challenge data
currently logged at INFO. Prefer sanitized fixtures and metadata-only reports.

- Missing challenge/fingerprint: inspect parsed CreateObject attributes first.
- Unknown key/family: verify catalogue matching; do not try another family.
- Import/dependency error: verify installation, packaged binaries and
  `cryptography`. Standalone development uses `.[test,docs]`, not the historic
  python-snap7 extra mentioned in some error messages.
- Blob/SessionKey vector mismatch: isolate entropy ordering, KDF/fingerprint,
  seed and checksum boundaries, each of which has its own recorded vectors.
- Accepted SetupSession followed by failure: distinguish activation,
  legitimation and first data request; preserve the PLC status. Issue #34 still
  needs firmware-specific reference evidence and a same-device retest.
- TLS failure: inspect TLS-in-COTP transport/certificate negotiation separately;
  the SessionKey vectors do not validate TLS behavior.
