# v1_session_key — S7CommPlus Session Authentication

Python port of [bonk-dev/HarpoS7](https://github.com/bonk-dev/HarpoS7) (MIT),
which is a clean-room re-implementation of the proprietary authentication in
Siemens' `OMSp_core_managed.dll`.

## When is this needed?

V1-initial S7-1200 PLCs (FW < V4.5, no TLS) require a **SessionKey handshake**
in the SetupSession step before they accept data operations. Without it, the PLC
returns an incomplete session and rejects all S7CommPlus requests.

Newer PLCs (V2/V3/TLS) use standard TLS certificates instead and do not need
any of this machinery.

## Authentication flow

```
PLC                                          Client
 │                                              │
 │◄──── CreateObject ───────────────────────────│  V1 framing
 │ response: session_id, public_key_fingerprint │
 │           session_challenge (20 bytes)        │
 │           ServerSessionVersion (Struct 314)   │
 │                                              │
 │  ┌─ Client-side (no network) ──────────────┐ │
 │  │ 1. Look up PLC's public key by          │ │
 │  │    fingerprint (keys.py)                 │ │
 │  │ 2. Generate random key1 (24B), key2     │ │
 │  │    (24B), IV (16B)                       │ │
 │  │ 3. Run Family-0 transforms to produce   │ │
 │  │    180-byte SecurityKeyEncryptedKey blob │ │
 │  │ 4. Derive 24-byte session_key via       │ │
 │  │    HMAC-SHA256(key2, fingerprint ||      │ │
 │  │    challenge[2:18])[:24]                  │ │
 │  └─────────────────────────────────────────┘ │
 │                                              │
 │◄──── SetupSession ───────────────────────────│  V2 framing
 │  SecurityKey blob (addr 1830)                │
 │  + ServerSessionVersion echo (addr 306)      │
 │                                              │
 │──── response: success ──────────────────────►│
 │                                              │
 │  ══ subsequent frames use V3+HMAC ══════    │
 │                                              │
 │◄──── SET_VARIABLE addr 323 = USINT(5) ───────│  activation
 │◄──── GET_VAR_SUB addr 303 (challenge) ───────│  legitimation, also
 │◄──── SET_VAR_SUB addr 1846 (solved blob) ────│  with empty password
 │                                              │
```

After a successful SessionKey SetupSession, the current synchronous connection
uses **V3 framing** with HMAC-SHA256 keyed by the 24-byte session key. It calls
`_session_activate()` and then `_post_auth_legitimation()`, including with an
empty password, before reporting a connected client. This documents the
implemented call path, not a guarantee for every PLC/firmware combination.

Legacy SessionKeys are renewed every 25 minutes by default, before the PLC's
key expiry window. Renewal reads a fresh challenge from address 303 and writes
a new SecurityKey to address 1830 while holding the same lock as application
requests. The PLC's response is authenticated with the old key; the new key is
installed only after that response is verified and accepted. A renewal failure
closes the connection instead of continuing with an expired or ambiguous key.

The interval is configurable in seconds through
`S7CommPlusClient.connect(legacy_session_key_refresh_interval=...)` (or the
low-level connection method). Pass `None` to disable automatic renewal. This
timer applies only to legacy V1-initial SessionKey sessions; TLS sessions do not
start it. It is also skipped for key family 03 (PLCSIM), whose firmware resets
the connection on a renewal SecurityKey write (see the family-03 note below).

Activation and firmware-specific failures require protocol evidence, not
changes to the arithmetic models. The CPU1515/FW2.9 investigation is tracked
in issue #34; do not infer a universal framing/activation change from this map.

## Contributor path through the handwritten code

The stable entry point is `S7CommPlusConnection.connect()` in
`s7commplus/connection.py` (the asyncio client mirrors it in
`async_client.py`). Its CreateObject parser saves the session challenge,
public-key fingerprint, and ServerSessionVersion. `_setup_session()` calls
`_try_session_key_auth()` only for non-TLS V1 sessions with both challenge and
fingerprint; `keys.parse_fingerprint()` and `keys.get_public_key()` select the
bundled key. A family-only fingerprint requires an explicit candidate from the
discovery path rather than silently trying all keys.

`handshake.authenticate_real_plc()` is the small cryptographic boundary: it
returns a 180-byte encrypted blob and a 24-byte session key. It delegates blob
construction to `real_plc/authenticator.py` and key derivation to
`key_derivation.py`. `_encode_security_key_struct()` owns the wire-level
SecurityKey wrapper; `_setup_session()` writes it at address 1830 alongside the
ServerSessionVersion echo at address 306 (with the V1-rejected PAOM string
removed). Only an accepted response installs `_session_key` and enables
IntegrityId tracking. `send_request()` and the response/fragment readers then
own V3 HMAC framing and verification.

After setup, `_session_activate()` sends address 323, and
`_post_auth_legitimation()` reads a *new* challenge at address 303 and writes
the 248-byte result to address 1846. The solver is
`legitimation.solve_legitimate_challenge_real_plc()`. The CreateObject challenge
must never substitute for a failed legitimation read. Renewal is handled by
`_renew_session_key_locked()`: it reads a fresh address-303 challenge and writes
another SecurityKey under the application-request lock. The old key verifies
the response before the new key is installed.

For a new real-PLC key family, add key selection and an authenticator parallel
to `real_plc/authenticator.py`, then extend the handwritten dispatch in
`handshake.py` and its explicit tests. Do not import retired reference code from
`old/` in the connection layer, and do not silently map an unknown family to
Family 0. This is a recommended extension boundary, not a claim that a
pluggable authenticator interface already exists.

### Diagnosing a failed connection

- Missing ServerSessionVersion: inspect CreateObject attribute parsing before
  any crypto; SetupSession cannot proceed without an echoable typed value.
- Missing challenge or fingerprint: `_try_session_key_auth()` skips the
  SessionKey path. Compare the PLC's reported family, firmware, and captured
  attributes; do not infer a bad cryptographic step from the skipped path.
- Unknown full fingerprint or family-only identifier: check `keys.py` and the
  discovery candidate. A candidate rejected by SetupSession is not proof that
  the bundled key or arithmetic is correct for that PLC.
- Blob generated but SetupSession rejected: compare the 1830/306 request layout,
  public-key family, and PLC response return value before looking at the
  cryptographic modules.
- Setup accepted but later request rejected: distinguish activation,
  legitimation, IntegrityId, V3 frame/HMAC, and fragmented-response verification.
  The address-303 challenge is distinct from the CreateObject challenge.
- Renewal failure: the connection is closed intentionally; check the fresh
  challenge read, authenticated SecurityKey write, and PLC expiry behavior.

Do not attach raw packet captures or debug logs containing challenges, session
keys, passwords, or private material to public issues. The real-PLC acceptance
guide describes the shareable artifact workflow.

## Module map

### Orchestration (human-readable)

```
v1_session_key/              S7CommPlus V1 SessionKey handshake (not used for TLS, V2 or V3)
├── __init__.py              Public API re-exports
├── ARCHITECTURE.md          This file
├── handshake.py             Entry point: 180-byte blob + 24-byte session key
├── legitimation.py          V1 password legitimation (DEADBEEF blob builder)
├── keys.py                  Public-key store (fingerprint → 40/64-byte key)
├── key_derivation.py        SHA-256 KDFs (challenge key, seed key+IV, session key)
├── blob_metadata.py         SecurityKeyEncryptedKey blob header/metadata
├── utils.py                 Key-ID derivation (SHA-256 → 8 bytes)
├── aes_ecb.py               AesEcb: AES-128-ECB wrapper (HarpoS7's HarpoAes; public API, not used by the handshake)
├── aes_gcm.py               AesGcm24: AES-GCM without associated data, 24-bit counter (HarpoS7's HarpoAesCtr; public API)
├── ghash.py                 GCM's GHASH multiplication with Shoup 8-bit tables (HarpoS7's HarpoHash; public API)
│
└── real_plc/                The blob algorithm for real S7-1200/1500 keys (families 00 and 01)
    ├── __init__.py
    ├── authenticator.py     RealPlcAuthenticator — top-level blob builder
    ├── seed.py              Encrypted seed and the three blob keys (HarpoS7's PreSeed, Seed,
    │                        Transform13 and KeyDerivation transforms)
    ├── curve.py             The seed's 160-bit prime-order curve and x-only Montgomery ladder
    ├── present.py           The PRESENT-80 variant behind the seed and keys (Monolith9/10)
    ├── checksum.py          GF(2^128) multiply mod x^128+x^32+x^15+x^2+1 for the blob's checksum
    └── fingerprint.py       8-byte challenge fingerprint: a 13-round SPN on AES's inverse S-box
```

The runtime needs no vendored HarpoS7 table: the curve's generator, the fixed
PRESENT-80 plaintexts and the fingerprint cipher's keys and wiring are small
enough to be constants in `curve.py`, `seed.py` and `fingerprint.py`, and tests
check them against the original tables.

HarpoS7's fingerprint is a white-boxed network of 496 nibble lookup gates.
`tools/recover_fingerprint.py` strips the white-box encodings layer by layer:
the first layer reads the challenge unencoded, so its S-box and key can be
matched directly, and every later wire is labelled with the plain bits it
determines. Underneath is `InvSubBytes(challenge ^ K)`, a fold of the 16 bytes
to 8, and 13 rounds that transpose 2-bit crumbs within two groups of four
bytes before a keyed inverse S-box, followed by fixed 4-bit output encodings.
Every recovered key byte and wiring choice is the only one that fits, and the
tests rerun the recovery and compare with the gate network and the HarpoS7
port.

### Retired reference code (repository only, not distributed)

Family-0 authentication executes none of the transpiled HarpoS7 monoliths or
their orchestration any more. They live under `old/` at the repository root,
outside the `s7commplus` package, so the wheel no longer ships them. Tests and
`tools/` still import them as byte-exact references for the compact runtime
forms, and the proof reports under `tools/*.json` pin their SHA-256, so the
moved files are byte-identical to what they were inside the package.

```
old/
└── family0/
    ├── pre_seed_transform.py, key_derivation_transform.py, seed_transform.py
    │                         Encoded HarpoS7 ports of the transforms in seed.py
    ├── encoding.py           Decoders for HarpoS7's encoded 160-bit values and spans
    ├── monolith11_compact.py  Proven-equivalent Monolith11 (used by encoding.decode)
    ├── checksum_transform.py, lut_generator.py  Table-driven checksum ports
    ├── fingerprint.py        Direct HarpoFingerprint port and its gate network
    ├── transform7.py         Original Transform7
    ├── transform7_compact.py  Integer setup + integer Transform12 + final monolith chain (reference for curve.py)
    ├── transform12.py, transform12_compact.py  Transform12 opcode dispatcher (packed and integer)
    ├── transform13.py        3×24-byte BigInt output via Monolith9/10
    ├── big_int_operations.py, big_int_transforms.py  192-bit packed arithmetic
    ├── monolith_wrappers.py  WithCopy adapters for Monolith3-7
    ├── monolith5_compact.py  Compiled, proven-equivalent Monolith5
    └── _generated/
        ├── monolith1.py … monolith11.py   Permutation ciphers (~30K lines)
        ├── nine/part1.py … part11.py      Monolith9 parts (~50K lines)
        ├── ten/part1.py … part3.py        Monolith10 parts (~15K lines)
        └── data/                          Vendored HarpoS7 tables (do not edit)
            ├── __init__.py                Binary data loaders
            ├── _constants.py              Python constant arrays
            ├── fp_data1.bin, fp_data2.bin  Fingerprint wiring and lookup tables
            ├── transform12_metadata.bin   Transform12 opcode tape
            └── transform12_big_int_data.bin  BigInt constant table
```

### Machine-transpiled (do not edit)

The monoliths in `old/family0/_generated/` are transpiled from HarpoS7's C# via
`tools/transpile_harpo_monolith.py`. Each `monolithN.execute(dst, src)` is a
straight-line uint32 arithmetic function verified byte-for-byte against upstream
test vectors. These proprietary transforms are intentionally opaque, so any
simplification needs evidence and equivalence checks. Monolith11 is the first
migrated exception: exhaustive bitwise analysis recovered a compact, exact
form in `old/family0/monolith11_compact.py`. The generated files are kept under
`old/` for provenance and are still checksummed by the manifest, but are no
longer executed or distributed.

## Artifact provenance and verification

[`old/family0/artifacts.json`](../../old/family0/artifacts.json) is the authoritative inventory for every
Python module and binary table inside `old/family0/_generated/`, including
handwritten glue, and all embedded public keys. It pins HarpoS7 v1.1.0 to
commit `b4ba7fab14bcca4274e69a4d6524a5a61fcd329d` and records each artifact's
classification, upstream source, generation method, byte size, and SHA-256.
The `fp_data2.bin` table includes the one-element `Data2Collection[1]` repair
from HarpoS7 commit `22b9dc0da3bf4b32f872b0b9ee2c2d30964e7654`; the
manifest records this upstream patch explicitly.
The original MIT license is in `LICENSE-HarpoS7`.

Run the complete deterministic check from the repository root:

```bash
python -m tools.verify_v1_session_key
```

The command checks runtime artifacts, the shared-data loader, public keys, and
the complete known-answer fixture inventory. The runtime inventory check also
runs in pre-commit; the complete check runs in CI. To independently derive and
compare programs, all four binary tables, inlined constants, public keys and
fixtures against a local pinned HarpoS7 checkout, run this one offline workflow:

```bash
python -m tools.verify_v1_session_key --upstream-root /path/to/HarpoS7
```

The individual binary/constant verifier is still available for regeneration:

```bash
python tools/verify_v1_session_key_upstream.py --upstream-root /path/to/HarpoS7
```

The upstream checkout must be at the base revision above and contain the
`fp_data2.bin` patch commit. The command is offline and does not modify runtime
files. Add `--output-dir /path/to/new-directory` to regenerate the four binary
tables into a new directory for inspection. It validates the constant *values*,
while the manifest validates the exact formatting and bytes of `_constants.py`.
To verify every checked-in transpiled monolith against the same pinned checkout,
run:

```bash
python tools/verify_transpiled_monoliths.py --upstream-root /path/to/HarpoS7
```

The transpiler emits unformatted Python and includes the local source path in
its docstring. This check compares Python syntax trees, so it verifies program
equivalence after ignoring formatting and the checkout path. The manifest check
above separately verifies the exact bytes of each checked-in output. The
Monolith9 and Monolith10 wrappers are human-maintained orchestration and are
covered by their existing vector tests.

For a read-only map of which 32-bit source, destination, and scratch words each
generated function accesses, run:

```bash
python tools/map_v1_session_key_monoliths.py
python tools/map_v1_session_key_monoliths.py --path old/family0/_generated/monolith1.py
```

The JSON output links each generated file to its C# source path. This is a
*syntactic* access map, not a dependency proof: an input listed for a function
may not influence every output. The mapper rejects dynamic word indexes rather
than silently presenting an incomplete map. Use it to select a smaller target
for tracing and differential tests; do not edit the verified generated code just
to make it look simpler.

To narrow the map to a single 32-bit destination word, run:

```bash
python tools/trace_v1_session_key_output.py 3 0
python tools/trace_v1_session_key_output.py 3 0 --steps
python tools/trace_v1_session_key_output.py 9 0 --json
```

The first argument is the monolith number (1–11), and the second is the
zero-based output word. The default output summarizes possible input words and
contributing assignment counts. `--steps` prints file/line locations and
direct dependencies for each contributing assignment; `--json` returns the
complete machine-readable backward slice. Monolith9 and Monolith10 follow
their ordered Part files and shared scratch array. The trace versions repeated
assignments so overwritten values do not appear as false dependencies. It is
conservative *word-level* data flow: a listed input may not affect every bit,
and constants or algebraic cancellation may remove actual influence. Treat
these results as navigation aids, not cryptographic proofs or replacement tests
for byte-exact vectors.

For Monolith11, a separate exhaustive bitwise analysis recovered a compact,
exact two-kernel form for all five output words. See
[`old/family0/MONOLITH11_ANALYSIS.md`](../../old/family0/MONOLITH11_ANALYSIS.md) for the formula, proof
boundary, and reproduction commands. Its compact form is
`old/family0/monolith11_compact.py`; the runtime no longer needs either,
because it passes decoded integers between transforms.

For Monolith5, fixed shifts make the bitwise-only method inapplicable. A
symbolic ROBDD/ANF recovery yields an exact, compact model with 32 nine-input
lane functions and a two-stream combination formula. Every lane function
further separates into three identical choose/majority span gates and one
symmetric combine. See [`old/family0/MONOLITH5_ANALYSIS.md`](../../old/family0/MONOLITH5_ANALYSIS.md) for
the formula, proof boundary, and reproduction command. This is also migrated:
`tools/compile_monolith5.py` unrolls the interpreted formula into the flat,
mechanically generated `old/family0/monolith5_compact.py`. Both are
retired together with the rest of the Transform7 chain (see below).

The same per-bit symbolic approach also recovers an exact decision model for
all 1,152 Monolith7 output bits, alongside smaller readable models for words
3–5 and 15–17. See [`old/family0/MONOLITH7_ANALYSIS.md`](../../old/family0/MONOLITH7_ANALYSIS.md) for coverage,
shared conditional-selection/majority cores, size tradeoffs, and verification.

Transform12's dispatched opcode tape can be decompiled into versioned packed
arithmetic equations and sliced across block boundaries. The 89 stages of its
second phase have identical branch alternatives and form a fixed two-input
arithmetic program. See [`old/family0/TRANSFORM12_ANALYSIS.md`](../../old/family0/TRANSFORM12_ANALYSIS.md)
for exact coverage and the distinction between tape equivalence and arithmetic
or curve interpretation.

[`MODEL_BENCHMARKS.md`](MODEL_BENCHMARKS.md) compares the recovered evaluators
with generated code at the byte interface. Monolith11 and Monolith5 have both
been migrated to runtime (see above); the interpreted Monolith5 evaluator
itself was slower than generated code, but compiling it into flat,
straight-line Python (`tools/compile_monolith5.py`) removed the
interpretation overhead and made it faster and smaller than generated — see
MODEL_BENCHMARKS.md for the measurements. The full Monolith7 analysis
evaluator remains slower/larger than generated and analysis-only; no
complete compact model exists yet for all 36 of its output words.

Family 03 (PLCSIM) has its own, much smaller authenticator in `plcsim/`
(HarpoS7's `AuthenticatePlcSim`). Its 216-byte blob is the 48-byte metadata, a
96-byte seed, a 16-byte IV, the challenge and `key1` encrypted with AES-GCM
(24-bit counter) under a key derived from `key2`, and the 16-byte tag. The seed
is **ECIES over NIST P-256**: the ephemeral point `k·G` (big-endian `x ‖ y`)
followed by the challenge key encrypted under a key and IV derived from
`x(k·PK)`, with its tag. `plcsim/seed.py` computes it with `cryptography`'s
P-256 and the existing KDF and `AesGcm24`, and is pinned to HarpoS7's
`GenerateEncryptedSeedTest` known answer. The session key derives from `key1`
(not `key2`, as on real PLCs). The Family-0 `RealPlcAuthenticator` still
supports only families 00 and 01, and `handshake.authenticate_session_key()`
dispatches on the family.

PLCSIM is **validated** on a real S7-PLCSIM Advanced V8 instance (CPU 1511-1 PN,
FW V2.8 project, on the PLCSIM virtual adapter) with the sync and async clients:
connect, SecurityKey setup, `browse()`, symbolic and byte-offset reads,
symbolic and byte-offset writes, data subscriptions, password legitimation, and
key handling. It uses the S7-1500 request layouts. CreateObject is parsed
structurally (attribute 233 carries the `03:…` fingerprint, 303 the 20-byte
challenge; no fixed offsets are used).

Four PLCSIM-specific behaviours were found and fixed (#66):

- A multi-fragment V3 response chains its continuation digests **feed-forward**
  (`HMAC(key, digest_{n-1} ‖ fragment_n)`), while real firmware resumes the
  finalized HMAC state; `FragmentHMACVerifier` now detects the dialect from the
  second fragment and accepts either, so `browse()` works.
- The SetupSession SecurityKey write echoes the PLC's own ServerSessionVersion
  **with elements 315–318 rewritten to the S7-1500 (real-PLC) values**. Echoing
  PLCSIM's own values back is accepted for the setup and serves reads, but it
  makes PLCSIM reject the post-auth legitimation; the real-PLC values are what
  S7CommRust and the HarpoS7 PoC (patched) use, and they work for both.
- PLCSIM Advanced does **not** want the address-323 session activation
  (`SET_VARIABLE` = USINT(5)) that real firmware needs: reads still work after
  it, but the next `CreateObject` / `SetMultiVariables` (write, subscription,
  delete) answers with a fatal SystemEvent and a TCP reset. The activation is now
  skipped for family 03, as S7CommRust's validated legacy handshake does.
- On the family-03 legacy session the response IntegrityId follows the body for
  the set-side operations too (`SET`/`CREATE`/`DELETE_OBJECT`), not only for
  `GET_MULTI_VARIABLES`/`EXPLORE`; those payloads are kept whole so the
  per-item error list parses correctly.

The post-auth legitimation is **implemented and validated**. HarpoS7 does have a
PLCSIM variant (`LegitimateScheme.SolveLegitimateChallengePlcSim`) — contrary to
an earlier note here — and
`v1_session_key.legitimation.solve_legitimate_challenge_plcsim` is a manual port
of it that byte-matches HarpoS7's known answer (the IV and the ECIES seed are
injected in the vector, since the scalar is random; the seed generator has its
own HarpoS7 known-answer test). It uses the same P-256 seed as the session
handshake and AES-GCM-encrypts the SHA-1 password hash and the address-303
challenge. On a password-protected (NoAccess) family-03 PLCSIM session the PLC
answers the address-303 read with a 20-byte challenge, and the client's 284-byte
blob is accepted once (a) the setup carries the real-PLC 315–318 values and
(b) the request uses HarpoS7's captured layout (object qualifier key 1, no
item-number byte, the IntegrityId before the trailing fill). The result is
`LegitimatedLevel1`: the client reaches `protection_level` 1, browses, reads and
writes; `Client` and `AsyncClient` both work. Automatic 25-minute
**renewal is disabled for family 03**: PLCSIM Advanced FW V2.8 resets the
connection when a new SecurityKey is written to address 1830, in both the
`SET_VARIABLE` and the `SET_MULTI_VARIABLES` layout, so a renewal would end a
long-lived session instead of extending it. Byte-offset `db_read`/`db_write` work
on a standard (non-optimized) DB and are refused with PLC error `0xA40013` on an
optimized DB, exactly as on real hardware; use symbolic access there. Deleting
the subscription container works once the payload uses the legacy object
qualifier.

[`MAINTAINER_GUIDE.md`](MAINTAINER_GUIDE.md) maps the stable handwritten
interfaces, source/fixture evidence, failure triage, model limits and issue #1
acceptance criteria. Start there before navigating generated programs.

### Review boundary

- Human-maintained flow and extension points live outside `_generated/`.
- `old/family0/_generated/` holds the generated `monolith*.py`,
  `nine/part*.py`, and `ten/part*.py`; `old/family0/monolith5_compact.py` is
  mechanically compiled from the recovered model. Do not hand-edit either.
- `old/family0/transform7.py` is the original Transform7 orchestration.
  `old/family0/transform7_compact.py`, which writes the four setup
  context slots with the proven integer model (`tools/transform7_setup_integer.py`
  composes the same carry-save steps), runs the Transform12 tape on plain
  integers (`old/family0/transform12_compact.py`: every slot and constant row is a
  canonical packing, so each BigInt primitive is a short integer formula), and
  keeps the final Monolith7/4/6 chain. Tests pin byte equality with the
  original, every tape dispatch and every primitive branch; Transform7 runs
  about 19x faster. The analysis tools and proof records keep instrumenting and
  pinning the original file. SeedTransform itself no longer runs either: the
  whole Transform7/Monolith1/Monolith2 chain decodes to an x-only scalar
  multiplication on the curve in `real_plc/curve.py`, which the runtime computes
  with a Montgomery ladder (see `MODEL_BENCHMARKS.md`).
- `old/family0/_generated/data/`: `_constants.py` and the four `.bin` files
  are generated data; its `__init__.py` loader is human-maintained glue.
- `real_plc/fingerprint.py`'s constants are recovered data: check them with
  `python -m tools.recover_fingerprint`, never edit them by hand.

When generated output intentionally changes, keep that mechanical diff separate
from handwritten behavior changes where practical. Regenerate from the pinned
upstream revision, run the upstream-derived vector tests, then update the size
and SHA-256 in `old/family0/artifacts.json` in the same generated-output commit. Adding a new
key family should start with a small authenticator interface parallel to
`real_plc/authenticator.py`; callers should never import generated monoliths
directly.

## How the blob is built (authenticator.py)

```
RealPlcAuthenticator(key1=random_24B, key2=random_24B)
│
├── write_seed(dst, public_key)
│   ├── seed.pre_seed(key1)              →  160-bit pre-seed (PreSeedTransform)
│   ├── seed.write_seed(dst, public_key)  →  60-byte encrypted seed (SeedTransform)
│   │   ├── ECDH: k = prng2 ^ SCALAR_MASK, ephemeral x(k·G), shared x(k·PK) (curve.py)
│   │   │   (originally Transform7 → Monolith1.Loop → Monolith2)
│   │   └── seed = pre-seed ^ seed_mask(shared) (Transform13)
│   └── seed.derive_keys(pre-seed)       →  challenge key, checksum key, hash key H
│
├── encrypt_full_blocks(dst, challenge)
│   └── AES-ECB(challenge_key, IV) XOR challenge[2:18], then key2 blocks
│       └── counter *= x in GCM's field (HarpoS7's RotateLeft31); checksum c = (c ^ block) * H (checksum.multiply)
│
└── encrypt_final_block(dst)
    └── Encrypt key2 leftover, zero-pad only for checksum, fold in the length, append AES(checksum_key, c * H)
```

## References

- [HarpoS7](https://github.com/bonk-dev/HarpoS7) — MIT, C# clean-room implementation
- [lircy/S7CommPlusV3Driver](https://github.com/lircy/S7CommPlusV3Driver) — ships HarpoS7 as precompiled native DLLs
- Cheng Lei et al., "The Spear to Break the Security Wall of S7CommPlus", Black Hat EU 2017
- Biham, Bitan et al., "Rogue7: Rogue Engineering Station Attacks on S7 Simatic PLCs", Black Hat USA 2019
