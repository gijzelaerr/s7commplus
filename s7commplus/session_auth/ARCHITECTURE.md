# session_auth — S7CommPlus Session Authentication

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
start it.

Activation and firmware-specific failures require protocol evidence, not
changes to the arithmetic models. The CPU1515/FW2.9 investigation is tracked
in issue #34; do not infer a universal framing/activation change from this map.

## Module map

### Orchestration (human-readable)

```
session_auth/
├── __init__.py              Public API re-exports
├── ARCHITECTURE.md          This file
├── keys.py                  Public-key store (fingerprint → 40/64-byte key)
├── legacy_auth.py           180-byte blob + 24-byte SessionKey entry point
├── key_derivation.py        SHA-256 KDFs (challenge key, seed key+IV, session key)
├── legitimate.py            Post-auth challenge solver (DEADBEEF blob builder)
├── blob_metadata.py         SecurityKeyEncryptedKey blob header/metadata
├── harpo_aes.py             AES-ECB primitives (used by checksum + seed encryption)
├── harpo_aes_ctr.py         Custom AES-CTR mode (non-standard counter increment)
├── harpo_hash.py            SHA-256-based hash with LUT mixing
├── utils.py                 Key-ID derivation (SHA-256 → 8 bytes)
│
├── family0/
│   ├── __init__.py
│   ├── authenticator.py     RealPlcAuthenticator — top-level blob builder
│   ├── fingerprint.py       8-byte challenge fingerprint (LUT + mutation chain)
│   ├── seed_transform.py    Encrypted seed generation (monolith chain)
│   ├── pre_seed_transform.py  Random key → pre-seed via Monolith9
│   ├── key_derivation_transform.py  Pre-seed → 3 AES keys via Monolith9/10
│   ├── checksum_transform.py  AES-ECB checksum of encrypted blocks
│   ├── lut_generator.py     Lookup table for harpo_hash
│   ├── transform7.py        Core EC point multiplication (monolith wrappers)
│   ├── transform12.py       Opcode-driven BigInt dispatcher
│   ├── transform13.py       3×24-byte BigInt output via Monolith9/10
│   ├── big_int_operations.py  192-bit arithmetic (add, sub, mul, square)
│   ├── big_int_transforms.py  BigInt higher-level ops
│   └── monolith_wrappers.py  WithCopy adapters for Monolith3-7
```

### Machine-transpiled (do not edit)

```
│   └── _generated/
│       ├── __init__.py
│       ├── monolith1.py … monolith11.py   Permutation ciphers (~30K lines)
│       ├── nine/part1.py … part11.py      Monolith9 parts (~50K lines)
│       ├── ten/part1.py … part3.py        Monolith10 parts (~15K lines)
│       └── data/
│           ├── __init__.py                Binary data loaders
│           ├── _constants.py              Python constant arrays
│           ├── fp_data1.bin, fp_data2.bin  Fingerprint lookup tables
│           ├── transform12_metadata.bin   Transform12 opcode tape
│           └── transform12_big_int_data.bin  BigInt constant table
```

The `_generated/` modules are transpiled from HarpoS7's C# via
`tools/transpile_harpo_monolith.py`. Each `monolithN.execute(dst, src)` is a
straight-line uint32 arithmetic function verified byte-for-byte against upstream
test vectors. These proprietary transforms are intentionally opaque, so any
simplification needs evidence and equivalence checks. Monolith11 is a concrete
exception: exhaustive bitwise analysis recovers a compact form below without
changing the generated implementation.

## Artifact provenance and verification

[`artifacts.json`](artifacts.json) is the authoritative inventory for every
Python module inside `_generated/`, including handwritten glue, every binary
runtime table, and all embedded public keys. It pins HarpoS7 v1.1.0 to
commit `b4ba7fab14bcca4274e69a4d6524a5a61fcd329d` and records each artifact's
classification, upstream source, generation method, byte size, and SHA-256.
The `fp_data2.bin` table includes the one-element `Data2Collection[1]` repair
from HarpoS7 commit `22b9dc0da3bf4b32f872b0b9ee2c2d30964e7654`; the
manifest records this upstream patch explicitly.
The original MIT license is in `LICENSE-HarpoS7`.

Run the complete deterministic check from the repository root:

```bash
python -m tools.verify_session_auth
```

The command checks runtime artifacts, the shared-data loader, public keys, and
the complete known-answer fixture inventory. The runtime inventory check also
runs in pre-commit; the complete check runs in CI. To independently derive and
compare programs, all four binary tables, inlined constants, public keys and
fixtures against a local pinned HarpoS7 checkout, run this one offline workflow:

```bash
python -m tools.verify_session_auth --upstream-root /path/to/HarpoS7
```

The individual binary/constant verifier is still available for regeneration:

```bash
python tools/verify_session_auth_upstream.py --upstream-root /path/to/HarpoS7
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
python tools/map_session_auth_monoliths.py
python tools/map_session_auth_monoliths.py --path s7commplus/session_auth/family0/_generated/monolith1.py
```

The JSON output links each generated file to its C# source path. This is a
*syntactic* access map, not a dependency proof: an input listed for a function
may not influence every output. The mapper rejects dynamic word indexes rather
than silently presenting an incomplete map. Use it to select a smaller target
for tracing and differential tests; do not edit the verified generated code just
to make it look simpler.

To narrow the map to a single 32-bit destination word, run:

```bash
python tools/trace_session_auth_output.py 3 0
python tools/trace_session_auth_output.py 3 0 --steps
python tools/trace_session_auth_output.py 9 0 --json
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

For Monolith11, a separate exhaustive bitwise analysis recovers a compact,
exact two-kernel form for all five output words. See
[`MONOLITH11_ANALYSIS.md`](MONOLITH11_ANALYSIS.md) for the formula, proof
boundary, and reproduction commands. The generated runtime code is unchanged.

For Monolith5, fixed shifts make the bitwise-only method inapplicable. A
symbolic ROBDD/ANF recovery yields an exact, compact analysis-only model with
32 nine-input lane functions and a two-stream combination formula. Every lane
function further separates into three identical choose/majority span gates
and one symmetric combine. See
[`MONOLITH5_ANALYSIS.md`](MONOLITH5_ANALYSIS.md) for the formula, proof boundary,
and reproduction command. The generated runtime code is unchanged.

The same per-bit symbolic approach also recovers an exact decision model for
all 1,152 Monolith7 output bits, alongside smaller readable models for words
3–5 and 15–17. See [`MONOLITH7_ANALYSIS.md`](MONOLITH7_ANALYSIS.md) for coverage,
shared conditional-selection/majority cores, size tradeoffs, and verification.

Transform12's dispatched opcode tape can be decompiled into versioned packed
arithmetic equations and sliced across block boundaries. The 89 stages of its
second phase have identical branch alternatives and form a fixed two-input
arithmetic program. See [`TRANSFORM12_ANALYSIS.md`](TRANSFORM12_ANALYSIS.md)
for exact coverage and the distinction between tape equivalence and arithmetic
or curve interpretation.

[`MODEL_BENCHMARKS.md`](MODEL_BENCHMARKS.md) compares the recovered evaluators
with generated code at the byte interface. Monolith11 is a promising runtime
candidate; the current Monolith5 and full Monolith7 analysis evaluators are
slower. The generated runtime is unchanged.

Family 03 (PLCSIM) is also listed in the public-key store and blob metadata,
but it needs a separate authentication implementation. The Family-0
`RealPlcAuthenticator` supports only families 00 and 01; family 03 cannot be
enabled by changing its family check or blob length.

[`MAINTAINER_GUIDE.md`](MAINTAINER_GUIDE.md) maps the stable handwritten
interfaces, source/fixture evidence, failure triage, model limits and issue #1
acceptance criteria. Start there before navigating generated programs.

### Review boundary

- Human-maintained flow and extension points live outside `_generated/`.
- `monolith*.py`, `nine/part*.py`, and `ten/part*.py` are generated source.
- `_constants.py` and the four `.bin` files are generated data.
- Package `__init__.py` files and the binary loaders are human-maintained glue.

When generated output intentionally changes, keep that mechanical diff separate
from handwritten behavior changes where practical. Regenerate from the pinned
upstream revision, run the upstream-derived vector tests, then update the size
and SHA-256 in `artifacts.json` in the same generated-output commit. Adding a new
key family should start with a small authenticator interface parallel to
`family0/authenticator.py`; callers should never import generated monoliths
directly.

## How the blob is built (authenticator.py)

```
RealPlcAuthenticator(key1=random_24B, key2=random_24B)
│
├── write_seed(dst, public_key)
│   ├── PreSeedTransform(key1)           →  60-byte pre-seed
│   ├── KeyDerivationTransform(pre-seed) →  3 × 16-byte keys
│   ├── SeedTransform(key1, public_key)  →  60-byte encrypted seed
│   │   ├── Transform7 (EC scalar mul)
│   │   ├── Monolith1.Loop → Monolith2 → Monolith8
│   │   └── Transform13 → Monolith11
│   └── Derive challenge/checksum AES keys and the checksum LUT
│
├── encrypt_full_blocks(dst, challenge)
│   └── AES-ECB(challenge_key, IV) XOR challenge[2:18], then key2 blocks
│       └── RotateLeft31 counter update and checksum accumulation
│
└── encrypt_final_block(dst)
    └── Encrypt key2 leftover, zero-pad only for checksum, append encrypted checksum
```

## References

- [HarpoS7](https://github.com/bonk-dev/HarpoS7) — MIT, C# clean-room implementation
- [lircy/S7CommPlusV3Driver](https://github.com/lircy/S7CommPlusV3Driver) — ships HarpoS7 as precompiled native DLLs
- Cheng Lei et al., "The Spear to Break the Security Wall of S7CommPlus", Black Hat EU 2017
- Biham, Bitan et al., "Rogue7: Rogue Engineering Station Attacks on S7 Simatic PLCs", Black Hat USA 2019
