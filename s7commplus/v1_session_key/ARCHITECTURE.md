# v1_session_key — S7CommPlus Session Authentication

Python port of [bonk-dev/HarpoS7](https://github.com/bonk-dev/HarpoS7) (MIT),
which is a clean-room re-implementation of the proprietary authentication in
Siemens' `OMSp_core_managed.dll`.

> The SessionKey research (HarpoS7's transpiled monoliths and ports, the
> recovery and proof tools and their write-ups) is not part of this repository.
> The runtime below is self-contained; its tests check it against answers
> recorded from that reference code (`tests/fixtures/family0/`).

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

On an S7-1200 (key family 01) the legacy SessionKey is renewed every 25 minutes
by default, before the PLC's key expiry window. Renewal reads a fresh challenge
from address 303 and writes
a new SecurityKey to address 1830 while holding the same lock as application
requests. The PLC's response is authenticated with the old key; the new key is
installed only after that response is verified and accepted. A renewal failure
closes the connection instead of continuing with an expired or ambiguous key.

The interval is configurable in seconds through
`S7CommPlusClient.connect(legacy_session_key_refresh_interval=...)` (or the
low-level connection method). Pass `None` to disable automatic renewal. This
timer applies only to legacy V1-initial SessionKey sessions; TLS sessions do not
start it. It is also skipped for key family 03 (PLCSIM), whose firmware resets
the connection on a renewal SecurityKey write (see the family-03 note below),
and for key family 00 (S7-1500). A CPU 1512C-1 PN FW V2.5 and two CPU 1517-3
PN/DP (FW V2.9 and V3.0) answer the SecurityKey write to address 1830 with a
fatal SystemEvent, request parsing error, and the connection is lost; on the
1517-3 FW V3.0 six request layouts gave the same answer (#184). Without a renewal the 1517-3 ends
the session one hour after the connect, so a client that stays connected longer
has to reconnect before then. What a Siemens client does at that point is not
known.

Activation and firmware-specific failures require protocol evidence, not
changes to the arithmetic models. The CPU1515/FW2.9 investigation is tracked
in issue #34; do not infer a universal framing/activation change from this map.

## Contributor path through the handwritten code

The stable entry point is `S7CommPlusConnection.connect()` in
`s7commplus/connection.py` (the asyncio client mirrors it in
`async_connection.py`). Its CreateObject parser saves the session challenge,
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
`handshake.py` and its explicit tests. Do not silently map an unknown family to
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
check them against answers recorded from the original tables.

HarpoS7's fingerprint is a white-boxed network of 496 nibble lookup gates.
Stripping the white-box encodings layer by layer recovered what it computes:
`InvSubBytes(challenge ^ K)`, a fold of the 16 bytes to 8, and 13 rounds that
transpose 2-bit crumbs within two groups of four bytes before a keyed inverse
S-box, followed by fixed 4-bit output encodings. Every recovered key byte and
wiring choice is the only one that fits. The tests check `fingerprint.py`
against 164 challenges answered by the gate network and the HarpoS7 port.

## Provenance and tests

The data taken from HarpoS7 v1.1.0 (commit `b4ba7fab14bcca4274e69a4d6524a5a61fcd329d`,
MIT, see `LICENSE-HarpoS7`) is pinned in the repository:

- `tests/fixtures/family0/public_keys.json` records the size, SHA-256 and
  upstream file of every public key embedded in `keys.py`;
- `tests/fixtures/family0/provenance.json` does the same for the upstream
  known-answer vectors the tests use.

Check both from the repository root (CI and the pre-commit hook run this):

```bash
python -m tools.verify_v1_session_key
python -m tools.verify_v1_session_key --upstream-root /path/to/HarpoS7  # also compare with a checkout
```

`tests/fixtures/family0/reference_vectors.json` holds the inputs, entropy and
answers recorded from HarpoS7's ports and transpiled chain for the
fingerprint, PreSeed, KeyDerivation, Transform13, the Transform7 ladder, the
seed and the complete authentication of both key families. A change to a
runtime constant or formula fails those tests; a deliberate change has to be
justified against the original code, not by re-recording the answers.

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
symbolic and byte-offset writes, data subscriptions from access sequences,
password legitimation, and key handling. Subscriptions to catalog tags are
created and deleted but get no values yet: `SubscriptionItem.from_tag` sends the
browsed SymbolCRC, which PLCSIM answers with item error 0x13. It uses the
S7-1500 request layouts. CreateObject is parsed structurally (attribute 233
carries the `03:…` fingerprint, 303 the 20-byte challenge; no fixed offsets are
used).

Four PLCSIM-specific behaviours were found and fixed (#66):

- A multi-fragment V3 response chains its continuation digests **feed-forward**
  (`HMAC(key, digest_{n-1} ‖ fragment_n)`), while real firmware resumes the
  finalized HMAC state; `FragmentHMACVerifier` now detects the dialect from the
  second fragment and accepts either, so `browse()` works.
- The SetupSession SecurityKey write echoes the PLC's own ServerSessionVersion
  **with elements 315–318 rewritten to the S7-1500 (real-PLC) values**. Echoing
  PLCSIM's own values back is accepted for the setup and serves reads, but it
  makes PLCSIM reject the post-auth legitimation; the real-PLC values, taken
  from the S7-1500 session-setup capture in HarpoS7 (MIT,
  `HarpoS7.PoC/Packets/SetMultiVarsRequest.cs`, `S71500Data`), work for both.
- PLCSIM Advanced does **not** want the address-323 session activation
  (`SET_VARIABLE` = USINT(5)) that real firmware needs: reads still work after
  it, but the next `CreateObject` / `SetMultiVariables` (write, subscription,
  delete) answers with a fatal SystemEvent and a TCP reset. The activation is now
  skipped for family 03 (seen live on PLCSIM Advanced V8).
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
item-number byte, the IntegrityId before the trailing fill). Both are scoped to
family 03: the setup rewrite is PLCSIM-only, and the other families keep the
pre-existing request layout (key qualifier = sequence number, an item-number
byte, and a three-byte tail) byte-for-byte, unchanged from before this work.
The result is
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

[`MAINTAINER_GUIDE.md`](MAINTAINER_GUIDE.md) describes how to change this code
safely: which files are handwritten, which data is pinned, and how to triage a
failure.

### Review boundary

- Every module in `v1_session_key/` is handwritten; none is generated.
- `real_plc/fingerprint.py`'s constants, `curve.py`'s domain parameters and
  `seed.py`'s fixed plaintexts and keys are recovered data: change them only
  with evidence from the original code, never to make a test pass.
- `keys.py`'s public keys are vendored from HarpoS7; adding or changing one
  means updating `tests/fixtures/family0/public_keys.json` with its upstream
  file and hash.

Adding a new key family should start with a small authenticator interface
parallel to `real_plc/authenticator.py`, with its own known-answer tests.

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
