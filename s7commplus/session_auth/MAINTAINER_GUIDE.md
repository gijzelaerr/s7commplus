# SessionKey maintainer and evidence guide

This guide addresses issue #1's maintainability/auditability scope. It is not a
claim to have reconstructed Siemens' original source or simplified every
cryptographic transform. Preserve `LICENSE-HarpoS7` and attribution when
reusing source-derived models. Runtime/generated implementations are unchanged
by the analysis work.

## Start at the handwritten boundary

`connection.py` owns negotiation, sequencing and network frames; it calls
`legacy_auth.authenticate_real_plc(challenge, public_key, family)`. That function
returns the **180-byte blob and 24-byte SessionKey**. It accepts families 00/01;
the key catalogue's family03 entries do not implement PLCSIM authentication.

The synchronous path is `connect` → CreateObject attributes →
`_try_session_key_auth` / `_setup_session` → `_session_activate` →
`_post_auth_legitimation`. SetupSession uses V2 framing even after V1
negotiation; successful SessionKey data frames use V3/HMAC. Legitimation runs
even with an empty password. The async client's legacy support is not the
same as the synchronous path: consult `docs/connections.rst` instead of
assuming parity from shared arithmetic helpers.

| Handwritten interface | Responsibility | First evidence to inspect |
| --- | --- | --- |
| `keys.parse_fingerprint`, `get_public_key`, `fingerprints_for_family` | Family/key lookup; unknown-key errors | `tests/test_session_auth.py`; manifest's 25 source-mapped keys |
| `legacy_auth.authenticate_real_plc` | Blob construction + SessionKey return boundary | `tests/test_session_auth_legacy_auth.py`, both complete upstream vectors |
| `family0.authenticator.RealPlcAuthenticator` | Metadata, seed, challenge/key2 encryption, checksum | Deterministic entropy sequence in the complete blob vectors |
| `key_derivation.derive_session_key` | HMAC(key2[:24], fingerprint(challenge) + challenge[2:18])[:24] | Complete SessionKey vectors and fingerprint regressions |
| `legitimate` | Post-setup challenge solution, distinct from initial key derivation | `tests/test_session_auth_legitimate.py`; connection's 303/1846 exchange |
| `family0.transform7`, `transform12`, `monolith_wrappers` | Proprietary arithmetic/encoding orchestration | Independent full-output reference, source slices, upstream vectors below |

Do not expose generated monoliths as an application API. For a new key within
an existing supported family, verify its upstream bytes/identifier and add it
to the embedded-key inventory. A genuinely new family needs its own
authenticator, blob/metadata rules and independently sourced vectors before
connection negotiation routes to it. Increasing a length constant or bypassing
a family guard is not an implementation.

## Classify a file before changing it

- Outside `_generated/`: handwritten library APIs/orchestration and analysis
  documents. `keys.py` also contains source-inventoried vendored key values.
- `monolith1..8/11.py`, `nine/part*.py`, `ten/part*.py`: mechanical source output.
- `_generated/monolith9.py` and `monolith10.py`: handwritten split-part wrappers.
- `_generated/data/_constants.py` and `.bin`: extracted source/resource data.
- `_generated/**/__init__.py`: handwritten package glue; the data loader also
  embeds source-verified `SHARED_DATA`. All are checksum-inventoried.
- `tests/fixtures/family0`: immutable upstream known-answer data, **not** new
  hardware captures. `provenance.json` maps every binary to source, size and hash,
  and embeds the two upstream Transform7 vectors as exact hex with hashes.
- `tools/`: checkout-only recovery, proof, tracing and benchmarking tools.
  They are not packaged runtime replacements. Solver records are run results,
  not independently checkable proof certificates.

## One offline verification workflow

From a source checkout, no PLC or download is required:

```bash
python -m tools.verify_session_auth
```

This checks 34 runtime/glue artifacts, 25 embedded public keys, 77 existing
binary fixtures and both embedded Transform7 vector sets. Default verification
uses only the standard library and does not import/execute the authentication
package. The authoritative upstream revision and the fingerprint-table repair
are in `artifacts.json`; binary layouts are recorded there too.

For independent source correspondence, supply a **local** HarpoS7 checkout at
the manifest's base revision, containing the recorded repair commit:

```bash
python -m tools.verify_session_auth --upstream-root /path/to/HarpoS7
python -m tools.verify_session_auth --upstream-root /path/to/HarpoS7 --models
```

The first checks transpiled ASTs, binary bytes, all extracted constant values,
public keys and known-answer fixture bytes. The second additionally regenerates
the saved Monolith5/7 Boolean models, checks setup proof accounting and checks
the final-chain recipe's symbolic provenance against the actual source. It does
not rerun all SMT obligations: install the optional `.[analysis]` extra and use
the proof commands/tests in `MONOLITH5_ANALYSIS.md` for fresh solver runs.
These commands are read-only; they never fetch source or contact a PLC.

To regenerate binaries safely into a **new** inspection directory:

```bash
python tools/verify_session_auth_upstream.py --upstream-root /path/to/HarpoS7 --output-dir /path/to/new-directory
```

For monolith regeneration use `tools/transpile_harpo_monolith.py` against the
pinned C# file. Retain its license and verify the resulting AST and vectors;
only formatting and the local source-path docstring are excluded from AST
comparison. Constant literals and handwritten wrappers/loaders are verified
against source values or integrity hashes, not claimed as automatically
regenerable Python text. Never refresh hashes merely to silence unexplained
drift. Keep mechanical output and handwritten behavior changes distinguishable
in commits, and run the full local release checks before every commit.

## Trace a constant or output to evidence

`artifacts.json` supplies exact upstream source paths. Transform7 constants
come from `HarpoS7.Family0/Data/Transform7Data.cs`; Transform12's constant row
index corresponds to `Transform12Data.cs:BigIntData`. The opcode tape is copied
from `Data/Blobs/Transform12Metadata.bin`, retaining its trailing byte.
Fingerprint mutations/tables come from `Fingerprint/{ContextMutator,
FingerprintConsts}.cs`, including the explicitly pinned Data2Collection repair.

```bash
python -m tools.trace_session_auth_output 9 0 --json
python -m tools.trace_session_auth_bits 5 0 --json
python -m tools.decompile_transform12 --phase2 --output-slot 27
python -m tools.transform7_reference --random-cases 2
python -m tools.prove_transform7_reference_topology
```

Word/bit traces are conservative dependency navigation, not influence proofs.
The full reference connects exact input-only setup → all 160 scalar-bit stages
→ fixed tail → destination-live encoded chain and returns every 72 output
bytes. It calls no original Transform7/12, generated execute function, or
runtime arithmetic helper. Monolith7 uses a regenerated Boolean decision model;
raw Monolith4/6 use strictly lowered versioned source-expression graphs, **not**
new compact arithmetic formulas. Differential tests compare every checkpoint,
upstream vectors, arbitrary raw encodings, noncanonical input representatives,
and the known legal setup carry exception. A source-derived symbolic check
compares all 11 destination-live wrapper calls, their distinct output origins
and the omitted dead slot-71 branch; negative controls change slots, pair mates,
argument order and finalization offsets. This checks wiring, not arithmetic.

The existing full 180-byte authentication blob and 24-byte SessionKey vectors
also pass with only Transform7 replaced by this independent reference in tests.
That verifies downstream composition without changing library runtime.
The proof boundary is source-derived models plus tests, not a full-pipeline
solver certificate or new hardware validation.

## Diagnose the boundary, not the entire generated package

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
  seed and checksum boundaries before looking at monolith assignments.
- Accepted SetupSession followed by failure: distinguish activation,
  legitimation and first data request; preserve the PLC status. Issue #34 still
  needs firmware-specific reference evidence and a same-device retest.
- TLS failure: inspect TLS-in-COTP transport/certificate negotiation separately;
  the legacy arithmetic reference does not validate TLS behavior.

## Issue #1 acceptance evidence and closure boundary

| Criterion | Local evidence |
| --- | --- |
| Handwritten flow and supported extension points are easy to identify | This guide, module map and actual connection entry path |
| Every generated/binary runtime artifact has provenance/integrity | Complete 34-file inventory including shared loader; 25 embedded-key records; binary formats |
| One verification workflow | `python -m tools.verify_session_auth`, with optional independent source/model checks |
| Drift fails CI with actionable output | Verifier regression tests, pre-commit hook and explicit quality-job check |
| Existing vectors/package/V1/TLS behavior retained | Full local suite/build checks; runtime functions and resource bytes unchanged |
| Representation changes need equivalence before replacement | No runtime replacement; exact model regeneration, known answers and compatibility negative controls |
| Hardware-validated behavior preserved | No wire/algorithm changes; no assertion of new firmware validation |

The maintainability issue does not require every generated transform to become
an ordinary field/curve formula. Remaining semantic recovery and selective
runtime migration are follow-up research. A mass rewrite is **not** justified:
the setup merge has a real carry exception; ordinary modular tail formulas
fail on arbitrary inputs; reachable scalar/tail invariants remain unproved.
Monolith11's compact model is a promising separately validated migration;
the full Monolith7 decision evaluator is larger/slower than generated code.

Independent review and Gijs's confirmation are required before closing the
issue; merge status alone does not establish completion.
