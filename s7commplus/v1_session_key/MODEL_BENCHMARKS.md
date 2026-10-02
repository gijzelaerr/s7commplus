# Recovered authentication model benchmarks

The benchmark compares the generated Monolith5, Monolith7, and Monolith11
implementations with their recovered analysis models. It checks the upstream
known-answer fixture and deterministic random inputs before timing each model.
An incorrect model stops the benchmark.

Run from the checkout with the same Python interpreter used by the application:

```sh
python -m tools.benchmark_v1_session_key_models --samples 9 --iterations 20 --source-count 8
```

The command prints JSON containing the interpreter and platform, seed, sample
configuration, output coverage, source/data size, cold import median, and call
latency median, median absolute deviation (MAD), minimum, and maximum. Select
individual implementations with `--implementations NAME ...`; use
`--import-repeats 0` to skip import subprocesses.

## Measurement scope

Every timed call accepts source bytes and returns destination bytes. The
generated adapter allocates a destination and calls `execute`; recovered models
unpack source words, call `execute_words`, and pack the result. This includes the
conversion and allocation required to use a word model at the existing byte
interface. Validation, imports, and input generation are outside call timing.

Monolith7 middle and tail models each recover only three of 36 words. Their
latencies measure those subsets only. The report never assigns them a speed
ratio against the complete generated transform. Their timings cannot be added
or extrapolated to predict a complete implementation.

Artifact size includes the implementation's Python module and direct model JSON
data, including the shared Monolith5 position JSON used by its gate model. It
does not include shared Python dependencies, bytecode caches, installed package
metadata, or interpreter memory. Cold import is measured inside fresh Python
processes, excluding process startup. Generated imports also initialize the
`s7commplus` package; imports are therefore a deployment footprint observation,
not an isolated comparison of source parsing. Existing bytecode caches are
allowed. Run on an otherwise idle machine and repeat on relevant interpreters
before relying on small differences.

## Initial findings

The measured run used CPython 3.13.14 on macOS 26.7 ARM64,
nine samples, twenty iterations, eight deterministic random sources, two warmup
passes, and three fresh-process imports. These are microbenchmarks of individual
transforms, not connection or whole-authentication measurements. Rerun on an
idle machine and treat small differences with caution before relying on them.

| Implementation | Output words | Median µs | MAD µs | Source and data bytes | Cold import ms |
| --- | --- | ---: | ---: | ---: | ---: |
| Monolith5 generated | all 12 | 228.42 | 4.89 | 154,417 | 32.11 |
| Monolith5 LUT model | all 12 | 559.73 | 0.53 | 14,956 | 1.80 |
| Monolith5 named gates | all 12 | 509.29 | 0.87 | 17,810 | 1.83 |
| Monolith5 compiled | all 12 | 103.36 | 0.58 | 94,288 | 28.82 |
| Monolith7 generated | all 36 | 148.68 | 1.58 | 101,505 | 25.54 |
| Monolith7 middle gates | 3–5 | 206.28 | 0.64 | 15,645 | 2.28 |
| Monolith7 tail LUTs | 15–17 | 43.44 | 0.50 | 13,584 | 2.00 |
| Monolith7 full BDD model | all 36 | 882.45 | 15.14 | 910,657 | 8.35 |
| Monolith11 generated | all 5 | 79.80 | 0.68 | 51,078 | 25.34 |
| Monolith11 formula | all 5 | 3.39 | 0.16 | 767 | 28.26 |

(Reproduce with `python -m tools.benchmark_v1_session_key_models --samples 9
--iterations 20 --source-count 8`. The Monolith11 formula's cold-import cost
now reflects that `tools/monolith11_model.py` re-exports the runtime
`old/family0/monolith11_compact.py`, which imports the `s7commplus` package.)

The Monolith11 formula is about 23.5 times faster than generated and its
source is about 67 times smaller; it is migrated to runtime
(`old/family0/monolith11_compact.py`). The Monolith5 LUT and named-gate
interpreters are each about 2.2-2.5 times *slower* than generated despite
their much smaller artifacts — per-position interpretation overhead (a
runtime loop, dict cache lookups, subset enumeration), not the underlying
arithmetic, dominates their cost. Compiling the same named-gate formula into
flat, straight-line Python (`tools/compile_monolith5.py`, "Monolith5
compiled" above) removes that overhead: it is about 2.2 times *faster* than
generated and about 1.6 times smaller, and is now also migrated to runtime
(`old/family0/monolith5_compact.py`). This confirms the prior recommendation
below — generate word-level operations before judging a representation by
formula count or source size alone. The Monolith7 middle evaluator takes
longer for three words than the generated implementation takes for all 36,
so interpreting its Boolean cores is currently a readability tool rather
than a speed optimization. The complete Monolith7 BDD evaluator is about 5.9
times slower and its source/data artifact is about nine times larger than
generated code; unlike Monolith5, there is no full-coverage factored form to
compile it from — only 6 of its 36 output words have one. Exact coverage is
useful for reverse engineering and verification, but this representation is
not a compact runtime replacement.

## Runtime recommendation

Retain the recovered models as independently checked analysis references in
this change, except Monolith11 and Monolith5: both are migrated to runtime
(`old/family0/monolith11_compact.py`, `old/family0/monolith5_compact.py`), validated
against the complete Family-0 authentication path, retained known-answer
vectors, and byte-for-byte differential checks against their retained
generated implementations. Their local per-call savings (roughly 80 µs for
Monolith11, roughly 125 µs for Monolith5) are not evidence of a
corresponding connection-speed improvement: transform call counts and
network or hardware costs determine the application effect — Monolith5 also
runs up to four times per `Transform7.execute()` call, so its savings
compound somewhat more than Monolith11's single call site. The size/clarity
win — retiring two generated permutation-cipher modules in favor of proven,
regenerable implementations — is the primary motivation, consistent with
issue #1.

For Monolith7, extending the shared-core factoring approach used for words
3-5 and 15-17 to the remaining 30 output words — the prerequisite for a
compilable full-coverage model, the same way Monolith5's named-gate model
enabled its compilation — is unproven further research, not a scoped
migration task; there is currently nothing complete to compile. Measure the
final complete implementation at the byte interface rather than selecting a
representation on formula count or source size alone: this benchmark's
Monolith5 result shows a slower interpreter can still compile into a faster
runtime implementation.

## Transform7 and whole-authentication timing

`old/family0/transform7_compact.py` runs Transform7's setup as the proven integer
arithmetic and interprets the Transform12 tape over plain integers
(`old/family0/transform12_compact.py`) instead of packed 24-byte lanes. The
original `transform7.py` is retained, unexecuted, as the reference. Median
timings on the machine above (CPython 3.13, macOS ARM64):

| Measurement | Before | After |
| --- | ---: | ---: |
| `Transform7.execute` (one call, 12 random cases byte-identical) | 193 ms | 9.8 ms |
| `handshake.authenticate_real_plc` (S7-1500 key) | 446 ms | 75 ms |

"Before" is the `master` checkout without any compact migration. Unlike the
single-transform microbenchmarks above, the second row *is* a whole-authentication
measurement, but still excludes network and PLC time. After this change,
roughly 57% of the remaining authentication time is spent in the generated
Monolith9 (the `nine` package, called 12 times per authentication), which is
the next candidate for recovery (done; see the next section).

## Monolith9/Monolith10 as PRESENT-80

Monolith9 is PRESENT-80 (standard S-box and P-layer, 31 rounds plus
whitening) on a byte-reversed block, and Monolith10 lays out its key schedule
with three fixed quirks; see `real_plc/present.py`. Every encoded
160-bit buffer the transforms exchange decodes through Monolith11's kernel as
the value XOR a fixed offset, so the authenticator now passes plain integers:

- PreSeedTransform is three encryptions of the key1 blocks under the fixed
  key `seed.PRE_SEED_KEY` (the round-key layout in `TRANSFORM1_DATA`).
- SeedTransform decodes the Transform7 span to its value and computes
  Transform13's contribution to Monolith11 directly; the encoding offsets
  cancel, so the seed is `pre_seed ^ seed.seed_mask(...)`.
- KeyDerivationTransform is six encryptions of `SHARED_DATA` blocks keyed by
  the low and high 80 bits of the pre-seed.

The runtime no longer executes Monolith8, Monolith9, Monolith10 or
Transform13. The handwritten `execute` ports remain as references, and tests
pin the value path against them, the upstream fixtures and the complete
encoded authentication chain.

| Measurement | Before | After |
| --- | ---: | ---: |
| Monolith8 → Transform13 → Monolith11 (20 random spans byte-identical) | 13.9 ms | 0.7 ms |
| `old.family0.seed_transform.execute` (300 seeded cases byte-identical) | 38.6 ms | 23.9 ms |
| `handshake.authenticate_real_plc` (S7-1500 key, Transform13 step only) | 75.8 ms | 60.1 ms |
| `handshake.authenticate_real_plc` (S7-1500 key, all Monolith9 calls) | 75.8 ms | 23.3 ms |

The authentication rows are medians of 15 runs in one session. The remaining
time is dominated by the Transform7 span computation (Monolith1, Monolith2 and
Monolith4), which the next section removes.

## SeedTransform as x-only ECDH

Transform7 followed by the Monolith1 loop and Monolith2 decodes to
`x(k * Q)` on the curve `y^2 = x^3 - x + B` over `GF(2^160 - 47)`, whose group
has the prime order `0x100000000000000000000F368CDA5CDB2EBFC69C7`:

- `Q` is the source's first 20 bytes read as a little-endian x-coordinate
  (the generator in `TRANSFORM7_DATA[0xD8:]`, or the PLC public key);
- `k = prng2 ^ SCALAR_MASK`, where the mask is the one
  `tools/recover_scalar_encodings.py` derives from the Transform12 branches;
- `B` is Transform12's doubling constant `_CONSTANTS[58] mod p`;
- the source's second 20 bytes and `prng1` only blind the packed
  representation; Monolith1 re-randomizes it and Monolith2 serializes the
  decoded value; infinity decodes to 0.

SeedTransform is therefore an ECDH: the blob carries `x(k*G)` and `prng1`,
and the seed is `pre_seed ^ Transform13(x(k*PK))`. `real_plc/curve.py`
computes both with an x-only Montgomery ladder, which also handles the
catalogue keys whose x-coordinate lies on the quadratic twist (about half of
them; no stored y-coordinate satisfies the curve equation).

The generated arithmetic is not quite modular: BigIntSubtraction drops a
carry when a value below 47 meets a non-canonical representative just below
`2^160`. Random intermediates reach that with probability around `2^-150`
per operation, so seeded tests over random entropy and every catalogue key
are byte-identical, but structured inputs (for example `x = 5`, or the
constructed cases in `tools/trace_scalar_seed_boundary.py`) make the original
return a point that is not the true multiple and that depends on the blinding
inputs. The ladder always returns the true multiple; tests record those cases
and keep the original chain as `old.family0.seed_transform.reference_execute_value`.

| Measurement | Before | After |
| --- | ---: | ---: |
| `seed.write_seed` (seeded cases byte-identical) | 21.5 ms | 1.2 ms |
| `handshake.authenticate_real_plc` (S7-1500 key) | 23.3 ms | 2.0 ms |

Authentication now executes no generated monolith; its remaining time is
split between the two ladders, the challenge fingerprint and the PRESENT-80
encryptions.

## Challenge fingerprint as a gate network, then as an SPN

HarpoFingerprint's per-step formulas combine a FP_DATA2 nibble with a nibble
of a context that ContextMutator changes between rounds, but that context
never depends on the challenge. Each step is therefore a fixed gate
`state[dst] = table[state[a] << 4 | state[b]]` over a 544-nibble state whose
first 32 nibbles are `challenge[2:18]`. The network has depth 29, and every
output nibble depends on all 32 challenge nibbles. Its tables are balanced
and none is XOR- or addition-separable, which is what white-box encodings
look like.

The layers give the cipher away. Gates come in pairs that read the same two
nibbles, so each pair is a byte function; the depth-3 gates are Latin squares
folding 32 nibbles to 16; and the other layers alternate between byte
bijections of one shared shape and "shuffles" whose outputs read exactly two
bits (a crumb) of each input nibble. The first layer reads the challenge
unencoded, and for each challenge byte exactly one key byte makes every
output crumb a bit pair `(j, j + 4)` of AES's inverse S-box. Labelling every
wire with the plain crumbs it determines then identifies the rest (see
`tools/recover_fingerprint.py`):

- `y = InvSubBytes(challenge[2:18] ^ K)`, then the state is `y[0:8] ^ y[8:16]`;
- 13 rounds, each splitting the 8 bytes into two groups of four, transposing
  each group's 4x4 grid of crumbs, and applying the inverse S-box under a key
  byte;
- 16 fixed, non-affine 4-bit encodings of the final crumbs, which look like
  the white-box's external output encoding.

Each of the 120 key bytes and 104 S-box source orders is the only one that
fits. The wiring and keys follow no evident schedule, so this is probably a
generated cipher rather than a published one. `real_plc/fingerprint.py` now
computes it directly. The tests rerun the recovery (about 4 s), compare the
cipher with the gate network and with the verbatim HarpoS7 port, and check the
transposition structure.

| Measurement | Direct port | Gate network | SPN |
| --- | ---: | ---: | ---: |
| `fingerprint_challenge` | 0.51 ms | 0.018 ms (after a 19 ms table build) | 0.010 ms |
| Runtime data | HarpoS7 tables | 66 KB `fingerprint_gates.bin` | about 1 KB of constants |
| `handshake.authenticate_real_plc` (S7-1500 key) | — | 1.44 ms | 1.33 ms |

The authentication row is a median of 15 runs in one session.

## The blob checksum and HarpoAesCtr

LutGenerator and ChecksumTransform are one GF(2^128) multiplication: the
table holds the multiples of `H`, and the checksum of `X` is `X * H`
modulo the irreducible `x^128 + x^32 + x^15 + x^2 + 1`, on little-endian
blocks. The authenticator therefore keeps `H` and the running checksum as
integers and calls `checksum.multiply`. The blob checksum is
GHASH-shaped (`c = (c ^ block) * H`, then the length and one more multiply,
encrypted under the checksum key), but in a different field and bit order
from GCM. The table-driven ports remain as references, pinned to `multiply`
and the upstream Transform3/Transform4 fixtures.

HarpoHash and HarpoAesCtr, which the SessionKey handshake does not use,
are standard: HarpoHash is GCM's GHASH multiplication with Shoup's 8-bit
tables, and HarpoAesCtr is AES-GCM without associated data, apart from a
24-bit counter increment. Tests match both against a textbook GHASH and
`cryptography`'s AES-GCM. Both modules are now written as that arithmetic
rather than as ports of HarpoS7's 32-bit register code: the Shoup table is
built from a bit-serial GCM multiply, the reduction table is computed from the
reduction rule, and HarpoAesCtr keeps `J0`, the counter, the running GHASH
and the ciphertext length under those names. HarpoS7's known-answer
vectors still pass unchanged, and a differential run against the previous
port matched on 400 random sessions with split blocks, truncated tags and
24-bit counter wraps. They have since dropped HarpoS7's names too: the
modules are `ghash.py` (`times_x`, `multiplication_table`, `multiply`,
`REDUCTION_TABLE`), `aes_gcm.py` (`AesGcm24` with `start`, `encrypt` and `tag`)
and `aes_ecb.py` (`AesEcb`).
