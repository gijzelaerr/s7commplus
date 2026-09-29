# Recovered authentication model benchmarks

The benchmark compares the generated Monolith5, Monolith7, and Monolith11
implementations with their recovered analysis models. It checks the upstream
known-answer fixture and deterministic random inputs before timing each model.
An incorrect model stops the benchmark.

Run from the checkout with the same Python interpreter used by the application:

```sh
python -m tools.benchmark_session_auth_models --samples 9 --iterations 20 --source-count 8
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
| Monolith7 compiled | all 36 | 2924.69 | 8.50 | 6,318,046 | 8.14 |
| Monolith11 generated | all 5 | 79.80 | 0.68 | 51,078 | 25.34 |
| Monolith11 formula | all 5 | 3.39 | 0.16 | 767 | 28.26 |

(Reproduce with `python -m tools.benchmark_session_auth_models --samples 9
--iterations 20 --source-count 8`. The Monolith11 formula's cold-import cost
now reflects that `tools/monolith11_model.py` re-exports the runtime
`family0/monolith11_compact.py`, which imports the `s7commplus` package.)

The Monolith11 formula is about 23.5 times faster than generated and its
source is about 67 times smaller; it is migrated to runtime
(`family0/monolith11_compact.py`). The Monolith5 LUT and named-gate
interpreters are each about 2.2-2.5 times *slower* than generated despite
their much smaller artifacts — per-position interpretation overhead (a
runtime loop, dict cache lookups, subset enumeration), not the underlying
arithmetic, dominates their cost. Compiling the same named-gate formula into
flat, straight-line Python (`tools/compile_monolith5.py`, "Monolith5
compiled" above) removes that overhead: it is about 2.2 times *faster* than
generated and about 1.6 times smaller, and is now also migrated to runtime
(`family0/monolith5_compact.py`). This confirms the prior recommendation
below — generate word-level operations before judging a representation by
formula count or source size alone. The Monolith7 middle evaluator takes
longer for three words than the generated implementation takes for all 36,
so interpreting its Boolean cores is currently a readability tool rather
than a speed optimization. The complete Monolith7 BDD evaluator is about 5.9
times slower and its source/data artifact is about nine times larger than
generated code; only 6 of its 36 output words have the small, readable
factored (shared-gate-core) form Monolith5's compiled result was built from.

The full 36-word BDD model *is* complete, however, so compiling it the same
way as Monolith5 (`tools/compile_monolith7.py`, "Monolith7 compiled" above)
was tried directly. Unlike Monolith5, **this does not pay off**: the result
is byte-exact but about 20 times *slower* and about 62 times larger than
generated, and about 3.3 times slower than the interpreter it was meant to
replace. Monolith5's model was word-parallel — 168 statements each doing
32-bit-wide bitwise work on whole `source[i]` words. Monolith7's full model
is bit-serial — 1,152 independently-derived bit computations with almost no
cross-bit sharing (~77,000 total node evaluations, only 22 of 1,152 bits
exactly duplicating another bit's computation). Unrolling a bit-serial walk
into ~77,000 discrete Python statements inside one function multiplies
per-statement interpreter overhead instead of removing it; the hand-written
ROBDD-walking loop is already more efficient per elementary operation than
that flat expansion. Exact coverage remains useful for reverse engineering
and verification; neither Monolith7 representation is a compact runtime
replacement today.

## Runtime recommendation

Retain the recovered models as independently checked analysis references in
this change, except Monolith11 and Monolith5: both are migrated to runtime
(`family0/monolith11_compact.py`, `family0/monolith5_compact.py`), validated
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

For Monolith7, the full 36-word BDD model was compiled the same way as
Monolith5, and it made things worse on both size and speed (see above) — the
"compile the interpreter into flat code" playbook that worked for Monolith5
does not transfer here, because the underlying model's structure is
fundamentally bit-serial rather than word-parallel. Extending the small
shared-core factoring approach used for words 3-5 and 15-17 to the remaining
30 output words remains unproven further research, not a scoped migration
task, and would need to actually produce word-parallel structure (not just
more per-bit coverage) to have a realistic chance of compiling faster than
the interpreter. Measure the final complete implementation at the byte
interface rather than selecting a representation on formula count or source
size alone: this benchmark's Monolith5 result shows a slower interpreter can
still compile into a faster runtime implementation, and its Monolith7 result
shows the reverse can also happen — compiling can make a slow interpreter
slower still.
