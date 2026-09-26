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
transforms, not connection or whole-authentication measurements. Other research
processes were active on the same machine; the Monolith5 generated maximum was
548.44 µs versus its 240.33 µs median. The broad differences below are useful
directional evidence, but rerun on an idle machine before a runtime migration.

| Implementation | Output words | Median µs | MAD µs | Source and data bytes | Cold import ms |
| --- | --- | ---: | ---: | ---: | ---: |
| Monolith5 generated | all 12 | 240.33 | 10.08 | 154,417 | 59.01 |
| Monolith5 LUT model | all 12 | 592.57 | 1.49 | 14,956 | 2.13 |
| Monolith5 named gates | all 12 | 541.24 | 3.02 | 17,810 | 2.16 |
| Monolith7 generated | all 36 | 163.98 | 1.00 | 101,505 | 30.24 |
| Monolith7 middle gates | 3–5 | 214.97 | 1.15 | 15,645 | 2.36 |
| Monolith7 tail LUTs | 15–17 | 44.43 | 0.32 | 13,584 | 2.05 |
| Monolith7 full BDD model | all 36 | 956.49 | 5.87 | 910,657 | 8.75 |
| Monolith11 generated | all 5 | 83.91 | 0.41 | 51,078 | 30.08 |
| Monolith11 formula | all 5 | 3.83 | 0.06 | 1,771 | 0.18 |

The Monolith11 formula is about 21.9 times faster in this run and its source
is about 29 times smaller. It is the strongest candidate for a separately
validated runtime migration. The Monolith5 LUT interpreter is about 2.5 times
slower despite its smaller artifact. Named gates improve on its latency by about
9%, but still take about 2.3 times as long as the generated implementation;
readable recovery alone does not imply
runtime improvement. The Monolith7 middle evaluator takes longer for three
words than the generated implementation takes for all 36, so interpreting its
Boolean cores is currently a readability tool rather than a speed optimization.
The complete Monolith7 BDD evaluator is about 5.8 times slower and its source/data
artifact is about nine times larger than generated code. Exact coverage is useful
for reverse engineering and verification, but this representation is not a
compact runtime replacement.

## Runtime recommendation

Retain the recovered models as independently checked analysis references in this
change. A follow-up migration of Monolith11 is worth evaluating with the complete
Family-0 authentication path, retained known-answer vectors, and byte-for-byte
differential checks. Its roughly 80 µs local saving per call is not evidence of
a corresponding connection-speed improvement: transform call counts and network
or hardware costs determine the application effect.

For Monolith5 and Monolith7, use the recovered named gates and Boolean functions
to generate word-level operations before considering runtime replacement.
Per-bit interpretation, source-bit extraction, and output packing dominate these
analysis evaluators. A larger Boolean representation can improve coverage and
understanding while increasing load cost and execution time. Measure the final
complete implementation at the byte interface rather than selecting it on
formula count or source size alone.
