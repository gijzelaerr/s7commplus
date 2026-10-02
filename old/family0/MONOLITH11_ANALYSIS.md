# Monolith11: recovered bitwise structure

This is a human-readable analysis of Family-0 Monolith11 that has since been
promoted to an implementation in `old/family0/monolith11_compact.py`, which
decodes HarpoS7's encoded values; the runtime now passes decoded integers and
needs neither.
Source and destination words below are zero-based, little-endian 32-bit
words. `old/family0/_generated/monolith11.py` (pinned HarpoS7) is retained for
provenance and is still checksummed by `artifacts.json`, but is no longer
called at runtime; `tests/test_v1_session_key_family0_monoliths.py` and
`tests/test_v1_session_key_bitwise_analysis.py` keep validating it directly
against upstream vectors and the compact model.

## Exact word-level form

For output word `i` in `0..4`, choose `K_even` when `i` is even and `K_odd`
otherwise:

```text
out[i] = K(src[3i], src[3i+1], src[3i+2])
       XOR K(src[15+3i], src[16+3i], src[17+3i])
```

Both kernels have the same shape, with the coefficients below:

```text
K(a, b, c) = (a AND A) XOR (b AND B) XOR (a AND b AND AB)
           XOR (c AND C) XOR (a AND c AND AC) XOR (b AND c AND BC)
```

| Kernel | A | B | AB | C | AC | BC |
| --- | --- | --- | --- | --- | --- | --- |
| `K_even` | `5DA724BA` | `6250A363` | `F6BDFCF6` | `86F79499` | `AFFF4FDF` | `5FFBFBAF` |
| `K_odd` | `ECB2D69E` | `C6D87455` | `DFDFDF77` | `104A21AB` | `A7773DFB` | `7DEFFE9F` |

These are 32-bit hexadecimal masks. They are coefficients of the algebraic
normal form (ANF), not additional keys or protocol fields. The runtime
implementation is in `old/family0/monolith11_compact.py`; `tools/monolith11_model.py`
re-exports it unchanged for existing analysis tools and tests.

## How this was established

The generated Monolith11 backward slices contain only bitwise AND, OR, XOR,
NOT, constants, and direct source-word reads. There is no shift, addition,
multiplication, or cross-word state in those slices. Each output bit can
therefore be considered as a separate Boolean function of the *same-position*
source bits. `tools/analyze_bitwise_monolith.py` rejects any other operation.

For each of the five output words and 32 bit positions, the analyzer evaluates
the complete truth table over the source words in that output's backward slice
(17–20 variables, at most 2^20 rows). A Boolean Möbius transform converts each
table to its unique ANF. The resulting monomials and 32-bit coefficient masks
match the compact form above exactly. Although each static slice mentions
17–20 source words, each output bit actually depends on only six: its two
three-word source triples. Every output bit has ANF degree two.

`tests/test_v1_session_key_bitwise_analysis.py` checks the exact ANF match for
all five output words, the upstream Monolith11 byte vector, and 100 seeded
random vectors against the generated implementation. The exhaustive ANF check
is a proof of equivalence *within the verified bitwise model*; the vectors
provide an independent check that the model matches the executable port.
It does not prove equivalence to every Siemens DLL or firmware version.

To reproduce the analysis for output word zero:

```bash
python -m tools.analyze_bitwise_monolith 11 0
python -m tools.analyze_bitwise_monolith 11 0 --json
```

The JSON includes each output bit's essential source words, ANF degree and
term count, truth-table digest, and the complete list of word-level ANF
monomials. Other generated monoliths may mix bit positions or have too many
inputs for exhaustive tables; the tool deliberately refuses those cases.
