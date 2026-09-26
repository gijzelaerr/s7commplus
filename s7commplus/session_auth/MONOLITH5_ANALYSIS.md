# Monolith5: recovered compact Boolean model

This is an exact compact model of the pinned, generated Family-0 Monolith5,
not a runtime replacement or a claim about every proprietary DLL version.
Source and destination are little-endian 32-bit words, numbered from zero.

Monolith5 consumes 54 source words and produces 12 output words. Its generated
body is mostly bitwise logic, but unlike Monolith11 it contains fixed shifts
and multiplications by two. The bitwise-only truth-table method therefore does
not apply directly. `tools/trace_session_auth_bits.py` follows every output
bit through the versioned backward slice, including constant masks, logical
right shifts, left shifts, and power-of-two multiplication modulo 2³².

## Recovered formula

The 12 output words form two streams, each with six 28-bit payload limbs.
Payload bits occupy word bits 2–29; word bits 0, 1, 30, and 31 are always zero.
Let `A[t]` be the first stream's payload bits and `B[t]` the second stream's,
for `t = 0..167`. The first bit of the second stream is always zero: `B[0]=0`.

An input bit lane is a nine-bit vector: for source triplet `c` (0–5) and bit
position `p` (0–31), take bit `p` of source words `18*s + 3*c + j`, with span
`s = 0..2` and member `j = 0..2`. Place those nine bits at positions `3*s+j`
of the vector. Call one of the 32 recovered nine-input truth-table functions
on this vector `F_k(c,p)`.

Each position record selects two or three such lane functions `f₀, f₁, …`
and a constant `a`. The exact two-output formula is:

```text
A[t]   = a XOR f₀ XOR f₁ [XOR f₂]
B[t+1] = r XOR XOR { product(f_j for j in S) : S selected by mask }
```

Here `r` is zero except for the first position, where one extra nine-input
lane function supplies a boundary correction. A product is Boolean AND; the
empty product is one. No selected term contains all three functions, so the
second stream is at most quadratic in these lane functions. The 32 truth
tables, 168 position records, and masks are in
`tools/monolith5_model.json`; `tools/monolith5_model.py` evaluates this formula.
Both are analysis-only and leave the generated runtime code unchanged.
Every recovered lane function is symmetric under permutation of the three
72-byte input spans; the test suite checks all 512 inputs and all six span
permutations for every truth table.

## Named gates and span structure

The nine-input functions have a second, more readable exact decomposition.
Every function applies the **same three-input gate** independently to each
input span and then combines the three results:

```text
s0 = g(x0, x1, x2)
s1 = g(x3, x4, x5)
s2 = g(x6, x7, x8)
F_k = h(s0, s1, s2)
```

The gate `g` is conditional selection (`choose`) or `majority`, with fixed
argument permutations and input inversions. Its normalized value at `000`
is zero. Under that normalization, exhaustive search finds exactly one
complete decomposition for each of the 32 functions. The symmetric combine
`h` belongs to four familiar operations:

| Combine | Exact formula | Number of lane functions |
| --- | --- | --- |
| XOR of three | `a XOR b XOR c` | 15 |
| Majority | `(a AND b) XOR (a AND c) XOR (b AND c)` | 15 |
| OR of three | `a OR b OR c` | 1 |
| Not all equal | `(a OR b OR c) XOR (a AND b AND c)` | 1 |

Here `choose(a,b,c) = b XOR ((a XOR b) AND c)`. For example, lane
function zero uses `choose(x0,x1,x2)` in each span and `not_all_equal`
to combine the three results. This structure explains the previously observed
symmetry under permutation of whole input spans. It does not by itself identify
the proprietary algorithm or establish a cryptographic interpretation.

`tools/recover_monolith5_gates.py` checks all 512 rows for every candidate
decomposition and recognizes the local gates through the shared Boolean
decomposition machinery. The saved `tools/monolith5_gate_model.json` contains
32 gate records. The evaluator `tools/monolith5_gate_model.py` applies each
gate to entire uint32 words, evaluating 32 bit lanes together; it reuses the
existing 168 position records to reconstruct all twelve output words.
The exhaustive tests compare all 16,384 lane-function truth rows with the
original LUTs, in addition to the known-answer vector and comparisons against
the generated implementation on structured, single-bit, and random inputs.

```bash
python -m tools.recover_monolith5_gates --formula 0
python -m tools.recover_monolith5_gates --verify tools/monolith5_gate_model.json
```

## Exact additive span identity

`tools/recover_monolith5_span_decoder.py` derives an additive interpretation of
the two raw streams directly from the recovered position and named-gate models.
Let A and B be their six-lane 168-bit payload integers, p = 2^160 - 47,
and s0, s1, s2 the three eighteen-word input spans. Then:

```text
A + B = C + D(s0) + D(s1) + D(s2) - p * majority(b0,b1,b2) (mod 2^168)
C = 51698806077986350461380052348415547004375582574557
bi = choose(si.word0_bit0, si.word1_bit0, si.word2_bit0)
```

D is a reusable sum of 169 signed, weighted local choose/majority gates. The
tool prints their complete coefficients with `python -m
tools.recover_monolith5_span_decoder`. No interpolation or chosen-input fitting
is used: integer truth-table transforms check every interior output pair;
`xor3 + 2*majority = sum` cancels their interactions. The first-position identity
`2*or3 - not_all_equal = sum - majority` leaves the explicit -p correction.
Top-position XOR interactions vanish modulo 2^168.

Tests check the known-answer vector, 1,000 seeded arbitrary-word inputs,
structured and single-bit inputs, and all boundary configurations with span
permutations against generated Monolith5. The derivation is exact relative to
the existing symbolically recovered gate/position models, not merely a sampled
identity.

This is **not yet a field decoder**: reducing a 168-bit sum before reducing
modulo p discards a multiple of 2^168, which is not zero modulo p. The identity
also does not determine A and B separately, so it cannot replace the exact
setup merge or its carry correction. Earlier Monolith3/4/6 encoded-span
identities still need source-derived proofs on their valid encoding domain.

## Binary normalization and Monolith4 carry investigation

The recovered decoder admits a further exact normalization, checked directly
from all 169 coefficients in `tools/recover_monolith4_span_identity.py`.
Its boundary gate h has weight H=(p+1)/2. Each of its other 168 gates has a
distinct weight +2^k or -2^k, k=0..167. Complement every negative-weight gate
to obtain an ordinary unsigned binary payload B. If n is the sum of the
negative weights, D=n+B+H*h and the recovered constant C is exactly -3*n.
Consequently the candidate field shadow is V=B+H*h modulo p, with no fitted
offset. These normalization statements are exact integer algebra, before any
modular reduction.

Substituting this into the already recovered exact Monolith5 identity gives:

```text
A+B = B0+B1+B2 + H*parity(h0,h1,h2) + majority(h0,h1,h2) (mod 2^168)
```

This uses 2H=p+1, so H*sum(h)-p*majority(h) becomes
H*parity(h)+majority(h). It is an exact reformulation of the symbolic model,
not interpolation. It still does not recover the two streams separately.

For Monolith4, the resulting decoded full-addition identity is now proved
by the carry-stage source proof below:

```text
T = B0+B1+(h0 & h1)
B_out = T mod 2^168
h_out = h0 XOR h1
overflow = T >= 2^168
V(out)-V(in0)-V(in1) = -12032*overflow (mod p)
```

The last equation follows algebraically from the decoded addition: the boundary
contributes -p*(h0 & h1), which vanishes modulo p, while a discarded carry
contributes -2^168, congruent to -12032. All 1,000 seeded arbitrary raw-span
tests match the complete formula and both overflow branches. Sampling alone
did not prove all 168 output bits; the later source proof completes that step.
The exact signed decoder also obeys the integer identity:

```text
D(out) = D(in0)+D(in1)-n-p*(h0 & h1)-2^168*overflow
```

This retains both corrections before modular reduction. Independent weighted
decoder tests cover all eight boundary-bit/overflow combinations. The tool's
historical `candidate_add` name is retained, but its decoded predictions are
now established for the pinned source, not merely sampled.

The tool separately proves h_out and the first **eight** B_out bits for every
uint32 source using canonical ROBDD equality against ripple-addition diagrams.
It interprets only demanded bits from versioned source slices, preserving
assignment versions, masks, fixed shifts, complements, and uint32 truncation.
The eight-bit proof peaks at 157,895 decision nodes. Wider attempts exceed the
existing two-million-node bound; integer polynomial expansion also grows too
large. Neither attempt is represented as a completed full-addition proof.
Further solver-backed verification would require an additional development
dependency. The approved development-only `analysis` extra supplies Z3 without
changing runtime dependencies. `tools/prove_monolith4_span_identity.py` first
checks an independent fixed-width AST translation and its demanded Boolean
translation against eight generated-code controls. It then checks each decoded
output bit incrementally, retaining only equalities already proved for all
source assignments as lemmas. Reports include source/model SHA-256 hashes,
solver version, completed query count, and timeout/unknown or counterexample
status. An unknown result exits unsuccessfully; it is never treated as proof.

The initial Z3 4.16.0 run with a 60-second solver budget established the
boundary bit and first 25 payload bits, then returned unknown/timeout on the
next query. That attempt was only a bounded source proof; the carry-stage
decomposition below subsequently proves all 168 bits. The runtime is unchanged.

```bash
python -m tools.recover_monolith4_span_identity
python -m pip install '.[analysis]'
python -m tools.prove_monolith4_span_identity --payload-bits 25
python -m tools.prove_monolith4_span_identity --timeout-ms 60000
```

The Monolith3/6 pair proofs below subsequently establish their corresponding
decoded equations. Remaining work is to track extra high bits and establish
encoding bounds through the whole setup. A decoded identity alone does not
justify replacing encoded runtime words.

## Carry-stage proof decomposition

`tools/prove_monolith4_carry_stages.py` expresses the addition proof in terms
of the actual decoded source functions, rather than growing ideal prefixes.
Let xk and yk be the normalized input payload bits and sk the decoded output.
Define ck = sk XOR xk XOR yk. The proof obligations are:

```text
h_out = h0 XOR h1
c0 = h0 AND h1
c(k+1) = majority(xk,yk,ck)        k=0..166
```

These 169 obligations imply all 168 payload sum bits by induction: sk is
xk XOR yk XOR ck by definition. No carry equality is assumed to prove itself.
The final overflow follows from the mathematical addition once this chain is
complete. Eight deterministic controls compare both the independent fixed-width
AST compiler and the demanded-bit compiler against generated output before any
solver queries. Reports pin source/model hashes and solver version.

Initially, dedicated stages [0,31) with Z3 4.16.0 all returned UNSAT, establishing
the boundary and a **30-bit payload prefix**. An isolated UNSAT proof of
carry_29_to_30 then extends the established prefix to **31 bits by composition**.
The isolated report correctly claims no prefix on its own: it does not include
the base cases. That was a partial result, superseded by the complete run below.

The full source run now returns **UNSAT for all 169 obligations**, proving the
boundary identity and all **168 payload bits** for arbitrary uint32 inputs.
It uses fresh Z3 SAT-tactic solvers over the unsimplified demanded-bit DAG,
without cut signals, retained lemmas, or reachable-state assumptions. Preserving
the source DAG and selecting the direct SAT tactic made previously stalled
queries tractable. The run used a 30-second budget per stage; total stage time
was about 530 seconds and the slowest stage about 7.05 seconds. Compilation and
the eight generated-code controls are outside the per-stage solver budget.

`tools/monolith4_carry_proof.json` records the full run, hashes, Z3 version,
timings, and every completed obligation. It is a solver-run record, **not an
independently checkable proof certificate**. Default tests check its provenance
and accounting, not the UNSAT answers themselves; rerun the optional harness to
replay the proof. Time budgets and proof frontiers can vary, and an unknown is
still neither a proof nor a refutation.

The experimental cone mode replaces nonlocal sub-DAGs with consistently shared,
independent Boolean cut signals. Every concrete source assignment specializes
those signals back to their original functions, so UNSAT proves a stronger
equation and therefore the source equation. SAT may be spurious. Refinement
expands cut definitions instead of inventing reachable-state constraints.
Initial aggressive cuts prove the base cases but lose correlations required
for later stages; widening them has not completed the full proof. An optional
lemma-retaining solver mode uses only previously proved equalities and was
slower in the tested run, so independent stage queries remain the default.

Dependency-free tests exhaustively check cone specialization and refinement on
small shared Boolean DAGs, including an original UNSAT expression whose
generalization is SAT. They also guard constant preservation, induction gaps,
partial-range completion, invalid query limits, source DAG preservation,
observer isolation, and explicit timeout reasons. CLI failures and timeouts
exit unsuccessfully, and a full proof requires every one of the 169 stages.

```bash
python -m tools.prove_monolith4_carry_stages --stop 31 --timeout-ms 10000
python -m tools.prove_monolith4_carry_stages --start 31 --stop 32 --timeout-ms 30000
python -m tools.prove_monolith4_carry_stages --timeout-ms 30000 --progress
python -m tools.prove_monolith4_carry_stages --abstract --stop 6
```

The Monolith3/6 pair proofs below extend this to the other setup wrappers.
Next is complete setup composition, including high bits, overflow, and
carry-sensitive packing. The completed Monolith4 proof
establishes only its decoded payload and boundary, not individual encoded output
words or the safety of a whole-pipeline modular rewrite. Runtime source and
dependencies remain unchanged.

## Monolith6: local carry proof and corrected pair halving

`tools/prove_monolith6_span_identity.py` establishes a decoded **pair** identity
from the pinned generated Monolith6 AST. There are three normalized inputs
`(Bi,hi)` and two outputs `(Oj,gj)`, with the same H=(p+1)/2 and M=2^168.
Define:

```text
q = parity(h0,h1,h2)
a = majority(h0,h1,h2)
T = B0+B1+B2+H*q+a
U = 2*(O0+O1)+g0+g1
U = T                         (mod M)
g0+g1 <= 1
```

This is not unconditional field halving: M is nonzero modulo p. The local
proof also establishes the signed wrap balance m is -1, 0, or 1. Consequently:

```text
m = (U-T)/M
2*(V(out0)+V(out1))-sum(V(in)) = M*m+p*(g0+g1-a)     (exact integers)
V(out0)+V(out1) = H*sum(V(in))+6016*m                (mod p)
2*(D(out0)+D(out1))-sum(D(in)) = n+M*m+p*(g0+g1-a)   (exact integers)
```

Here the exact-integer V means B+H*h before reduction; D=n+V remains the
weighted signed decoder. These equations use only 2H=p+1 and M mod p=12032,
not a primality assumption. The m calculation currently uses actual output
high bits; it is **not an input-only prediction** from the current decoder.

The source proof decomposes the equation into local integer columns. Let nik
be input i's payload bit k, Nk=sum_i(nik), and fk=bit_k(H). Set:

```text
ak = majority(h0,h1,h2)            if k=0
ak = majority(n0,k-1,n1,k-1,n2,k-1) otherwise
rk = floor((Nk+fk*q+ak)/2)
g0+g1 = N0+q+a0-2*r0
o0,k-1+o1,k-1 = Nk+fk*q+r(k-1)-2*rk   k=1..167
m = o0,167+o1,167-r167
-1 <= m <= 1
```

The initial column and 167 subsequent columns telescope to U=T modulo M;
the top-bit equation gives its exact wrap balance. The carries are explicit
input functions, not assumed equalities or growing ideal-prefix recurrences.
Each equality is proved independently for all source assignments. Four-bit
bitvector arithmetic encodes these small integer comparisons exactly: counts
are at most five, carries at most two, and column differences lie between
-6 and 6, so no mismatch can alias zero modulo 16. Dependency-free tests check
these bounds and the integer equations independently.

With Z3 4.16.0, all **170 obligations returned UNSAT**: boundary exclusivity,
initial column, 167 local columns, and the wrap bound. Stage time totaled about
5.46 seconds, with no stage exceeding 0.10 seconds in the recorded run. This
excludes source compilation and eight generated-runtime controls comparing both
the independent fixed-width AST and demanded-bit compilers. A full-width query
previously timed out after 60 seconds, and the slower prefix formulation remains
available as `--prefix-queries`; neither a timeout nor an interrupted run is a
completed proof.

`tools/monolith6_span_proof.json` records the source/model hashes, Z3 version,
timings, and all completed obligations. Like the Monolith4 record, it is **not
an independently checkable proof certificate**. Normal tests verify provenance
and accounting without requiring Z3; rerun the optional harness for the proof.
The shared demanded-bit evaluator now supports separately cached versioned
Monolith3/4/6 programs and output spans. Concrete controls exercise all three
on one backend, retaining the existing Monolith4 defaults and bounded proof.

`tools/recover_monolith6_span_identity.py` checks 1,000 arbitrary raw sources:
all corrected shadows match, with wrap counts m=-1:256, m=0:515, and m=1:229.
It preserves a stronger negative control for decoded-only state. Compare an
all-zero 216-byte source with one whose uint32 word 17 has bit 9 set. All
three `(Bi,hi)` inputs are identical, but O0 decreases by 2^167, O1 is unchanged,
and the output pair shadow decreases by 6016 modulo p. The first source has
m=1, the second m=0. The bit sits outside the current input decoder and shifts
into the output's highest payload position. Therefore the existing input
payload/boundary model cannot determine even the complete output-pair shadow
for arbitrary raw sources. This is a synthetic kernel counterexample, not a
hardware authentication-failure claim.

```bash
python -m tools.recover_monolith6_span_identity
python -m tools.prove_monolith6_span_identity --timeout-ms 10000 --progress
```

Monolith3's corresponding proof is now complete below. Next: track these extra
high bits or prove encoding bounds through the real setup call graph. The
conditional affine setup composition still assumes the uncorrected halving
relationship and does not incorporate these wraps. This pair proof does not
recover the individual output split or justify a modular runtime substitution.
Runtime code and dependencies remain unchanged.

## Monolith3: a virtual plain-input span and corrected quarter input

`tools/prove_monolith3_span_identity.py` shares Monolith6's local carry proof,
but the third input is a **virtual span**, not a third decoded 72-byte buffer.
Monolith3 receives two encoded spans followed by a 24-byte plain integer N.
Let L=N mod 2^170, e=L bit 0, Q=L>>1, and d=L bit 169. The virtual span is:

```text
h_virtual = e
B_virtual = Q mod M
```

With this substitution, all three-input carry equations from the Monolith6
section hold for the generated Monolith3 source. Its two boundary gates are
exclusive, and the normalized virtual-span wrap m' lies in {-1,0,1}. Restoring
the extra bit of Q gives the full signed wrap m=m'-d, hence -2<=m<=1. Set
a=majority(h0,h1,e), q=parity(h0,h1,e), and g=g0+g1. Then:

```text
T = B0+B1+Q+H*q+a
U = 2*(O0+O1)+g
U-T = M*m
2*V_out_pair-V_in_pair-Q-H*e = M*m+p*(g-a)    (exact integers)
2*D_out_pair-D_in_pair-Q-H*e = 2*n+M*m+p*(g-a)
V_out_pair = H*V_in_pair+H^2*L+6016*m         (mod p)
```

Since 2H=p+1, Q+H*e is L/2 modulo p and H^2 is the inverse of four;
no primality assumption is needed. If using the original 192-bit N rather than
L, the exact residue equation is:

```text
V_out_pair = H*V_in_pair+H^2*N+6016*m-12032*(N>>170)   (mod p)
```

The final term comes from 2^170/4=2^168, which is 12032 modulo p.
The real setup's plain inputs are five-word values in zero-initialized
six-word buffers; `rotate_right_30` multiplies its value by four, so those plain
inputs fit within 162 bits. This removes the plain truncation term there, but
does not yet prove that encoded-span wrap corrections vanish in the whole setup.

All **171 obligations returned UNSAT** with Z3 4.16.0: boundary exclusivity,
initial column, 167 local columns, the normalized wrap bound, and cancellation
of the upper 22 plain bits from the decoded pair sum. Total stage time was about
4.47 seconds, with the slowest query about 0.039 seconds, excluding compilation
and eight independent fixed-width/demanded-bit runtime controls. These queries
allow all 42 source uint32 words to vary freely, including arbitrary upper
plain bits. None of the sampled arithmetic identities is assumed as a lemma.

The upper-bit cancellation proof is semantic, not an absence claim. Individual
output encodings retain dependencies on those bits, so conservative source
support does not establish they are unused. The column equations prove that
they cancel in each pair count through payload bit 166 and in the boundary
count; the final query proves the remaining top-column count is invariant when
plain bits 170..191 are zeroed. Together these establish cancellation for the
entire decoded pair shadow, not for the individual output words or split.

`tools/monolith3_span_proof.json` pins source/model hashes, solver version,
scope, timings, and completed obligations. It is a solver-run record, not an
independently checked proof certificate. Dependency-free tests check its
provenance/accounting, all 192 single-bit plain boundaries, all low-two-bit
division choices, and exact integer columns/corrections against synthetic
generated executions. The shared Monolith6 proof was replayed successfully
after adding the virtual-span specialization.

`tools/recover_monolith3_span_identity.py` checks 1,000 arbitrary raw sources;
all corrected shadows match, with m=-2:126, m=-1:373, m=0:382, and m=1:119.
Wrap measurement still uses actual output high bits: it is not an input-only
replacement formula. An all-zero 168-byte source and one with word 17 bit 9 set
have identical decoded encoded inputs and identical plain input, yet O0 grows
by 2^167 while O1 is unchanged. Their output pair shadows differ by +6016 modulo
p, with m moving from zero to one. As with Monolith6, the current input decoder
does not determine the full pair shadow for arbitrary raw sources. This remains
a synthetic kernel witness, not a hardware-failure claim.

```bash
python -m tools.recover_monolith3_span_identity
python -m tools.prove_monolith3_span_identity --timeout-ms 10000 --progress
```

The decoded setup-wrapper identities are now source-derived: Monolith4's
addition, Monolith3/6's corrected pair halving, and Monolith5's combined packing.
Their correction-aware composition is described below. Establishing input-only
high-bit/encoding invariants is still required for a compact runtime rewrite.
Runtime code and dependencies remain unchanged.

## All-correction setup composition

`tools.trace_transform7_setup_shadows.compose(corrected=True)` walks the actual
setup AST, assigns one additive residue correction c0..c22 to each wrapper in
source-call order, and retains arbitrary individual pair splits. Every split
cancels at the four modeled context exits. It validates that each subsequent
merge copies precisely that Monolith5 call's two 24-byte output streams, rather
than assuming its operands from the destination alone. All arithmetic below is
modulo p, with division meaning multiplication by a unit inverse; no primality
assumption is needed.

For each call, its correction is determined by the preceding source-derived
kernel relation, not by subtracting the observed field output from the affine
prediction:

- Monolith3: c=6016*m - 12032*(N >> 170), relative to
  (V0+V1)/2 + N/4. The wrap uses the decoded output pair; N is the entire
  192-bit plain input, so generic raw calls retain the truncation correction.
- Monolith4: c=-12032*overflow, relative to V0+V1. Overflow is the
  input-derived predicate B0+B1+h0*h1 >= 2^168; the actual decoded output is
  checked against the complete input-derived addition equation.
- Monolith6: c=6016*m, relative to (V0+V1+V2)/2. The wrap again uses the
  decoded output pair.
- Monolith5: let T=B0+B1+B2+H*parity(h0,h1,h2)+majority(h0,h1,h2), and
  let A,B be its actual packed 168-bit output streams. Then
  m=(A+B-T)/2^168 is an integer by the exact combined-payload identity,
  and c=12032*m, relative to V0+V1+V2. This is the previously omitted
  packed-sum wrap; a congruence modulo 2^168 is not equality modulo p.

The resulting four residue expressions are the earlier affine expressions
**plus** weighted call corrections and each slot's own final-merge correction.
The complete coefficients are printed by the trace command and pinned in
tests. Their dependency neighborhoods are:

| Context slot | Wrapper-call corrections that survive |
| --- | --- |
| 46 | 0, 2, 3, 4, 5 |
| 48 | 0, 1, 2, 3, 6, 9, 10, 11, 12, 13, 14, 17, 18, 19, 20 |
| 70 | 0, 1, 2, 11, 12, 13, 14, 15, 16 |
| 94 | 21, 22 |

Calls 7 and 8 have no downstream consumers affecting these four setup slots.
This observation alone is not authorization to remove their runtime calls.
For example, slot 46 is

    d/4 + X/4 + Y/2 + R/8 + c0/2 + c2 + 2*c3 + c4 + c5 + merge46

Here X is the first source coordinate, Y and R have setup's forced bit 2,
d is the bundled nonzero span shadow, and merge46=(94-2^128)*E46. Each E
is the already derived lost-carry predicate on that slot's two **prepared
individual** streams. Their modular sum alone does not determine E.

`tools/trace_transform7_setup_corrections.py` copies inputs before aliased
wrapper writes, independently measures each correction, checks its decoded
identity, verifies all four merge outputs byte-for-byte, and evaluates the
corrected AST expressions against the real setup context residues. In 132
synthetic cases it checks 3,036 wrappers and 528 merges with no residue
mismatches. All sampled wrapper wraps and plain truncations are zero; exactly
one final merge has the known lost carry. On that legal bundled-base-point
witness, the corrected composition predicts slot 46 = 94, whereas the
uncorrected affine candidate predicts 2^128. No interpolation is needed to
evaluate the corrected composition.

Tests additionally exercise 64 arbitrary raw executions of **each** wrapper,
including nonzero wraps and Monolith3's high-plain-bit truncation. An independent
handwritten call-graph recurrence checks 100 arbitrary assignments of all
correction symbols, including symbols that did not become nonzero in sampled
real setups. A source mutation using the wrong merge operand is rejected.

```bash
python -m tools.trace_transform7_setup_corrections
```

This closes the algebraic correction-accounting gap, not the encoding-invariant
proof gap. The result is an exact composition of source-derived **decoded
relations with measured corrections**, checked on synthetic setup executions;
it is neither an input-only replacement nor a universal proof that legal
setups have zero wraps. The four expressions predict residues, not arbitrary
encoded pair members or exact context representatives from input residues
alone. Next: prove the high-bit/range invariants for the 21 contributing calls,
or recover any nonzero correction predicates from legal setup inputs, while
preserving the final merge's representative-sensitive carry behavior. Runtime
and generated code remain unchanged.

## Reachable encoded setup ranges and the exact slot-94 identity

`tools/prove_transform7_setup_ranges.py` specializes the generated-source bit
DAGs through the actual setup call graph. Its inputs are arbitrary 160-bit
X, Y, and R, with setup's forced bits applied to Y/R. The initializer and
RotateRight30 statements must match explicit AST templates. It snapshots
wrapper reads before writes, rejects unsupported statements/signatures,
unexpected context reallocations, and strided pointers, and validates merge
operands with the earlier composition tool. Merged context bytes are modeled
as fresh unconstrained bits because no later setup wrapper reads them; they are
not silently reused as their premerge values.

A decoded payload bound is **not** sufficient provenance. Toggling word 17 bit
9 in the bundled encoded-zero span leaves both input decoded spans unchanged
and below 2^160, but changes the first Monolith3 wrapper's wrap from zero to
one. This strengthens the earlier arbitrary-raw-source witness: even the
correct decoded range cannot exclude the extra high-bit correction. The new
proof therefore expands the actual preceding encoded calls rather than
assuming arbitrary encodings with a small decoded payload are valid.

The range argument combines generated-source SAT queries with integer
consequences of the pinned, complete Monolith3/4/6 kernel proofs:

- For each Monolith3/6 pair, prove its two normalized payload top bits are zero.
  Established input bounds make the local carry r167 zero, so the proved
  column theorem gives m=top_count-r167=0. Monolith3's plain windows also
  stay below 2^162, ruling out truncation and the virtual top bit.
- With zero wrap, 2*(B0+B1)+h0+h1=T as **integers**. An upper bound on T
  bounds the pair's sum. Keep this paired bound instead of accidentally
  doubling it when both output spans are passed to a subsequent wrapper.
- For Monolith4, derive the output bound from B0+B1+h0*h1 and the complete
  decoded-addition theorem. These are labeled `derived`, not fabricated
  UNSAT solver results; their maxima are below 2^168, so no overflow occurs.
- For Monolith5, prove both packed streams are below 2^167. Their sum and
  the bounded target T are then below 2^168; the exact packing congruence
  becomes integer equality, so the packed-sum wrap is zero.

Only proved queries and these justified integer consequences become later
lemmas. Each SAT query retains facts for its actual call ancestors, not every
earlier branch's unrelated carry network. An unknown/timeout yields no bound;
dependent calls are explicitly skipped while independent branches continue.
SSA bindings likewise retain only variables actually read by each assignment,
avoiding the previous quadratic copying of all live variables per statement.

Before solving, eight synthetic real setups replay the lazy raw high-bit
snapshots, including otherwise undecoded high bits. The independent uint32
compiler validates all supported generated statements and helper/prologue/
writeback shapes, now including Monolith5. Dependency-free tests compare every
raw output bit of Monolith3/4/5/6 against eight arbitrary generated executions
each; optional solver tests separately replay Monolith5's fixed-width compiler.
The complete Monolith3/6 proofs and Monolith4's checked prefix are preserved
after the shared source-interpreter changes.

`tools/transform7_setup_range_proof.json` records completed, timed-out, and
dependency-skipped obligations, as well as kernel/data hashes and exact integer
caps. It is a solver-run/proof-accounting record, not an independently checked
certificate. The saved attempt has 16 UNSAT source queries, five integer
deductions, two query timeouts (calls 10 and 14), and six dependency-skipped
obligations. It proves zero wrap/truncation corrections for 15 of the 23 calls:
0..9, 11..13, 21, and 22. This original expanded-DAG attempt is incomplete;
the compositional invariant proof below supersedes its two timeouts without
changing or relabeling the historical results.
However, all
wrapper corrections contributing to context slot 46's **premerge residue**
vanish for the modeled legal input domain, closing that part of the original
affine candidate's proof gap. Its final merge still needs the exceptional
carry correction: the earlier legal witness returning 94 instead of 2^128
remains valid and unchanged.

The independent slot-94 branch goes further. Its three source queries prove
the plain range, Monolith3 pair top-bit bounds, and Monolith5 packed-stream
bounds without any other setup branch's lemmas. The initializer/rotation makes
N=4*X, and both encoded inputs have B=h=0. Therefore:

    T3 = N/2 = 2*X
    2*(B0+B1) + h0+h1 = 2*X
    h0+h1 <= 1  =>  h0=h1=0 and B0+B1=X
    T5 = X  =>  A+B=X as integers

Since 0<=A,B<=X<2^160, Prepare is the identity on each stream, their sum
cannot produce an overflow or lost carry, and the final merged slot 94 is
**exactly X as a 160-bit representative**, not merely X modulo p. This
includes inputs X=p and X=p+1; reducing them to field residues would lose
the now-proved representative identity. Tests preserve these noncanonical
boundaries and independently replay the three fast source obligations.

```bash
python -m tools.prove_transform7_setup_ranges --timeout-ms 30000 --progress
```

The command exits nonzero while any obligation is unknown or dependency-skipped.
Slot 94's exact identity does not establish equivalence for the remaining three
merged context slots, the scalar dispatches, or the final encoded authentication
output. The compositional proof below closes the remaining Monolith6 queries
and their downstream dependencies using a stronger upper encoding invariant.
Individual packed streams or legal input carry predicates are still needed
before removing runtime wrappers. No runtime or generated implementation has
been replaced.

## Hidden upper encoding: closing the setup proof compositionally

The raw bits above the normalized 168-bit payload are not arbitrary padding.
In each encoded span's last triple of words, physical bits 9..31 obey another
23 three-input truth tables. Define a triple code as A+2*B+4*C. Each table
admits four of its eight codes; these are the definition of its upper encoded
zero state, not a claim that the raw words themselves are zero. The first two
conditions can be written readably as:

    physical bit 9:  NOT (B if A else C) = 0
    physical bit 10:      B if C else A  = 0

The first condition explains the bundled-span one-bit counterexample above.
It suffices for local no-wrap, but does not preserve itself: its output depends
on the next physical bit's encoding. Continuing this argument recovers the
remaining tables, including choose and majority gates with inversions. Both
bundled input spans satisfy all 23 upper-zero conditions exactly.

`tools/prove_monolith_setup_invariant.py` proves the resulting invariant
directly from each generated kernel. Inputs are otherwise arbitrary uint32
words, with normalized payload bits 166/167 zero and all 23 upper conditions;
Monolith3 additionally has plain bits 162..191 zero. Its **73 independent
source obligations all return UNSAT**:

- Monolith3/4/6 each preserve all 23 upper conditions and produce zero at
  normalized payload bit 167, for all their encoded output spans.
- Monolith5 produces both packed streams below 2^167.

These are conditional kernel theorems, not sampled pattern assertions. Each
query uses the complete generated-source DAG, no cut signals, and no other
query's answer. The checked-in truth tables are an explicit readable Boolean
invariant; their discovery alone is not the proof. The saved record pins all
four kernels and both decoder/model files and is not a proof certificate.

The compositional setup proof checks the exact source initializer, rotation,
call graph, aliases, and merge operands using the earlier SetupDAG. Concrete
input spans must satisfy the upper conditions. A later span inherits them
only from an entire output span whose preceding call has already been proved.
Independent integer bounds establish B<2^166 at every call; the local theorem
then proves its output top bits, and the complete decoded carry theorems
establish zero wrap. Integer pair-sum caps are retained jointly, rather than
double-counting both members. The exact Monolith5 congruence lifts to an
integer sum because both streams and their bounded target are below 2^168.
No global expansion of earlier output gates or sampled range lemma is needed.

The original partial expanded-DAG report remains unchanged. All 23 setup
wrappers have zero correction in the new induction, so the previously
recovered affine **premerge residue** formulas for slots 46/48/70/94 hold
throughout the legal input domain. `tools/transform7_setup_invariant_proof.json`
records the distinct compositional deductions as `derived`, not invented
UNSAT answers, and pins the local and decoded-kernel records it relies on.
Eight actual synthetic setups independently replay raw high-bit snapshots
before the full induction. The final merged outputs still have the previously
derived representative-sensitive carry correction; proving zero wrapper
corrections must not remove that correction or imply whole authentication
equivalence. Slot 94 retains the stronger exact representative identity X.

```bash
python -m tools.prove_monolith_setup_invariant --progress
python -m tools.prove_transform7_setup_ranges --compositional --progress
```

Next: recover the two packed streams or derive legal-input final carry
predicates for slots 46/48/70, preserving the reachable slot-46 witness. Then
an input-only exact setup model can replace the last measured corrections in
the checkout analysis, before considering any separately validated rewrite.
The individual carry-save recovery below now closes this setup-model gap.

## Individual carry-save outputs and the input-only exact setup

The decoded pair identity hides a simpler construction: the **individual**
outputs are carry-save arithmetic, not merely two unknown parts of a sum.
Given three decoded spans (Bi,hi), define ordinary nonnegative integers:

    q = h0 XOR h1 XOR h2
    a = majority(h0,h1,h2)
    U = B0 XOR B1 XOR B2
    V = H*q
    W = (majority(B0,B1,B2) << 1) OR a
    S = U XOR V XOR W
    C = majority(U,V,W)

Here majority on integers is bitwise `(x&y)|(x&z)|(y&z)`. The familiar
carry-save equality S+2*C=U+V+W gives exactly the previously recovered
target sum(Bi)+H*q+a. On the proved reachable setup domain:

    Monolith6: (B_out0,h_out0) = (S>>1,S&1)
               (B_out1,h_out1) = (C,0)
    Monolith3: same operation with virtual input (N>>1,N&1)
    Monolith5: packed stream A = S mod 2^168
                            B = (C<<1) mod 2^168

The complete two-stream Monolith5 formula is valid for **arbitrary raw uint32
inputs** after normalization. For Monolith3/6, both boundary bits, all 167
lower bits of the first span, and all 168 bits of the second span are also
unconditional source identities. The first span's bit 167 requires the upper
encoding/range invariant established above. Without that condition, the
bundled-span high-bit witness still defeats an input-decoded-only formula.
The individual decoded equations do not reconstruct the randomized raw
encoded words, which can still have otherwise irrelevant input dependencies.

`tools/prove_monolith_carry_save.py` checks **1,012 independent generated-source
bit obligations**, all UNSAT: 338 each for Monolith3/6 and 336 for Monolith5.
Only two obligations are conditional; no query assumes another query's answer.
Both independently controlled source compilers are checked against eight
arbitrary generated executions per kernel. The report pins kernels, decoder
models, upper truth tables, and solver version. It remains a solver-run record,
not an independently checked proof certificate.

`tools/transform7_setup_integer.py` now evaluates the setup from X/Y/R using
only these readable XOR/AND/shift equations, decoded Monolith4 addition, and
the exact source-derived preparation/merge equations. It recovers **both
packed streams**, so their 160-bit fold and final lost-carry predicates are
input-only computations too. It needs no measured output, interpolated affine
offset, generated-kernel call, or runtime arithmetic helper. All 23 wrapper
steps are retained for inspection, including dead calls 7/8, and it returns
the exact representatives of slots 46/48/70/94, not just their field residues.

`tools/prove_transform7_setup_integer.py` checks every recipe call against the
actual strict source SetupDAG with distinct provenance tokens rather than
numeric probes. Encoded input origins, input constants, all symbolic plain
expressions (including OR 4 and 4*X), call order, merge order, and the exact
packed pair consumed by each merge must agree. It requires the complete
individual-bit and legal-setup invariant records plus decoded-addition proof,
and pins model/merge/shared-source hashes. This closes the compositional
argument for the input-only setup model, while retaining the exceptional
representative-sensitive merge behavior.

As independent experimental verification, 1,003 synthetic setups compared
all pre-call decoded inputs, all 23 decoded outputs or packed stream pairs,
and all four exact final context representatives: **23,069 wrapper steps and
4,012 slot outputs matched**. This includes zero/maximal inputs and the legal
base-point carry witness, where slot 46 is correctly 94 rather than 2^128.
Source-derived proof and synthetic testing are distinct evidence; neither is
new hardware validation or proof of a modular rewrite of the scalar phases.

```bash
python -m tools.prove_monolith_carry_save --progress --summary
python -m tools.prove_transform7_setup_integer
python -m tools.transform7_setup_integer --carry-witness
python -m tools.benchmark_transform7_setup
```

The correctness-gated setup-only benchmark uses the same 60-byte input and
80-byte exact representative output interface on both sides. In the documented
macOS arm64/Python 3.13.14 run (seven samples, ten iterations, eight cases, two
warmups), native setup capture had median 7,158.51 us with MAD 81.55 us; the
input-only model had median 33.02 us with MAD 0.33 us: approximately **217x**
for this scope. Native capture includes dispatcher-patching/observation
overhead. This is not a whole-Transform7 or authentication speedup, and no
runtime performance change has shipped.

The previously missing exact setup model is complete. The library/generated
runtime is unchanged. Further work can connect it to the already exact scalar
recurrence and fixed tail, or pursue reachable arithmetic invariants inside
those phases before any mass rewrite.

## Dependency neighborhoods

The source-word neighborhoods repeat across the two six-word outputs:

| Output words | Possible source words in each of the three 18-word input spans |
| --- | --- |
| 0 and 6 | 0–2 |
| 1 and 7 | 0–5 |
| 2 and 8 | 0–8 |
| 3 and 9 | 0–2, 6–11 |
| 4 and 10 | 0–2, 9–14 |
| 5 and 11 | 0–2, 12–17 |

Add offsets 0, 18, and 36 to the second column for the three actual input
spans. For example, output word 0 can depend on source words 0–2, 18–20,
and 36–38. These are conservative *bit-level* dependencies from the earlier
trace: cancellation can remove an input. The symbolic recovery finds the
actual Boolean functions, including those cancellations.

Run the detailed trace with:

```bash
python -m tools.trace_session_auth_bits 5 0
python -m tools.trace_session_auth_bits 5 0 --json
```

## Equivalence and limits

`tools/recover_monolith5.py` symbolically interprets each output's versioned
backward slice using reduced ordered binary decision diagrams (ROBDDs). It
converts each exact Boolean function to its unique algebraic normal form,
checks the first-stream lane separation, factors every second-stream bit,
and deterministically regenerates the compact data. It rejects unsupported
operations, mixed first-stream lanes, unexpected factorization residuals,
nonzero padding bits, or a change in the expected function count. Verify the
checked-in model with:

```bash
python -m tools.recover_monolith5 --verify tools/monolith5_model.json
```

The test suite checks the symbolic engine on a small exhaustive expression,
regenerates and compares the complete saved model, checks the upstream
Monolith5 known-answer vector, and differentially compares 100 seeded random
inputs against the generated implementation. Thus the model is equivalent to
the pinned generated Monolith5 *within the supported uint32 expression and
sound backward-slice model*. It does not prove equivalence to every Siemens
DLL or firmware version, and it has not replaced the hardware-validated
runtime implementation.
