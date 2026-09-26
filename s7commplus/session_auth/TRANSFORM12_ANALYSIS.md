# Transform12: exact arithmetic tape decompilation

`tools/decompile_transform12.py` decodes the pinned Transform12 tape into
versioned arithmetic equations. It can inspect individual dispatch blocks,
trace selected exit slots, and compose the deterministic second phase of
Transform7 into one program. This is analysis tooling; the runtime tape and
interpreter are unchanged.

## Tape coverage and operands

The 498 Transform7 dispatch alternatives partition the first 60,858 tape
words without gaps or overlaps. These contain 34,253 multiplies, 2,510
squares, 16,907 additions, and 7,188 subtractions. The resource has 60,906
complete words plus one trailing zero byte. Its final 48 complete words and
trailing byte are outside every dispatched range; they are not interpreted as
instructions by this analysis.

Each context slot occupies 24 bytes; the 3,576-byte context contains 149 slots.
Source indices below 256 address context slots and higher indices address the
768-row auxiliary table. Square consumes only its first operand. Reserved
encoded bits are recorded and ignored just as in the interpreter.
All dispatched instructions fit their buffers and have zero reserved bits.

The auxiliary rows have 478 distinct integers after `Prepare`; 285 prepare
to zero. The tool prints both row references and their prepared integers on
request. It preserves the original packed values for evaluation.

## Versioned equations and exact evaluation

Every write creates a new value, so an instruction that reads its destination
sees the previous version. An output slice follows those versions backward
to entry context slots and constant rows. Across dispatch boundaries, the
composer replaces block entry references with the previous block's exit
versions. It also retains original tape indices for source navigation.

An independent SSA evaluator uses the same vector-tested BigInt primitives as
the runtime. It resolves initial reads before writing any final slots, and
therefore preserves aliased reads and writes. This verifies the decompilation
and composition of the program, rather than claiming an independent recovery
of the arithmetic primitives themselves. The primitives include packed
`Prepare`/`Finalize` and overflow behavior; replacing them with ordinary
modular arithmetic requires separate proof.

```sh
python -m tools.decompile_transform12 --catalogue
python -m tools.decompile_transform12 --catalogue --json
python -m tools.decompile_transform12 --dispatch 496 --constants
python -m tools.decompile_transform12 --dispatch 496 --output-slot 27
```

## The second phase is a fixed two-input arithmetic program

Stages 0–159 dispatch on `prng2` bits from bit 159 down to bit 0. Stages
160–248 dispatch on the first 89 bits of the work-buffer copy of `prng1`.
For **every** stage in that second group, its two alternatives have identical
versioned equations, operands, destination bindings, and buffer sizes. Their
locations in the tape differ; their operations do not. This equality is
checked before composing the fixed phase. The observation concerns second-loop
dispatch choices; Transform7 also uses `prng1` earlier.

The 89 fixed blocks contain 2,000 arithmetic instructions. Their four exit
slots consumed by Transform7 are 27, 61, 71, and 97 (byte offsets `0x288`,
`0x5B8`, `0x6A8`, and `0x918`). Tracing those four outputs retains 1,989
equations and 119 constant rows, but only two entry slots: 5 and 87.

```sh
python -m tools.decompile_transform12 --phase2
python -m tools.decompile_transform12 --phase2 --output-slot 27 --constants
python -m tools.decompile_transform12 --phase2 --json
```

The final fixed block illustrates the resulting readable structure. Let
`U`, `V`, `A`, and `B` denote its entry slots 14, 65, 81, and 82, and `Kj`
denote packed constant-table row `j`. All functions below denote the exact
packed arithmetic primitives, with their original operation order:

```text
exit71 = add(multiply(K53, A), B)
exit61 = multiply(U, exit71)
exit97 = multiply(A, add(subtract(U, A), B))
D = subtract(A, B)
Q = multiply(K482, multiply(square(U), D))
R = multiply(K482, multiply(V, D))
S = multiply(K481, multiply(A, D))
T = multiply(K480, multiply(U, add(A, B)))
exit27 = add(subtract(add(subtract(K483, R), Q), S), T)
```

This recovers the program's data flow and a deterministic arithmetic tail.
It does not yet identify the tail as a particular curve-coordinate conversion
or field-inversion formula. The next semantic analysis can focus on a fixed
two-input program rather than 178 apparently conditional blocks.

## Independent integer semantics

`tools/transform12_integer_model.py` recovers the arithmetic without calling
Prepare, Finalize, or any runtime arithmetic helper. Canonically packed operands
represent an unsigned 160-bit integer: each of the first five little-endian
uint32 words stores 28 bits shifted left by two; the sixth stores the remaining
20 bits shifted left by two. All 768 constant rows use this packing. Canonical
packing does **not** mean a representative is reduced modulo a field modulus.
Arbitrary noncanonical Prepare inputs are outside this model's domain.

The overflow fold multiplies the bits above position 159 by 47, consistent with
the candidate modulus `p = 2^160 - 47`. But ordinary `% p` is not an exact
replacement for the current implementation:

- Addition leaves results below `2^160` unreduced. On overflow it adds 47 to
  only the low 128 bits. A carry beyond those four words is discarded and an
  additional 94 is added to the low word instead of incrementing word five.
- Subtraction subtracts an additional 47 only for negative differences, then
  truncates the signed representation to 160 bits.
- Multiplication and square fold overflow at most twice. If overflow remains,
  the final correction adds 47 to the low uint32 without propagating its carry,
  and the result is truncated to 160 bits.

A concrete counterexample uses **two already reduced operands**:
`a = p - 1`, `b = 2^128 + 47`. Runtime addition returns `140`, whereas
`(a + b) % p = 2^128 + 46`; these are not even congruent modulo `p`.
This is a compatibility finding, not evidence that this input occurs in an
actual authentication session, or a reason to silently change the runtime.

The independent model matches all 498 dispatches byte-for-byte on a seeded
canonical context, plus ten complete fixed-tail contexts. Boundary and seeded
random tests compare more than 8,000 primitive results with the runtime. This
provides a smaller exact reference for further semantic recovery, but does not
prove equivalence for every possible operand or identify the cryptographic
construction. A field-level simplification needs additional range/invariant
proofs or must preserve these compatibility corrections.

## Compact mathematical shadow

`tools/recover_transform12_formulas.py` symbolically interprets the fixed tail
in the polynomial ring `(Z/pZ)[x,y]`, where `x = in5`, `y = in87`, and
`p = 2^160 - 47`. It expands and cancels coefficients exactly, without reducing
exponents, assuming primality, or fitting formulas to sampled values. At most
75 nonzero terms occur in any intermediate polynomial; the four final
polynomials contain only nine terms in total.

Let `Kj` denote the decoded integer in constant row `j`, reduced modulo `p`.
The recovered formulas are:

```text
e = (p - 1)/2 - 40
z = x^e
t = x^(p - 2)
out71 = y
out61 = z*y
out97 = x^79*(z + y)
out27 = K483 + K482*t*y + K481*out97 + K480*out61
```

All equations in this section use arithmetic modulo `p`. The exponent `p-2`
is inverse-like, and `(p-1)/2` suggests a character-like power, but those
interpretations require additional primality and nonzero-input arguments.
The formulas alone do not establish a curve-coordinate interpretation.

**These are not byte-equivalent runtime replacements.** Even the small entry
inputs `x=y=1` cause divergence. The first loss of modular congruence is at
SSA value 429, tape word 34725: subtraction receives `2` and `p+3`. Exact
arithmetic returns `2^160-1`, whose residue is 46, rather than the modular
result `p-1`. The final slots 27, 61, and 97 then differ from the shadow;
slot 71 agrees for this witness. Both entry inputs being below `p` is therefore
insufficient to justify a modular rewrite. This does not establish that the
witness occurs in a real authentication session.

```bash
python -m tools.recover_transform12_formulas
python -m tools.recover_transform12_formulas --compare 1 1
```

The first command regenerates exact sparse polynomial coefficients. The second
locates the first divergence between independent compatibility arithmetic and
the modular shadow. Tests verify the complete coefficient identities, compare
compact formulas with both polynomial evaluation and a modular tape interpreter
on boundary/random inputs, and preserve the packed-runtime mismatch witness.
The next task is recovering input/intermediate invariants or retaining exact
corrections alongside the short mathematical structure.

## Reachability through Transform7

`tools/trace_transform7_tail.py` instruments the real Transform7 orchestration
temporarily, without changing library source. It captures the context before
dispatch 320/321 (stage 160) and after the last dispatch, validates all 249
dispatch ranges, and checks the independent exact tail against the captured
exit bytes. A second complete Transform7 run substitutes only the four compact
shadow outputs before PrepareFinalize and the downstream monoliths, then
compares the complete 72-byte destination.

The sweep uses deterministic synthetic PRNG pairs, the seed generator's bundled
base-point data, and bundled public keys `00:181B7B0847D11694` and
`01:BD426B091F08731A`. No live secrets, PLC access, or new hardware capture are
involved. The default report aggregates checks; `--details` includes per-case
checks and hashes of synthetic destinations, not raw key material. The patching
is single-threaded diagnostic instrumentation, not a runtime execution option.

```bash
python -m tools.trace_transform7_tail --random-cases 32
```

With seed `0x712`, all **111 cases** passed: three public sources, each with
five structured PRNG pairs and 32 seeded random pairs. Every observed pair of
tail-entry representatives was nonzero and below `p`. All exact-model tail
bytes matched. No intermediate lost modular congruence; shadow outputs matched
both residues and packed representatives, and substituting them left every
complete Transform7 destination unchanged. The structured pairs cover zeros,
one, all-one bits, the highest scalar bit, and alternating patterns.

This is reachability **sampling**, not proof that all reachable inputs satisfy
the needed invariants. In particular, the independently established `x=y=1`
counterexample remains a reason not to switch the runtime to compact modular
formulas. The next proof obligation is deriving constraints on the tail inputs
and intermediate representatives from the first 160 dispatch stages.

The downstream source also reveals an unused branch: slot 71 is normalized at
offset `0x6A8`, then passed to the last Monolith7 call, which writes work-buffer
regions `[0x4E0,0x528)` and `[0x498,0x4E0)`. Neither region is read again before
Transform7 returns. The live final result uses slots **27, 61, and 97** instead.
A negative-control test replaces slot 71 with zero: tail bytes differ, but the
final destination does not. Replacing live slot 27 with zero changes the final
destination, ensuring the instrumentation does not simply report success for
every substitution. Removing this dead branch is a later cleanup decision;
the runtime is unchanged. Slicing away slot 71 alone does not shorten the
1989-equation tail slice, because its dependencies are shared with live outputs.

Tests also verify scalar-bit dispatch selection and restoration of the patched
dispatcher after both normal execution and exceptions.

## Exact first-phase live-state recurrence

`tools/recover_transform12_phase1.py` works backward from tail-entry slots
5 and 87 through all 160 first-phase stages. At each boundary it slices **both**
alternatives and propagates the union of their required entry slots. This is
structural SSA dependency analysis, not sampled branch coverage or algebraic
simplification; it preserves every scalar choice and keeps any shared input
needed by either next-stage alternative.

The recovered initial state is exactly slots **46, 48, 70, and 94**. Every
subsequent input boundary has five live slots: four changing representatives
plus slot 94. No instruction in any of the original 320 first-phase alternatives
writes slot 94, so its preservation is a code-level invariant independent of
the selected scalar. The last stage produces only the two required tail inputs.
The first stage therefore maps three changing values plus one fixed value to
four changing values plus that fixed value; the intermediate stage layouts
vary, and are recorded explicitly rather than assumed interchangeable.

In Transform7, the initial live slots correspond to context byte offsets
`0x450`, `0x480`, `0x690`, and `0x8D0`. They are written by the setup monolith
chains and BigIntAddition before the first dispatch. The recurrence's scalar
selector is the unsigned little-endian integer in `prng2`, consumed from bit
159 down to bit 0. It does not replace or dismiss the setup's dependence on
`prng1` or the public source data.

The checkout-only `execute_state(initial, scalar)` independently evaluates
this recurrence using integer compatibility equations. It retains at most
five live boundary representatives, without the 149-slot context or packed
Prepare/Finalize calls. Within each stage it still evaluates live temporary
SSA values. Across both alternatives, slicing retains 56,497 of the original
56,858 instructions; only 361 are excluded. This is a state-space reduction,
not a claim that the remaining arithmetic has collapsed into short formulas.

```bash
python -m tools.recover_transform12_phase1
python -m tools.recover_transform12_phase1 --stage 159 --branch 0
```

Tests compare every one of the 320 branch exits with the original packed tape
interpreter, check the boundary layouts and unmodified slot 94, and compare
13 complete scalar paths while filling ignored initial slots with unrelated
values. The Transform7 tracer now captures the context before the first
dispatch as well, so it checks the recurrence against the tail entry actually
produced by the real setup and selected path.

The repeated 111-case sweep also matched this independent first-phase model.
Nevertheless, these structural invariants alone do **not** establish nonzero
tail inputs, inputs below `p`, or congruence-preserving intermediate ranges.
The model accepts all canonically packed 160-bit representatives, including
those above `p`; it intentionally preserves compatibility corrections. The
remaining semantic problem is deriving constraints on the four setup values
and their evolving recurrence, now without unrelated scratch slots.

## Candidate setup encoding and a reachable exception

`tools/recover_transform7_setup.py` captures the real setup before its first
scalar dispatch, then interpolates a candidate affine map from four fixed
synthetic probes. This is **interpolation, not symbolic recovery** of the setup
monoliths. Fresh random probes test the candidate independently of those four
recovery probes. The tool uses only synthetic integers and temporarily patches
the dispatcher in a single thread; it must not receive live secrets.

Write `X` and `Yraw` for the first and second little-endian 160-bit source
integers, and `Rraw` for the first PRNG integer. The real setup forces bit 2
in both `Yraw` and `Rraw`, so the candidate uses `Y = Yraw OR 4` and
`R = Rraw OR 4`, not the unmodified inputs. For `p = 2^160 - 47`, it predicts
the residues of slots 46, 48, and 70 as:

```text
s46 = c46 + X/4   + Y/2    + R/8
s48 = c48 + 3X/32 + 5Y/16  + 15R/64
s70 = c70 + X/8   + Y/4    + 3R/16
```

Here division means multiplication by the corresponding unit's modular
inverse, not integer division. These inverses exist because `p` is odd; no
primality assumption is needed. The recovered offsets are:

```text
c46 = 119837857766959630917594351638328714638160910892
c48 = 1075284659745460397989926177318336564412678890279
c70 = 419432502184358708211580230734150501233563188122
```

The candidate also predicts `s94 = X` modulo `p`. Centering the three mixed
values as `u=s46-c46`, `v=s48-c48`, and `w=s70-c70` gives the particularly
small inverse:

```text
X = -16v + 20w
Y = 3u + 8v - 12w
R = -4u + 8w
```

Matrix multiplication verifies that this is exactly the inverse of the
candidate affine map modulo `p`. This identifies a useful potential input
representation; it does not prove that the source integers are conventional
curve coordinates, or that this map matches every byte-level setup execution.

With seed `0x714`, four structured and 1024 fresh random setup probes matched
the candidate residues. A deliberately constructed **reachable** exception
then disproves universal equivalence. Use the actual bundled base-point source
`TRANSFORM7_DATA[0xD8:]` and the valid first-PRNG integer:

```text
Rraw = 1456322070154714087054275448276265639382807574476
```

This value is within the allowed 160-bit range and already has bit 2 set.
Solving the candidate's first row targets `s46=2^128`, but the real setup
returns `s46=94`; its other two mixed values match the candidate. The four-word
addition carry correction explains this exact discrepancy. With the second
PRNG integer set to 1, substituting the candidate's three values before the
first dispatch changes the **complete 72-byte Transform7 destination**.
This is not an arbitrary malformed public point: the source is the same
bundled base-point data that SeedTransform uses. It is nevertheless a synthetic
execution, not a hardware capture or a demonstration of an authentication
failure on a PLC.

```bash
python -m tools.recover_transform7_setup --random-cases 1024
```

The report labels the map as a candidate and includes the targeted probe after
the ordinary verification probes; that final mismatch is expected. Tests lock
the rational coefficients, offsets, and inverse identity, verify fresh samples
and forced-bit behavior, and preserve both the setup exception and its final
Transform7 effect. The intended cleanup therefore needs exact compatibility
handling, not just an affine setup followed by ordinary field arithmetic.

## Source-derived setup merge correction

`tools/transform7_setup_merge.py` removes interpolation from the final merge
step. Its domain is precisely six 28-bit payload lanes shifted left by two,
including all 28 payload bits of the sixth lane. The recovered Monolith5 model
establishes this output packing. Such a stream represents an integer
`N < 2^168`, not necessarily a canonical 160-bit operand. The model rejects
other packing rather than extending the equations to arbitrary Prepare inputs.

Substitution of these lane expressions into Prepare gives the following exact
closed form, with `L=2^160`, `p=L-47`, and `h=N>>160`:

```text
v = (N mod L) + 47*h
P(N) = v             if v < L
       v - L + 47    otherwise
```

The initial word assembly has disjoint bit segments, so its carries vanish.
Only the final addition of `47*h` can carry through the five assembled words.
Since `0 <= h <= 255`, any overflow leaves `v-L <= 11984`; the final low-word
addition of 47 therefore cannot overflow uint32. This establishes the formula
and `0 <= P(N) < L` for every stream in this packing domain. It also establishes
`P(N) ≡ N (mod p)` without requiring primality. Representatives in `[p,L)`
are still possible and must not be silently canonicalized for byte equivalence.

For two streams `A` and `B`, set `S=P(A)+P(B)` and `W=2^128`. The exact final
setup-addition representative is:

```text
E = (S >= L) AND ((S mod W) >= W-47)
T = S                         if S < L
    S - L + 47                if S >= L and not E
    S - L + 47 + 94 - W       if E
```

This is derived from the original four-word carry propagation, not fitted from
examples. In the exceptional branch write `S mod W = W-47+m`, where
`0 <= m <= 46`. Adding 47 produces low four words equal to `m` and a carry
past their 128-bit boundary. The original code discards that carry rather than
incrementing the fifth word, and adds 94 to the low word. Since `m+94 <= 140`,
this extra addition cannot carry. Relative to the ordinary overflow fold,
the difference is therefore exactly `94-W`, independently of the fifth word.
The nonexceptional cases retain the ordinary fold unchanged. In every case,
`0 <= T < L` and:

```text
T ≡ A + B + (94-W)*E (mod p)
```

The affine setup map remains a candidate for `(A+B) mod p`; this derivation
does **not** symbolically establish that relationship to the earlier monolith
chains. It isolates a complete exact correction once the two streams are
known. The real bundled-base-point witness has
`S=L+W-47`, `E=true`, ideal residue `W`, and exact result `94`.

The predicate cannot in general be inferred from the modular sum alone. For
example, streams `(W,0)` have ideal residue `W` and exact result `W`, whereas
streams `(L-1,W-46)` have the same ideal residue and exact result `94`.
Recovering just the affine residues loses the information required to choose
the exact representative and exceptional branch.

```bash
python -m tools.transform7_setup_merge
```

The command captures and verifies all four real setup additions for the
synthetic bundled-base-point witness. Tests cover all 256 possible high bytes
at fold boundaries, all 47 exceptional low-128-bit remainders and neighboring
thresholds with multiple fifth-word values, 2000 seeded 168-bit operand pairs,
and fresh full setup captures. They compare exact packed output bytes and the
derived residue correction, including representatives above `p`. This is a
source/algebra derivation supported by tests, not a solver-generated formal
verification of the complete authentication code. The runtime is unchanged.

## Conditional setup composition from source

`tools/trace_transform7_setup_shadows.py` applies a candidate span shadow V:
the **signed** weighted gate sum from Monolith5, plus C/3, reduced modulo p.
This is deliberately not the 168-bit decoder reduced again modulo p.
For setup-produced encodings, the observed wrapper identities are:

```text
Monolith3: V(out0)+V(out1) = (V(in0)+V(in1))/2 + plain(in2)/4
Monolith4: V(out) = V(in0)+V(in1)
Monolith6: V(out0)+V(out1) = (V(in0)+V(in1)+V(in2))/2
Monolith5: rawA+rawB = V(in0)+V(in1)+V(in2) (mod p)
```

All divisions here mean inverses of units modulo p; no primality assumption is
needed. `plain` reads the first 24 bytes as an unsigned little-endian integer.
Tests observe all 23 setup wrappers on 132 deterministic structured/random
cases, including the bundled-base-point carry witness: 3,036 comparisons match.
These are **sampled hypotheses, not symbolic wrapper proofs**. A negative
control shows the Monolith4 identity fails for arbitrary raw input spans, so a
proof needs the valid-encoding domain, not just unconstrained input words.
The preserved counterexample differs by -2^168 modulo p (that is, -12032),
making the distinction between the two moduli concrete.

The tool separately walks the actual Transform7 setup call AST and composes
these hypotheses using exact rational coefficients. Each output pair retains
an independent unknown split variable; none survives the four setup exits.
The resulting equations, conditional on the wrapper identities and the plain
input initialization/rotation semantics, are:

```text
ideal46 = d/4     + X/4  + Y/2  + R/8
ideal48 = 23*d/32 + 3X/32 + 5Y/16 + 15R/64
ideal70 = 7*d/8   + X/8  + Y/4  + 3R/16
ideal94 = X
```

V(data[0:72]) is zero and d = V(data[72:144]) is
479351431067838523670377406553314858552643643568. The derived offsets and
matrix exactly match the independently interpolated candidate, without using
recovery probes to obtain them. X is the first source integer; Y and R include
the setup's forced bit 2. The final RotateRight30 gives plain(in2)=4X.

This advances the candidate from a fitted map to a **conditional source
composition**, not a proof of the entire setup. Individual pair members are
not assumed affine. The two-stream merge and its exact carry correction still
apply: all wrapper checks pass on the known witness even though its ideal46
is 2^128 and its compatibility result is 94. Runtime code is unchanged.

```bash
python -m tools.trace_transform7_setup_shadows
```

## Verification

Tests compare all 498 decoded programs byte-for-byte with the tape interpreter,
exercise aliased assignments, trace selected outputs, and compare the composed
second phase with all 89 runtime dispatches using mixed branch choices. The
catalogue test verifies prefix coverage, the excluded suffix, and all identical
branch pairs. Malformed ranges and buffer references are rejected.

The catalogue records SHA-256 hashes of both binary resources, so reports can
be associated with the exact analyzed revision. Preserve the HarpoS7 attribution
and `LICENSE-HarpoS7` when reusing the derived equations or tooling.
