# Scalar-stage semantic recovery

These checkout-only tools recover polynomial identities and source-compatible
arithmetic models, not replacement runtime cryptography. Never supply live
keys, challenges or PRNG material.

## Current endpoint

- The source-specific exact evaluator covers all 320 scalar branches and the
  fixed tail, retaining all 161 boundaries and 72 output bytes. Actual equation
  data is independently checked against source-derived witnesses; this is not
  a monolithic generated-kernel/whole-pipeline SMT certificate.
- [Exact saturated history](#exact-saturated-history-algebra) replaces the old
  Boolean lift history with the injective `(raw%p,min(raw,47))` representation.
  Its 48-state positive semiring yields exact multiplication associativity.
  Subtraction retains explicit field-dependent cuts.
- [Local gadget contracts](#universal-addition-cancellation-and-small-subtraction-restoration)
  cover all 69 matching add/subtract cancellation/restoration patterns. The
  [factoring conditions](#exact-conditions-for-algebraic-factoring-and-reassociation)
  state precisely when reassociation/distributivity preserve raw results.
- [Caller-level counterexamples](#caller-visible-seed-counterexamples-with-bundled-public-keys)
  use a bundled public key, constructed synthetic nonce, actual PreSeedTransform
  and the complete 180-byte authentication blob builder. The exact reference
  agrees with original code; an uncorrected ordinary ladder changes blob bytes.
  An offline C# replay of the pinned upstream sources also matches the original
  Transform7, normalization, PreSeed and final-seed checksums for this case.

The remaining hard problem is a compact, stage-independent **corrected** curve
algorithm. The exact model still retains source-specific field/carry equations;
the results below do not complete that simplification or justify a mass runtime
rewrite. No production/generated code, wire behavior or binary fixtures change.
Hardware validation and independent human acceptance remain separate.

```sh
python -m tools.recover_scalar_curve
python -m tools.recover_scalar_shadow --stage 1 --branch 0 --formulas
python -m tools.recover_scalar_shadow --catalogue
python -m tools.recover_scalar_encodings --summary
python -m tools.prove_transform12_residue_defects
python -m tools.trace_scalar_defects --effective-scalar 0
```

## What is established

All 320 first-phase branch programs can be expanded into sparse polynomials in
their four/five live entry residues, over the ring Z/pZ, p = 2^160 - 47. The
catalogue regenerates all 56,497 live instructions and hashes each complete
coefficient list. Tests independently interpret the modular tape numerically
for every branch; the first two stages additionally match manually written
short formulas by **complete coefficient equality**, not sampled fitting.

The curve-shaped formulas use a = -1 and b = constant table row 58:

```
b = 0xfdec56a0f1a148a7ca6f04463a24f5f56c3f3a4f
y² = x³ - x + b
```

The unmodified reference base point in Transform7's data satisfies this
equation. The discriminant is a unit modulo p. Neither observation establishes
that all protocol inputs are on this curve or proves primality of p.

## First stage: conditional setup shadow

X is the source x-coordinate; Y = source_y | 4 and R = prng1 | 4.
Compose the actual setup AST's conditional affine expressions, without probes
or interpolation. The source-derived carry corrections are excluded here;
the existing exact setup model remains authoritative.

Let s = Y²R⁴ and define homogeneous x-doubling:

```
N(X,Z) = X⁴ + 2X²Z² - 8bXZ³ + Z⁴
D(X,Z) = 4Z(X³ - XZ² + bZ³)
```

First scalar bit 0:

```
slot1  = Y⁴ D(X,1) + s²
slot44 = Y⁴ N(X,1)
slot82 = (X+1)s
slot83 = s
```

First scalar bit 1:

```
slot1 = s; slot44 = Xs; slot82 = R⁸; slot83 = 0
```

Both leave slot94 = X. Decode pairs as
`(slot44, slot1-slot83²)` and `(slot82-slot83, slot83)`.
These are the doubled/base pair for bit0, and base/infinity pair for bit1,
subject to the usual nondegeneracy conditions for projective point meaning.
Y here is a scale, **not** the unmodified reference point's y-coordinate.

## Second stage: unconditional polynomial coordinate change

Write entry slots as `slot1=Z+V², slot44=X, slot82=U+V, slot83=V,
slot94=t`. This is a bijective change of polynomial coordinates.

```
H = XV-UZ
A = 2(XV+UZ)(XU-ZV) + 4bZ²V² - tH²
J = (XU+ZV)² - 4bZV(XV+UZ)
Q = J-tA
```

A/H² has the differential-addition form when t is the difference point's
x-coordinate. Q is retained explicitly; it is not zero for arbitrary entries.
Complete symbolic substitution proves Q=0 after **either conditional
first-stage shadow branch**, without inverses or nonzero assumptions.

Branch0 exits:

```
slot19 = N(X,Z)+H⁴+Q; slot27 = D(X,Z)
slot31 = A+H²;        slot85 = H²
```

Branch1 exits:

```
slot19 = A+D(U,V)²;     slot27 = H²
slot31 = N(U,V)+D(U,V)+Q; slot85 = D(U,V)
```

Both preserve slot94=t. With Q=0, the shared exit decoder is
`(slot19-slot85², slot27)` and `(slot31-slot85, slot85)`.
Branch0 doubles the first pair and adds the two pairs; branch1 adds them and
doubles the second pair. This establishes a two-stage descending x-only
ladder interpretation of the modular shadow. The complete stage recovery
below extends it through the remaining encodings.

The decoded second-stage exits also preserve Q=0. For each branch the tool
expands Q(next) into 760 terms and divides by Q(entry), obtaining a 267-term
quotient and **zero remainder**. It multiplies the quotient back to check the
complete identity. Thus `Q(next)=Q(entry)*quotient` holds as a polynomial ring
identity, with no coordinate inverses or primality assumption. This proves
propagation through the second stage; the generic relation proof below
extends propagation through the remaining recovered encodings.

## Exact-runtime negative controls

The existing legal setup carry witness still contradicts the unconditional
affine setup prediction, even with the unmodified **on-curve reference base
point** as source. An on-curve restriction alone therefore does not eliminate
the setup problem. A new witness reaches the second scalar stage from
accepted synthetic Transform7 inputs `source_x=2^128+48, source_y=0, prng1=0`
and scalar prefix `00`. At tape word25470, addition of `p-2` and `source_x`
returns **140**, while the modular result is **2^128+46**. Exit slots19 and31
then disagree with the modular polynomials. Tests reproduce both stage exits
byte-for-byte using the original Transform12 interpreter.

This is a synthetic API-domain witness, **not an on-curve or vendored-key
witness**. It disproves unrestricted runtime replacement; it does not show
that an actual key exchange hits this edge. Source/tool hashes accompany the
regenerated report. No production algorithm, wire behavior, generated kernel
or binary fixture is changed.

## Complete scalar shadow

`recover_scalar_encodings` now recovers **all 158 intermediate encodings**,
not just the first two stages. Discovery solves symbolic coefficient equations
jointly across both branches, modulo Q. Every accepted decoder has an exact
polynomial inverse; both encoder/decoder compositions are checked. A separate
check applies it to the **unreduced source polynomials**, proves ideal
membership, and multiplies the quotient back to reconstruct the difference.
Including initialization and the final outputs, there are 1,278 source
coordinate identities. The generic ladder preserves Q by two polynomial
ideal identities, so the condition established at initialization propagates
through all intermediate stages under modular-shadow semantics.

There are 78 branch inversions in the intermediate stages. The first stage
is not inverted; the last stage is inverted and retains the second point.
Initialize `P0=(xY,Y), P1=(R²,0)`, with Y and R already forced as above.
Each compact step doubles one point and differentially adds the pair.
The descending point indices yield the effective scalar:

```
effective = selector XOR 0xf8e62e8673b79ca477a1d36333b1c0de6c706448
tail slot5 = projective denominator Z
tail slot87 = projective numerator N
```

`scalar_ladder_model` implements the short formulas. Independent tests
interpret the complete modular tape and compare both final representatives,
including their projective scaling. The scalar-mask identity is also checked
as an integer index recurrence, without a curve group-order assumption.
The regenerated report contains every decoder/encoder, source/tool hashes,
identity quotient hashes and a complete encoding digest.

## Primitive defect model and source-AST proof

`transform12_residue_defects` retains exact uint160 representatives with
explicit deviations from ordinary ring arithmetic:

- Addition's correction is **94-2^128**, precisely when `a+b >= 2^160` and
  its low128 part is at least `2^128-47`.
- Subtraction's residue correction is **47**, precisely when `a-b < -p`.
- Multiplication preserves residues throughout the uint160 input domain.
  Three ordinary high160 folds reproduce its representative; after the second
  fold the value is below `2^160+2209`, so the final low-word correction cannot
  lose a carry.

The optional development-only Z3 command proves six obligations against the
**actual AST of the checkout integer model**: addition/subtraction lifted
representatives, multiplication's three-fold representative and three fold
bounds. It abstracts the initial product to an arbitrary uint320 value,
making the fold theorem stronger than the input-product domain. All six are
UNSAT. This is **not** a generated-kernel SMT proof: correspondence between
that integer model and packed runtime remains separately tested, including
new boundary/random packed primitive controls.

## Exact projective representatives: counterexamples

For the unmodified on-curve reference point, PRNG1=0 and effective scalar0,
the exact scalar trace encounters three addition defects, first at stage79,
tape word36796. It retains tail denominator **p**, congruent to zero, and a
different numerator from the compact model. Thus the ordinary nonzero inverse
precondition is disproved by an accepted reachable source input.

Effective scalars1 and2 preserve the same affine curve point but disagree in
the required projective representatives. The final 72 output bytes disagree.
Replacing zero tail results61/97 with p repairs scalar0's output but **fails
for scalars1 and2** (also 3,4,16 in exploratory checks). These are retained
negative controls, not candidates for a production fallback rule.

We therefore have a complete compact **modular scalar shadow**, but not an
equivalent compact exact authentication algorithm. The remaining obstacle is
recovering a self-contained representative/defect schedule, plus proving final
encoded-output correspondence. On-curve validity, Q=0 and the correct affine
point do not suffice. The following transport model explains the tested
projective-scale mismatches, but does not yet recover the schedule. No runtime
algorithm, generated source, binary fixture or wire behavior is changed.

## Symbolic carry transport and event-assisted scale replay

Run `python -m tools.transport_scalar_defects --effective-scalar 0`.
The tool lifts every live SSA operation at an observed defect-bearing stage
into a sparse polynomial in independent correction variables. It injects an
error at each observed addition/subtraction site and retains nonlinear terms;
it does not interpolate corrections or assume that every error is a scale.
Inputs at the stage boundary are fixed numerical representatives, so these
are **local symbolic identities**, not identities over all possible inputs.
Assigning the actual carry corrections reconstructs every exact exit residue.
Missing, duplicated, foreign or operation-mismatched sites are tested controls.

For the on-curve reference point with PRNG1=0 and effective scalar0:

- Stage79's two independent errors cancel completely at the decoded boundary,
  for all values of the injected errors. Both point scales remain 1. This does
  not mean their representative effects are irrelevant to later predicates.
- Stage80's error leaves the first point unchanged. The second point's
  coordinates are `(C+E,0)`, where `C=47^4 * 2^128`
  (`1660469400499131922331423267767258137845825536`).
  Its scale relative to the error-free stage is `s=1+E/C` modulo p.
  C is a unit; with the actual `E=94-2^128`, s is also a unit.

This constant has a readable origin: stage79's second point is
`(47*2^32,0)`, and stage80 doubles it to `((47*2^32)^4,0)`.
That fourth power is below p, so C needs no reduction. The corrected numerator
is therefore `(47^4-1)*2^128+94`. This uses the recovered boundary and doubling
identity; it does not require a primality or Fermat-theorem assumption.

Cross-product identities alone are not sufficient: a zero vector can have
zero cross product without representing a point. The report therefore also
checks a full coordinate scale identity and tests whether the actual scale is
a unit. Degenerate and point-distorting negative controls are retained.

The subsequent homogeneous propagation is compact:

```
ladder bit0: (a,b) -> (a^4, a^2*b^2)
ladder bit1: (a,b) -> (a^2*b^2, b^4)
```

Complete monomial degrees prove these scaling rules for arbitrary scales.
The replay compares decoded exact coordinates against the scaled compact
ladder at **all 160 boundaries**, not just the final affine point. Tested
effective scalars include 0,1,2,3,4,16, a longer suffix, `2^79-1` and a
full-width scalar. Every tested boundary agrees. Retaining observed tail tags
also reconstructs the exact uint160 tail, including denominator p versus0.

There is a further closed expression. Conditional on scales `(1,s)` after
stage80 and no later nontrivial corrections, with effective scalar
`0 <= n < 2^79`, the final second-point scale is

```
s ** (2^79 * (2^79 - n)) modulo p
```

More generally, after m suffix bits, put q=2^m. Starting with exponent pair
`(0,1)`, its exponents are `(q*(q-n-1), q*(q-n))`. Each effective bit e uses
ladder bit `1-e`; substitution of `q'=2q, n'=2n+e` directly preserves both
integer branch recurrences. There is no prime-modulus or curve-group-order
assumption and no exponent reduction. The tool compares the closed expression
against the complete scale replay when the observed schedule permits it.

**Boundary of this scale replay:** it still executes the exact SSA to observe the
carry sites, corrections and representative tags. Agreement therefore does
not establish a self-contained compact exact algorithm, a global proof of
the observed schedule, a byte-equivalent runtime replacement, or PLC
interoperability. Unsupported/non-scaling corrections are reported explicitly
rather than silently forced into a scale model. The next research task is
recovering those carry predicates/tags without the original full trace, then
proving correspondence through the representation-sensitive final output.
The following predictor removes that exact-trace dependency, but not the
source-dependent guard/tag machinery.

## Carry prediction without a full exact arithmetic trace

Run `python -m tools.predict_scalar_defects --effective-scalar 0`.
The new evaluator supplies residues from source-derived sparse polynomials.
For a canonical uint160 encoding, a residue greater than46 has exactly one
representative. Only residues0..46 can be either r or p+r.

Two cheap **necessary** conditions exclude impossible carry defects before
requesting operand representatives:

```
add: ordinary result residue in [47,92], OR
     residue >= 2^128 and low128(residue) < 47
sub: operand residues a < b <= 46
```

The evaluator visits guards in source order. If a necessary condition holds,
it obtains the operand representatives, checks the actual carry predicate,
and injects the detected correction into the result polynomial. Descendant
polynomials and cached residues/tags are repaired before later guards run.
This preserves nonlinear interactions between multiple defects. There is no
full exact-instruction-trace fallback or pre-recorded event schedule.

Ambiguous representatives are resolved on demand with lift bits. Conditional
on the operation's **corrected** residue r being0..46, the p-lift bit is:

```
add: a+b >= p
sub: a-b >= p OR a-b < -p
mul: a*b >= p
representative = r + p*lift_bit
```

Zero residues allow further pruning: addition returns p iff either operand is
positive, multiplication iff both are positive, and subtraction iff a>b.
A nonzero residue already proves positivity without resolving its lift bit.
These rules preserve p versus0 and p+r versus r, rather than normalizing them
away. None calls the old integer-model or lifted arithmetic executor.

One consequence is an **exact** compact multiplication formula, implemented
as `compact_multiply` (the three-fold oracle is retained separately):

```python
product = a * b
r = product % p
result = r + (p if r <= 46 and product >= p else 0)
```

Folds preserve the residue; lifts above46 are unique; the product-threshold
lemma selects the small lift. This is not merely a modular-shadow formula.
Packed runtime boundary/random controls include noncanonical inputs and
small-positive outputs, such as `(p-1)^2 -> p+1`, not1.

`python -m tools.prove_scalar_predicate_guards` proves **11** obligations
against the actual guard/lift Python AST and integer-model AST: both necessary
guards, unique/ambiguous lift bounds, ordinary-sum residue bounds, three small
lift rules and three zero-tag rules. Multiplication abstracts a*b to an
arbitrary uint320 product, just as the existing fold proof does. All are UNSAT;
UNKNOWN remains a failure. These are primitive-domain lemmas, **not** a
whole-predictor or generated-kernel SMT certificate. The small guard compiler
rejects unfamiliar expressions and ignored statements.

For the reference point, PRNG1=0 and effective scalar0, the full evaluator
predicts the three known carry events and exact **72-byte Transform7 output**.
It represents 29,168 source instructions including the fixed tail, but calls
no legacy arithmetic executor; it uses 279 zero-tag rules, eight potential
guard sites and 22 repaired source nodes. These counts are case-specific, not
a worst-case bound or performance guarantee. Source polynomials and the lazy
tag dependency graph are still retained. Tail events also carry unique SSA
identities because stitched original tape addresses may repeat.

Tests exercise all320 scalar branches with2,560 boundary/random layouts,
all160 exact boundaries on selected complete runs, arbitrary synthetic sources,
native full outputs for all three bundled public sources, and negative
controls with missing guards and canonical-only tags. They explicitly forbid
calls to all six old primitive executor functions in the new evaluator.

## Unreduced source recurrence after Q is lost

Run `python -m tools.recover_scalar_relation_terms`.
Direct comparisons of complete, unreduced polynomial coefficient dictionaries
recover the following source law for **arbitrary** decoded stage coordinates:

```
ordinary differential ladder step
if stage in 1..15 or 144..159:
    doubled numerator += Q  (modulo p)
```

The denominator and differentially added point are unchanged by this Q term.
The final stage observes only the retained second point. There are **1,268**
unconditional intermediate/final coordinate identities, plus the existing ten
initial identities conditional on the source-derived setup shadow. Unlike
the earlier proofs modulo Q, these retain the error term rather than requiring
Q=0. Numerical controls include states with nonzero Q.

## Concrete limit: field/scale state cannot replace representative history

A verified **synthetic on-curve** source point is:

```
x = 2^128 + 48
y = 917984300236617229462155822449362250189314875415
PRNG1 = selector = 0
```

The curve equation is checked exactly; no primality assumption is needed to
verify this candidate. It is not a captured PLC public key. Stage1's two
addition defects at words25470/25476 turn Q from zero to nonzero. After the
complete scalar phase, both the exact and ordinary-shadow denominators are
units, but their projective cross product is
`1307426275097508917995851978661085928554276274481`, **not zero**.
Thus their affine points differ: no rescaling repairs the ordinary ladder.
The new predictor agrees byte-for-byte with the original Transform7 on this
input, including the full72-byte result.

There is also an information-loss control at a synthetic valid stage boundary.
Take decoded coordinates `(16,0,4*x,4)` with fixed difference x above; Q=0.
Under the initial encoder, changing raw slots1/44 from16 to p+16 leaves every
decoded coordinate and Q identical. Yet the next source stage has additional
carry defects, including a subtraction correction47, and its second point
changes. Reachability of both boundary lifts from complete Transform7 is not
asserted. This proves that coordinates/Q alone do not determine the general
exact stage transition: representative bits cannot simply be discarded.

The current limit is a **source-independent compact exact rewrite**, not
offline reproduction of the open code. Ordinary curve multiplication,
projective-scale correction, canonical-only lifts and dropping relation terms
all have concrete negative controls. A richer source-dependent polynomial/tag
evaluator now reproduces the tested complete outputs. Standalone primitive
guard/tag rules are derived below; compressing entire stage transitions remains
unresolved. An exploratory
all-independent-error expansion at stage80 succeeds with138 error variables
and542 terms in its largest decoded coordinate; this is not a feasible-guard
proof and does not remove those dependencies. No mathematical impossibility
claim, hardware validation, runtime substitution or independent acceptance
claim follows. Further research needs new structural factoring/synthesis of
the guard/tag transitions; a PLC is not required for that mathematical task.

## Standalone residue/lift primitive rules

`scalar_representative_rules.py` removes source dependencies from each primitive.
An exact uint160 representative is `(r,t)` with canonical residue `0<=r<p`
and Boolean lift `t`; `t=1` is legal only for `r<=46`. Its integer value is
`r+p*t`. This bit is necessary, not redundant geometric state.

For addition write `s=ra+rb`, `k=ta+tb`, and `B=2^128`. The defect predicate is:

| Lift count | Necessary and sufficient addition defect |
| --- | --- |
| 0 | `s>=p+47` and `s mod B>=B-47` |
| 1 | `s>=47` and `s mod B<47` |
| 2 | `s>=47` |

If defective, add `94-B` to the field sum; the output lift is always zero.
Otherwise the output lift is true exactly when:

- `k=0` and `p<=s<p+47`;
- `k=1` and either `s<47` or `s>=p`;
- `k=2` and `s<47`.

For subtraction the defect is exactly `not ta and tb and ra<rb`. Add47 to
`ra-rb` in that case. The output lift is true for this defect, or for
`ta and not tb and ra>=rb`. No reconstructed uint160 subtraction is needed.

For multiplication let `v=ra*rb`, `r=v mod p`. The output lift is true iff
`r<=46`, both exact operands are positive, and
`ta or tb or v>=p`. Operand positivity is `ri!=0 or ti`. Thus all three
primitives have an exact residue/bit normal form; only multiplication needs a
field product, and no repeated high160 folds are required.

`prove_scalar_representative_rules.py` compiles the actual single-return
Python guard/tag AST and actual integer-model arithmetic AST. Six core obligations
are UNSAT across all uint160 input pairs: both defect predicates, both corrected
expression bounds, and both complete addition/subtraction representatives.
Addition obligations partition the lift count exhaustively into0/1/2; every
case must be UNSAT. Signed162-bit source compilation suffices for these
uint160 sums/differences; multiplication keeps its separate322-bit proof.
The source compiler sizes conditional integer literals from its operand width.
The corrected expressions lie in `(-p,2p)`, so one conditional canonical fold
is sufficient in the proof. This is not a multiplication, packing, generated
kernel, or whole-ladder SMT certificate. The multiplication formula follows
the existing residue-preservation/unique-lift/product-threshold lemmas and is
also checked against the independent three-fold oracle and packed runtime.

`scalar_representative_program.py` uses only these primitives to execute the
recovered source graph, then the existing setup/finalizer research models. It
reproduces full72-byte outputs and every boundary in the permanent controls,
including the on-curve point-changing carry example. Tests cover all320 source
branches with2240 boundary/random layouts, every small-residue/lift pair,
direct packed primitive comparisons, and negative controls for discarded lifts
and suppressed defects. Patching old arithmetic and polynomial executors to
throw does not stop this evaluator. The polynomial predictor now uses the
same standalone rules at potential carry sites, while retaining its separate
residue-polynomial and lazy-tag machinery.

This is a primitive-level exact simplification, not a source-independent
four-coordinate ladder. It still executes each selected source instruction;
compressing those instructions and their tag dependencies at stage level is
the next research boundary. No runtime replacement or hardware claim follows.

## Bounded stage carry/tag/output plans

`scalar_stage_plan.py` combines source field operations at compile time into
sparse polynomial formulas. Every potentially defective addition/subtraction
introduces a separate correction variable `e<SSA>`. Its value is decided in
source order: zero or `94-2^128` for addition, zero or47 for subtraction.
Products of these variables retain nonlinear carry interactions. Unlike the
earlier predictor, detecting a correction does not rebuild source descendants.

Simple exact constant folding/CSE would eliminate only9 of58486 instructions
across both alternatives of160 stages and the fixed tail. Independent-error
polynomials fit ordinary stages, but unrestricted expansion exceeds4096 terms
at the initial stage and fixed tail. The new compiler introduces formula
anchors `f<index>` when expansion would exceed a declared term/work bound.
Anchors refer only to earlier bindings. They do not invoke an older arithmetic
executor or assume a curve relation. A bound as small as two terms still works;
larger bounds trade fewer anchors for larger expressions, not guaranteed speed.

Three constant carry exclusions, checked by additional actual-predicate AST
SMT obligations, eliminate safe correction variables:

- Addition with either constant operand `c<=2^128-47` cannot lose the upper
  carry: its sum is below the first defective total `2^160+2^128-47`.
- Subtraction with a constant second operand `c<=p` cannot wrap twice.
- Subtraction with a constant first operand `c>=47` cannot wrap twice.

The addition bound has a concrete outside-boundary control: with
`c=2^128-46`, adding `2^160-1` does defect, returning94 instead of the ordinary
residue `2^128`. Disabling that guard or forgetting representative lifts changes
outputs. The primitive-rule solver now requires all9 obligations to be UNSAT;
UNKNOWN or timeout remains failure.

Across all320 source stage alternatives,20129 guards remain and1584 constant
carry sites are excluded. With the default256-term limit, the preliminary
all-stage compilation required252 anchors (at most13 in one stage); the fixed
tail requires more. These are plan-specific structure counts, not a ratio of
runtime cost saved. In the public-base-point effective-scalar-zero full-output
control, three real defects remain unchanged and only four guards need exact
carry/lift decisions. Necessary guard formulas are still evaluated for the
other retained sites. No faster-performance claim is made.

The independent structural validator recomputes correction frontiers, checks
anchor acyclicity, checks guard/input/tag inventories and enforces polynomial
bounds. Every carry guard refers only to earlier, already-finalized correction
values; every source field refers at most to its own correction. Thus lazily
cached anchor and field values need no runtime invalidation. This is a
structural check, **not an algebraic-equivalence or whole-compiler SMT proof**.
Output fields above46 have unique representatives; ambiguous small fields
retain on-demand source-dependent lift rules, including the proved zero-tag
shortcuts. The source tag dependency metadata is compiled once, not replayed
as a complete numerical arithmetic program.

The permanent controls cover all320 alternatives with2560 boundary/random
layouts, exact output and carry-event equality, all scalar boundaries, full
72-byte results, arbitrary sources, the on-curve point-changing carry example,
and term bounds2/8/64/256. Runtime evaluation also succeeds when old arithmetic,
the earlier SSA/polynomial executors, and polynomial construction/repair helpers
are patched to throw. Corrupted frontiers, forward correction reads and anchor
cycles fail the structural checks.

For readability, ``python -m tools.scalar_stage_plan --stage 80 --branch 1``
prints named output field equations, anchors, carry-site tape provenance and
field carry dependencies. `s<slot>` is an input residue, `e<SSA>` a correction,
and `f<index>` a bounded formula anchor. Field-only carry dependencies do not
include every indirect dependency of the carry decisions or lift rules; they
must not be mistaken for a complete exact-representative dependency trace.

This advances stage-level reconstruction from an instruction interpreter to
bounded carry/tag/output formulas, including the difficult initial and tail
groups. The plans are still source-specific and retain many guards and some
lift dependencies. Compressing their feasible guard conditions and translating
them into a small, independently understandable stage recurrence remains open.
Runtime code, wire behavior, binary fixtures and hardware-validation boundaries
are unchanged.

## Independent stage algebra translation checks

Run `python -m tools.verify_scalar_stage_algebra` to check all 320 branch plans
and the fixed tail, or select `--stage 80 --branch 1`. The default 256-term
plans pass **58,486 field identities and 62,361 guard identities** across 321
programs. Each guard has three checked equations: the uncorrected result and
both operands. Additional full audits pass at bounds 2/8/64. Permanent controls
repeat all four bounds on the difficult initial and tail plans.

The checker uses a separately implemented polynomial ring modulo `2^160-47`;
it does not call compiler algebra, constant-decoding, carry-exclusion or
structural-validation helpers. For each source instruction it checks that the
compiled field is the source operation on the preceding fields, plus exactly
one independent correction variable where required. These are coefficient
identities for arbitrary input residues and arbitrary correction values, not
sampled evaluations, fitted formulas, or identities conditioned on curve
membership. No primality, Fermat theorem or exponent reduction is assumed.

Anchor definitions refer strictly backward. Whole-polynomial replacements by
anchors are justified by exact coefficient equality; local differences are
then reduced through anchor definitions while preserving common factors.
This matters at tail SSA74: an old anchor equals one current operand while
also appearing inside the other operand. Treating all such symbols as
independent incorrectly rejects the valid translation; indiscriminately
expanding them can instead exhaust memory. Unresolved identities or exhausted
term/work/exponent budgets fail closed, with no probabilistic fallback.

Input/tag/guard inventories, source SSA ordering, polynomial canonical forms,
constant exclusions and correction frontiers are independently rechecked.
Certificates include instruction/identity counts and SHA256 digests of the
supplied source graph, plan and constant table; the CLI also reports checker,
compiler, decompiler and packing-model file digests. The certificate describes
the checked inputs, not a signature, separate reviewer approval, or an
independently verifiable proof artifact.

`python -m tools.scalar_stage_plan --effective-scalar 0 --verify-algebra`
checks all 161 selected plans before their respective evaluations and retains
the same full 72-byte result. Adding `--verify-algebra` to a stage description
includes its certificate. The flag is optional and affects research tools
only; library runtime code and wire behavior remain unchanged.

Permanent negative controls alter field/guard coefficients, anchor definitions,
correction weights, source graphs, inventories and frontiers. A doubled
correction coefficient passes the structural validator but fails the algebra
checker. The tail alias regression rejects an altered output, and verification
succeeds with compiler helpers patched to throw. Verification failure stops
the research evaluator before an unchecked plan is executed.

**Remaining trust boundary:** the recovered SSA and existing canonical packing
decoder are trusted. Constant carry exclusions rely on the separate primitive
source-AST lemmas, not a new solver invocation here. The checker does not prove
runtime polynomial evaluation, necessary carry filters, actual guard/lift
decisions, setup, scalar selection, packed generated kernels or finalization.
This is an independent implementation of local algebra validation, **not
independent human review, whole-pipeline SMT, or a compact exact curve ladder**.
Guard/tag compression and a separately justified runtime rewrite remain open;
issue #1 still awaits independent review and user acceptance.

## Lazy nonzero-product lift pruning

For a multiplication or square whose output residue is **1..46**, neither
canonical input residue can be zero. Write their residues as `a,b` and lifts
as `ta,tb`. The exact integer product expands as

```
a*b + p*(ta*b + tb*a) + p*p*ta*tb
```

Thus the output lift is `a*b>=p or ta or tb`. If the residue product already
crosses p, neither operand lift is needed. Otherwise a lift is possible only
for an input residue at most 46, and a true first lift settles the decision
without querying the second. `scalar_representative_rules.nonzero_product_lift`
implements this with lazy Boolean callbacks. The bounded stage evaluator uses
it only for nonzero ambiguous multiplication/square outputs. Zero outputs
retain their separate positivity rule: applying the shortcut to `p*0` would
incorrectly select p instead of 0. Larger residues still have unique outputs.

Run `python -m tools.prove_scalar_product_shortcuts`. All **seven** obligations
are UNSAT: equivalence of the actual callback-rule AST to the existing
product-threshold AST, the settled-product cut, exclusion of zero operand
residues by a nonzero output residue, and four exact distributive lift
expansions. The solver abstracts the residue product to a nonnegative integer;
this stronger relaxation avoids nonlinear input multiplication. The zero-input
case retains the necessary zero-product implication. Canonical-residue bounds
and legal lifts are explicit. No prime-modulus assumption is needed.

The guard AST compiler accepts only declared, zero-argument Boolean callback
results; other calls fail closed. This models the returned predicate, **not
Python short-circuit execution or callback side effects**. Actual lazy-demand
tests use throwing callbacks, below-threshold lift-sensitive inputs, zero-output
controls and a source-stage comparison against an eager baseline. Changing the
rule to drop input lifts makes its proof fail with SAT; UNKNOWN/timeout is not
accepted as proof. The separate primitive fold/threshold lemmas and packing
correspondence remain trust boundaries, not newly proved packed kernels.

In a permanent recovered-source control, stage 1 branch 0 has all five raw input
slots set to `p+1`. The lazy rule reduces evaluated tag rules from 49 to 33 and
lift queries from 54 to 24, while preserving all outputs and carry events against
both the independent lifted reference and canonical packed-SSA executor at
term bounds 2/8/64/256. These are legal synthetic stage inputs; reachability from
a complete Transform7 input or a PLC exchange is not asserted. A small toy
graph separately isolates the pruning of an earlier square's tag dependency.

The CLI reports `nonzero_product_rules` and `product_lift_queries`; query counts
include cache hits, not just newly evaluated tag rules. The public reference
point at effective scalar 0 exercises no nonzero-product shortcut and retains
279 tag rules and the same full 72-byte result. **No runtime speedup is claimed.**
This is a proved local cut in the remaining source-dependent lift graph, not
general carry-guard compression, a compact exact curve ladder, whole-pipeline
SMT, or a library runtime rewrite. Runtime and wire behavior remain unchanged.

## Decided-defect subtraction lift pruning

Subtraction has a compact rule once its exact defect `d` is already decided:

```
lift = d or (rb <= ra <= 46 and ta and not tb)
```

This includes zero outputs. In the original tag rule, the second true case
`not ta and tb and ra<rb` is exactly the defect predicate. Replacing that case
with the known decision removes the need to revisit operand lifts for
decreasing residues. A defect settles the output as lifted; without a defect,
either input residue above 46 or `ra<rb` settles it as unlifted. Only
`rb<=ra<=46` needs lifts: query the left first, and query the right only if
the left is lifted. `scalar_representative_rules.subtraction_lift` implements
this decision with lazy callbacks, preserving the original standalone tag
function as a separate reference.

The stage evaluator uses this for all ambiguous subtraction outputs rather
than a separate raw comparison at zero. Subtracting an **identical source
Operand** settles the result as zero without any lift queries. Equal residues
from different operands are not sufficient: raw representatives `p+1` and 1
have equal residues, yet their difference is p rather than 0. The decided
defect must be exact; it is not merely a necessary carry filter or a guessed
schedule. Guards still decide corrections in source order before these lazy
queries. Excluded constant guards use the separately proved impossibility of
the defect, not an unresolved decision treated as zero.

Run `python -m tools.prove_scalar_subtraction_shortcuts`. All **seven**
obligations are UNSAT across every uint160 operand pair. The actual callback
predicate AST is compared with both the existing tag AST and the actual
integer-model subtraction AST. Additional checks cover large-residue cuts,
known defects, zero/raw-comparison equivalence, identical operands and the
order/false-left-lift cut. Signed 162-bit source intermediates suffice; this
does not use a nonlinear product abstraction or assume a prime modulus.

The proof models stable Boolean callback results, not their Python execution.
Permanent tests separately use throwing callbacks, every small residue/lift
pair and large boundaries, canonical packed-SSA execution, zero-output pruning,
equal-residue/different-lift negative controls and identical-source-operand
pruning. Dropping the defect branch changes `0-(p+46)` from p+1 to 1 and makes
the source-AST proof fail with SAT. UNKNOWN and nonpositive solver timeouts
remain failures, not proof results.

For a permanent synthetic recovered-source control, stage 1 branch 0 has all
five raw inputs set to 1. Holding multiplication behavior fixed, subtraction
pruning reduces tag evaluations from 49 to 47 and subtraction lift queries from
12 to 6. Outputs and carry events agree with both the independent lifted
reference and canonical packed-SSA executor at bounds 2/8/64/256. Complete-input
reachability of this stage boundary is not asserted. The earlier product-only
control keeps subtraction demand eager to isolate that independent cut and
retain its historical counts.

The CLI adds `subtraction_rules` and `subtraction_lift_queries`; these count
ambiguous subtraction resolutions and callback queries, including cache hits.
The public reference-point effective-scalar-zero full output remains unchanged
with 279 tag evaluations, six subtraction rules and one subtraction lift query.
A limited complete-input search found no tag-evaluation reduction; no general
speedup or complete-input pruning benefit is claimed. This advances local
lift-graph simplification, not carry-guard compression or a compact runtime
rewrite. Library runtime, wire behavior and hardware-validation boundaries
remain unchanged.

## Addition lift-count elimination

Addition's three lift-count cases collapse to a rule on the canonical input
residue sum `s=ra+rb` and, only when needed, the two legal operand lifts:

```
lift = (p <= s < p+47) or (s <= 46 and (ta or tb))
```

This is valid globally, including zero outputs, and **does not require a
defect decision**. With one lifted operand, that operand's residue is at most
46, so `s<=p+45`; with two, `s<=92`. The original lift-count cases therefore
reduce to the wrap interval or a small sum with at least one lift. A defective
sum cannot meet either condition. Corrections are still required to compute
the output residue and still decided by the unchanged source-order guards;
this is not elimination of addition defects or carry checks.

`scalar_representative_rules.addition_lift` implements the expression with
lazy callbacks. The wrap interval settles the tag without querying either
operand; outside both intervals the tag is false. Only sums at most 46 query
lifts, with the left queried first and the right skipped when the left is true.
The stage evaluator uses this for zero and nonzero ambiguous addition outputs.
The original `addition_tag` and standalone `add` remain independent references.

Run `python -m tools.prove_scalar_addition_shortcuts`. Seven obligations,
each partitioned exhaustively over lift counts 0/1/2, give **21 UNSAT cases**
for every uint160 input pair. The actual lazy-rule AST is compared with both
the original tag AST and the actual integer-model addition AST. Checks also
cover defective sums, the wrap interval, excluded intervals, the small-sum OR
and equivalence to raw positivity at zero. Signed 162-bit intermediates suffice;
no product abstraction or prime-modulus assumption is used.

As with the other local proofs, stable Boolean callback results are modeled,
not Python callback execution or packed kernels. Permanent tests separately
cover query order, throwing callbacks, all small legal lift pairs, large
boundaries, zero outputs and canonical packed-SSA execution. Removing the wrap
interval changes a source output from p+1 to 1 and produces a SAT proof failure.
UNKNOWN/timeouts are not accepted as proofs.

At recovered stage 1 branch 0, all five raw inputs set to 1, addition pruning
reduces evaluated tag rules from 47 to 42 and addition lift queries from 16 to
5. Both runs retain identical multiplication/subtraction behavior and agree on
all outputs and carry events with the independent lifted reference and
canonical packed-SSA executor at bounds 2/8/64/256. The eager addition baseline
retains the original zero-output positivity shortcut, avoiding a spurious
improvement from making that baseline unnecessarily eager. Earlier product and
subtraction controls hold addition demand at its old baseline to isolate their
individual cuts and preserve historical counts. Full-input reachability of
these synthetic stage boundaries is not asserted.

The CLI adds `addition_rules` and `addition_lift_queries` (queries include cache
hits). A limited complete-input search found no reduction in evaluated tags
or addition queries. The public reference-point effective-scalar-zero case
retains 279 tag evaluations, two addition lift queries and the same 72-byte
result. The new sum check may evaluate both input residues where the old zero
positivity check stopped after the first; no general operation-count reduction
or runtime speedup is claimed. This removes another source-dependent lift
decision, not the remaining lift graph, general carry-guard complexity or the
need for a compact independent ladder. Library runtime, generated code,
fixtures, wire behavior and hardware-validation boundaries remain unchanged.

## Exact lazy carry predicates

The addition defect separates into three regions on canonical residues `a,b`:
large sums need no operand lifts, sums47..92 need both legal lifts, and a
low128-word wrap needs one. `lazy_addition_defect` implements these regions;
`lazy_subtraction_defect` is `a < b <= 46 and not ta and tb`. Callbacks are
only requested in unresolved regions. The original eager representative
arithmetic remains an independent reference.

Run `python -m tools.prove_scalar_lazy_guards`. All21 exhaustive lift-count
cases are UNSAT against the actual eager predicate and integer-model ASTs.
Callback-order tests, throwing callbacks, mutated predicates, source packed
execution and complete72-byte controls cover execution separately. At the
synthetic stage1/all-p+1 boundary, tag evaluations fall33→24 without changing
outputs or any source carry event. This is not a whole-pipeline SMT proof.

## Boolean correction domains and output-driven evaluation

The optional `--boolean-corrections` compilation mode uses `e²=c*e`, where
each source correction is actually0 or its operation's constant `c`. Source
derived constants and proof mode appear in the independent coefficient
certificate. The default certificate still proves the stronger identity for
arbitrary formal error variables. Polynomial anchors retain strict error-read
frontiers; mixed products of different errors must not be discarded.

Across321 source programs, stored monomials fall1,836,319→1,785,403;147
programs improve. Early normalization can worsen anchor layouts, so compilation
compares it with post-normalization of the original layout and chooses the
smaller representation. These are storage counts, not a runtime speed claim.

`--demand-guards` resolves only dependencies of required outputs. An explicit
iterative scheduler handles deep, small-budget tail plans without depending on
the Python recursion limit. Undefined, forward and cyclic correction reads
fail closed. Zero monomials can skip later bindings. The optional
`--cofactor-fields` additionally specializes only already-known immutable
inputs, finalized corrections and cached anchors, then builds bounded exact
two-value decision DAGs. Independent coefficient certificates check both
specialization and decisions; exact polynomial leaves handle exhausted budgets.
No division or prime-modulus assumption is made, including zero/nonunit weights.

On the public reference point, effective scalar0, PRNG0 and budget256:

| Mode | Resolved guards | Tag rules | Reported defects |
| --- | ---: | ---: | ---: |
| Complete source-order guard trace |10,400|279|3|
| Boolean domains + output demand |6,302|276|2|
| Above + certified cofactors |6,131|276|2|

All160 stage boundaries and72 destination bytes remain identical. The omitted
defect is unneeded for these outputs. **Demand mode is not a complete source
carry trace**; CLI `complete_guard_trace=false` and `skipped_guards` make this
explicit. The on-curve point-changing carry control still needs all10,675
guards and retains30 defects. No general speedup or compression ratio is
claimed. Counters describe committed logical queries; paused probes are counted
separately by `scheduler_retries`, and cofactor nodes are reported separately.

Relevant tools/tests: `verify_scalar_stage_algebra.py`,
`scalar_correction_dag.py`, and the stage-algebra, correction-domain,
demand-guard and correction-DAG test modules. All320 branches and budgets
2/8/64/256 have independent numerical/coefficient controls; these remain
source-specific exact plans, not an independently understood compact algorithm.

## Shared first-defect equations and a simpler square lift

`scalar_predicate_dag.py` compiles the actual restricted predicate ASTs into
typed, shared integer/Boolean equations. Literal folding, canonical-residue
intervals and Boolean identities require no curve assumption. Nine primitive
frontend SMT obligations compare the equations with actual helper ASTs; all
are UNSAT. Bad folding produces SAT and UNKNOWN is not accepted as proof.

The conditional square lift is especially small:

```
output residue <= 46: lift = (input residue >= 7) or input_lift
```

A square below p with an input at least7 would have residue at least49,
contradicting the precondition. Inputs0..6 need their lift, including raw0
versus rawp. Four actual-AST integer-square obligations are UNSAT. The optional
`--square-shortcuts` stage-plan flag retains the old behavior by default for
isolated historical controls. All source branches, boundaries, output bytes,
callback cuts and a missing-lift SAT mutation have permanent tests. This
does not reduce guard/tag counts in the public full-output control.

`python -m tools.scalar_first_defect` builds a canonical-point-coordinate
catalogue for316 intermediate branches. It uses complete unreduced polynomial
coefficients for equality, not hash-only comparisons or a Q=0 assumption.
Evaluation stops at the first actual correction and does not replay source
instructions or recompile Python helper ASTs. Tests compare its first event,
raw operands, representative and correction against the independent fold
oracle for every intermediate branch and arbitrary legal boundaries.

The20,007 potentially unsafe guard sites have9,230 distinct field pairs but
16,562 distinct complete predicates. Equal fields do **not** imply equal raw
lifts: representation histories retain substantial complexity. The catalogue
has393,455 stored equations and19,549 field polynomials;359,785 equations
are reachable from guard/tag roots. This is
not a compactness success. It is explicitly a **first-defect** model, not a
post-correction continuation, final-stage/tail model or whole-runtime proof.

The AST compiler rejects source/runtime mismatches by checking the inspected
function name, bytecode, constants and names against the loaded function.
This prevents reading an edited source body beneath a previously imported
function and accidentally proving a different predicate. Restart tools after
editing helpers; a long validation run must use frozen code. A constant-mutated
loaded function is a permanent fail-closed regression control.

## Seven-state, output-conditioned lift machine

`scalar_lift_categories.py` provides one finite-state description covering
every primitive's representation lift, **given its exact corrected output
residue and defect decision**. It does not compute either prerequisite.

| States | Canonical residue | Lift |
| --- | --- | --- |
|0 /1|0|false /true|
|2 /3|1..6|false /true|
|4 /5|7..46|false /true|
|6|47..p-1|false, uniquely|

For corrected output0..46, addition and nonzero multiplication share exactly
the same transition: either input has state6 or an odd (lifted) state.
Subtraction lifts on its defect, or when the left is lifted and the right is
small/canonical. Zero-product lift is raw positivity of both inputs. Squaring
lifts when its input state is at least4 or odd. Outputs above46 are unique.
The table is certified only for feasible operand/output combinations, not
arbitrary state triples; its API rejects incompatible defect/output classes.

Run `python -m tools.prove_scalar_lift_categories`:34 actual-AST obligations
are UNSAT, covering all four legal input lift pairs, exact products and both
addition/subtraction lazy realizations. Defective addition's corrected residue
is always **at least94**, so its output is unambiguously canonical and the
small-output addition rule does not need a defect test. Defective subtraction
always has corrected residue1..46 and a true lift. Products use exact integer
products and quotient equations, not an abstract multiplication or prime
assumption. Removing required input lifts produces SAT; UNKNOWN/timeouts fail.

`--category-lifts` applies the unified rules to stage plans, with defaults
unchanged for historical isolation controls. Tests cover all320 branches at
budgets2/8/64/256, primitive boundary pairs, every full stage boundary,72-byte
references and the on-curve point-changing carry control. The separate
`--small-product-shortcuts` flag isolates the product reduction; its eight
actual-AST obligations also prove against the earlier rule/source threshold.

This completes a compact **primitive lift description**, not a compact
whole-stage carry/lift algorithm. All reachable first-defect predicates now
use only Boolean logic, linear integer sums/comparisons and low128 masks on
canonical field leaves: there is no integer multiplication in that layer.
The nonlinear field polynomials and their dependencies remain. Exploratory
ROBDDs on eight representative stage circuits, two variable orders and both
independent-comparison/category-aware encodings exceed20,000 allocated nodes
per attempt despite original Boolean circuits of951..2,881 nodes. This is a
bounded negative result, not impossibility. Feasibility-aware arithmetic
constraints are the next research direction; enlarging BDDs is not itself
progress toward a compact rewrite.

## Executable coefficient checks for the Q-aware recurrence

`python -m tools.scalar_relation_ladder` independently checks the executable
`recover_scalar_relation_terms.generalized_step` described above. The two
canonical transitions were already recovered in earlier research:

```
stages1..15 and144..159: generic ladder, with Q added to doubled numerator
stages16..143:          generic ladder, without that addition
```

The recovered per-stage coordinate bijections and branch flips are retained.
`Q=J-t*A` is computed from the current canonical coordinates; it is not assumed
zero. The actual compact numerical formula is executed on coefficient objects
and compared with independently expanded source output polynomials. All1,268
decoded coordinate identities are exact in the full polynomial ring:1,264
for158 intermediate stages plus4 for the final retained point. This needs
neither curve membership, inversion nor primality. The final stage uses the
same Q-on-double variant and retains its second point.

Permanent controls exercise all318 covered branches on arbitrary stage entry
states, a nonzero-Q counterexample, mutations of the actual numerical formula,
and rejection of sampled symbolic branches. This strengthens translation
validation of the existing off-relation recurrence, but does not erase corrections
or output lift bits. The exact all-p+1 source control still differs from the
field-only model. A mass runtime rewrite is not justified: the remaining hard
part is a compact exact description of the stage-dependent carry/lift history,
not the ordinary field recurrence. Generated/runtime code, fixtures and wire
behavior remain unchanged; issue1 still requires independent review and user
acceptance before closure.

A new control holds canonical coordinates `(1,1,1,0,1)`, Q=0, the ladder
branch, the ordinary-stage policy and all incoming lift bits fixed. Using
each stage's own encoder, stage16 has no defect whereas stage32 has one;
the decoded doubled numerator differs by47. These are legal synthetic stage
entries, not asserted complete-pipeline reachable states. This isolates
stage-specific representation history even without incoming lifted values
or a nonzero relation error; phase formulas alone cannot replace it.

## Structural raw-value implications and constant-product cuts

`scalar_structural_guards` records lower bounds saturated at47, and ancestors
that cannot exceed an intermediate's raw representative when that representative
is at most46. These are facts about uint160 representatives, **not** monotonicity
of field residues. Small raw additions equal their unreduced sums. Small raw
products equal their unreduced products. Thus addition inherits both operands;
squares inherit their operand; products inherit an operand when the other has a
proved positive raw lower bound. General subtraction does not inherit ancestors.

A subtraction's extra-wrap defect requires `raw_left - raw_right < -p`, hence
`raw_left <=46`. Consequently a defective `subtract(add(u,x),b)` implies a
defective `subtract(u,b)`, and similarly for the other add operand, a square,
or a product with a proved positive other factor. The right operand must be
the identical SSA value: equal field polynomials do not establish this rule.
In particular `subtract(add(b,x),b)` never has the extra-wrap defect, even
though the addition can wrap or have its own correction.

The source-specific inventory has369 additional always-safe subtraction sites
and154 further dominance candidates across both branches and the finalizer.
Stage16 branch0 provides a concrete example: subtraction SSA24 is dominated
by earlier SSA9. The optional `--structural-guards` evaluator settles a guard
only from its static proof or an **already resolved** zero-correction dominator.
It introduces no new correction demand and retains every formal error variable
and coefficient certificate. A bound `raw>=47` also settles the output lift
as true whenever the corrected residue is0..46.

Positive raw constant products have an additional exact conditional rule:

```
output residue0..46, raw constant c>0:
    output_lift = input_residue >= floor(46/c)+1 OR input_lift
```

Zero multipliers are handled separately. This includes zero output residues,
constants at least p and nonunits; neither primality nor invertibility is used.
The same SSA operand multiplied by itself uses the already proved square cut.
`prove_scalar_structural_guards` checks17 valid primitive obligations and two
deliberately invalid monotonicity rules against actual integer-source ASTs and
exact integer factor lemmas. `prove_scalar_constant_lifts` checks96 obligations
against actual lift/product-threshold ASTs. The latter explicitly does not claim
an AST proof of the threshold producer: concrete producer partitions are tested
and the high-constant floor identity is checked mathematically. Unknown solver
results are failures. These remain primitive proofs, not generated-kernel or
whole-stage SMT proofs.

The prefix-only catalogue can exclude static and dominated sites outright:
every earlier defect must be false before the first defect is reached. Its
optional structural mode has19,642 guard sites,9,051 distinct field pairs,
16,282 complete predicates and357,607 stored predicate nodes, versus20,007,
9,230,16,562 and393,455 respectively without these cuts. Exact output and
first-defect controls cover all source branches, including earlier corrections;
full byte checks retain the point-changing control. This is useful pruning,
but the catalogue is still source-specific and large. It is not the missing
compact, independently understandable exact whole-stage algorithm and does
not justify replacing the runtime.

### Entry-specialized bounds without source replay

The evaluator also specializes these raw lower bounds from the actual entry
values, using `min(raw_entry,47)`, never `min(residue,47)`. On the public
synthetic case with Boolean corrections, demand/cofactor fields and category
lifts, this reduces6,131 guard evaluations and276 lift-history rules to6,015
and181. There are1,321 structurally settled guards and51 settled lifts. The
point-changing control still has30 defects and10,675 demanded corrections;
2,649 of its carry checks are settled structurally. These counts do not prove
a speedup or compact whole-stage equivalence.

`scalar_raw_bound_dag` compiles intermediate source bounds once into12,793
shared saturated equations. This particular scope has only positive-semiring
nodes: general subtractions conservatively reset the bound to zero. All316
branches therefore admit polynomial bounds over five entry variables in the
semiring with addition and multiplication saturated at47. Coefficients also
saturate at47. A positive coefficient c permits exponent contraction once
`c*2**exponent>=47`, but never below1: integer inputs0 and1 must be preserved.
A coefficient47 monomial makes any term with a containing variable support
irrelevant. These transformations are not ordinary field-polynomial reductions.

`scalar_raw_bound_polynomials` stores7,001 shared polynomials with16,439 terms
total and at most12 terms in any polynomial. Exhaustive checks of the48-element
semiring establish associativity, distributivity and the power contractions.
Differential controls compare the normalized polynomials with every compiled
bound equation and every source branch's entry-specialized bounds. The optional
prefix mode is executable with:

```
python -m tools.scalar_first_defect --structural-guards --entry-bounds
```

Its bound facts are evaluated lazily before subtraction guards and as lift
shortcuts. Lift facts are scoped to the current source branch: equal tag roots
in other stage encodings do not transfer their raw bounds. Evaluation uses the
normalized polynomials, not source instructions or the bound-equation graph.
Permanent controls disable all those source/graph replay paths. The main
predicate graph remains357,607 nodes; the initial inlining experiment grew it
to423,030 and was replaced with separate bound annotations. A further
48-valued decision-diagram experiment exceeded its50,000-state budget; this is
a bounded negative result, not an impossibility theorem.

### Mutually exclusive corrections

Every defective addition or subtraction has raw output at least47. A later
defective subtraction requires its raw left operand and all recorded low-output
ancestors to be at most46. Therefore the corresponding correction pairs cannot
both be nonzero. Across321 source programs this supplies8,353 pairs.

`scalar_stage_plan --boolean-corrections --exclusive-corrections` uses these
source-derived constraints to reduce `E_i*E_j=0`, alongside the existing
`E_i**2=c_i*E_i` domains. Independent correction pairs retain their nonlinear
mixed terms. The independent coefficient checker reconstructs the implications
from source SSA and constant decoding without calling the compiler's analyzer;
certificates explicitly list the source correction pairs and require matching
proof modes. This is a proof over constrained correction domains, **not** an
arbitrary-error polynomial identity. Incorrect compiler exclusions and deleted
valid mixed terms are negative controls.

At the256-term budget, stored formulas shrink from1,785,403 to1,774,638 terms,
with93 source programs improved. The compiler retains the smallest early- or
late-normalized layout and cannot worsen the Boolean-only formula-size metric.
This is a modest further reduction; the remaining stage-specific carry history
is still the unresolved part of a compact exact rewrite.

## Complete compiled field/carry/lift stages

`scalar_compiled_stage` closes the earlier evaluator's dependency on source
instruction metadata for lift recovery. It compiles **all** stage arithmetic
into field polynomials plus actual helper-AST carry and lift Boolean equations.
Unlike `scalar_first_defect`, it retains corrected field operands, current
subtraction defects and every subsequent lift dependency. Multiple defects,
their nonlinear interactions and the representation-sensitive finalizer are
retained. An evaluated stage contains no `Program`, `Instruction`, source
constant-table lookup or arithmetic/lift helper callback. Anchor scheduling and
Boolean evaluation are iterative, including the two-term-budget finalizer.

The independent `verify_scalar_compiled_stage` validates the actual compiled
data, not merely a compiler-side certificate. It reconstructs field, correction
and anchor bindings for the independent coefficient checker, checks carry
operand references and weights, canonically rebuilds typed Boolean nodes
without trusting compiler interval metadata, and validates actual carry/lift
roots against the source primitive contracts. It checks every exit reference
as well. It does not call the stage compiler, compiler algebra, constant decoder
or constant carry-exclusion helpers. The separately proved arithmetic/helper
contracts and predicate frontend remain explicit trusted dependencies; this
is not a new generated-kernel or whole-pipeline SMT proof, nor independent
human review.

All 321 compiled data sets cover 58,486 field identities, 62,361 guard-field
identities, 20,787 carry contracts and 58,486 lift contracts at each supported
formula budget. Permanent controls mutate actual coefficients, Boolean roots,
exit references, carry weights and interval metadata, and disable source and
helper replay during numerical evaluation. Full-output controls preserve all 72
bytes and all 161 boundaries, including the point-changing case and post-defect
events. The three complete-trace events in the public example are retained;
the earlier two-event demand-only trace omitted an unobservable event.

```
python -m tools.scalar_compiled_stage --verify-data --exclusive-corrections
```

This completes a self-contained, source-specific **research evaluator** for the
scalar arithmetic and representative history. It does not recover a compact
stage-independent curve algorithm: the field coefficients and Boolean equations
still encode the source-dependent history, and are substantial data. That
compression problem remains distinct from modeling every operation exactly.
Runtime/generated code, binary fixtures, wire behavior and issue1's independent
review/acceptance requirements remain unchanged.

## Independently verified factored field data

`scalar_field_circuit` factors the compiled field polynomials into a globally
shared modular arithmetic circuit. It extracts common monomials, normalizes a
leading coefficient only when `gcd(coefficient,p)=1`, and uses multivariate
Horner form. Unit checks avoid a primality assumption. These are identities in
the unrestricted polynomial ring, including arbitrary simultaneous correction
values; factoring introduces no new correction-domain constraints.

`verify_scalar_field_circuit` independently expands the actual circuit nodes
and compares every formal coefficient. It does not use builder routines,
compiler algebra, source instructions, numerical fitting or curve relations.
Budgets are explicit failures, not incomplete success. Mutation controls cover
coefficients, roots, powers and cyclic edges. Both expansion and numerical
evaluation are iterative. Numerical caches are scoped to one stage's bindings;
abstract variable ordinals shared across stages do not share numerical values.

At the 256-term budget, the 321 source programs have 66,432 interned field roots
and 814,815 stored terms. Their shared circuit has 460,674 nodes, including 447,737
arithmetic nodes. Counting integer items in the coefficient representation gives
4,907,379 versus 1,435,517 in the circuit representation including all field-root
references: about 71% fewer. This is **not** a byte-size, memory, computation or
speed measurement, and does not count the retained Boolean equations.

`scalar_factored_stage` coefficient-checks the factorization before discarding
the original polynomial coefficients and SSA site inventory. The evaluator
retains all carry/lift equations, correction bindings, field anchors and minimal
guard provenance. One immutable field circuit is shared by the complete
catalogue. The optional field kernel in `scalar_compiled_stage.evaluate` uses
that circuit with the existing causal correction and iterative anchor scheduler.
Factoring can change which anchors are demanded; those diagnostic counters are
not semantic outputs. Full raw boundaries, defects and output bytes must agree.

```
python -m tools.scalar_field_circuit
python -m tools.scalar_factored_stage
```

The first command checks all 66,432 coefficient identities. The second first
translation-validates the original 321 complete equation data sets, then checks
the factored field data, discards the originals and evaluates all 161 boundaries
and 72 output bytes. Controls also cover the point-changing case, multiple
defects, source/helper replay disabled, every source branch and the two-term
finalizer. This is useful lossless compression of the exact research model,
not recovery of the missing compact stage-independent curve algorithm or
authorization to replace runtime/generated code or close issue #1.

### Formula budget and shared Boolean templates

Factoring the two-term-budget plans is substantially smaller than factoring the
256-term plans. The checked CLI supports `--max-terms` so this tradeoff is
reproducible rather than an undocumented compiler change:

| Term budget | Field roots | Shared arithmetic-circuit nodes | Field-circuit integer items, including roots |
| --- | ---: | ---: | ---: |
| 2 | 87,191 | 38,780 | 199,692 |
| 8 | 68,359 | 133,128 | 463,689 |
| 64 | 66,456 | 320,414 | 1,019,598 |
| 256 | 66,432 | 460,674 | 1,435,517 |

The node column includes literals and variable leaves as well as arithmetic
operations. Lower budgets use more field anchors and therefore more binding
metadata; the table is **not** a total-storage or speed comparison. More field
roots need not mean more arithmetic nodes: anchors prevent polynomial expansion
and shared circuits factor their small defining equations.

The factored catalogue also shares carry/lift Boolean templates. A field leaf
remains an abstract **stage-local field ordinal**, not a value from another
stage. Each stage supplies its own checked field equations, input lifts and
fresh numerical caches. This is valid sharing of functions of formal field/lift
arguments, not equality of different stages' raw values or lift histories.

An independent DAG projection checker preserves every original leaf and
operation, permitting only explicit commutative argument reordering. It checks
actual nodes and type/interval metadata without using the sharing builder,
predicate frontend or compiler interning table. Guard, event-operand tag and
exit roots are remapped and checked separately. Actual node, metadata and
certificate mutations are negative controls. The compilation-only interning
table is discarded before numerical evaluation.

At budget 2, the 739,044 original predicate nodes share into 407,930 nodes. Their
opcode/argument integer-item metric shrinks from 2,166,375 to 1,330,640. Budget 256
has nearly the same shared Boolean size. This still does not count all binding,
type/bounds, guard or catalogue metadata and is not a byte-size or speed claim.
Both budgets retain exact post-defect results and complete traces:

```
python -m tools.scalar_factored_stage --max-terms 2
```

### Why this is exact, and what is still missing

For each uint160 representative `r`, `r = mu + p*tau`, with canonical
`mu=r%p`, Boolean `tau`, and `tau` possible only for `mu<=46`. The primitive
contracts give the exact corrected residue and output lift from the incoming
residues/lifts, including addition/subtraction defects. The checked field
identities retain those corrections and their nonlinear interactions. Causal
guard ordering and backward anchor references therefore establish the source
stage's raw outputs by induction, without assuming a curve relation or that
the first defect is the only defect.

Circuit coefficient expansion preserves every field equation in the stronger
unrestricted formal ring. Boolean DAG projection preserves every carry/lift
equation as a function of its stage-local field/lift arguments. Thus composing
these transformations preserves the full stage semantics under the original
primitive/source-bridge contracts. Chaining checked stages preserves all scalar
boundaries and the existing setup/finalizer model's output. This is a composition
argument with explicit trusted primitive and source bridges, **not** a new
monolithic packed-kernel/whole-pipeline SMT proof or independent human review.

The exact source-compatible research model and its lossless compaction are now
executable. The remaining genuinely different question is whether the substantial
stage-dependent representation history can be expressed as a small,
independently understandable curve-level algorithm. Neither factorization nor
template sharing answers that question; the stage 16/stage 32 counterexample still
rules out replacing this history with the ordinary two-policy recurrence alone.

Field-circuit certificates also check operational dependencies, not only ring
equality. A cancelled term such as `0*unavailable_variable` has a valid zero
polynomial but can still request an unresolved correction or cyclic anchor
before evaluation finds the zero. The default checker therefore requires every
root's syntactic variable dependencies to be contained in its original field
polynomial's variable support. Factoring introduces no new bindings, preserving
the original causal anchor/correction guarantees. An explicitly weaker
`strict_dependencies=False` mode certifies only the ring identity, records that
limitation in the certificate, and is not used for stage lowering. A permanent
negative control demonstrates why the stronger check is needed.

Lowered equation metadata explicitly requires its external field kernel. Calling
the ordinary evaluator on stripped metadata without that kernel fails rather
than silently treating the empty coefficient placeholders as zero equations.
Source translation validation likewise requires the original coefficient data.

A development-machine timing diagnostic (three warm runs per synthetic case,
other local tests running concurrently) found medians of 37.1/37.9 ms for the
source reference, 194.4/209.2 ms for the unfactored budget 2 compiled model, and
236.3/254.1 ms for the factored/shared-template model, for the public and
point-changing cases respectively. All outputs matched. Compilation plus
source-data validation took 27.6 s and factoring plus verification 10.8 s in that
run. These are non-isolated diagnostics, not rigorous benchmarks. They show why
data compaction must not be described as a runtime improvement or justification
for replacing the existing implementation.

## Exact saturated-history algebra

`scalar_saturated_history.py` makes a semantic reduction of the remaining lift
history, rather than factoring another Boolean graph. For every legal raw value
define

```
mu = raw % p
s  = min(raw, 47)
raw = mu + p * (mu <= 46 and s == 47)
```

The pair `(mu,s)` determines the complete uint160 representative. The previous
raw-bound analysis could only assert `raw>=bound`; this new `s` is exact.

### Addition and multiplication need no internal lift history

The actual source integer primitives satisfy these identities across their
entire domains, including defective addition and zero/lifted multiplication:

```
s(add(a,b))      = min(s(a) + s(b), 47)
s(multiply(a,b)) = min(s(a) * s(b), 47)
```

Thus their saturation plane is the 48-element nonnegative saturated semiring.
Its addition and multiplication are associative, commutative and distributive.
These are **saturation identities**, not permission to reassociate the defective
field-addition plane. That plane still includes every actual correction.

A useful stronger consequence is that actual raw multiplication itself is
associative: its residue is the modular product, its saturation is the
saturated product, and the pair determines the raw result. Any multiplication
or square tree therefore collapses exactly to this compact formula:

```
mu = product(factor % p for factor in factors) % p
s  = min(product(min(factor,47) for factor in factors), 47)
result = mu + p * (mu <= 46 and s == 47)
```

The implementation accumulates the two products incrementally, never forming
an enormous unfurled integer. It handles literal zero and p-lifted zero
distinctly and needs no prime-modulus, curve, inverse or nonzero assumption.

All 48 saturation states are necessary for this particular context-independent
quotient and the `raw>=47` observation: for `a<b<=47`, adding `47-b` distinguishes
the two observations. This is not a lower bound on every possible coupled
field/curve model or a proof that a compact curve replacement is impossible.

### Subtraction is the remaining coupling

Subtraction cannot be reconstructed from `s(a),s(b)` alone. For example,
`s(48)=s(47)=47` but the actual subtraction result has saturation1, not0.
Its output canonical residue `r` and the input canonical residues `a,b` give
the exact reconstruction:

```
lift = a<=46 and b<=46 and (
    s_a==47 and s_b<47
    or a<b and s_a<47 and s_b==47
)
s_out = 47 if r>=47 or lift else r
```

The lifted case requires two small canonical residues; a large canonical
operand makes a small subtraction output canonical. Equal input saturations
also guarantee a canonical subtraction output. An exactly zero right
saturation means a literal raw zero, so subtraction is identity. These facts
are source-AST proved and checked wherever lowering applies them.

`addition_carry` and `subtraction_carry` are short, readable numerical formulas
using canonical residues and lazy `s==47` observations. Their **actual loaded
ASTs**, as well as `subtraction_small_lift`, are checked against the actual
source integer primitives. The development-only proof has 15 obligations:
14 UNSAT identities and one deliberately incorrect saturation-only subtraction
rule returning SAT. Product fold checks cover arbitrary uint320 products; the
nonnegative factor transfer proof is independently split into exhaustive cases.

### Complete evaluator and independent data checks

The new catalogue keeps the already verified corrected field equations, but
discards the entire original carry/lift Boolean DAG. Positive-semiring nodes
and subtraction cuts supply the exact saturation values. The evaluator
includes all subsequent and interacting defects, uses iterative scheduling,
and retains no source program, source constant table or old tag interpreter.
Its caches are fresh for every stage. Shared field/input ordinals remain
stage-local bindings, not values shared between unrelated stages.

The separate actual-data checker first validates the supplied field-plane
witness against source using the existing independent checker. It then walks
source transfers and checks the **new actual saturation roots**, subtraction
field bindings, causal graph edges, guard operands and output bindings without
calling the new builder, lowerer, numerical evaluator or compiler constant
decoder. A stripped/missing original field-plane witness is rejected.
Certificates bind reachable equation data, so appending other stages' shared
templates cannot invalidate a previously checked stage or change its bindings.

At term budget 2, all 321 programs / 58,486 source values lower to **34,694** shared
saturation nodes: 17,312 multiplication, 10,725 addition, 6,354 subtraction
cuts, 261 canonical field caps, 37 literals and five input templates. Compared
with 407,930 shared Boolean-history nodes, this is about **91.5% fewer history
nodes**. Different node types do different work; this is not a total-storage,
byte-size or speed comparison, and the field plane is not included in it.

Permanent checks include both 2 and 256 term budgets, all 320 source branches
with 14 corner/mixed/random entry cases each, exact saturation at every source
site for two adversarial entries per branch, post-defect nonlinear interactions,
the iterative tail, mutated actual data and disabled old/source code paths.
Both full-output controls preserve all 72 destination bytes, all 161 boundaries
and complete carry traces (three public-case defects and 30 point-changing-case
defects). The primitive identities and local data validation support a stage
induction under the existing integer-to-packed source bridge; this is not a
monolithic generated-kernel/whole-pipeline SMT proof, hardware validation or
independent human review.

```
python -m tools.prove_scalar_saturated_history
python -m tools.scalar_saturated_history --max-terms 2
pytest tests/test_session_auth_scalar_saturated_history.py
```

### Further probes and the remaining research boundary

A read-only exact sparse-polynomial probe expanded all 34,694 saturation nodes
over independent input/subtraction/field-cut atoms. It found29,126 distinct
normalized saturated forms, 58,081 terms and a maximum of 56 terms, with no
fallback anchors at a 128-term budget. This suggests that complete positive
blocks can become small formulas. That probe is **not** an integrated or
independently certified polynomial lowerer; it does not remove subtraction
cuts or their field dependencies.

A separate structural-template probe found 316 different expression shapes
for the 316 intermediate branches even after anonymizing all constants and
inputs, allowing commutative operand ordering and ignoring output-slot order.
This rules out reuse of one unchanged expression-tree skeleton by merely
renaming its leaves for those programs. It is not an impossibility result for
algebraic, conditional or parameterized compact algorithms.

Before the carry-formula wrapper extraction, a three-warm-run diagnostic found
public/point-changing medians of 64.9/76.5 ms for the new saturated model, with
other tests running concurrently. All bytes matched. These are not isolated
benchmarks, not final-version performance measurements and not a production
performance claim; production is unchanged.

The addition/multiplication **representation-history abstraction is now exact
and independently understandable**. The outstanding hard part is smaller and
more explicit: simplifying the stage-specific subtraction/field cuts and
their corrected curve-coordinate effects into a small equivalent curve-level
algorithm. The ordinary two-policy recurrence still cannot replace those
effects. No mass runtime rewrite, issue closure or claim of that remaining
goal's completion follows from these results.

## Exact semantic shift macros in the fixed tail

`scalar_shift_macros.py` identifies 42 local patterns in the fixed tail:
38 add-then-subtract and four subtract-then-add patterns with the same literal
constant `47<=c<p`. None occurs in the scalar-stage programs. These apparently
canceling shifts are **not raw no-ops** and must not be deleted as ordinary
field-algebra identities.

Let `k=94-2**128` be the actual addition correction and `mu=raw%p`.
The source integer ASTs give these compact exact contracts:

```
C(raw,c) = subtract(add(raw,c),c)
beta_C  = raw+c >= 2**160 and (raw+c) % 2**128 >= 2**128-47
C(raw,c) = (mu + k*beta_C) % p                  # canonical result

L(raw,c) = add(subtract(raw,c),c)
beta_L  = mu<c and mu>=2**128 and mu%2**128<47
r       = (mu + k*beta_L) % p
L(raw,c) = r + p*(r<=46)                       # lifted small result
```

For example, `C(p+1,47)=1`, whereas `L(1,47)=p+1` and `L(0,47)=p`.
Dropping the residue correction is also wrong: there are field-changing carry
counterexamples, not only different encodings of the same residue.

The canonicalizer can depend on its incoming lift for a general constant.
However, that dependency disappears in either of these proved domains:

```
47<=c<=2**128-47
c=p-n, 1<=n<2**128-94
```

The first domain has no addition defect. In the second, its carry becomes the
field-only predicate `mu>=2**128+n and (mu-n)%2**128<47`.
Every one of the 42 recovered tail constants belongs to these domains:
`228`, or `p-n` for `n` in `1,27,87,781,1562,19200,38400`.
Thus all 42 patterns have exact replacements depending **only on the input
canonical residue**, with an explicit canonical/lifted output convention.

`prove_scalar_shift_macros.py` checks the actual carry-predicate ASTs against
composed actual source addition/subtraction ASTs for all uint160 operands and
the entire declared constant domains. Four identities are UNSAT, including
lift independence and the near-p closed carry predicate. Two deliberately
incorrect no-op/uncorrected formulas return SAT. This is a local macro proof
under the existing source-to-packed bridge, not a whole-tail or generated-kernel
proof. Tests exercise all recovered constants, exact carry boundaries, lifted
and zero representatives, random operands, rejected domains and disabled
source arithmetic calls.

The equation view is a readable decompilation annotation, for example:

```
v7 = canonical_residue_shift(mu(s5), p-27)
v11 = lifted_shift(mu(v6), p-27)
```

Other uses of each inner value must be preserved. The tool deliberately emits
annotations rather than deleting or rewriting the original source program.
It does not assert that 42 disjoint instruction pairs can all be removed: some
patterns overlap or have shared intermediate values.

```
python -m tools.prove_scalar_shift_macros
python -m tools.scalar_shift_macros --equations
pytest tests/test_session_auth_scalar_shift_macros.py
```

These are recovered, independently understandable formulas for actual
obfuscation gadgets, not another sampled reconstruction. They improve the
tail's semantics/readability and eliminate incoming lift dependence locally;
the unresolved scalar-stage curve/correction simplification remains separate.

## Universal addition cancellation and small subtraction restoration

The large-constant macros above are not the whole matching-pattern inventory.
`scalar_cancel_macros.py` recovers 61 exact `subtract(add(a,b),a)` gadgets:
60 in the fixed tail and one in the initial scalar branch. It also recovers
four tail `add(subtract(a,b),b)` gadgets with a literal `b<47`.
The following contracts cover arbitrary uint160 operands in their declared
domains, not just these constants or selected source inputs.

Write `mu_b=b%p`, `k=94-2**128`, and
`beta=(a+b>=2**160 and (a+b)%2**128>=2**128-47)`. Then:

```
subtract(add(a,b),a)
  = (mu_b+k*beta)%p + p*(a<47 and b>=p and a+mu_b<47)

add(subtract(a,b),b), for 0<=b<47
  = a%p + p*(a%p<=46 and (a>=p or a<b))
```

The first subtraction cannot introduce its own field defect. In particular,
canceling any `a>=47` forces a canonical output, while canceling a small `a`
may preserve or discard the remaining operand's small lift. Examples:
`cancel_add(45,p+1)=p+1`, but `cancel_add(46,p+1)=1`.
The small restoration is also not generally identity:
`restore_small_subtract(0,1)=p`, while `restore_small_subtract(1,1)=1`.
Both numeric macros execute their readable formulas without source arithmetic
callbacks. `prove_scalar_cancel_macros.py` proves three all-domain obligations
against the composed actual source ASTs and actual predicate ASTs; two incorrect
raw-identity rules are SAT negative controls.

Together with the four large-constant restorations above, all 69 source-local
matching add/subtract cancellation/restoration gadgets have exact contracts:
68 in the tail and one in scalar stage 0. This is a narrow, mechanically
matched syntactic inventory, not a claim that every obfuscation gadget has been
identified. Shared/overlapping inner values still prevent blanket instruction
deletion. No original program or production code is rewritten.

```
python -m tools.prove_scalar_cancel_macros
python -m tools.scalar_cancel_macros
pytest tests/test_session_auth_scalar_cancel_macros.py
```

## Caller-visible seed counterexamples with bundled public keys

Checking only Transform7's raw 72 bytes would leave a legitimate question:
does SeedTransform's Monolith1 normalization and Monolith2 zero-nonce rejection
erase the differences? `trace_scalar_seed_boundary.py` answers this at the
actual caller boundary, with fixed public/synthetic inputs and bounded loops.
It supplies exactly one PRNG1 and one selector. A request for another selector
records first-nonce rejection; it does not fabricate eventual acceptance.
Monolith1 is bounded at 32 iterations and fails closed if exceeded. All other
SeedTransform steps run their original code.

Three implementations are compared: original Transform7, the byte-exact
independent reference, and the conditional compact ordinary modular ladder.
The last deliberately retains the **exact fixed tail and encoded finalizer**;
only setup/scalar arithmetic is replaced. Thus a mismatch is not attributable
to swapping the tail for an unproved modular exponent formula.

A reproducible caller-visible counterexample uses the existing bundled key
`00:0448ACCBD5A0BFD2`, selector 0, and the constructed synthetic PRNG1:

```
978004156713030480091955929130383740779312767983
```

This nonce is not a random search hit. Let `(a,b,c)` and `d` be the recovered
affine setup candidate's slot-70 row/offset and let `C21` be the first scalar
addition's literal. Solving the unit-coefficient equation

```
r = (2**128-C21-d-a*x-b*(y|4))*c**(-1) mod p
```

gives the nonce above, with its forced bit already set. Original setup capture
agrees with the exact setup model and has **no setup merge defect**. At the
first scalar addition (tape word 30506), the raw sum is exactly `p+2**128`.
The ordinary residue is `2**128`, but the source result is **94**. This is
a field-changing defect, not merely different representatives of one point.

Both the original and modular candidate accept the first nonce. The original
and exact reference agree on every raw Transform7 byte, normalization count,
acceptance decision and all 60 seed bytes. The modular candidate changes the
seed's first 20 bytes; the final 40 bytes agree. SHA-256 checksums for the
zero-filled synthetic Transform1 input are:

```
original/reference: dc1fe5f0d18e7f7af671c39b597f2fe2b02907a82b28a64047c1829d454dc655
modular candidate:  effb442f73d880a6233309bb7f35c1ceb6ed84989a7ec766f835e5991de8e300
```

The earlier synthetic on-curve carry example likewise changes the final seed;
tests retain that control and a nonzero synthetic Transform1 input. A positive
control using bundled key `00:1B580465BB0551B2` and a constructed setup carry
has different raw Transform7 bytes but the **same** final seed. Public-generator
zero/unit-scalar controls also preserve the caller's rejection/acceptance
behavior. These distinguish actual observability from raw representation
differences; they do not assume every raw carry changes authentication output.

The bundled-key counterexample is also checked with an **actual PreSeedTransform
output**, generated from the fixed synthetic 24-byte key `bytes(range(24))`,
and through the complete original `authenticate_real_plc` blob builder. The
five entropy requests have fixed, size-checked synthetic values for key2,
key1, IV, PRNG1 and selector; unexpected retries fail instead of looping.
Original and exact-reference implementations produce the same complete
180-byte authentication blob and 24-byte derived session key. The modular
candidate changes the encrypted-seed slice at offsets 48..67, while metadata,
remaining blob bytes and session key agree. Thus the counterexample is not
dependent on feeding an unreachable all-zero Transform1 buffer to SeedTransform.

```
python -m tools.trace_scalar_seed_boundary
pytest tests/test_session_auth_scalar_seed_boundary.py
```

The bundled key and nonce are public/synthetic, not a live session capture.
No PLC exchange, firmware-specific acceptance, literal curve-coordinate
interpretation of the key bytes, or whole-pipeline SMT proof is claimed.
The result does rule out replacing this API's scalar computation with the
uncorrected ordinary ladder, even if normalization and retry remain intact.
Recovering a compact stage-independent **corrected** curve algorithm remains
open; the exact saturated-history model and local gadget contracts do not
silently solve that separate problem.

An additional cross-language check is preserved in
[`csharp_scalar_boundary/README.md`](csharp_scalar_boundary/README.md). The
unmodified HarpoS7 Family0/Utilities sources at
`b4ba7fab14bcca4274e69a4d6524a5a61fcd329d` were compiled with the local .NET
10.0.401 SDK/10.0.12 runtime and already cached CommunityToolkit.HighPerformance
8.2.2 DLL. Restore had no remote package sources or new dependencies. The
retargeted build is not the original .NET 8 binary. Its two original Transform7
72-byte checksums, both normalization counts (2), actual PreSeed checksum and
final 60-byte seed checksum match original Python and the exact reference.
The final seed checksum is
`f1c44e2fbf2c8271d45f05e5690ebade88692c7380c9af438fcedfebd79bcc8a`.
The harness invokes original C# monoliths in the source seed call order with
fixed entropy and bounded normalization, rather than calling the random
`SeedTransform.Execute` entry point. This confirms the observed carry case in
the pinned upstream implementation; it is still a selected-input execution
check, not an all-input proof, independent human review or hardware validation.

## Exact conditions for algebraic factoring and reassociation

The saturated-history result provides a useful rewrite criterion, beyond
compressing history data. The residue/saturation pair is injective, and
saturation is an exact homomorphism for source addition and multiplication.
Consequently two add/multiply expressions with the same nonnegative formal
polynomial over the same **raw** inputs have the same saturation, even if their
field residues differ because of addition defects. Raw equality then reduces
to checking their corrected field equality. Literal constants retain their
actual nonnegative values in this saturation argument; reducing them modulo p,
using negative coefficients or treating subtraction as saturated addition
would invalidate it.

For three arbitrary raw uint160 operands, let `A` and `M` denote exact source
addition/multiplication and let
`beta(a,b)=(a+b>=2**160 and (a+b)%2**128>=2**128-47)`. Since
`gcd(94-2**128,p)=1`, the primitive contracts give these exact laws:

```
M(M(a,b),c) = M(a,M(b,c))                         # unconditional

A(A(a,b),c) = A(a,A(b,c)) iff
  beta(a,b)+beta(A(a,b),c) = beta(b,c)+beta(a,A(b,c))

M(a,A(b,c)) = A(M(a,b),M(a,c)) iff
  (a%p)*beta(b,c) % p = beta(M(a,b),M(a,c))
```

Addition can therefore be reassociated only when its actual carry counts
balance. Under multiplication, the defects must balance **with the factor's
field weight**, not merely have the same count. For example, with
`b=p-100` and `c=2**128+100`, both sides distribute exactly for `a=p`, `a=1`
and `a=p+1`. For `a=2`, both addition predicates are true but the raw outputs
differ. This is why indiscriminate ring factoring changes the open code, even
when the transformation looks algebraically harmless.

These are compositional algebraic consequences of the existing all-domain
primitive contracts and the proved saturation quotient, not an additional
whole-expression SMT certificate. The finite 48-state semiring's three laws
are exhaustively checked. Raw numerical controls exercise the exact
if-and-only-if conditions, unconditional multiplication associativity, lifted
zeros/ones and deliberately constructed carry corners:

```
pytest tests/test_session_auth_scalar_semiring_rewrites.py
```

This supplies precise proof obligations for a later mass rewrite. It does not
establish those obligations for all proposed scalar-stage factoring rules or
remove the remaining source-specific carry predicates.
