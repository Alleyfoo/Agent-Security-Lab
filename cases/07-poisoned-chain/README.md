# Case 07 — Corrupting downstream artifacts through your own

**Phase:** 2 (in-process attack case; the finding surfaced during Phase 5)
**Baseline finding:** discovered while measuring
[case 06](../06-process-isolation/README.md)
**Ladder level:** 1 — a hostile agent implementation writing inside its grant
**Baseline result:** `undetected`
**Controlled result:** `detected_after_occurrence`

---

## Research question

> Can a stage corrupt every downstream artifact by corrupting only its own?

Answer at the baseline: **yes**, and the run certifies itself clean while it
happens.

## Threat

A hostile schema agent. Level 1, and unusually cheap even by that standard: it
writes one well-formed artifact to the key it was granted. No reach-around, no
private attribute, no protocol abuse. Every control in the repository holds
throughout — the receipt ledger is intact, the hashes verify, the attribution
is honest, the routing table is pinned, the verdict is runner-derived.

The next stage is **not** hostile. It is the ordinary `TransformAgent`, doing
its job correctly. That is the mechanism: the honest stage does what it is
supposed to do with the input it is given, and the input is a lie.

## Existing assumption

**"The runner derives the conclusion from its own evidence, so the conclusion
is sound."** That is [case 05](../05-false-verdict/README.md)'s claim and it
holds. What this case tests is a different sentence hiding inside it: that the
*evidence* covers the thing the conclusion is about.

The four derived checks are:

```text
chain_complete          every expected artifact exists
all_writes_allowed      every receipt passed
schema_matches_output   schema.columns == cleaned.columns
row_counts_consistent   raw.row_count == cleaned.row_count
```

Three of the four compare **derived artifacts to each other**. The fourth
compares a single scalar back to the source. Nothing compares the *content
shape* of the output to the artifact the chain started from.

So a poisoned upstream stage is laundered by an honest downstream one into a
chain that is internally consistent in every way the runner looks at. The lie
becomes the standard the rest of the run is measured against.

## Attack

```bash
python cases/07-poisoned-chain/attack.py
```

Three attacks, all through the same one-key write, plus a fourth measurement
that is not an attack at all.

### A — Fabricated schema

The schema profile declares `columns: ["fabricated"]`. The transform builds the
cleaned output from that schema.

```text
  source columns  : ['Order ID', 'Customer', 'Date', 'Total']
  output columns  : ['fabricated']
  first output row: {'fabricated': None}
  verdict         : ok    failing checks: none
```

Every column of real data gone, twenty rows of `None`, certified clean.

### B — Dropped column

The schema omits one column — here `Total`, the money field. Structurally the
subtlest and operationally the worst: the output is well-formed, plausible, and
missing an amount.

```text
  source columns  : ['Order ID', 'Customer', 'Date', 'Total']
  output columns  : ['Order ID', 'Customer', 'Date']
  first output row: {'Order ID': '1001', 'Customer': 'Alice Tan', 'Date': '2026-01-03'}
  verdict         : ok    failing checks: none
```

The output is well-formed, plausible, and missing the money. Row counts still
agree — twenty rows in, twenty rows out — so the one check that does look back
at the source sees nothing wrong, because it compares a scalar.

### C — Renamed column

The schema declares `Totl`. The transform looks up a field that does not exist
in the source rows and writes `None` for every one of them. The column is
present, correctly typed, and empty.

```text
  output columns  : ['Order ID', 'Customer', 'Date', 'Totl']
  first output row: {'Order ID': '1001', ..., 'Totl': None}
  columns that are entirely None: ['Totl']
  verdict         : ok    failing checks: none
```

Four columns in, four columns out, correct row count. One of them is empty.

### D — What the honest pipeline already does

Not an attack. A measurement of a clean run, included because a case about
data fidelity that ignored the baseline's own fidelity would be dishonest.

```text
  source first row: {'Order ID': '1001', ..., 'Total': '42.50'}
  output first row: {'Order ID': 1001,   ..., 'Total': 42.5}
    Order ID: '1001' -> 1001
    Total:    '42.50' -> 42.5
  verdict         : ok
```

No agent is hostile. The schema stage infers `integer` for a column of digit
strings and the transform coerces it, which is the pipeline working as
designed. `"1001"` is an identifier; `1001` is a number that happens to have
the same digits. This is the concept note's §9 sitting in the fixture, and
**no check in this case catches it** — every column matches and no check looks
at a value.

## Observed unsafe result — `undetected`

All three attacks certified clean. No receipt recorded an anomaly, no hash
failed, no attribution was forged, and the verdict was derived by the runner
from its own evidence exactly as case 05 requires. The evidence simply did not
cover the question.

Worth stating plainly, because it is the uncomfortable part: **every control in
the repository held, and the data was destroyed anyway.**

## Control

One claim:

> The run's derived conclusion compares the output's content shape back to the
> source artifact, not only to other derived artifacts.

### C1 — `output_matches_source`

A fifth check in `derive_verdict()`: the cleaned output's columns must equal
the source artifact's columns, in order. A mismatch names what was added and
what went missing.

> **Guarantee:** a downstream artifact whose column set diverges from the
> artifact the chain started from is detected before the run is certified,
> whichever stage caused the divergence and whether or not it was hostile.

**This extends case 05's control rather than adding a separate mechanism, and
that is a deliberate choice with a cost.** Case 05's claim was *who computes
the conclusion*; this case's claim is *what the conclusion is computed over*.
They share an implementation because a second derivation would drift, for the
reason case 05 already recorded. The cost is that case 05's tests pinned a
four-check vocabulary and had to be updated — see *Tests changed elsewhere*.

## Observed protected result — `detected_after_occurrence`

```text
  A: verdict warn   failing checks: ['output_matches_source']
     output columns do not match the source:
       missing ['Order ID', 'Customer', 'Date', 'Total'], added ['fabricated']
  B: verdict warn   missing ['Total'], added []
  C: verdict warn   missing ['Total'], added ['Totl']
  D: verdict ok     (the honest run is unaffected)
```

`detected_after_occurrence`, not `prevented`. The corrupt artifacts are written
and stay written — nothing stops a stage writing whatever it likes to the key
it was granted, and a control that tried would have to understand the data.
What changes is that the run stops certifying them.

Note that `review_required` stays **false** in all three. The validation agent
is honest here, so it derives the same `warn` the runner does; there is no
disagreement to flag. The two signals mean different things and this case is a
good demonstration of it: `warn` says the chain is wrong, `review_required`
says the validator and the runner disagree about whether it is.

## Residual limitation

**Structure is compared; values are not.** A stage that keeps every column name
and mistypes them all passes: declaring the money column `integer` truncates
`"42.50"` to `42` for every row, the shape is intact, and the check is
satisfied. Worse, the damage is selective — text columns survive, because a
coercion that fails leaves the value alone — so the output looks mostly fine.

**Identifier fidelity is lost on the honest path**, per measurement D, and
nothing here addresses it. Closing that needs the canonical artifact to carry
field semantics, so that "identifier" is a fact about the data rather than a
guess made from its shape. That is the concept note's §3 and §9, it is a
different and larger claim, and it should not be smuggled in as a fifth check.

**Only the raw→cleaned pair is compared.** The schema profile itself is checked
only against the cleaned output. A chain with more stages would need this
stated per hop, and the current check would not generalise for free.

**The runner still does not know what the data means.** Four structural checks
plus one shape comparison is not a statement that the output is correct.

## Containment response

The run completes and reports `warn` with the divergence named. No quarantine:
nothing is corrupt in the sense cases 02–04 use the word — the artifacts are
exactly what their producer wrote and their hashes verify. The workflow's own
conclusion is the containment.

Deliberately *not* halting mid-run. The check needs both ends of the chain, so
it can only run once the cleaned output exists, by which point the stages have
all acted. A mid-run variant would need each stage's output compared to the
source as it is written, which is a different design.

## Recovery requirement

Re-run from intake with a known-good schema stage. The source artifact is
untouched and hash-verified throughout — this is the case where the immutable
canonical artifact earns its keep, since the thing to recover *from* is
provably the thing the run started with.

## Blast radius

**Every artifact downstream of the poisoned one**, which here is all of them:
the cleaned output and the verdict that certified it. Anything that consumed
the output of an affected run consumed the corruption, and there is no
provenance graph to identify what did (Phase 8).

The radius is bounded by the run — the source artifact is untouched, and the
poison does not persist into later runs the way case 03's route tampering did.

## Tests changed elsewhere

Per `cases/README.md`, a slice that changes existing security infrastructure
says which tests it replaced and why.

| Test | Change |
|---|---|
| `test_case_05::test_derivation_is_a_pure_function_of_the_evidence` | Pinned a four-name check vocabulary. `ALL_PASSED` is now derived from `verdict.CHECKS`, so a future case adding a check does not leave it asserting a stale set. |
| `test_case_05::test_a_conclusion_with_no_evidence_is_rejected` | Asserted exactly 4 named differences; now `len(CHECKS)`. |
| `test_case_05::test_residual_prose_is_not_compared` | Its hostile validator claimed the old four checks, which now reads as a real disagreement. Fixed by the `ALL_PASSED` change. |
| `test_case_06::test_finding_a_poisoned_upstream_stage_launders_into_a_consistent_chain` | The tripwire this case exists to trip. Rewritten as `test_a_poisoned_upstream_stage_is_caught_across_the_boundary`. |

No test was weakened. The first three pinned an implementation detail of case
05's control rather than its claim, which is why they broke; case 05's actual
claims are untouched and still pass.

---

## What this proves

That deriving a conclusion from trustworthy evidence is not enough if the
evidence only describes derived state. Three of case 05's four checks compared
artifacts the pipeline produced against each other, so an honest downstream
stage laundered a poisoned upstream artifact into a chain that agreed with
itself — and the lie became the standard everything after it was measured
against. One comparison back to the source artifact detects all three
demonstrated attacks, and leaves the honest run alone.

It also shows how cheap this class of attack is. No control was defeated. A
single well-formed write to a granted key, by a Level 1 adversary, destroyed
every column of a dataset while the receipt ledger, the hashes, the routing
table, the attribution binding and the runner-derived verdict all held.

## What this does not prove

It does not prove the output is correct — the check compares column shape, and
the residual tests show a mistyped schema silently truncating money while
passing. It does not address the fidelity loss the honest pipeline already
causes, which is measured here and left open. It does not generalise to a
longer chain, since only the raw→cleaned pair is compared. And it prevents
nothing: the corrupt artifacts are written, and detection happens once the
chain is complete.

---

## Tests

`tests/adversarial/test_case_07_poisoned_chain.py`
