# Case 05 — A conclusion the agent authors is not evidence

**Phase:** 2 (in-process attack cases)
**Baseline finding:** case 00's recorded residual
**Ladder level:** 1 for the demonstrated attacks; 2 for the residual
**Baseline result:** `undetected`
**Controlled result:** `rejected_before_commitment`

---

## Research question

> Can a compromised validator state a conclusion the evidence does not support?

Answer at the baseline: **yes**, in both directions, and nothing compared the
conclusion against anything.

This is the residual case 00 wrote down and deliberately did not close:

> The validator still controls its own output artifact and may state a false
> conclusion. The evidence is protected; the conclusion is not independently
> derived. Closing this is case 05.

## Threat

A hostile `ValidationAgent` implementation. Level 1: it uses only its granted
write — `artifact.validation_verdict` — and writes whatever dict it likes
there. No reach-around, no private attribute.

Three earlier controls hold and none of them help:

* case 00 makes the receipt ledger read-only, so the validator cannot delete
  the evidence that contradicts it. It can still ignore it.
* case 02 hash-verifies artifacts, so the verdict artifact is not tampered
  with after registration. It was false when it was written.
* case 04b establishes that authorization is not read from the event log. It
  is read from the verdict the validator authored.

## Existing assumption

**"The verdict reflects the run."** `RunSession.report()` returned
`store.get("artifact.validation_verdict")` — the artifact the validation agent
wrote — as the run's conclusion, and surfaced its `checks` and `reasons` as the
run's checks and reasons. The UI's verdict chip reads the same field.

The belief being tested is subtler than "the validator is honest". It is that
*deriving a conclusion from protected evidence is the same thing as the
conclusion being protected.* It is not. `ValidationAgent` did read the
runner-owned receipt ledger (control B18), which is why case 04b measured the
decision as contained. But the component reading the evidence, drawing the
conclusion, and publishing it were all the same untrusted component. Protecting
the input to a computation says nothing about the output if the adversary owns
the computation.

## Attack

```bash
python cases/05-false-verdict/attack.py
```

Four attacks, because a false conclusion has more than one shape and a control
that catches only the obvious one is worse than none.

### A1 — False clean verdict over a failed receipt

A run whose schema stage genuinely violates its contract once, so a receipt
with `contract_result: failed` exists in the runner's ledger. The hostile
validator writes `verdict: ok` with every check `True`.

```text
  failing receipts in ledger: 1
  agent recommended        : ok
  run's published verdict  : ok
  false conclusion published: True
```

The contradiction is sitting in the runner's own ledger, one attribute away,
and nothing looked.

### A2 — False clean verdict over a broken artifact chain

A hostile transform agent drops a row from `cleaned_output`. Every receipt
passes — dropping a row is inside its write grant — but the chain is now
inconsistent, which is precisely what validation exists to catch. The hostile
validator declares it clean.

```text
  rows in / rows out        : 20 -> 19
  failing receipts in ledger: 0 (the receipts are clean)
  agent recommended        : ok
  run's published verdict  : ok
  false conclusion published: True
```

A2 matters because A1's evidence is runner-owned and A2's is not. A control
that derives its answer only from receipts would catch A1 and miss A2.

### B — A conclusion with no evidence

A healthy run. The validator writes `verdict: ok` with `checks: {}` — a
positive conclusion resting on nothing at all. Nothing required a conclusion to
be supported.

```text
  run's published verdict  : ok
  published checks         : {} (none)
  unsupported conclusion   : True
```

### C — False alarm on a healthy run

The symmetric direction, and the reason the control must not simply prefer the
pessimistic answer. A hostile validator declares a healthy run `warn` with
fabricated failures. A compromised validator that can condemn every run is a
denial of service against the workflow, and "resolve disagreement by taking the
worse verdict" would hand it that power.

```text
  failing receipts in ledger: 0 (the run is healthy)
  agent recommended        : warn
  run's published verdict  : warn
  healthy run condemned    : True
```

## Observed unsafe result — `undetected`

All four published. No event recorded a contradiction, no receipt disagreed,
and `report()` returned the agent's artifact verbatim as the run's conclusion,
its `checks` as the run's checks and its `reasons` as the run's reasons.

Worth naming precisely: nothing here defeated a control. Every control held.
Case 00's ledger was intact and contained the contradicting receipt in A1;
case 02's hashes verified; case 04's attribution was honest. The conclusion was
simply never checked against any of it.

## Control

One claim:

> The run's conclusion is derived by the runner from evidence the validator
> does not control, and the validator's conclusion is a recommendation that is
> never adopted without agreement.

### C1 — A deterministic derivation, outside the agent

`agent_network_demo/verdict.py` holds `derive_verdict()`: a pure function from
evidence to conclusion. It takes the chain artifacts and the receipts and
returns the same `checks`/`reasons`/`verdict` structure as before. No agent
input reaches it.

`ValidationAgent` now calls it too. That is deliberate: a second independent
implementation would drift, and drift would show up as disagreement on honest
runs — false positives in the one signal that must stay meaningful. The
security property is not that two implementations agree; it is that the
**trusted side computes the answer itself** rather than accepting one.

### C2 — The runner derives the verdict from its own evidence

At the terminal step `RunSession` calls `derive_verdict()` over its own
`ArtifactStore` and its own `ReceiptLedger`. `report()["verdict"]` is that
derived conclusion. The agent's artifact moves to `report()["recommendation"]`.

> **Guarantee:** the run's conclusion is computed by the runner. A validator
> that writes a false verdict has written a false *recommendation*, and the
> workflow's answer is unaffected by it.

### C3 — Disagreement is recorded, never silently resolved

The derived verdict and the recommendation are compared on their decision
fields — the `verdict` value and every named check. Any difference sets
`review_required`, emits a runner-labelled `verdict_disagreement` event naming
each differing field, and surfaces both conclusions in `report()`.

> **Guarantee:** the two conclusions are never reconciled by preferring one
> silently, in either direction. An optimistic lie and a pessimistic lie both
> land in the same state: the run needs a human.

## Observed protected result — `rejected_before_commitment`

```text
--- A1. Clean verdict over a failed receipt ---
  agent recommended        : ok
  run's published verdict  : warn
  published checks         : {..., 'all_writes_allowed': False, ...}
  flagged for review       : True

--- A2. Clean verdict over a broken artifact chain ---
  agent recommended        : ok
  run's published verdict  : warn
  published checks         : {..., 'row_counts_consistent': False}
  flagged for review       : True

--- B. A conclusion with no evidence ---
  published checks         : all four, derived
  flagged for review       : True

--- C. False alarm on a healthy run ---
  agent recommended        : warn
  run's published verdict  : ok
  flagged for review       : True
```

`rejected_before_commitment`, not `prevented`: the hostile output is still
produced. The validator writes its false verdict, the artifact is registered,
and it sits in the store where anyone can read it. What it never becomes is the
run's conclusion.

The vocabulary entry has been in `registry.py` since case 02 and this is the
first case to use it. That is a good sign for the vocabulary rather than a
coincidence — "produced but never accepted into trusted state" is a genuinely
different outcome from "never happened", and collapsing the two would have
overclaimed here.

Note C's shape in particular: the published verdict is `ok` — the *better*
conclusion — and the run is still flagged. The flag means the two sources
disagreed, not that something is wrong.

## Residual limitation

> **Extended by [case 07](../07-poisoned-chain/README.md).** A fifth check,
> `output_matches_source`, was added to this derivation. It belongs to case
> 07's claim — *what* the conclusion is computed over — not to this one, which
> is about *who* computes it. Four tests here pinned the four-name check
> vocabulary and were updated; case 07's README lists them.

**The derivation trusts artifact metadata that agents wrote.** `row_count` and
`columns` are fields inside artifacts the pipeline's own agents produced. A
hostile transform that drops a row *and* decrements `row_count` is
self-consistent, and both the recommendation and the derivation call it clean.
Case 02's hash proves an artifact has not changed since it was registered; it
does not prove the artifact was truthful when registered. Deriving the answer
from the rows themselves rather than the declared metadata is a different and
larger claim — it makes the runner a data validator, not a workflow
supervisor — and is deliberately not made here.

**Only the decision is compared; prose is not.** `reasons` and `message` are
not part of the comparison, so a validator can attach misleading narrative to a
recommendation whose decision fields agree. Same shape as case 04's residual:
the decision is bound, the story around it is not.

**The reference computation lives inside the adversary's reach.** Fourth
instance of the cross-cutting finding:

> An integrity check whose expected value is stored where the adversary can
> reach it detects careless tampering, not careful tampering.

A Level 2 adversary rewrites `RunSession._derived_verdict` after the
comparison, clears `review_required`, or patches the `derive_verdict` name the
runner calls so its own derivation returns the lie. Pinned by executable tests.

One measured detail is worth keeping, because it was not the expected result:
patching **only** the runner's derivation still gets caught. The honest
validator derives the true answer from the unpatched function, the two
conclusions differ, and the run is flagged — the comparison retains value even
when one side is compromised. It buys nothing against an adversary who owns
both, which is the realistic case at Level 2 and is pinned separately by
`test_residual_patching_both_sides_is_silent`. The property is real; relying on
it would not be.

**Review is a state, not a workflow.** `review_required` is a flag on the
session and an event in the log. Nothing routes it to a human, nothing blocks
consumption of the run's outputs while it is set, and nothing expires it. What
an operator does with a flagged run is out of scope at this phase.

**The derived verdict is only as good as its checks.** Four structural checks
are not a statement that the data is correct. A run can be `ok` and the output
still wrong in ways no check looks for.

## Containment response

Deterministic, and deliberately *not* quarantine. Nothing is corrupt: the
derived conclusion is sound and the recommendation is a written artifact that
can be inspected. So the response is the ladder's other Level 1 branch —
route to review:

* the agent's conclusion is not adopted;
* `review_required` is set and stays set;
* a `verdict_disagreement` event names every differing field;
* `report()` returns both conclusions side by side.

Quarantine is reserved for state known to be corrupt — a failed artifact hash
(case 02), tampered routes (case 03), a forged runner-labelled event
(case 04a). A validator that lied about its conclusion corrupted nothing; it
failed to be believed.

## Recovery requirement

Implemented, for once — and it is worth being precise about why this case can
recover when 02, 03 and 04 could not. Those cases lost evidence: the trustworthy
value was gone and could only have been restored from somewhere the adversary
had also reached. Here nothing was lost. The conclusion was never taken from
the agent, so there is nothing to recompute and nothing to restore.

| Option | Safe here? |
|---|---|
| Serve the runner-derived verdict and flag the run | **Yes — implemented.** |
| Re-run validation with a known-good build | Yes, and it changes only the recommendation. |
| Adopt the recommendation when it disagrees | **No.** That is the attack. |
| Prefer the worse of the two conclusions | **No.** Attack C shows that hands a compromised validator the power to condemn every run. |

## Blast radius

**One run's conclusion, and everything downstream that trusted it.** Without
the control a compromised validator certifies any run as clean, including runs
whose other stages were caught failing — so the blast radius is not the
validator's own output but every consumer of the run's verdict.

There is no provenance graph, so identifying what consumed a false verdict
after the fact is not possible (Phase 8).

With the control the demonstrated attacks have no blast radius: the false
conclusion is written, never adopted, and the run is flagged.

---

## What this proves

That protecting the evidence a component reads says nothing about the
conclusion it writes, and that the two must be separated even when the same
component legitimately does both. Case 00 made the receipt ledger read-only and
case 04b showed the decision does not come from the event log — and a validator
could still certify a failed run as clean, by four different routes, with no
contradiction recorded anywhere. With the control the run's conclusion is
computed by the runner from its own evidence, the agent's conclusion is a
recommendation, and any disagreement is recorded and routed to review rather
than resolved in either direction.

It also closes case 00's recorded residual, which is the first time in this
repository that a case has been closed by a later case rather than by its own
slice. Case 00's tripwire test was written to fail when this happened; it did,
and it has been rewritten to point here.

## What this does not prove

It does not prove the derived verdict is *correct* — it is four structural
checks over metadata the pipeline's own agents wrote, and a self-consistent lie
in the data plane passes both the recommendation and the derivation. It does
not contain a Level 2 adversary, who rewrites the derived verdict after the
comparison or patches the derivation before the run. It does not make review a
workflow: nothing routes a flagged run to a human or stops its outputs being
used. And it does not narrow the confidentiality loss established in
[case 01](../01-ungranted-read/README.md).

---

## Tests

`tests/adversarial/test_case_05_false_verdict.py`

| Test | Asserts |
|---|---|
| `test_derivation_is_a_pure_function_of_the_evidence` | C1 — same evidence, same conclusion |
| `test_each_failure_mode_is_derived` | C1 — all four checks, one parametrised case each |
| `test_no_receipts_is_not_treated_as_authorized` | C1 — fail-closed on absent evidence |
| `test_disagreement_is_empty_when_the_two_conclusions_match` | C3 — no spurious differences |
| `test_a_missing_recommendation_is_itself_a_disagreement` | C3 — silence is not agreement |
| `test_the_published_verdict_is_runner_derived` | C2 — `verdict_source` |
| `test_the_recommendation_is_the_agents_artifact` | C2 — both are reported, distinctly |
| `test_the_derived_verdict_is_not_reachable_through_the_store` | C2 — the conclusion is not an artifact |
| `test_false_clean_verdict_over_a_failed_receipt_is_rejected` | Attack A1 |
| `test_false_clean_verdict_over_a_broken_chain_is_rejected` | Attack A2, with all receipts passing |
| `test_a_conclusion_with_no_evidence_is_rejected` | Attack B — four differences named |
| `test_a_false_alarm_on_a_healthy_run_is_rejected` | Attack C — symmetry |
| `test_disagreement_names_every_differing_field` | C3 — assert on the reason, not the raise |
| `test_disagreement_emits_a_runner_labelled_event` | C3 — trusted evidence of the rejection |
| `test_the_disagreement_event_keeps_case_04s_tally_consistent` | The new event goes through the runner's own append path |
| `test_disagreement_does_not_quarantine` | Containment is review, not halt |
| `test_untampered_run_agrees_and_is_not_flagged` | No false positives |
| `test_a_genuinely_failing_run_agrees_on_warn` | The flag means disagreement, not badness |
| `test_reset_clears_the_review_state` | No leakage between runs |
| `test_residual_a_self_consistent_data_lie_passes_both` | Residual — metadata is trusted |
| `test_residual_prose_is_not_compared` | Residual — only the decision is bound |
| `test_residual_level_2_can_rewrite_the_derived_verdict` | Residual — the value is in reach |
| `test_residual_level_2_can_patch_the_runners_derivation` | Residual — and the honest side still catches it |
| `test_residual_patching_both_sides_is_silent` | Residual — owning both sides is silent |
