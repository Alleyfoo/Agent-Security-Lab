# Cases

One security concept per case. One central claim per case that can pass or
fail independently of every other case.

---

## Case contract

Write this **before** any code. A case that starts with an implementation
instead of a contract is rejected.

```text
Threat                 Who is assumed hostile, and what they already control.
Existing assumption    The belief this case tests.
Attack                 The concrete executable path.
Observed unsafe result What happens without the control (must be demonstrated).
Control                The mechanism, located outside the compromised component.
Observed protected     What happens with the control.
Residual limitation    What is still possible afterwards.
Containment response   The deterministic reaction, from the ladder's table.
Recovery requirement   What an operator must do to return to a trusted state.
```

## Required contents

Every case directory holds:

* `README.md` — the contract above, plus the mandatory framing:

  ```text
  What this proves
  What this does not prove
  ```

* one executable attack (runnable standalone, so a reader can watch it work);
* one automated adversarial test under `tests/adversarial/`;
* one expected result, asserted rather than printed;
* one statement of remaining limitations;
* visible evidence in the UI or the generated report.

## Adversarial-test-first rule

The order is not negotiable:

1. Write the hostile test and **prove the attack succeeds** against the current
   code. A control whose attack was never demonstrated is unfalsifiable.
2. Implement the control outside the compromised component.
3. Prove the same attack now fails, **for a specific, observable reason** —
   assert on the denial reason, not merely on "an exception was raised".

## Acceptance criteria

A case is complete only when all ten hold:

1. The threat is clearly documented.
2. The attacker's starting authority is stated.
3. The unsafe behaviour is reproducible.
4. The control exists outside the compromised component.
5. The attack is blocked or detected as claimed.
6. The result is visible in an automated test.
7. The result is visible in the demo or report.
8. The remaining limitation is documented.
9. The containment response is deterministic.
10. The affected blast radius can be explained.

> A passing test alone is not enough if the security claim is vague.

## Planned cases

## Current scope — agent confinement only

Per manager direction, only the first research question is in scope:

> Can an agent be restricted to its assigned function when it is manipulated,
> malicious, or fully captured?

Deferred, and explicitly **not** allowed to influence current slices unless
required to expose or enforce the agent boundary: production customer-service
architecture, multiple-LLM topology, external logging design, information-flow
control, capability signing, orchestrator compromise, full deployment
architecture. They remain documented future questions below.

## In-process cases

Numbering is stable once created. Cases 03–05 were renumbered from the original
charter list when the scope narrowed to confinement.

| Case | Phase | Baseline finding | Central claim |
|---|---|---|---|
| [`00-receipt-handle`](00-receipt-handle/README.md) ✅ | 2 | L7 | The component being audited must not be able to edit the evidence it is audited against |
| [`01-ungranted-read`](01-ungranted-read/README.md) ⚠️ | 2 | L1, L2 | A scoped view constrains interface access but not same-process reach-around, and the bypass is invisible in the read log |
| [`02-artifact-mutation`](02-artifact-mutation/README.md) ✅ | 2 | L3 | In-place mutation creates no new key, so the store diff is blind to it; hash verification detects it |
| [`03-mutable-route-table`](03-mutable-route-table/README.md) ✅ | 2 | L6 | Routing data must not be mutable from the namespace the routed code runs in |
| [`04-forged-runner-event`](04-forged-runner-event/README.md) ✅ | 2 | L4 | Audit-record corruption and authorization corruption are separate effects and must be measured separately |
| [`05-false-verdict`](05-false-verdict/README.md) ✅ | 2 | case 00 residual | A conclusion an agent authors is not evidence; the runner must derive the mechanical verdict itself |
| [`07-poisoned-chain`](07-poisoned-chain/README.md) ✅ | 2 | case 06 finding | Checks that compare derived artifacts to each other are laundered by an honest downstream stage; one must look back at the source |

Every case above is recorded in the canonical registry
([`registry.py`](registry.py)) and rendered in [`REPORT.md`](REPORT.md). Case 04
is registered as two entries — `case-04a` for the record, `case-04b` for the
decision — because they have different results and one row would hide which
effect actually changed a decision.

## Transition gate to process isolation

Phase 5 does not begin until the in-process cases establish which interface
controls genuinely work, which attacks remain possible through shared memory,
which unauthorized writes can be detected, which unauthorized reads remain
invisible, which runner-owned structures agents can affect, which conclusions
remain agent-authored, and which evidence remains trustworthy.

`REPORT.md` maintains that map. **All seven entries are now answered**, so the
gate is met and the transition statement is earned:

> The remaining attacks cannot be closed honestly while agent and trusted
> infrastructure share a Python process. The next control changes the trust
> boundary rather than hiding references inside the same boundary.

The evidence is specific: case 01 is wholly open with no in-process control
available, and every closed case's residual has the same shape — the reference
value sits inside the adversary's reach (cases 02, 03, 04a and 05). One
problem, not four.

Meeting the gate authorizes Phase 5 to *begin*; it settles nothing about what
process isolation buys. Case 06's initial claim must stay narrow — a separate
process prevents direct inspection and modification of the runner's Python
memory and object graph — and must not imply filesystem confinement, network
confinement, host isolation, capability security, correctness of permitted
output, or resistance to OS compromise. Each of those is measured separately or
not claimed.

## Phase 5 cases

| Case | Phase | Central claim |
|---|---|---|
| [`06-process-isolation`](06-process-isolation/README.md) ✅ | 5 | A stage in a separate interpreter cannot reach the runner's memory — and that is all it cannot do |

## Phase 3 cases

| Case | Phase | Central claim |
|---|---|---|
| [`08-derived-authority`](08-derived-authority/README.md) ⚠️ | 3 | Comparison: a stored per-stage grant against a grant derived at use time. Measures minimum tamper set, authority, scope and persistence — it does not apply a control |
| `09-skill-registry` | 3 | Can the execution plane create, modify, replace or select an unapproved skill definition? |

Case 08 is registered ⚠️ because it changes nothing in the product. Both arms
are measured as they are, and the named capability is obtainable in both — so
its baseline and controlled results are identical by construction, which is
what an honest comparison looks like in this registry.

## Deferred — out of current scope

Documented so they are not forgotten, and not to be started while the
confinement question is open.

| Case | Phase | Question |
|---|---|---|
| `07-host-compromise` | 5 | Co-tenancy is not a trust zone |
| `08-capability-replay` | 3 | A grant with no workflow, audience, expiry or use count is replayable |
| `09-confused-deputy` | 4 | Holding authority is not proof that a request to use it is legitimate |
| `10-information-flow` | 6 | A chain of individually valid steps can be a forbidden flow |
| `11-audit-tampering` | 7 | Append-only-by-API is not tamper-evident |
| `12-orchestrator-compromise` | 5 | The orchestrator must not be able to declassify unilaterally |
| `13-provenance-quarantine` | 8 | After a producer is declared compromised, dependent outputs are identifiable |

Legend: ✅ control implemented and attack blocked · ⚠️ open finding, control
deferred to a later phase.

## Cases without a control at their own phase

Some findings have no in-process answer. Case 01 is the first: its control is
process isolation in Phase 5, so it cannot satisfy acceptance criteria 4 and 5
today.

Such a case is still written in full — contract, executable attack, adversarial
tests — but its tests assert the attack **succeeds**, and carry a `TRIPWIRE`
message naming the phase that should break them. When the control lands the
tests fail, and that failure is the instruction to rewrite the case.

Two rules apply to these:

* **Never relax a tripwire test to make a suite green.** Fix the case or fix
  the control.
* **Never ship a partial fix that closes one path of a class.** Case 01
  documents a refused patch (`ClosureStoreView`) for exactly this reason. If a
  patch would let the repository describe a boundary it does not have, it is
  cosmetic security regardless of how much code it contains.

## Sequencing rule

Do not start a later phase while an earlier phase's security claim remains
ambiguous or untested. Do not combine unrelated security concepts into one
implementation slice.

## Before modifying security infrastructure

1. Identify the existing tests that cover it.
2. Add regression guards.
3. Confirm the baseline behaviour still holds.
4. Preserve existing passing cases unless the change intentionally replaces
   them — and say so if it does.

The 72 tests at `v0-baseline-inprocess` are the regression floor. A slice that
reduces that count must explain which test it replaced and why.
