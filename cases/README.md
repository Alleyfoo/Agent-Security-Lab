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
| `04-forged-runner-event` | 2 | L4 | Audit-record corruption and authorization corruption are separate effects and must be measured separately |
| `05-false-verdict` | 2 | case 00 residual | A conclusion an agent authors is not evidence; the runner must derive the mechanical verdict itself |

Cases 00, 01 and 02 are recorded in the canonical registry
([`registry.py`](registry.py)) and rendered in [`REPORT.md`](REPORT.md).

## Transition gate to process isolation

Phase 5 does not begin until the in-process cases establish which interface
controls genuinely work, which attacks remain possible through shared memory,
which unauthorized writes can be detected, which unauthorized reads remain
invisible, which runner-owned structures agents can affect, which conclusions
remain agent-authored, and which evidence remains trustworthy.

`REPORT.md` maintains that map. Cases 03, 04 and 05 are the remaining entries.

The transition statement, when it is earned:

> The remaining attacks cannot be closed honestly while agent and trusted
> infrastructure share a Python process. The next control changes the trust
> boundary rather than hiding references inside the same boundary.

## Deferred — out of current scope

Documented so they are not forgotten, and not to be started while the
confinement question is open.

| Case | Phase | Question |
|---|---|---|
| `06-agent-process-compromise` | 5 | What process separation actually buys, measured rather than asserted |
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
