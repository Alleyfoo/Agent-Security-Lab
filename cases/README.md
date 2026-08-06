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

Numbering is stable once created. Phase mapping per the project charter.

| Case | Phase | Baseline finding | Central claim |
|---|---|---|---|
| [`00-receipt-handle`](00-receipt-handle/README.md) ✅ | 2 | L7 | The component being audited must not be able to edit the evidence it is audited against |
| `01-ungranted-read` | 2 | L1, L2 | A scoped view constrains interface access but not same-process reach-around, and the bypass is invisible in the read log |
| `02-ungranted-write` | 2 | TB-4 | The outbound store diff catches bypassed writes because it compares observed state, not self-report |
| `03-forged-routing` | 2 | L6 | Routing data must not be mutable from the namespace the routed code runs in |
| `04-path-traversal` | 2 | TB-1 | `realpath` confinement holds; the check point and the use point must not diverge |
| `05-capability-replay` | 3 | L8 | A grant with no workflow, audience, expiry, or use count is replayable |
| `06-confused-deputy` | 4 | — | Holding authority is not proof that a request to use it is legitimate |
| `07-agent-process-compromise` | 5 | L1–L7 | What process separation actually buys, measured rather than asserted |
| `08-host-compromise` | 5 | — | Co-tenancy is not a trust zone |
| `09-information-flow` | 6 | — | A chain of individually valid steps can be a forbidden flow |
| `10-audit-tampering` | 7 | L4, L5 | Append-only-by-API is not tamper-evident |
| `11-orchestrator-compromise` | 5 | — | The orchestrator must not be able to declassify unilaterally |
| `12-provenance-quarantine` | 8 | — | After a producer is declared compromised, dependent outputs are identifiable |

Baseline findings promoted to the front of Phase 2 because they had no case
number in the charter's list:

* **L7 — the validator holds a live handle to the receipt list it audits.**
  Charter-forbidden anti-pattern. **Done — [case 00](00-receipt-handle/README.md).**
* **L3 — artifacts mutate in place, and the `source_hash` that would detect it
  is only verified during snapshot hydration.** The detection primitive already
  exists; it just is not wired into the live read path. Still open; number it
  `00b` or fold it into `02` when its contract is written.

A case-00 residual limitation also needs its own slice eventually: **the
validator's verdict is agent-authored and the runner does not cross-check it.**
Separate security claim, so not folded into case 00.

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
