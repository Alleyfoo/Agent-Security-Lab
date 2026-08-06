# Case 00 — The audited component edits its own evidence

**Phase:** 2 (in-process attack cases)
**Baseline finding:** L7
**Ladder level:** 1 (manipulated / malicious agent)
**Status:** control implemented, attack blocked

Numbered `00` because it precedes case `01` in execution order while leaving the
charter's `01`–`12` numbering intact.

---

## Threat

A hostile `ValidationAgent` implementation. The threat model lists *agent
implementation code* as untrusted, so this adversary is assumed, not exotic.

Its starting authority is exactly what the runner grants the validation stage:
read access to three artifacts, one contracted output key, and the receipt
collection it is meant to audit.

It needs **no** memory inspection, no debugger, no reach-around past a private
attribute, and no privilege escalation. This is what separates case 00 from
case 01: the attack runs entirely through the sanctioned interface.

## Existing assumption

Baseline control **B18** — "the verdict is derived only from runner-owned
receipts, not from agent event claims" — was taken to mean authorization
evidence is independent of the agent being audited.

## Attack

`ValidationAgent` was constructed with the runner's actual receipt list
(`demo_runner.py:112` at `v0-baseline-inprocess`):

```python
ValidationAgent(self._receipts)      # the runner's own list object
```

so `validator.receipts is runner._receipts` was `True`. The hostile validator
deletes every failing receipt before auditing:

```python
self.receipts[:] = [r for r in self.receipts
                    if r.get("status") == "ok"
                    and r.get("contract_result") == "passed"]
```

To make a failing receipt exist in the first place, the schema stage violates
its write contract once and then behaves on retry. The workflow reaches
validation with a genuine `contract_result: failed` receipt in the record.

Run it:

```bash
python cases/00-receipt-handle/attack.py
```

## Observed unsafe result

Against `v0-baseline-inprocess`:

```text
--- honest validator ---
  receipts in runner record : 5
  failing receipts present  : 1
  final verdict             : warn
  reasons                   : ['runner receipts contain authorization failures']

--- HOSTILE validator ---
  [attacker] scrubbed the receipt list via the handed-over object
  receipts in runner record : 4
  failing receipts present  : 0
  final verdict             : ok
  reasons                   : ['all checks passed']
```

Note the second line of each block. The corruption is **not** confined to the
validator's own view — `RunSession.receipts()` is the runner's authoritative
accessor, and it is what `report()` and the UI read. A stage failed its
contract, the runner correctly recorded it, and the audited component erased
that record from the system of account.

## Control

A runner-owned append-only ledger with a read-only handle
([`agent_network_demo/receipts.py`](../../agent_network_demo/receipts.py)):

```text
ReceiptLedger   append-only, held by the runner
ReceiptView     read-only handle given to agents: deep-copies on read,
                raises ReceiptIntegrityError on every mutation
```

The control lives **outside the compromised component** — the validator
receives `self._receipts.view()` and has no path to `append`, `clear`,
`__setitem__`, slice assignment, in-place item edits, or reordering.

Two details that matter:

* `ReceiptView.__iter__` deep-copies **per item**, otherwise an auditor could
  edit a receipt in place while iterating over it.
* `ReceiptLedger.append` stores a deep copy, so a later edit to the caller's
  dict cannot retroactively rewrite the record.

Mutation methods are spelled out individually rather than trapped through
`__getattr__`, so each denial names the operation attempted.

## Observed protected result

Same attack, unchanged, against the controlled code:

```text
--- HOSTILE validator ---
  [attacker] BLOCKED: ReceiptIntegrityError: receipt assignment denied: the
  receipt record is runner-owned evidence and is read-only for agents. The
  audited component may not modify the evidence it is audited against.
  receipts in runner record : 5
  failing receipts present  : 1
  final verdict             : warn
```

The hostile run is now indistinguishable from the honest one.

## Residual limitation

> **CLOSED by [case 05](../05-false-verdict/README.md).** The text below
> records what case 00's own control does and does not do, which has not
> changed. What changed is downstream: the agent-authored artifact is now a
> *recommendation*, and the run's conclusion is derived by the runner. The
> tripwire test named here asserted the false verdict became the run's
> conclusion; case 05 broke it, and it has been rewritten as
> `test_case_00_still_cannot_stop_a_false_recommendation`.

**The verdict is still an agent-authored artifact.** Case 00 protects the
*evidence*, not the *conclusion drawn from it*. A hostile validator can rebind
its own `self.receipts` to a fabricated list and write a clean verdict anyway —
it controls its own process-local names, and no control can take that away.
That remains true and always will: authorship is not constrainable from
outside the component that authors.

The limitation was **bounded** even before case 05, which is what made it
tolerable to record and defer: the false verdict is contradicted by the
runner's receipt record, which the attacker can no longer reach
(`test_residual_but_the_runner_record_still_shows_the_failure`). The lie is
detectable by comparing two records that no single compromised component
controls — and case 05 is exactly that comparison, performed by the runner
instead of left to a reader.

Also unchanged, by design:

* A Level 2 adversary reaches `view._ledger._receipts` directly. In-process
  reach-around is baseline finding L1 and is case 01's subject.
* The ledger is append-only *by API*, not tamper-evident. No hash chain binds
  the entries — Phase 7.

## Containment response

Per the ladder's deterministic table: **agent contract violation → reject the
operation and stop the workflow.** Already baseline behaviour — `step()` only
advances `self._current` on the success path, so the failing stage is retried
rather than skipped, and the failure stays in the record.

`ReceiptIntegrityError` is deliberately *not* a `ContractError`. It signals a
component attacking the audit plane rather than an ordinary contract breach,
and the two should never be conflated in triage.

## Recovery requirement

1. Treat the verdict artifact from the affected run as untrusted.
2. Recompute the authorization result from `RunSession.receipts()`, which the
   validator could not alter.
3. Re-run validation with a known-good validator build.

No other artifact is affected: the attack targets the audit plane only, and
`raw_input`, `schema_profile`, and `cleaned_output` were produced before the
validation stage ran.

## Blast radius

One workflow's audit record and its verdict artifact. No data-plane artifact,
no other run, no policy, no grant. The attacker gains the ability to make one
run *look* clean, and — after the control — not even that.

---

## What this proves

Within one process, an agent that goes through the interfaces it is given
cannot alter the trusted runner's record of what happened. Corrupting that
evidence now requires full in-process compromise (ladder Level 2) instead of
merely a hostile agent implementation (Level 1). The bar rose by one rung, and
that is the exact, measurable amount of authority this control buys.

## What this does not prove

It does not prove the verdict is trustworthy — a compromised validator can
still state a false conclusion, and only the runner's independent record
contradicts it. It does not contain a Level 2 adversary, who reaches the
underlying list through private attributes exactly as in baseline finding L1.
It does not make the receipt record tamper-evident: there is no hash chain, no
signature, and no external anchor, so an attacker with process access can still
rewrite history without leaving cryptographic evidence.

---

## Tests

`tests/adversarial/test_case_00_receipt_handle.py` — 18 tests:

| Test | Asserts |
|---|---|
| `test_runner_does_not_hand_the_validator_its_own_receipt_record` | Regression guard on L7 |
| `test_hostile_validator_cannot_scrub_failing_receipts` | The attack fails, with the specific denial reason |
| `test_runner_evidence_survives_a_hostile_validator` | End-to-end: failure still recorded, verdict still `warn` |
| `test_every_mutation_path_on_the_view_is_denied` (×11) | Every mutation method denied and the record untouched |
| `test_view_yields_copies_so_receipts_cannot_be_edited_in_place` | Per-item deep copy on iteration and indexing |
| `test_ledger_copies_on_append_so_later_caller_edits_do_not_apply` | Copy-on-append |
| `test_case_00_still_cannot_stop_a_false_recommendation` | The limit of this control, after case 05 closed the residual |
| `test_residual_but_the_runner_record_still_shows_the_failure` | The residual limitation is bounded |

Suite: **90 passed** (72 baseline + 18). No baseline test was modified or
removed.
