# Case 04 — Forged runner-labelled audit event

**Phase:** 2 (in-process attack cases)
**Baseline finding:** L4
**Ladder level:** 1 for the demonstrated attacks; 2 for the residual
**Baseline result:** `undetected` (audit record) · `prevented` (authorization decision)
**Controlled result:** `prevented` (audit record) · `prevented` (authorization decision)

---

## Research question

> Can an agent append an event claiming to be the trusted runner?

Answer at the baseline: **yes**, by two independent Level 1 routes, neither
noticed.

The case exists to keep two effects apart. They are usually collapsed into one
sentence — "the audit log was forged" — and the collapse hides the only fact
that matters operationally: *which of them actually changed a decision.*

| Effect | What is corrupted | Registered as |
|---|---|---|
| 1 | The human-readable record of who did what | `case-04a` |
| 2 | The authorization decision derived from that record | `case-04b` |

Measuring them together would have produced a single misleading result in
either direction: "the audit trail is forgeable, therefore authorization is
compromised" (false — it is not derived from the log), or "the verdict is
unaffected, therefore the forgery does not matter" (false — the record a human
reads is the thing that was corrupted).

## Threat

An agent that uses only what the runner hands it. `agent.run(envelope, view,
log)` passed the live `EventLog`, and `EventLog.append` authenticated nothing:
`Event.agent` is a caller-supplied string.

A second route needs even less. The runner read the acting identity off the
agent object — `agent.name` — for the receipt it writes, for error events, and
for the step snapshot. An agent that assigns itself `name = "trusted_runner"`
has the runner write the lie on its behalf.

Both are **Level 1**: a hostile agent implementation using ordinary, documented
Python. No reach-around, no private attribute, no frame walking.

The Level 2 variant — reaching the `EventLog` object itself through the object
graph — is the residual this case's second layer addresses.

## Existing assumption

Two beliefs are under test, and they are not equally true.

**"The event log is the audit trail."** `EventLog` is append-only *by API*
(baseline control B19) and every entry carries an `agent` field, so the log
reads like an attributed record of who acted. Nothing established that the
attribution was assigned by anyone trustworthy.

**"A forged event corrupts the decision."** Baseline control B18 —
`ValidationAgent` derives `all_writes_allowed` from the runner's receipt
ledger, not from log events — already makes this false. `test_forged_agent_
permission_event_cannot_change_verdict` in `tests/test_demo_runner.py` has
locked it in since the baseline. This case measures it rather than assuming
it, because an unmeasured containment is indistinguishable from luck.

## Attack

```bash
python cases/04-forged-runner-event/attack.py
```

Four attacks: two that forge the record, one that measures the decision, one
that goes around the interface.

### A1 — Forged event through the handed log

A hostile transform agent appends an `Event` with `agent="trusted_runner"`,
`action="step_receipt"`, `contract_result="passed"` — the exact shape the
runner writes — for a stage that has not run.

```text
  events labelled trusted_runner: 5
  receipts the runner actually wrote: 4
  forged event in the log : True
```

Five events carry the runner's identity; the runner wrote four. Nothing
compared the two numbers. The forged entry has a sequential `event_id`, a
plausible timestamp and the runner's exact field shape — read on its own, it is
not distinguishable from a real receipt.

### A2 — The agent renames itself

One line: `name = "trusted_runner"`. The runner then writes the receipt, the
error event and the step snapshot under that identity itself.

```text
  receipts attributed to trusted_runner: 1
  workflow quarantined    : False
  runner identity taken   : True
```

This is the worse of the two. The forged attribution is not in the narrative
log — it is in the **receipt ledger**, the record case 00 made read-only
precisely so it could serve as evidence. Nothing was reached around. The runner
read the identity off the agent object and wrote it down.

### B — The authorization decision

The same run, twice: once clean, once with the forged events in place. The two
verdicts are compared field by field. The forgeries are attributed to agents
and appended straight to the log — the strongest in-process forgery the
runner's tally does not cover — so the measurement means the same thing before
and after the control.

```text
  clean  verdict : ok {'chain_complete': True, 'all_writes_allowed': True,
                       'schema_matches_output': True, 'row_counts_consistent': True}
  forged verdict : ok {'chain_complete': True, 'all_writes_allowed': True,
                       'schema_matches_output': True, 'row_counts_consistent': True}
  decision corrupted: False
```

Identical. `test_the_validator_follows_the_ledger_not_the_log` makes the two
sources disagree outright — a log full of runner-voiced "passed" receipts
against a ledger holding one failure — and the verdict follows the ledger:
`warn`, `all_writes_allowed: False`.

### C — Level 2 reach-around

The log object is not handed to the agent any more once C1 lands, so this
attack reaches it through `gc.get_objects()` — the technique case 01
established. `log._log` on the handle is cheaper and works too; the tests use
that form.

```text
  EventLog found in the object graph: True
  events labelled trusted_runner: 5
  receipts the runner actually wrote: 4
  workflow quarantined    : False
  forged and unnoticed    : True
```

## Observed unsafe result — `undetected` (record) · `prevented` (decision)

Both Level 1 routes succeeded and the Level 2 route succeeded. No receipt
recorded an anomaly, no error was raised, and nothing compared the events
carrying the runner's identity against the events the runner had written.

The decision was never in danger. That is not luck and it is not this case's
doing: `ValidationAgent` derives `all_writes_allowed` from the receipt ledger,
which is baseline control B18, and this case is the measurement that turns that
from an assumption into a result.

## Control

One claim, narrowly stated:

> An event attributed to an identity the agent was not assigned cannot be
> appended through the interfaces the agent is given, and an event carrying the
> runner's identity that the runner did not write is detected before the next
> step proceeds.

Three layers, because the attack has three shapes.

### C1 — Author-bound log handle

`EventLog.view_for(author)` returns an `EventLogView`. The view stamps
`Event.agent` with the author the runner assigned and raises
`AuditIntegrityError` if the caller claims a different one. `view_for` refuses
to mint a handle under the runner's own identity at all.

> **Guarantee:** an agent using the handle it is given cannot write an event
> attributed to anyone else. Prevention, not detection — the append never
> lands.

The view narrows *attribution only*. Read-back (`all`, `as_dicts`, `len`) is
kept, so this slice makes exactly one claim and does not quietly reduce an
unrelated capability.

### C2 — Identity comes from the route, not from the agent

The runner takes the acting identity from `route.agent` — runner-owned policy —
rather than from `agent.name`. Without this, C1 is defeated by one line, since
the runner would mint the view under whatever name the agent advertises.

> **Guarantee:** the identity in the receipt, the error event, the step
> snapshot and the log handle is the one the routing table assigned. An agent
> does not get to name itself in the trusted record.

### C3 — Runner-owned tally of runner-labelled events

`RunSession` counts the events it appends under its own identity and verifies
after every step that the log contains exactly that many. A mismatch raises
`AuditIntegrityError` and quarantines the run.

> **Guarantee:** an event carrying the runner's identity that the runner did
> not write is detected before the workflow advances.

C3 is the analogue of case 02's post-step sweep and case 03's route
fingerprint, and it earns its place for the same reason: C1 prevents the
attack the interface permits, C3 catches the variant that goes around it.

## Observed protected result — `prevented` (record) · `prevented` (decision)

```text
--- A1. Forged runner receipt through the handed log ---
  forgery BLOCKED         : AuditIntegrityError: event attribution denied:
                            'transform_agent' may not append an event
                            attributed to 'trusted_runner'.
  forged event in the log : False

--- A2. The agent renames itself to the trusted runner ---
  receipts attributed to trusted_runner: 0
  workflow halted         : contract violation: event attribution denied:
                            'schema_agent' may not append an event attributed
                            to 'trusted_runner'.
  runner identity taken   : False

--- C. Level 2: append straight to the EventLog object ---
  workflow quarantined    : True
  runner error            : audit integrity failure: the runner wrote 2
                            event(s) under 'trusted_runner' but the log holds
                            3 - an event carrying the runner's identity was
                            written by something else
  forged and unnoticed    : False
```

Note the two different responses, which is the distinction C1 and C3 exist to
keep. A1 and A2 are *blocked attempts* — nothing corrupt entered the record, so
they take the Level 1 containment path: the operation is refused, the step
fails as a contract violation, the workflow halts, and the run is **not**
quarantined. C is *corruption already present* — the forged event is in the
log — so it quarantines.

For A2 the identity never reaches the ledger at all: C2 takes it from the
route, so the receipt says `schema_agent` regardless of what the agent calls
itself. What halts the run is the agent's own work event, which still claims
the runner's identity and is refused by C1.

## Residual limitation

**Attribution is bound; content is not.** An agent may still append an event
under its own true identity whose `action` is `step_receipt` and whose
`message` reads like a runner receipt for another stage. The `agent` field is
now honest, so a reader who checks it is not deceived; a reader who skims the
prose is. Closing that means reserving an action namespace and constraining
message content — a different claim, deliberately not made here.

**C3 covers the runner's label only.** The runner has no independent record of
what an agent legitimately wrote, so it cannot tally agent-labelled events. A
Level 2 adversary that reaches the `EventLog` and appends under *another
agent's* identity is not detected. C1 closes that at Level 1; past Level 1 it
is open, and pinned by an executable test.

**The reference value lives inside the adversary's reach.** The same wall cases
02 and 03 hit:

> An integrity check whose expected value is stored where the adversary can
> reach it detects careless tampering, not careful tampering.

`RunSession._runner_event_count` is an ordinary attribute on the session
object. An adversary who appends a forged runner event *and* increments the
counter passes C3. This is pinned by an executable test, not asserted.

**Everything below the API is untouched.** `log._log` on the handle is a
one-attribute step to the real `EventLog`; the object graph reaches it too. The
in-memory `_events` list and the on-disk JSONL remain writable by same-process
code. The file is still
truncatable (baseline finding L5), there is no hash chain binding entries, and
no entry is bound to any identity cryptographically. Non-repudiation remains
absent. This case raises the level of adversary required to forge attribution;
it does not make the log tamper-evident, and the stronger term must not be used
until a chain exists (Phase 7).

**Runner-authored error events are attributed to the agent.** `_emit_error`
labels the event with the acting agent's identity even though the runner wrote
it. Noticed while implementing C2 and recorded rather than fixed: changing it
would alter the meaning of existing events for a claim this slice does not
make.

## Containment response

Deterministic: an attribution mismatch raises `AuditIntegrityError`, which
quarantines the session on the same path as `ArtifactIntegrityError` and
`RouteIntegrityError` — the run stops and refuses further steps.

`AuditIntegrityError` is distinct from `ReceiptIntegrityError`. Both concern
the audit plane, and they concern different objects: the ledger is the
runner's evidence for a decision, the log is the narrative record. Corrupting
one is not the same incident as corrupting the other, and case 04b is the
measurement that says so.

## Recovery requirement

Not implemented, consistent with cases 02 and 03. Assessed:

| Option | Safe here? |
|---|---|
| Abort the step and quarantine | **Yes — implemented.** |
| Delete the forged event | **No.** The log has no delete operation by design (B19), and removing evidence of tampering to restore a clean-looking trail is the attack, not the remedy. |
| Rebuild the log from the receipt ledger | **No.** The ledger records the runner's own steps only; it cannot reconstruct agent work events, and a reconstructed log would assert more than it knows. |
| Anchor entries outside the process | Correct answer, out of scope (Phase 7). |

Operationally: treat the whole log for that run as untrusted narrative and read
`RunSession.receipts()` instead, which is the only record this case leaves
standing as evidence.

## Blast radius

**One run's narrative record.** The log file is per-run
(`events_<run_id>.jsonl`), so a forged event does not reach another run's
trail — unlike case 03, whose blast radius was the process lifetime.

The decision plane has no blast radius here: nothing derives authorization
from log events, which is what 04b measures.

What is lost without the control is the ability to answer "who did this?" from
the audit trail at all — including for the honest stages of the same run,
since one forged entry that is indistinguishable from a real one devalues
every entry beside it.

---

## What this proves

That the `agent` field in the audit log recorded a claim, not an observation,
and that two independent Level 1 routes could set it to the trusted runner's
identity — one through the log handle the runner passed in, one by the agent
simply renaming itself so the runner wrote the lie on its behalf. With the
control, the identity in the trusted record is assigned by runner-owned policy,
an agent cannot append under another identity through the interfaces it is
given, and a runner-labelled event the runner did not write is detected before
the workflow advances.

It also proves, separately and by measurement rather than assertion, that
forging the record did **not** corrupt the authorization decision: the verdict
of a run under forged events is field-for-field identical to a clean run,
because `ValidationAgent` reads the runner's receipt ledger and never the log.

## What this does not prove

It does not prove the log is trustworthy evidence of authorization — it is not
evidence of authorization at all, and the case's value is establishing exactly
that. It does not make the log tamper-evident: no chain, no signature, no
external anchor, and the on-disk file remains rewritable (L5). It does not
contain a Level 2 adversary, who reaches the `EventLog` through the object
graph and can update the runner's tally alongside a forged event. It says
nothing about content, only attribution. And it does not narrow the
confidentiality loss established in
[case 01](../01-ungranted-read/README.md).

---

## Tests

`tests/adversarial/test_case_04_forged_runner_event.py`

| Test | Asserts |
|---|---|
| `test_handle_refuses_an_event_claiming_the_runner` | C1 — denial names both identities |
| `test_handle_refuses_another_agents_identity` | C1 — not just the runner's label |
| `test_handle_stamps_an_unattributed_event` | C1 — author and run are stamped |
| `test_no_handle_can_be_minted_under_the_runner_identity` | C1 — the runner's identity is not delegable |
| `test_a_handle_needs_an_author` | C1 — no anonymous handle |
| `test_the_returned_event_is_a_copy` | C1 — `append(e).agent = …` cannot edit the record |
| `test_read_back_through_the_handle_is_a_copy` | C1 — nor can mutating `all()` |
| `test_the_agent_receives_a_handle_and_not_the_log` | The runner hands over the view, bound to the route's identity |
| `test_forged_runner_receipt_through_the_handle_is_blocked` | Attack A1 — runner-labelled events equal receipts written |
| `test_a_renamed_agent_cannot_take_the_runner_identity` | Attack A2 — no receipt claims the runner |
| `test_identity_in_the_trusted_record_comes_from_the_route` | C2 — any rename is ignored, not just the runner's |
| `test_level_2_append_under_the_runner_identity_is_detected` | C3 — `AuditIntegrityError`, quarantined |
| `test_audit_integrity_failure_is_recorded_as_a_receipt` | Detection leaves trusted evidence |
| `test_quarantined_run_refuses_further_steps` | Fail-closed |
| `test_untampered_run_is_unaffected` | No false positives |
| `test_forged_events_do_not_change_the_verdict` | **04b** — verdict identical to a clean run |
| `test_the_validator_follows_the_ledger_not_the_log` | **04b** — when the two disagree, the ledger wins |
| `test_residual_matching_tally_passes_verification` | Residual — the reference value is in reach |
| `test_residual_forgery_under_an_agent_label_is_not_detected` | Residual — C3 covers the runner's label only |
| `test_residual_content_is_not_bound` | Residual — attribution is bound, content is not |
