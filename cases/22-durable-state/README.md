# Case 22 — Durable-state independence

**Phase:** 5 (isolation) applied to the approval plane
**Baseline finding:** case 21's seventh probe — the gate's persisted store
stayed writable from the worker boundary
**Ladder level:** Level 2 against the boundary; Level 1.5 against the store
**Baseline result:** `undetected`
**Controlled result:** `prevented` — for a protocol whose vocabulary cannot
forget

---

## The claim

> Compromise of the worker boundary cannot create, modify or **delete** durable
> gate authority except through the gate's exposed protocol.

Deletion is attacked as hard as insertion, and it turns out to be the more
interesting half. After cases 19 and 20 the durable store holds **security
state**, not persistence: a consumption record is what makes a spent approval
spent.

## Three arms

```text
D0  the store is a file the worker writes          (case 21's arm B)
D1  the store is owned by the gate; the protocol
    offers approve / execute / state and nothing else
D2  the same, plus one ordinary maintenance operation
```

**Modelled versus measured**, stated because the distinction is the difference
between an honest arm and a strawman: D1 and D2 *model* the store being
unreachable except through the protocol — this platform cannot enforce that
with separate OS users, exactly as case 12's arm A modelled permission checks
rather than emulating Unix. What is genuinely **measured** is what the
protocol's own vocabulary permits, which is where D2 fails.

## Results

```bash
python cases/22-durable-state/attack.py
```

| Attack | D0 | D1 | D2 |
|---|---|---|---|
| forge an approval | **yes** | no | no |
| resurrect a spent approval | **yes** | no | no |
| resurrect via maintenance | — | no | **yes** |
| destroy the durable record | **yes** | no | no |

### D0 — case 21's residual, and the attack it never ran

Insertion was obvious. **Deletion is the one to notice:** removing the
consumption record makes a spent approval live again, so one legitimate review
authorises a second execution — and *neither case 19 nor case 20 detects it*,
because both trusted the record they were reading.

The worker can also truncate the file outright, which is availability rather
than authority and is recorded as its own row.

### D2 — the finding

D2 differs from D1 by exactly one operation: a compaction of the kind every
persistent store eventually grows. It drops the consumption records, and the
approval goes live again.

Insertion is still refused. Destruction is still refused. That is precisely why
this is easy to miss — the hole is not a general collapse, it is one verb.

> **Moving the store behind a protocol moves the attack surface to the
> protocol's vocabulary. A vocabulary that can forget is a vocabulary that can
> forge.**

This is case 09's lesson — *an allowlist of names is not an allowlist of
transformations* — arriving at the durable plane. The store being unreachable
is necessary and is not the claim; the claim has to cover what the gate itself
will do on request.

### And the gate still works

Every arm approves, executes, refuses a second execution, and refuses a
non-reviewer. A store nobody can write is not a control if the gate cannot
record an approval either.

## Residual limitation

**D1/D2's unreachability is modelled, not enforced.** No separate OS user, no
container, no database credential. What this case can honestly claim is
conditional: *given* a store reachable only through the protocol, these four
attacks behave as measured.

**One maintenance verb, one shape of deletion.** Real stores also have
retention policies, backup restores, schema migrations and replica
divergence — each of which is another way to forget, and none is measured.

**No detection.** Nothing here notices that a consumption record went missing.
An append-only chain would make the gap visible and is not built; case 10's
ledger is the obvious model and case 11's containment the obvious response.

**Availability is out of the claim.** D0's truncation is recorded because it
happened, not because the case addresses it.

---

## What this proves

That case 21's residual was worse than it looked. The writable store admits not
only forged approvals but *forgotten* ones, and forgetting a consumption record
is a resurrection attack that the two sign-off cases are structurally unable to
see.

And that moving the store is necessary and not sufficient. The protocol becomes
the surface, and one ordinary maintenance operation — genuinely the sort of
thing a team adds in month three — reopens the whole mechanism while insertion
and destruction stay closed.

## What this does not prove

It does not demonstrate an enforced boundary. D1 and D2 model unreachability
and this platform cannot enforce it; the measured half is the protocol's
vocabulary.

It does not enumerate the ways a durable store can forget — one verb was
tested, and retention, restore and migration are untouched.

It adds no detection: a missing consumption record is invisible here.

---

## Tests

`tests/adversarial/test_case_22_durable_state.py`
