# Case 23 — Two real principals

**Phase:** 5 (isolation)
**Status:** **contract only — blocked on the environment, and the block is
recorded rather than modelled around.**
**Not registered** in `cases/registry.py`: it has no results, and a registered
case ships a runnable attack.

---

## The question

Cases 21 and 22 took the application side as far as it goes. What remains is
embarrassingly concrete rather than conceptual:

> Compromise of the worker boundary cannot create, modify or delete durable
> gate authority except through the gate's exposed protocol — **because the
> operating system or database refuses it**, not because the case modelled it.

```text
worker process / principal
    |
    | approved protocol
    v
gate process / principal
    |
    | exclusive credential
    v
durable store
```

Deliberately boring. No orchestrator, no secret manager, no service mesh, no
certificates. A separate UID with file permissions, or a database credential
the worker genuinely does not possess, is enough to answer the question — and
anything more would be decoration that makes the result harder to read.

## Why it is not built

**This machine cannot currently produce a second principal.**

| Mechanism | Status |
|---|---|
| second local user + file ACLs | one local account; creating another needs administrator rights |
| Docker container with a non-root UID and a named volume | Docker is installed (29.0.1) and **the daemon is not running** — `npipe:////./pipe/dockerDesktopLinuxEngine` is absent |
| WSL with real uids | a `docker-desktop` distribution is registered; no general-purpose distribution verified |
| database with a per-principal credential | no server available locally, and SQLite has no credential model |

Case 22 already had to write *modelled, not enforced* on its own arms. Doing it
twice would turn a caveat into a habit, so this case stops at the contract.

**What would unblock it:** starting Docker Desktop, or an administrator
creating a second local account. Either is a one-time environment change and
neither is a design decision.

## The attacks, once a real boundary exists

Re-run the ones cases 21 and 22 already measured, against enforcement rather
than modelling. Each must fail **with an OS or database refusal**, and the
refusal is the evidence:

1. direct store insertion — write an approval into the durable store;
2. deletion of consumption state — remove the record that makes a spent
   approval spent (case 22's resurrection, the most important one);
3. replacement of gate code or volatile state;
4. reading the gate's credential;
5. bypassing the protocol;
6. **using any maintenance path that exists** — case 22's D2 finding, which
   must be re-checked against the real boundary because it is the one that
   survives process separation.

## The pass condition, stated before building

An isolation result requires all six to fail **for a reason the case did not
write**. A `PermissionError` raised by the operating system counts. A check
inside the gate's own Python does not — that is the application claim again,
and cases 19 to 22 have already measured it.

## What this case may then claim

> Two-sided sign-off is an isolation-backed control: the worker cannot reach
> durable gate authority except through a protocol whose vocabulary preserves
> the invariants.

And what it may not: anything about hosts, networks, containers as trust
zones, or an adversary with administrator rights. The boundary being tested is
one principal separation on one machine.

## Sequencing

Detection comes **after** this, not before, and the two must not be mixed.

```text
this case asks    can the attacker mutate the authoritative record?
detection asks    if it becomes inconsistent anyway, can we tell?
```

Mixing them invites the argument that detecting a mutation compensates for
still allowing it. The detection staircase, pre-registered so it is not
invented ad hoc:

```text
D0  mutable current state only        deletion invisible (case 22 measured this)
D1  append-only event history         deletion conflicts with history
D2  chained or externally anchored    a history rewrite is itself detectable
```

Building D1 or D2 before the isolation boundary exists would put
tamper-evidence around a store the attacker can rewrite wholesale, which is
the cosmetic-security failure this repository refuses.

---

## What this proves

Nothing yet. This is a contract, and the environment blocker is part of it.

## What this does not prove

In particular it does not license reading cases 21 and 22 as isolation
results. They are process and protocol results with the boundary modelled, and
they say so.

---

## Tests

None yet. When built: `tests/adversarial/test_case_23_real_principals.py`,
skipping cleanly when no second principal is available rather than passing
vacuously.
