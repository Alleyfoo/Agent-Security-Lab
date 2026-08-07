# Case 11 — Contain a contradiction the moment it appears

**Phase:** 3 (authority model)
**Baseline finding:** case 10's recorded residual — conflicts are reported and
nothing acts on them
**Ladder level:** the case 08 attacker; may alter persisted policy or workflow
records, may not modify evaluator code
**Baseline result:** `detected_after_occurrence`
**Controlled result:** `prevented` — for the effect named below, and no other

---

## Research question

> When the production record contradicts itself, does anything stop the object
> before it acts on a binding it cannot trust?

Case 10 replaced a stored artifact map with a derived one and found that an
append-shaped rebinding becomes *inert*: first production wins, so the forged
record changes no grant, and the contradiction stays visible in the record. It
then recorded what it had deliberately not built:

> **Conflicts are reported, not acted on.** `conflicts_for()` will tell a
> caller the record contradicts itself; nothing calls it during a run.

So the object kept working. Two more steps ran and it reached `validated`, with
its own authority record saying two different things about where
`table_preview` lives. That is the whole subject of this case.

## Scope, held deliberately narrow

No new surfaces, no new records, no new arms. The step lifecycle reads the
record it already has:

```python
def check_containment(obj, ledger):
    conflicts = ledger.conflicts_for(obj.object_id)
    if conflicts:
        raise ObjectContainedError(...)
```

called first in `run_step`, **before** validation and before any grant is
derived, so a contained object never resolves authority at all. `contain=False`
exists so the unsafe result stays reproducible — the same reason case 09's
`pinned` is optional — and is not a deployment switch.

## Attack

```bash
python cases/11-conflict-containment/attack.py
```

### Results

| | no containment | contained |
|---|---|---|
| A append a contradiction, then keep working | **completes, state `validated`** | stopped at `profiled` |
| B retry after the refusal | — | refused 3/3 |
| B reload the record and resume | — | stopped |
| C overwrite instead of append — read obtained | — | **obtained** |
| C overwrite — did containment fire? | — | **never fired** |
| D contradiction about a type no step reads | — | stopped |
| D untampered run | completes | completes |

### A — the effect that changes

Without containment the object runs `clean_table` and `validate_chain` and
finishes. With it, the next step refuses:

```text
ObjectContainedError: object 'obj_812' is contained: its production record
contradicts itself ('table_preview': 'artifact.raw_input' then
'artifact.key_material'). no step runs against a record that cannot say which
key holds a type
```

The object does not advance, produces nothing, and never derives a grant.

### B — quarantine with no new state

This is the reason the case could stay as narrow as the manager required. Case
02 needed a quarantine *flag* because the corruption it found lived in data the
flag was separate from. Here the contradiction is **in** the persisted record,
so a reloaded ledger re-detects it and a resumed object is contained again.
Nothing had to remember the incident, because the incident is the record.

### C — the blind spot, and it is the important one

Case 10's residual is that *overwriting* a production record still obtains the
capability, at the same tamper cost as writing a stored map, because it
destroys the evidence rather than adding to it.

Containment reads that evidence. So it stops the attack that was already inert
and is blind to the attack that works — the overwritten run completes normally
with the unauthorized read obtained, and the check never fires. The two facts
are the same fact: a contradiction is what an *append* leaves behind, and only
appends leave one.

### D — what it costs

Two costs, both measured rather than assumed.

**A one-line forged append is now a permanent denial of service.** Exactly the
edit case 10 measured as harmless stops the object for good; persisted, it
stops every later process that loads the record. Case 10 already found a DoS in
the produced-once invariant — for a type *not yet* produced — and containment
widens it to any type in the record and makes it the designed response rather
than an accident.

**The check is object-scoped, not grant-scoped.** A contradiction about
`key_material`, which no skill in this workflow reads, still contains the
object. That is a choice: a record that cannot say which key holds one type is
not trustworthy evidence about the others. The cost of the choice is that the
denial-of-service surface is every type in the record, not only the ones the
remaining steps need.

## Observed unsafe result — `detected_after_occurrence`

Case 10's endpoint, reproduced here as this case's baseline with
`contain=False`: the contradiction is in the record, `conflicts_for()` reports
it, the object completes anyway and no part of the run looks.

## Control — the lifecycle refuses to run on a contradicted record

> **Guarantee:** an object whose production record contradicts itself runs no
> further step, and the refusal survives a retry, a reload and a resume without
> anything having to remember it.

`prevented`, and the vocabulary requires saying precisely what:

* **prevented** — the object executing any further step against a
  self-contradicting authority record. It never advances, never produces, never
  derives a grant.
* **not addressed** — the unauthorized read itself, which an append never
  obtained (case 10) and an overwrite still obtains (below). This case moves no
  confidentiality result.

## Residual limitation

**The one attack that works is invisible to it.** An overwrite leaves no
contradiction, so containment never fires and the object completes with the
capability obtained. This case narrows *which* forgeries are survivable; it
does not narrow which ones succeed.

**It is an availability trade, not a free improvement.** The cheapest possible
forgery — one appended line — now guarantees an object never completes. Whether
that is the right trade depends on whether a stopped object is preferable to
one that carries on with a record known to be corrupt; this repository's answer
elsewhere is yes (cases 02, 03, 04a all quarantine), and the cost is recorded
rather than absorbed.

**The check lives where the adversary lives.** `check_containment` is ordinary
in-process code reading an ordinary in-process list. It is the containment for
a corrupt record, not evidence that the record is honest, and an adversary who
reaches `_records` to overwrite is already past it. The cross-cutting finding
applies unchanged.

**Containment is at the lifecycle, not at the derivation.** `derive_grant`
still answers on a contradicted record — deliberately, because case 10's
published measurement is taken there and moving the check would change it. A
caller that resolves a grant without running a step is uncontained.

## Containment response

`ObjectContainedError`, a subclass of `LedgerIntegrityError` — the same
corruption, a different response. `LedgerIntegrityError` is the ledger refusing
to write; `ObjectContainedError` is the step lifecycle refusing to run. Fails
closed: there is no sound grant available from a record that contradicts
itself.

Scoped to one object. Other objects in the same ledger continue to completion,
which is asserted rather than assumed.

## Recovery requirement

Not implemented, and it is the honest gap. Deleting the forged record is
indistinguishable from the attack — the ledger holds no independent account of
which of two contradicting entries is legitimate, even though
first-production-wins makes the derivation behave as though it does. An
operator must reconstruct outside the model. This is the same wall case 09 hit
with the registry: the process cannot say what the record *should* have said.

## Blast radius

One object, permanently, including retries and resume. Not the run, not other
objects, not later deployments — the ledger is per-object in what it contains
and the check is per-object in what it reads.

---

## What this proves

That the derived model can hold a control the stored model cannot have at all.
Containment needs a contradiction to find, and a stored map keeps none — a
write is total, the previous binding is gone, and the object is left holding a
map that is internally consistent and wrong. Case 10 showed the two records
behave differently under tampering; this shows the difference is usable, not
merely observable.

It also shows quarantine did not need new state here. The corrupt record is its
own marker, so the refusal is durable across reload and resume with nothing
added to remember it — a cheaper containment than case 02's flag, for the
narrow reason that the corruption is in the record the lifecycle already reads.

## What this does not prove

It does not close case 10's residual. Overwriting still works, and containment
is structurally blind to it.

It does not improve any confidentiality result. The appended rebinding it now
stops was already inert; what changes is that the object stops rather than
continuing on a record known to be corrupt.

It does not come free, and the direction of the cost is the opposite of the
benefit: the cheapest forgery in the model is now a guaranteed denial of
service for that object.

It says nothing about the skill registry, case 09's half of the trust root,
which a scope guard asserts from this side.

---

## Tests

`tests/adversarial/test_case_11_conflict_containment.py`
