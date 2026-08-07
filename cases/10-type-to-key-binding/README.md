# Case 10 — The type-to-key binding

**Phase:** 3 (authority model)
**Baseline finding:** case 08's cheapest surface — the artifact map
**Ladder level:** the case 08 attacker; may alter persisted policy or workflow
records, may not modify evaluator code
**Baseline result:** `undetected`
**Controlled result:** `detected_after_occurrence`

---

## Research question

> Can a stage obtain an unauthorized read by rewriting the record that binds an
> artifact type to a concrete key?

Case 08 measured this as the cheapest authority surface in the object model:
one edit, persisted, surviving resume, and reading as bookkeeping rather than
policy — which is why it was the surface that case nearly failed to test.
[Case 09](../09-skill-registry/README.md) deliberately left it alone and said
so in an executable scope guard.

## Map maintenance came first

Case 08's arm B never changed its artifact map: the harness set it up and
resolved against it. So "the workflow writes the map as it progresses" was a
statement about the architecture, not a measured property, and tampering
against a map nothing maintains would have measured nothing.

`object_model.evaluator` now has a real step lifecycle — resolve, execute,
record what was produced, advance the state, persist — and both arms of this
case run the same three-step workflow to completion. Untampered, they resolve
identical grants at every step. That parity is the precondition for the
comparison and is asserted, not assumed.

## The two arms

```text
stored    the object carries {artifact_type: key}; a completed step writes
          its output into that map, and the map is persisted with the object

derived   a runner-owned append-only ProductionLedger records what each
          completed step produced; the map is computed from it, first
          production wins, and a type may be produced at most once per object
```

The derived arm is the same move case 08 tested one level up, applied to the
map itself: the map is a stored *conclusion* — "type T is at key K" — and the
premises are older and narrower. A step ran, it was required, and it produced
one artifact of one type.

## Attack

```bash
python cases/10-type-to-key-binding/attack.py
```

Three attacks, all mid-flight against a live workflow.

### Results

| | stored | derived |
|---|---|---|
| A rebind an existing binding, through the API | **obtained** | refused |
| A rebind, appended past the API | **obtained** | inert — and the conflict stays visible |
| A rebind, by overwriting the existing record | **obtained** | **obtained** |
| B pre-seed a type before its producer runs | no | no — but see below |
| C tamper after completion, then resume | **obtained** | no — conflict visible |

**Minimum tamper set is 1 in both arms.** As in case 08, the count does not
separate them. What separates them is the *kind* of edit that works.

### A — Rebinding

In the stored arm every route works, because the map is a dict and a write is a
write.

In the derived arm the API refuses outright:

```text
'table_preview' was already produced for 'obj_812' at key 'artifact.raw_input'
by 'intake'; refusing to record it again at 'artifact.key_material'
```

Reaching past the API and appending anyway is **inert** — first production
wins, so the forged record does not take effect — and it leaves a conflict the
record still shows:

```text
conflicts: ["'table_preview': 'artifact.raw_input' then 'artifact.key_material'"]
```

Only *overwriting* the existing record works, and that is a different operation
from appending: it destroys the evidence rather than adding to it.

### B — Pre-seeding a future type

Ineffective in both arms, for different reasons, and the derived arm's reason
is a liability rather than a defence.

Stored: the legitimate producer overwrites the pre-seeded entry when it runs,
so the attack is simply pointless.

Derived: the legitimate producer **fails permanently**.

```text
the legitimate producer FAILED: LedgerIntegrityError: 'cleaned_output' was
already produced for 'obj_812' at key 'artifact.key_material' by 'attacker';
refusing to record it again at 'artifact.cleaned_output'
```

The invariant that makes rebinding hard also makes the workflow brittle. One
forged append and that object can never complete — a denial of service the
stored map does not have. This was not predicted; it fell out of the
measurement.

### C — Surviving resume

The attack case 08 identified as the map's worst property. In the stored arm
the tampering survives reload and a resumed run reads the wrong key. In the
derived arm the appended record is inert on reload as well, and
`conflicts_for()` still reports it — the ledger is reloaded from its JSONL
file, conflicts and all, precisely so this is measurable rather than an
artefact of in-memory state.

## Observed unsafe result — `undetected`

In the stored arm all three of A's routes and attack C obtain the capability
and nothing anywhere notices. The map is not compared against anything, because
there is nothing to compare it to: it *is* the record.

## Control — derive the map, do not store it

`ProductionLedger` records `(object_id, at_state, skill, artifact_type, key)`
for every completed step, append-only by API, with one invariant: **an artifact
type is produced at most once per object.** `artifact_map()` derives the
binding from it, first production winning.

> **Guarantee:** rebinding a type that has already been produced is refused
> through the interface, inert if appended past it, and visible as a conflict
> afterwards. Only destroying the original record works, and that is a louder
> operation than a dictionary write.

`detected_after_occurrence`, not `prevented`: a Level 2 adversary that
overwrites the record still wins, and nothing stops the write.

## Residual limitation

**Overwriting an existing production record still works**, with the same
minimum tamper set as the stored map. The ledger is append-only *by API*, in
the same sense as the product's `EventLog` — it is not tamper-evident, there is
no chain binding the entries, and same-process code reaches `_records`. This is
the sixth appearance of the cross-cutting finding.

**The invariant is a denial-of-service surface.** One forged append for a type
not yet produced permanently prevents its legitimate producer from recording,
and the object cannot complete. The stored map has no equivalent weakness. A
control that trades silent corruption for loud unavailability may well be the
right trade, but it is a trade and it is recorded as one.

**Conflicts are reported, not acted on.** `conflicts_for()` will tell a caller
the record contradicts itself; nothing calls it during a run. Making
conflict-checking part of the step lifecycle is a further claim this case does
not make.

> Closed by [case 11](../11-conflict-containment/README.md), which made the
> step lifecycle read it. That case also measured what it costs, and found the
> control is blind to the overwrite residual above — a contradiction is what an
> *append* leaves behind, and only appends leave one. This case's own
> measurements are unchanged: they are taken at `derive_grant`, which has no
> containment and deliberately did not grow one.

**The ledger is not an independent authority**, for the same reason case 09's
version pin is not. It records what happened in this process, and a Level 2
adversary edits the record of what happened.

## Containment response

None automatic. The API refusal stops the ordinary path; past it, the
derivation makes the tampering ineffective rather than detected-and-halted, and
the conflict sits in the record until something looks. Reporting a conflict as
an incident during the step lifecycle is the obvious next control and is
deliberately not built here — it became case 11.

## Recovery requirement

Better than the stored map, and this is the derived arm's clearest practical
advantage: the original binding is still in the record. First-production-wins
means recovery is *already what happens* — the legitimate value is what the
derivation returns. In the stored map the original key is simply gone, and
there is nothing to recover it from.

## Blast radius

Unchanged in reach, changed in durability. A successful edit affects one
object, including its retries and resume. In the derived arm an append-shaped
edit affects nothing and a DoS-shaped edit stops that object permanently.

---

## What this proves

That the shape of a record decides what tampering with it costs, independently
of how well it is protected. The stored map and the derived ledger are both
unprotected in-process data with a minimum tamper set of one, and they behave
completely differently: a dictionary write is total and silent, while an
append-only record with a produced-once invariant makes the cheap edits inert
and leaves the contradiction in place.

It is the first case in this comparison series where the derived model is
materially better rather than merely different — three of five measured cells,
including the resume case case 08 called the map's worst property.

## What this does not prove

It does not close the surface. Overwriting a production record obtains the
capability at the same cost as before, and the ledger is append-only by API
rather than tamper-evident.

It does not come free: the produced-once invariant introduces a
denial-of-service the stored map does not have, and that finding came out of
the measurement rather than the design.

It does not make the ledger an independent authority, and it does not touch the
skill registry, which case 09 measured as the wider-scope surface of the two.

---

## Tests

`tests/adversarial/test_case_10_type_to_key_binding.py`
