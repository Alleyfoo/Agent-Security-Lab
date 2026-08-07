# Case 14 — The selector map

**Phase:** 3 (authority model)
**Baseline finding:** case 13's condition 1 — a premise that looks independent
and is not
**Ladder level:** Level 1.5, the configuration adversary (named in this slice)
**Baseline result:** `undetected`
**Controlled result:** `undetected` — an enumeration, not a control

---

## The question

> What facts does authority depend on, and which of those facts can one
> attacker-controlled pivot change simultaneously?

Case 13 found *an* example of false independence. This does not look for
another; it enumerates the selectors across all three arms and executes every
pivot the map implies.

**A premise** is a fact authority depends on. **A selector** is what that fact
is looked up by. The distinction is the case:

> Two records are independent. Two *premises* are independent only if no
> attacker-alterable selector reaches both.

## The map

```bash
python cases/14-selector-map/attack.py
```

`*` marks a selector the Level 1.5 adversary can alter.

| Arm | Premise | Stored in | Keyed by |
|---|---|---|---|
| A | may this subject read this key? | permission table | subject\*, key |
| A | may this domain meet this type? | label policy | subject\*, key |
| A | …the same, stage-keyed | label policy | stage, key |
| B | does the step name this key? | workflow definition | step record\* |
| B | does the connection reach this key? | connection scope | step record\*, connection\* |
| C | which key holds this artifact type? | production ledger | object\*, artifact type |
| C | which types may this skill read? | skill contract | skill name |
| C | which skill does this object require? | transition table | object type\*, state\* |
| C | does the artifact declare itself? | artifact declaration | key |
| C | may this object type have this type read? | object-type policy | object type\* |

The transition table is on the **execute** path — it governs which
transformation runs, not what it may read. A reader would reasonably assume
otherwise, so a test pins it.

## Every shared selector, pivoted

| Arm | Selector | Pivots in one edit? |
|---|---|---|
| A | the subject the stage runs as | **YES** |
| A | the stage/executable being run | no |
| B | the connection the step names | no |
| B | the workflow step record | no |
| B | the workflow step record — *over-scoped tenant* | **YES** |
| C | the object id | no |
| C | the object type | no |

**2 of 7.** The five that do not are where the case earns its keep, because
they fail for four different reasons.

### Arm A — the pivot that works

Case 13's finding, now located on the map rather than discovered by accident.
Both premises are keyed by the subject, so reassigning which subject the stage
runs as moves both at once. Key the domain on the stage instead — a selector
this adversary does not control — and the identical edit yields nothing.

### Arm B — independence that belongs to the deployment, not the architecture

Two findings here, and both qualify case 12's headline.

**The unit of measurement matters.** Case 12 counted *field* mutations and
reported a minimum tamper set of 2. Two of the three fields it counted — the
input list and the connection name — are fields of **the same step record**, and
an adversary with write access to the workflow definition sets both in one
write. Counted in records rather than fields, arm B's two premises are one
write apart.

**It still holds in an ordinary tenant — for a reason that is not
architectural.** The single record write fails closed because no existing
connection reaches both the step's legitimate inputs and the target. Give the
tenant one ordinary over-scoped credential — pre-existing state, established
before the attack and not counted as an edit — and the same single write
obtains the capability.

So arm B's advantage in case 12 was real and was **being enforced by the
competence checklist**, not by the architecture. That is worth knowing precisely
because over-scoped connections are the most common misconfiguration in real
workflow tenants. A test asserts that the over-scoped credential is exactly what
case 12's checklist rejects, so this cannot be read as arm B being strawmanned.

### Arm C — a pivot that moves a premise and still loses

The most useful negative in the case. Retyping the object to a permissive type
that already exists in the deployment **does** move a premise: afterwards the
object-type read policy genuinely admits `key_material`. It obtains nothing,
because a third premise on a different selector — the skill contract, keyed on
the skill name — still says `infer_schema` reads `table_preview` and nothing
else.

`moved` and `obtained` are reported as separate columns for exactly this cell.
A pivot that shifts a premise and still fails is a different result from one
that shifts nothing, and collapsing them would hide which premise did the work.

This is the clearest measured instance of the principle: arm C's premises are
keyed by genuinely different things, so no single alterable selector reaches
two of them in a way that yields.

## The inversion worth stating

Case 12 measured arm C as having the most authority-bearing records and being
among the cheapest to attack. On *selector hygiene* the ordering reverses: the
simplest architecture has the worst pivot exposure, and the most expressive has
the best.

| Arm | Records | Yielding pivots |
|---|---|---|
| A — identity | fewest | **the most** |
| B — workflow | middle | one, and only given a common misconfiguration |
| C — object | most | **none** |

These are not contradictory measurements; they are different questions. How many
records hold authority is not how many of them one edit can move.

## Residual limitation

**One capability, one workflow position, one adversary.** Unchanged from cases
08, 12 and 13, and a different target could expose selectors this map does not
list.

**The map is hand-built and its completeness is asserted, not derived.** A test
requires every shared alterable selector to carry an executed pivot — which
caught one missing pivot while this case was being written — but nothing proves
the premise list itself is exhaustive. A premise nobody wrote down has no
selector on this map.

**`alterable` is a judgement per selector**, recorded as data so it can be
argued with. The classification says the artifact key and the skill name are not
directly writable by this adversary; both are *derived* from records it can
write, and a longer chain than this case follows might reach them.

**Nothing here is a control.** No arm was changed and no product code was
touched.

---

## What this proves

That independent records and independent premises are different things, and
that the difference is measurable rather than rhetorical. Seven shared selectors
were executed; two collapse two premises into one edit, and the five that do not
fail for four distinguishable reasons — an unalterable selector, an absent
target in the deployment, an empty lookup, and a third premise keyed on
something else.

It also converts case 12's arm B result from an architectural claim into a
conditional one: two premises, one record, and an advantage that depends on the
credential inventory.

## What this does not prove

It does not show arm C is secure. It has no yielding pivot *on this path for
this capability*, which is a narrower statement than it sounds, and case 12
measured its minimum tamper set at 1 by two routes that need no pivot at all.

It does not close anything. Every premise remains inside the Level 1.5
adversary's reach, and this case adds no control, no detection and no
containment.

It does not establish that the premise list is complete for any arm.

---

## Tests

`tests/adversarial/test_case_14_selector_map.py` — every pivot, both negatives
that matter, the completeness check on the map, and the assertion that arm B's
over-scoped credential is what case 12's checklist forbids.
