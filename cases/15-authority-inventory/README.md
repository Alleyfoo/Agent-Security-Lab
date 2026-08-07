# Case 15 — The authority inventory

**Phase:** 3 (authority model)
**Baseline finding:** case 14 — both yielding pivots depended on what the
deployment already contained
**Ladder level:** Level 1.5, the configuration adversary
**Baseline result:** `undetected`
**Controlled result:** `undetected` — an audit, not a control

---

## The question

> What pre-existing authority in a normal deployment turns a narrow compromise
> into a broad one?

Cases 12–14 measured architectures. This measures **deployments**. For each
model, one piece of authority a normal competent installation plausibly holds:

```text
arm A   an identity that already holds the target authority
arm B   a credential scoped across two boundaries
arm C   an approved skill that legitimately reads the target
```

None is a misconfiguration in the ordinary sense. Somebody's job needs key
material, somebody's integration spans two systems, somebody's workflow rotates
keys. They are what a deployment accumulates.

## The instrument this case adds

Commits and scope were already measured. The new one is the **standing
authority inventory** — what an auditor would list if asked *who or what may
reach this today*:

| Arm | Inventory |
|---|---|
| A | every `(subject, key, operation)` the permission table grants |
| B | every `(connection, key)` any credential's scope reaches |
| C | every `(skill, artifact type)` an approved contract declares readable |

And the measurement is whether the attack **changes** it. An attacker who must
*create* authority appears in a diff of what authority exists. An attacker who
only has to *point at* authority that already exists does not.

## Results

```bash
python cases/15-authority-inventory/attack.py
```

| Arm | Pre-existing authority | Commits | Scope of the cheapest edit | Audit sees it |
|---|---|---|---|---|
| A | absent | 1 | every future run by that subject | yes |
| A | **present** | 1 | every future run by that subject | **NO** |
| B | absent | 2 | every run of the definition | yes |
| B | **present** | **1** | every run of the definition | **NO** |
| C | absent | 1 | every object until redeployment | yes |
| C | **present** | 1 | **one object** | **NO** |

### The finding, and it is architecture-independent

> In all three models, the cheapest yielding edit against a deployment that
> already holds the authority **leaves the standing inventory unchanged**. The
> attacker stops having to create authority and only has to point at it.

Without the pre-existing authority, the cheapest yielding edit is visible in
every arm. With it, it is invisible in every arm. The models differ in
everything else and agree on this.

### The benefit to the attacker takes three different shapes

Reporting only one number would have hidden two of the three.

* **Arm A — visibility only.** Same cost, same scope. Reassigning the stage to
  `svc_keys` creates no authority anywhere; the permission set is untouched, so
  a permissions audit sees exactly what it saw yesterday. Remove that identity
  and the route disappears entirely — the model refuses a subject it does not
  know. The route was never about the permission table; it was about the
  deployment.
* **Arm B — the cost halves.** 2 commits become 1. Case 12 credited arm B's
  minimum of 2 to the architecture; it belongs to the deployment not containing
  a credential that spans both sides. With one present, a single write to the
  step record points at it, and the credential inventory never changes.
* **Arm C — the scope collapses.** Same cost, and the edit required drops from
  *deployment-wide* to *one object*. Widening a skill contract reaches every
  object until redeployment and is exactly what a skill audit lists. Retyping
  one object to a permissive type that already exists reaches one object and
  lists as nothing.

That last one is the object model's expressiveness cutting the other way from
case 14: narrow per-object bindings are a real advantage, and they also give an
attacker a narrow, quiet edit where the alternative was broad and loud.

## What this says about controls

The control this suggests is an **inventory audit, not a change diff**. A diff
of what changed cannot see an attack that changes nothing an auditor lists, and
in every arm that is the attacker's preferred route once the authority is
there.

The question an audit has to ask is not *what changed* but:

> What authority exists in this deployment, what could point at it, and would
> anyone notice if something did?

## Residual limitation

**One item per model.** A real inventory has many, and the interactions between
them are unmeasured. Nothing here says these three are the most important ones,
only that each is plausible and each is sufficient.

**"Normal deployment" is a judgement, not a measurement.** Each item is argued
for in prose and none is drawn from a survey of real installations. A reader who
thinks an over-scoped credential is not normal should discount arm B's row
accordingly — the case's structure survives, the plausibility claim is the soft
part.

**The inventories are the ones this case defined.** A different auditor listing
different things would get different visibility answers. A test asserts each
inventory can at least see the target authority, so "unchanged" is a real
result rather than an artefact of listing the wrong thing.

**No control, no detection, no containment** is added by this case.

---

## What this proves

That the same architecture is more or less exposed depending on what its
deployment already holds, and that the effect is measurable in three
independent ways — cost, scope, and visibility to an audit. It also shows the
three models agree on something for the first time: whatever else differs,
pre-existing authority converts the attack from creating authority to pointing
at it, and that conversion is invisible to a change diff in all three.

It converts case 12's arm B result one step further. Case 14 showed its two
premises live in one record; this shows its remaining advantage depends on the
credential inventory, and measures what it costs when that inventory supplies a
target.

## What this does not prove

It does not show any model is safer. Every arm has a yielding route with and
without the pre-existing authority; what changes is cost, scope and visibility,
not possibility.

It does not establish that an inventory audit would catch anything. The case
argues that a change diff cannot see these attacks and does not build or
evaluate the audit that could.

It does not measure interactions between multiple pieces of pre-existing
authority, which is where a real deployment lives.

---

## Tests

`tests/adversarial/test_case_15_authority_inventory.py` — every cell, the three
shapes of benefit, and two assertions about the instrument itself: that each
inventory can see the target authority, and that the "cheapest route" model
prefers invisibility over narrow scope, which is what an attacker with two
equal-cost routes would do.
