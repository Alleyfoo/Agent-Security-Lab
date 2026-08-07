# Case 16 — Authority reachability

**Phase:** 3 (authority model)
**Baseline finding:** case 15 — the attack all three models converge on is
invisible to an inventory diff
**Ladder level:** Level 1.5, the configuration adversary
**Baseline result:** `undetected`
**Controlled result:** `detected_after_occurrence`

---

## The question

Case 15 found that once useful authority exists, an attacker need not create or
widen anything — they change what *points* at it, and the standing inventory
does not move. So an audit asking *"did anybody gain new permissions?"* answers
**no** while effective access has changed completely.

There are three questions, not one:

```text
what authority exists?           ->  the inventory        (case 15)
what can currently reach it?     ->  this case
what does that combination permit?
```

Everything before case 15 concentrated on the first and third. The middle one
is the entire attack.

> **Audit authority reachability, not only authority inventory or changes to
> it.**

## Two views

```text
actual     work that reaches the authority as the deployment stands
potential  work that could reach it through a binding change alone —
           no new authority created, nothing widened
```

`potential` is what makes this an audit rather than an alarm: it flags the
exposure **at rest**, before any attack.

Each layer's idiom expresses the same structure differently, which is the point
of the layer model in [`docs/security-concepts.md`](../../docs/security-concepts.md) §0:

| Arm | Work | Reaches authority via | The question a reader asks |
|---|---|---|---|
| A | a stage | the subject it runs as | *this identity is legitimate, but these stages could run as it* |
| B | a step | the credential it names | *this credential is legitimate, but these steps could use it* |
| C | an object | the transformation its type requires | *this skill is approved, but these object types can cause it to run* |

## Results

```bash
python cases/16-reachability/attack.py
```

### At rest — before anything is attacked

| Arm | Paths in effect | Paths one binding away |
|---|---|---|
| A | 0 | **4** |
| B | 0 | **4** |
| C | 0 | **1** |

Nothing is wrong in any of these deployments. An inventory audit reports a
legitimate service identity, a legitimate connection and an approved skill. And
in each one, ordinary work is a single configuration change away from authority
it was never meant to touch.

**This is the more useful half of the case.** Detection after the fact is worth
less than a view that says *this is how exposed you are today*.

### Under case 15's invisible attack

| Arm | Inventory diff | Reachability diff |
|---|---|---|
| A | blind | **detects** |
| B | blind | **detects** |
| C | blind | **detects** |

And it names the route rather than raising an alarm:

```text
A  stage schema  --subject svc_keys--> artifact.key_material
B  step schema   --connection conn_ops--> artifact.key_material
C  object obj_812 as key_rotation --skill rotate_keys--> artifact.key_material
```

## Keeping two properties apart

The series had been letting *narrow blast radius* and *easy detection* blur
together. They are separate, and arm C shows why: it has the narrowest exposure
measured anywhere here (1 path against 4), its attack is the quietest by
inventory, and it is detected by reachability exactly like the others.

> A small blast radius neither brings detectability with it nor prevents it.
> Case 15's "narrow and quiet" is two findings, and only one of them is a
> problem this case addresses.

## Why this is honest rather than alarmist

A reachability view that counts routes which do not work would drown a real
deployment in noise. Two constraints keep it usable, and both are tested:

* **arm B does not count a credential that cannot carry the step.** `conn_keys`
  holds the target and covers nothing else, so rebinding a step to it *breaks*
  that step — case 15 measured exactly that. It is not a path.
* **an honest deployment reports zero.** Remove the identity, the credential or
  the skill and the potential set is empty in each arm, so a non-empty result
  is a fact about the deployment rather than an artefact of the query.

`potential ⊇ actual` is also asserted; if it ever failed, the two views would be
measuring different things and the diff would be meaningless.

## Residual limitation

**It is a detection, not a prevention.** `detected_after_occurrence` is the
honest class: the binding changes, the path appears, and something has to be
looking. Nothing here stops the edit.

**The view is computed from the records the adversary can write.** A Level 1.5
adversary who also rewrites the stored baseline snapshot defeats the diff — the
sixth appearance of the cross-cutting finding, and the reason the at-rest view
matters more than the diff. An exposure report is useful even if nobody trusts
the baseline.

**Signal-to-noise is unmeasured.** These deployments have four stages and two
credentials. A real one has thousands of potential paths, most of them
legitimate, and nothing here shows the view stays readable at that size. That
is the first thing to measure before claiming this is deployable.

**One target, one capability.** The view is computed for `artifact.key_material`
and nothing establishes that it generalises to every authority in a deployment.

**Reachability is one hop.** Only direct paths are computed. A path that needs
two binding changes, or that runs through an artifact produced by another
object, is not modelled.

---

## What this proves

That the middle question is answerable, in all three idioms, from records that
already exist — and that answering it detects the attack all three models
converge on, which the inventory diff could not see. It also shows the exposure
is visible *at rest*: in a deployment where an audit reports nothing wrong, the
view names how much ordinary work is one binding away from sensitive authority.

And it separates two properties the series had been conflating, using the arm
that made them look identical.

## What this does not prove

It does not prevent anything, and it does not survive an adversary who edits
the baseline it compares against.

It does not show the view scales. Four stages and two credentials is not a
deployment, and the noise question is the one that decides whether this is
useful outside a laboratory.

It does not make any arm safer than any other. All three were blind by
inventory and all three are detected by reachability — which is the point, and
is a statement about the principle rather than about any model.

---

## Tests

`tests/adversarial/test_case_16_reachability.py`
