# Case 13 — Does a second independent premise raise the cost?

**Phase:** 3 (authority model)
**Baseline finding:** case 12's principle, and the prediction pre-registered
from it
**Ladder level:** the case 08 attacker, unchanged from case 12
**Baseline result:** `undetected`
**Controlled result:** `undetected` — an experiment on laboratory arms; it
applies no control to the product

---

## The pre-registered prediction

Written into `cases/REPORT.md` **before this case was built**, which is the
whole point of pre-registering it:

> If the principle is architectural rather than incidental to arm B, then
> adding a second independent premise to arm A or arm C should raise that arm's
> minimum tamper set to 2 — without changing which model it is. If it does not,
> the principle is really a fact about workflow configuration.

The principle under test, from case 12:

> Authority is harder to forge when it must be derived from independent
> premises than when it is read from one writable conclusion.

## Result: confirmed, under two conditions the prediction did not state

```bash
python cases/13-second-premise/attack.py
```

| Configuration | Minimum tamper set |
|---|---|
| A — permission table only (case 12) | 1 |
| A — + label policy, **domain keyed on the subject** | **1** |
| A — + label policy, **domain keyed on the stage** | **2** |
| C — binding + skill contract (case 12) | 1 |
| C — + artifact declaration | **1** |
| C — + artifact declaration + object-type read policy | **2** |

Two of the four configurations with a second premise still sit at 1. The
principle is real and it is not automatic.

### Condition 1 — the premises must not share an index the attacker can pivot

Arm A's second premise is a MAC-style label policy over the DAC permission
table: a subject's domain and a resource's type must be allowed to meet. Not
invented for the comparison — it is the structure of SELinux and AppArmor.

Both single widenings now fail:

```text
widen the permission table only   no   (the label policy denies)
widen the label policy only       no   (the permission table denies)
```

And then, keyed on the subject:

```text
reassign the subject only         OBTAINED
```

One edit. The label policy is a genuinely separate record, genuinely consulted,
and worth **nothing** against this route — because both premises answer a
question *about the subject*, so changing which subject the stage runs as moves
both at once.

Key the domain on the **stage** instead — which is what SELinux actually does,
deriving a domain from a transition on the executable's label rather than from
the uid — and the identical attack fails. The only difference between the two
rows is what the second premise is looked up by.

> **Independence of records is not sufficient. The premises must not be
> functions of the same attacker-controlled key.**

This is the confused-deputy shape arriving in the authority model: the attacker
does not forge a permission, it changes which principal the question is asked
about.

### Condition 2 — one premise per authority surface, not per model

Arm C's second premise is that artifacts declare what they are: the artifact at
key *K* carries `(object_id, artifact_type)` and the binding must agree with
it. Idiomatic rather than bolted on — canonical artifacts carrying their own
identity is on the concept note's list of what they are *for*.

It closes case 10's surviving route completely:

```text
overwrite the binding only        no   (the artifact disagrees)
```

And does nothing whatever about the other one:

```text
widen the skill contract only     OBTAINED
```

Because the skill-contract route never lies about *which artifact* is which. It
widens what the transformation may read, and the artifact at that key honestly
declares itself to be exactly the type the widened contract now asks for.

Adding a second premise for that surface — the object type declares which
artifact types may be read on its behalf — brings the minimum to 2.

> **A premise raises the cost of the surface it covers, and only that surface.
> An arm with more authority-bearing surfaces needs more premises to reach the
> same minimum tamper set.**

That is a direct cost to the object model, and it compounds case 12's finding.
Case 12 measured it as having the most authority-bearing records (5, of which 2
yield). This case measures the consequence: it needed **two** added premises to
reach the tamper cost arm A reached with one, and arm B had by accident.

## What this does not change

**The bound still holds and is still the important half.** Every premise here
sits inside the same adversary's reach. Two edits is a price, not a wall. This
case raises prices; it does not move anything outside the boundary, and the
cross-cutting finding is untouched.

**Nothing here is a control in the product.** Both arms are laboratory
reference models. `object_model/` is not modified — case 13 layers onto case
12's arms, and case 12's arms are frozen because they published a table. A test
asserts both.

**One capability, one workflow position, one attacker**, exactly as narrow as
cases 08 and 12.

---

## What this proves

That case 12's principle is architecture-neutral, as claimed — it worked in an
identity model and in an object model, neither of which had it before — and
that it is conditional in two ways nobody had stated. A second premise buys
nothing if it is keyed on something the attacker can pivot, and it buys cost
only on the surface it covers.

Stated as a rule that can be applied rather than admired:

> To raise the cost of forging authority, add a premise that is (a) consulted
> at use time, (b) not a function of an index the attacker can change, and (c)
> on the specific surface being defended. Missing any of the three buys
> nothing.

## What this does not prove

It does not show any of these arms is now secure. Two edits is a price and
every premise is inside the adversary's reach.

It does not show the object model is worse — it shows expressiveness is paid
for in premises, which is a cost, not a defect, and one a designer can choose
to pay.

It does not test the principle beyond one capability at one workflow position,
and a surface no premise covers is unaffected by any of this.

---

## Tests

`tests/adversarial/test_case_13_second_premise.py` — every cell above, plus
assertions that each added premise is genuinely consulted, that neither breaks
the honest run, and that case 12's arms still measure what they published.
