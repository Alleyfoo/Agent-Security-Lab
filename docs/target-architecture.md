# Target architecture — bottom-up, object-driven

Restated direction. The important part is **the direction of control**: work is
driven by objects from below, not by a manager issuing instructions from above.

This document is the contract. Nothing here is built yet, and the sections
marked **measured** are the only ones with evidence behind them.

---

## 1. The model

```text
object  →  authorised skill  →  result / next object
```

A work object carries a **reference**, not instructions:

```text
call skill X on object Y
```

It does **not** carry free-form operational text. An agent may reason freely
about the object; its externally effective actions are limited to the skills
explicitly available to it. Skills are therefore part of the governance
boundary — an agent cannot invent a capability, call arbitrary infrastructure,
or enlarge its own authority.

Normal flow stays local. When the agent cannot complete safely — ambiguity,
authority exceeded, a defined risk condition — it raises an **exception** and
escalates upward to a reviewer with greater authority.

## 2. Two-sided sign-off

For important or irreversible actions, one component may propose but may not
execute:

```text
worker proposes  →  independent reviewer approves
                 →  execution gate verifies both
                 →  action executes
```

* the reviewer is independently authorised;
* the worker cannot forge, bypass, or grant itself that approval;
* the executor deterministically verifies that proposal and approval refer to
  **the same action on the same object** before executing.

## 3. The seven claims, and what is already known about each

| # | Claim | Status |
|---|---|---|
| 1 | An agent can only cause effects through its authorised skills | **partly measured — and false at Level 2** |
| 2 | Skills operate only on authorised object types/scope | **partly measured** |
| 3 | Compromising an agent must not enlarge its authority | **measured at Level 1, false at Level 2** |
| 4 | Routine work stays local | not measured |
| 5 | Errors, ambiguity and higher-risk decisions escalate upward | not measured |
| 6 | Important actions require a second independent authority | **not built — and the lab has a warning about it** |
| 7 | The execution layer, not the prompt, enforces this | standing rule, not yet a structural test |

### Claim 1 — effects only through authorised skills

Case 09 measured the closest thing: a worker cannot create, modify, replace or
select a skill definition through any interface it holds. That is real and it
is `prevented` **for a Level 1 worker**.

It is **false for a fully compromised agent process.** Case 06 measured an
isolated stage's ambient authority directly: same uid, same filesystem, network
reachable, no resource limits. An agent that can open a socket does not need a
skill to cause an effect. Claim 1 is therefore a claim about *the execution
layer's interfaces*, not about the process, and it must be stated that way or
it overclaims.

**What would have to be built:** the skill set as the only effect path implies
ambient authority is removed, which is an execution-isolation problem (layer 3
in `security-concepts.md` §0), not an application-layer one.

### Claim 2 — skills operate only on authorised object types

Partly present in `object_model`: `OBJECT_TYPES` limits which skills an object
type may run, and `verify_pins` binds the definition in use to the one the run
started with. Cases 12 and 14 found the weak point precisely: the *binding*
from object to skill is what an attacker moves, not the skill itself. Case 14's
arm-C pivot retyped an object so a different transformation became required.

### Claim 3 — compromise must not enlarge authority

Measured at Level 1 across cases 00, 03 and 04a: an agent using the interfaces
it holds cannot edit the receipt ledger, the routing table, or the identity an
event is attributed to. All three are `prevented`.

At Level 2 it is false and the repository says so in six places — the
cross-cutting finding. Case 01 is wholly open.

### Claim 6 — the warning the lab has earned

This is the one where existing measurement changes the design rather than
merely checking it.

> **Two approvals are only two premises if no single attacker-controlled
> selector can move both.** (Case 13, mapped in case 14.)

Case 13 built exactly this shape and measured it failing: a genuinely separate
record, genuinely consulted, worth nothing because both premises were looked up
by the same key the attacker could change. The obvious implementation of
two-sided sign-off has that shape:

```text
proposal record   keyed by (request_id)     written by the worker
approval record   keyed by (request_id)     written by the reviewer
execution gate    looks both up by request_id
```

If the worker controls `request_id` — or the object reference, or whatever the
gate joins on — then one edit re-points both lookups and the second signature
is decoration. Case 14's arm A is this failure exactly: reassigning *which
subject* the work ran as moved the permission check and the label check
together.

**Design conditions this implies**, all three of which are measurable:

1. the join key must not be writable by the proposer;
2. the reviewer's authority must not be derivable from anything the proposer
   controls — case 15's finding, since a reviewer identity that already exists
   and is reachable by ordinary work is a pre-existing authority the proposer
   can point at;
3. the gate must compare **the content of the action**, not just the presence
   of two records — otherwise an approval for action A executes action B, which
   is case 05's false-verdict shape moved to the approval plane.

## 4. What this changes about the current model

`object_model`'s `QueueItem(object_id, skill)` is already a reference rather
than an instruction, and `validate()` already re-derives the required skill
from the object's own state rather than trusting the item. That is closer to
this direction than it looks.

What is genuinely new: **escalation** (claims 4 and 5) and **two-sided
sign-off** (claim 6). Neither exists in any form, and neither has a case.

## 5. Recommended first slice

Claim 6, and only claim 6. It is the most security-critical, it is the one the
lab already has a measured warning about, and it is falsifiable in the way this
repository requires:

> Build proposal / approval / execution-gate as three records, then attack it
> as a Level 1.5 configuration adversary and measure the **minimum
> independently committed state changes** needed to make the gate execute an
> action no reviewer approved.

The prediction to pre-register, from cases 13 and 14: **the naive
implementation will measure 1**, because the join key is the pivot. If it
measures 1, the design conditions above are not advice — they are the finding.

Claims 4 and 5 (locality and escalation) need a definition of "risk condition"
before they can be measured at all, and that definition is a policy question
rather than a measurement.

## 6. Standing rule, unchanged

> Security must not depend primarily on prompts telling an agent what to do or
> not do. The restriction exists structurally in the runtime.

This is already a rejection criterion in `cases/README.md` and
`security-concepts.md` §4. Claim 7 makes it an architectural requirement, and
it should become an executable test: **no security-relevant decision may read
model-authored text.** Case 04b measured the closest existing instance — the
decision plane never reads the narrative event log — and that was found by
measurement rather than by design.
