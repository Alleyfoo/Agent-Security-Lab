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

### Claim 1 — split into two claims, and they stay split

The single sentence *"an agent can only cause effects through its authorised
skills"* is too strong while the process still has ambient OS authority. A
runtime with `socket()`, `open()` and `subprocess()` available does not care
what the skill registry says. **Frozen as two separate claims:**

```text
Application claim
    The agent runtime exposes externally consequential operations only
    through authorised skills.

Isolation claim
    The agent process possesses no ambient authority capable of bypassing
    that runtime.
```

| | Status |
|---|---|
| **application claim** | `prevented` for a Level 1 worker — case 09: a worker cannot create, modify, replace or select a skill definition through any interface it holds |
| **isolation claim** | **false today.** Case 06 measured it directly: same uid, same filesystem, network reachable, no resource limits, and three stages of four still share the runner's process |

**They must never be collapsed.** If they are, every later "security by
function" result quietly assumes a sandbox the application architecture did not
provide — which is the cosmetic-confinement failure mode this project exists to
avoid.

Stated positively, the split makes the idea stronger rather than weaker:

> **Security by function is only meaningful once raw authority has been removed
> underneath it.**

The application claim is layer 1 in `security-concepts.md` §0; the isolation
claim is layer 3. Case 06 is the only case that has ever moved the isolation
claim, and it moved it for one stage.

### Independence has layers, and "we used two agents" is not one of them

Case 15 points straight at this: two decisions are worthless if they share one
authority path. Naming the layers separately so a future case cannot claim
independence it did not measure:

```text
decision independence     a different actor and reasoning context
credential independence   the worker cannot exercise reviewer authority
state independence        the worker cannot mutate the record that makes
                          the reviewer appear to have approved
gate independence         neither worker nor reviewer can bypass or rewrite
                          the gate itself
```

Two model instances sharing one writable approval store and one service
credential have **decision** independence and none of the other three. That is
the shorthand this taxonomy exists to prevent.

A first case need not implement all four. It must say which ones it has.

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

### The sign-off contract — three separate properties

Frozen after case 19 measured them behaving differently. They are not one
requirement and must not be collapsed:

```text
CONTENT BINDING
    The approval applies to this exact action.

AUTHORITY INDEPENDENCE
    The worker cannot manufacture reviewer approval.

CONSUMPTION / FRESHNESS
    The approval authorises one specific execution occurrence.
```

**Content binding is necessary for integrity and insufficient for freshness.**
That is case 19's correction to the earlier draft of this document, which
implied binding the action was most of the job. R1 gives:

```text
the approval says exactly WHAT may happen
```

and not:

```text
the approval says WHICH OCCURRENCE may happen
```

So identical action content collapses distinct executions into one authority
object — and the rung that closed swapping opened replay by construction.

### An approval is a consumable, not a fact

The shift that made the difference. Not:

```text
reviewer approved X
```

but:

```text
reviewer grants one execution of X
```

Which implies state, and therefore a state transition the gate performs:

```text
approval = { action_digest, approval_id, state = unused }

gate, atomically:
    verify action_digest
    verify reviewer authority
    verify state == unused
    consume the approval
    execute the action
```

**Atomicity is load-bearing and case 19 does not measure it.** The obvious
failure is the classic one:

```text
check unused | check unused | execute | execute | mark used
```

Two executors racing one valid one-use approval. **Pre-registered as the next
sign-off case**, with the prediction that the current implementation loses the
race: `execute()` marks `consumed` only after the checks, with nothing between
them, so any concurrent caller passing the check first also executes.

### Action identity is not execution identity

Case 19 found that content binding cannot distinguish occurrences. Case 20
produced the identifier that does, and the pair should never be collapsed:

```text
action_digest   answers  WHAT was approved?
execution_id    answers  WHICH exercise of that approval is this?
```

Two legitimate operations can be byte-identical — *pay supplier EUR100* twice
is two occurrences of one action. A sink deduplicating on the action digest
would silently drop the second real payment, which case 20 asserts.

The chain that results, each layer answering its own question instead of one
identifier doing everything:

```text
object state
    -> action
    -> digest        -> proposal
                     -> approval
    -> one-use claim -> execution_id
                     -> external sink
                     -> receipt
```

### Reclaim, when it is eventually built

Case 20 left an approval stuck in `claimed` after a crash, deliberately
unmeasured rather than quietly designed away. A lease is the obvious answer and
immediately reintroduces the race:

```text
A claims -> A performs the effect slowly -> lease expires
         -> B reclaims -> B performs the effect -> A finishes
```

An idempotent sink saves this **only if both share an execution id**. If
reclaim mints a new one, duplication is back. So the invariant to pre-register
for that case:

> **Reclaim may transfer ownership of an execution, but must not create a new
> execution occurrence.**

Which implies the durable record owns the execution id, generated once at
approval, with the executor as the thing that changes:

```text
approval -> execution_id (generated once) -> claim(executor) -> reclaim(other)
```

Not measured. Recorded so it is not invented ad hoc later.

### What authority should actually bind to

Not the request. **`request_id` must not be security-sensitive at all** — it may
remain a correlation and debugging identifier, and nothing may authorise on it.
Authority binds to *action content*:

```text
ACTION = skill + object + parameters + object version/state (+ policy version)

action_digest = H(canonical(ACTION))

worker:    propose(action_digest)
reviewer:  approve(action_digest)
gate:      receives the actual action, independently computes
           H(actual_action) and requires it to equal both attestations,
           then executes *that action* - not whatever currently lives
           under request 123
```

One change of shape, several classes closed at once: re-pointing the join,
reusing an approval for a different action, mutating parameters after review,
and — if object version is in the digest — acting on a stale approval after the
object moved. Replay needs a nonce or lifecycle rule on top; the digest alone
does not close it.

This is what the first case must measure rather than assume.

### The hierarchy case 19 measured, and what is still missing

```text
R0   two records ≠ two-sided authority
R1   content integrity
R2   credential separation
R3   record integrity        (zero measured effect against the tested attacker)
R4   execution freshness / one-use

still missing:
     gate isolation
     store isolation
     ambient-authority removal
```

R3 measuring zero against this attacker does **not** mean append-only is
useless. It means its security contribution is threat-specific — it was
decisive in cases 10 and 11 on the artifact plane and did nothing here. Keeping
that distinction visible is one of the things this laboratory is for.

### The claim, stated as precisely as the measurements now allow

> Important actions require two independently authorised parties to attest to
> the exact action, and the resulting approval must be bound to a single
> execution lifecycle. The gate must enforce that binding. **This control
> applies only within the boundary in which the approval store and the gate
> remain trustworthy.**

The last sentence is the part usually missing from such statements, and case 19
measured it rather than assuming it: at every rung, one commit by an adversary
who can write the approval store defeats the whole mechanism.

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
