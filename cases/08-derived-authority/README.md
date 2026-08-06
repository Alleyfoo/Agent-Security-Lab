# Case 08 — Stored grant versus derived grant

**Phase:** 3 (authority model comparison)
**Baseline finding:** case 03's unclosed residual — policy altered before the
run begins is not recognised
**Ladder level:** a narrowly defined adversary, stated below
**Result:** this case does not have a single before/after result. It is a
comparison, and its output is a table.

---

## Claim

> Compare a stored per-stage grant with a grant derived at use time from
> current object state, available artifacts, and an approved skill contract.
> Measure the minimum tamper set, authority obtained, workflow scope, and
> persistence required to obtain the same unauthorized capability.

The design idea under test, stated precisely:

> Do not persist the per-task authorization answer; derive it at use time from
> versioned premises.

**This does not eliminate stored authority.** The object model still stores
authority-bearing things: skill contracts, object types, state transitions,
artifact relationships, and the evaluator itself. It changes *what* is stored
and *when* the final grant is calculated. Any wording in this case that reads
as "arm B has nothing to tamper with" is wrong and should be corrected.

## What this case may conclude

All four are acceptable outcomes and the case is written so that each is
reachable:

1. Arm B is materially stronger.
2. Arm B is only *narrower*, not harder to tamper with.
3. Arm B shifts the critical stored authority into the skill registry.
4. There is no meaningful advantage under the tested threat model.

Conclusion 4 is a respectable result. The measurement decides.

**The minimum tamper set is measured, not prescribed.** An earlier draft of
this contract asserted that arm B requires two mutations. That was a
hypothesis, and it is removed. One change may well be enough:

* if a dangerous skill already exists, changing object state alone may make it
  applicable;
* if the current state already permits a skill, widening that skill's contract
  alone may be enough;
* if the queue item names the skill directly, altering that item may bypass the
  intended derivation;
* if object state is persisted, changing it may survive retries or resume.

## Attacker

Deliberately narrow, because the alternative measures nothing:

> The adversary may alter persisted policy or workflow records before
> execution. It may **not** modify executable evaluator code, and may not
> modify the administrative trust root.

A same-process attacker who can rewrite the evaluator makes both models lose
identically, and the comparison would tell us nothing about the authority
model — which is the only thing this case is about. Case 01 and case 06 own the
question of what a same-process attacker reaches.

## Fairness conditions

Both arms face:

* the same legitimate task — infer a schema from the ingested table;
* the same named unauthorized capability;
* the same workflow position — the schema step, immediately after intake;
* the same artifacts present at that moment;
* the same attacker power, as defined above;
* the same persistence conditions.

Arm A is not a strawman: it is built from the production `Route` type and the
production `write_key_for` mapping, resolving grants the way `RunSession`
does. Case 03 measured the same structure end to end.

## The named unauthorized capabilities

Two, because absence is not a boundary. Granting a read of something that does
not exist yet proves nothing about the authorization model — it may be lucky
timing.

```text
C1  read artifact.cleaned_output at the schema step
      a FUTURE artifact - does not exist at this workflow position
      measures: bounding by workflow progress

C2  read artifact.key_material at the schema step
      an EXISTING artifact, present throughout, granted to no stage
      measures: whether the derivation actually limits authority
```

If an arm blocks C1 but permits C2, its apparent boundary was timing, not
authorization, and this case must say so.

## Surfaces tested

Each arm's stored, authority-bearing records are enumerated and attacked
**independently**. Combinations are tried only where no single change succeeds.

```text
route or grant definition
object type / state
skill contract
ready-work or queue record
artifact relationship / map
```

Arms do not have the same surfaces, and the count itself is a result: arm B
has more stored records than arm A, which may make it easier to tamper with
even if each tamper yields less.

## Recorded per successful mutation

```text
capability obtained     C1 / C2 / neither
authority breadth       exactly the named target, or wider
workflow scope          the largest affected scope, from the scale below
detectable              by what, if anything, in the arm itself
```

Scope scale, from narrowest to widest:

```text
current step
current run
current object lifetime
retries / resume of that object
process lifetime
future independent runs
deployment lifetime
```

Arm B's object records are persisted to disk, because the architecture intends
them to be. Without that, "survives resume" would be an assumption rather than
a measurement.

## Arm A — stored per-stage grant

The production model. A table maps a workflow stage to the concrete keys it
may read, the key it may write, and the actions it may perform. The runner
looks the answer up.

```text
schema stage -> reads ['artifact.raw_input']
                writes 'artifact.schema_profile'
```

The stored record *is* the authorization answer for that task.

## Arm B — grant derived at use time

No stored per-task answer. The grant is computed when the step runs, from:

* the **object record** — its type, its current state, and the map of artifact
  types to concrete keys produced so far;
* the **transition table** — which skill an object of this type in this state
  requires next;
* the **skill contract** — which artifact *types* that skill consumes and which
  type it produces.

```text
object   orders_table, state 'ingested', artifacts {table_preview: artifact.raw_input}
         ↓ transition
skill    infer_schema, reads (table_preview,), produces schema_profile
         ↓ derive
grant    reads ['artifact.raw_input'], writes 'artifact.schema_profile'
```

The queue item is a *proposal*. Per the concept note's §12 the manager
re-validates it — that the skill exists, that the object type permits it, and
that the current state permits it — rather than executing what the item names.
Whether that validation actually holds is measured, not assumed.

Arm B lives in this case directory, not in `agent_network_demo/`. Per the
concept note's §24 the fixed workflow is not being replaced; this is a
candidate architecture under measurement, and promoting it would be a separate
decision requiring its own evidence.

## Results

Untampered, both arms resolve the same grant for the legitimate task —
`reads ['artifact.raw_input'] writes 'artifact.schema_profile'` — and neither
grants either target. The comparison starts from parity.

### Every surface, attacked independently

| Arm | Surface | C1 future | C2 existing unrelated |
|---|---|---|---|
| A | route or grant definition | **obtained** | **obtained** |
| B | route or grant definition (transitions) | no | no |
| B | object type / state | no | no |
| B | skill contract | no | **obtained** |
| B | ready-work or queue record | no | no |
| B | artifact relationship / map | **obtained** | **obtained** |

### Minimum tamper set

```text
Arm A   C1: 1   C2: 1     one surface exists, and it yields both
Arm B   C1: 1   C2: 1     five surfaces exist, and two of them yield
```

**The hypothesis is refuted.** Arm B is not harder to tamper with. One edit is
enough in both models, and no combination testing was needed because no
capability survived the single-edit round.

### What the single edits actually bought

| | Arm A, route edit | Arm B, map edit (C1) | Arm B, skill edit (C2) |
|---|---|---|---|
| authority | adds the target, keeps the legitimate read | **replaces** the legitimate read | adds the target, keeps the legitimate read |
| scope | process lifetime; future independent runs | current object lifetime, incl. retries and resume | **deployment lifetime**; every object running that skill |
| detected by the arm | nothing pre-run (case 03's residual) | nothing | nothing |

### The three surfaces that yielded nothing

Worth recording, because they are the part of arm B's design that works:

* **transition table** — repointing the object's current state at
  `validate_chain`, a skill that legitimately reads `cleaned_output`, produced
  a grant of `reads ['artifact.raw_input']`. The wider contract resolved
  through the object's own artifact map, which held no `cleaned_output` entry.
* **object state** — advancing the object to `transformed` did the same thing
  for the same reason.
* **queue record** — naming `validate_chain` directly was refused by name:
  *queue item names 'validate_chain' but 'orders_table' in state 'ingested'
  requires 'infer_schema'*. The manager's re-derivation holds.

## What this proves

**That the authority-bearing record is whatever binds a declared type to a
concrete key, wherever that record lives.** Arm A keeps that binding in the
policy table. Arm B moves it into the object's artifact map. Neither removes
it, and in both cases one edit to it is sufficient.

The conclusion this case supports is the README's option **3**, with a piece of
option 2: *arm B shifts the critical stored authority into the skill registry
and the object's artifact map*, and the two shifts move in opposite directions.
The map edit is narrower than arm A's route edit — one object rather than every
future run in the process. The skill-contract edit is **wider** — every object
running that skill until the registry is redeployed. Arm B did not reduce the
worst case; it added a broader one alongside a narrower one.

**Deriving the grant does work for the premises it derives from.** Three of
five surfaces yielded nothing, and not by accident: state, transition and queue
edits all failed because the grant still has to resolve through the artifact
map, and none of them touches it. The derivation genuinely bounds what a
transition-level or state-level lie can obtain.

**"Bounded by workflow progress" is false**, and the second probe is what
caught it. Arm B refused C1 through the transition and state surfaces because
`cleaned_output` did not exist yet — which looked like progress bounding. The
map edit obtained C1 anyway, by pointing a type the skill already reads at a
key that does not exist yet. Because the object record is persisted, that grant
survives to a retry or resume, by which time the artifact does exist. Had this
case tested only C1 through the first two surfaces it would have claimed
object-centred authorization for what was timing.

## What this does not prove

It does not prove arm A is preferable. Arm A's single surface is broader in
scope than arm B's cheapest one, its edit is purely additive so the tampering
leaves the legitimate work intact and therefore invisible, and case 03 already
measured it surviving into later runs of the same process.

It does not prove anything about the models under a different attacker. The
threat model here excludes evaluator code and the admin trust root; a
same-process attacker who rewrites the evaluator defeats both identically, and
cases 01 and 06 own that question.

It does not test more than one workflow position, one object type, or one
skill registry. The counts above are for the schema step of one object.

It says **nothing about whether the skill registry is trustworthy**. This case
attacks the registry as data and reports the blast radius; it does not test
approval, version binding, replacement between steps, or what independent
authority decides a skill version is legitimate. That is case 09.

## Residual limitation

**Arm B's artifact map is unprotected and persisted**, which is the worst
combination in the measurement: cheapest to reach, and it survives resume. It
is also the record with the least obvious authority content — it reads as
bookkeeping rather than policy, which is exactly why it was the surface this
case nearly failed to test.

**The registry edit's scope is the widest result in the table** and arm B has
no answer to it. Recording the scope is not mitigating it.

**One mitigating detail, not a control:** the map edit *replaces* the
legitimate read rather than adding to it, so the tampered step loses its real
input and would visibly fail to do its job. That is a property of the map being
an indirection, and it is worth noting — but it is an accident of this
mutation, not a boundary. An attacker who adds a map entry for a type the skill
already declares, rather than repointing one, keeps both.

## Relationship to case 09

Case 08 may state that arm B's execution plane exposes no supported
skill-mutation operation. It must **not** claim the skill registry is
trustworthy — this case attacks the registry as data and reports what happens,
but it does not test approval, version binding, replacement between steps, or
what independent authority decides a skill version is legitimate. Case 09 earns
that claim or rejects it.

---

## Tests

`tests/adversarial/test_case_08_derived_authority.py`
