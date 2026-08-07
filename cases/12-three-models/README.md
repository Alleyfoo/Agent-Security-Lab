# Case 12 — Three models, one workflow

**Phase:** 3 (authority model)
**Status:** **contract only — nothing built, nothing measured.**
**Not yet registered** in `cases/registry.py`, because it has no results and a
registered case must ship a runnable attack.

---

## The question

> Does the object/reference/skill model have fundamentally different security,
> data-flow, and failure properties from established ways of connecting work
> together?

Not *which model is most secure*. Three architectures get the same useful
workflow and the same events, and the case reports how they behave.

The hypothesis is that the three models differ in **where authority is
attached**:

```text
Unix                 authority follows the subject/process
Workflow automation  authority follows the configured workflow/action
Object model         authority is derived for a transformation of one object
```

Whether that produces a measurable difference is the thing to determine.

## Readiness — the direction's own precondition

> *"This comparison should come after the current foundational cases are strong
> enough to define the controls and metrics fairly."*

Assessed against what the repository actually has. The twelve properties the
direction lists fall into three families, and they are **not equally ready**:

| Family | Properties | Ready? |
|---|---|---|
| **Authority & tamper** | where authority is stored; standing vs task-specific; minimum stored change; scope of one tamper; what it reaches | **Yes.** Cases 08–11 built exactly this vocabulary and applied it twice. `registry.py` records blast radius per case and REPORT.md now carries a *Where authority is stored* map |
| **Data flow & provenance** | source data each worker receives; canonical copying vs reconstruction; what stays visible after corruption; replay from trusted source | **No.** See below |
| **Failure behaviour** | malicious worker; modified config; silent corruption vs rejection vs quarantine vs unavailability | **Partly.** The result vocabulary covers the first three outcomes; unavailability has no home — `docs/threat-model.md` §7 excludes it, and the review found four controls spending it anyway |

### Why the data-flow family is not ready

The repository's only data-movement instrument is
[`agent_network_demo/key_vs_paste.py`](../../agent_network_demo/key_vs_paste.py),
and it cannot be used for this comparison:

* **It simulates rather than measures.** Paste-arm volume is computed
  analytically (`base_content * p + …`), not observed from a running workflow.
  Nothing counts what a worker actually received.
* **Its comparator is the arm this direction forbids.** It measures references
  against "re-serialize the whole table at every boundary". The fairness rule
  here is explicit: *do not make the workflow arm blindly copy full payloads if
  a sensible workflow would pass an ID.* A competent arm B passes IDs, and
  against that comparator the key/paste distinction largely disappears.

That second point is worth recording as a finding before any code is written:
**an existing artifact in this repository encodes the assumption the new
direction rules out.** It is not wrong about the architecture it describes; it
is not evidence about conventional workflow tools.

Replay is in the same position. Every case records a *Recovery* paragraph and
most of them say "not implemented". Nothing measures whether work can be
replayed from trusted source state — it is asserted, per case, in prose.

### Consequence for sequencing

One family is ready, two need an instrument built first. That is the same
lesson case 10 recorded when it built map maintenance before attacking the map:
**tampering with a record nothing maintains measures nothing**, and equally,
comparing data movement nothing counts measures nothing.

Proposed split, one claim per case, all three arms and one workload shared:

| Case | Family | Precondition |
|---|---|---|
| **12** | authority & tamper | none — ready now |
| **13** | data flow & provenance | a real instrument that observes what each worker received |
| **14** | failure behaviour | a decision on what availability means (`threat-model.md` §7) |

**This document is case 12's contract only.**

## The shared workload

The same business operation in all three arms — the one the repository already
runs, so the arms differ in architecture and in nothing else:

```text
ingest an orders CSV  →  infer its schema  →  clean/transform it  →  validate
```

Same fixture (`agent_network_demo/fixtures/sample_payload.csv`), same four
steps, same final output. An arm that cannot produce the same result is not a
fair arm and its numbers are void.

**Functional equivalence is a precondition, asserted before any attack** — the
mistake case 10 avoided by building map maintenance first, and the reason its
parity assertion exists.

## The attacker — one, fixed, applied identically

The review found that cases 08, 10 and 11 measured an adversary the compromise
ladder has no row for, and that the object model's improvements were therefore
never shown to hold against a fully captured agent. **A three-arm comparison
would repeat that error three times unless the adversary is fixed first.**

Primary adversary, and the only one case 12 uses:

> **May alter persisted configuration or workflow records. May not modify
> executable code, and may not modify the administrative trust root.**

This is case 08's attacker, generalized so it means the same thing in each arm:

| Arm | What the adversary may edit |
|---|---|
| A — identity | the subject/permission tables and resource modes — the ACL, not the kernel |
| B — workflow | the workflow definition, its step configuration, and connection scoping |
| C — object | object state, artifact map, production ledger, skill registry |

Why not the other two levels, stated so the choice is falsifiable:

* **Level 1** (a malicious worker using its own interfaces) is a real question
  and belongs to case 14, where "what happens when one worker is malicious" is
  the claim. It is not this case's adversary.
* **Level 2** (arbitrary in-process code) makes all three arms lose
  identically, as case 08 recorded when it excluded evaluator edits. A
  comparison under Level 2 measures process isolation, which is case 06's
  subject, not authority placement.

Same attacker power for equivalent claims is a fairness rule, not a
convenience: a result comparing arm C under one adversary with arm A under
another is void.

## The named capability

Reused from cases 08 and 10 deliberately, so the numbers are comparable across
the whole series rather than only within this case:

> Obtain a read of `artifact.key_material` at the schema step — an artifact the
> legitimate workflow never grants that step.

## Fairness conditions

The comparison must be against **competent** versions of the other models. Each
arm gets an explicit competence checklist, and a violated checklist voids that
arm's result rather than counting as a finding.

### Arm A — identity and permission

Represents the traditional identity + ACL approach. **A minimal reference model
of that idea, not an emulation of Unix** — real uid/mode semantics are not
available on this repository's platform, and claiming to have measured Unix
would be false. What is modelled: subjects, standing permissions, resources
with owners and modes, and a mandatory check on every access.

Competence checklist:

* each stage runs as its **own** subject — no single subject performing the
  whole workflow;
* least privilege per subject: only the resources that stage's work requires;
* the permission check is **mandatory**, not advisory — a stage cannot decline
  to call it;
* permissions are revocable and the model says so;
* no superuser stage, and no stage that is exempt from the check.

Explicitly *not* claimed: that this measures Linux, containers, capabilities,
SELinux, seccomp, or namespaces.

### Arm B — configured workflow

Represents the workflow-automation approach: a trigger, predefined actions,
outputs feeding the next action, authority coming from the step's configuration
and the credentials its connection holds.

Competence checklist:

* steps pass **references/IDs**, not copied payloads, wherever a competent
  workflow author would — the direction is explicit and `key_vs_paste.py` is
  the counter-example to avoid;
* per-connection credentials scoped to a resource set — **not** one credential
  with access to everything;
* dynamic references and conditions are permitted; the graph being defined
  ahead of time is the architectural property, not a handicap;
* the configuration is the authority, and it is checked at use time like any
  other arm's.

### Arm C — object / reference / skill

The existing `object_model/` package, unchanged. It carries cases 09, 10 and
11's controls, which raises a fairness question the case must answer rather
than assume:

> **Do arms A and B get equivalents of the skill-registry pin (09), the derived
> map (10), and conflict containment (11)?**

Rule, from the direction: *do not give our arm protections the other arms are
forbidden from using unless that protection is the architectural feature being
tested.* Applied here:

* **Version-pinning a definition (09)** is not architecture-specific. Arm A can
  pin its permission table and arm B its workflow definition. **Both get it.**
* **Deriving the binding rather than storing it (10)** *is* the architectural
  feature under test. Arms A and B keep their native stored form. This is the
  hypothesis, not a handicap — and the case must report if the stored forms
  turn out to be equally good.
* **Containment on a contradiction (11)** is available only to a record that
  keeps contradictions. The review already established a stored map keeps none.
  Arms A and B get it **if their native record can express it**; the honest
  expectation is that they cannot, and that is a result rather than a favour.

Every one of these three decisions is recorded per measurement so a reader can
see which protection each arm had.

## What is measured

Five properties, all in the authority family, each reported per arm:

1. **Where authority is stored** — enumerate every authority-bearing record.
2. **Standing or task-specific** — does the authority exist between runs?
3. **Minimum tamper set** — the smallest number of stored changes that obtains
   the named capability. Measured per surface, not per arm, as case 08 did.
4. **Scope of one successful tamper** — step, object, run, process, or future
   work. On a scale, not as a word.
5. **Persistence** — does it survive a retry, a resume, a later independent
   run, a redeployment?

## Hypothesis, pre-registered so it can be refuted

Case 08 wrote a hypothesis into a draft contract as an acceptance condition,
corrected it to a metric before measuring, and had it refuted. Same discipline:

> **The minimum tamper set will be 1 in all three arms.** Both existing
> comparisons measured 1 in every arm. If arms A and B are also 1, the honest
> headline is that all three models store authority somewhere and one edit
> obtains it — and they differ in **scope**, not in **cost**.

This is a prediction to be refuted, not an acceptance condition. If an arm
requires two, that is the finding.

Secondary prediction, also to be tested: **arm A's tamper has the widest scope**
(a standing permission reaches every future run by that subject), arm B's is
next (every run of that workflow), and arm C's is narrowest (one object). If
that holds, the object model's contribution is scope narrowing rather than
tamper resistance — which the review already suspects and this case can settle.

## What this case may conclude

All are acceptable and the case is written so each is reachable. From the
direction, unabridged:

1. The models are equivalent for this property.
2. The conventional model is simpler and better for fixed workflows.
3. The object model reduces data movement but not tamper resistance.
4. The object model narrows compromise to one object rather than one process.
5. The object model improves provenance but spends availability.
6. The object model merely relocates stored authority.
7. The object model provides no meaningful advantage under this threat model.

Conclusion 6 is the one the series has been trending toward — case 08 already
said the object model "redistributes stored authority rather than removing it".
A result confirming it is a good result.

## What this case will not do

* Build Unix, Power Automate, or a production object system. Minimal reference
  implementations sufficient to run the same operation, and nothing more.
* Claim anything about products. Arm A is not Linux and arm B is not Power
  Automate; they are reference models of two architectural ideas.
* Compare properties from different metric families. Data flow and failure
  behaviour belong to cases 13 and 14 and their instruments do not exist yet.
* Aggregate five properties into one verdict. Each is reported separately, and
  a single "score" across them is exactly the vague claim this repository bans.

---

## What this proves

Nothing yet. This is a contract.

## What this does not prove

Nothing yet, and in particular the readiness assessment above is an argument
about instruments, not a measurement of the three models.

---

## Tests

None yet. When built: `tests/adversarial/test_case_12_three_models.py`.
