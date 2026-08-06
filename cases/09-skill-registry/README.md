# Case 09 — Can the execution plane mint a transformation?

**Phase:** 3 (authority model)
**Baseline finding:** case 08's widest-scope result — a skill-contract edit
reaches every object running that skill until redeployment
**Ladder level:** 1 for the demonstrated attacks; 2 for the residual
**Baseline result:** `undetected`
**Controlled result:** `prevented` — scope stated below

---

## Research question

> Can the execution plane create, modify, replace, or select an unapproved
> skill definition?

Four verbs, deliberately. They are different operations and a control that
stops one need not stop the others.

## Why this case exists, and what it is not allowed to claim

[Case 08](../08-derived-authority/README.md) measured a skill-contract edit
obtaining an unauthorized read with the broadest blast radius in the
repository: every object running that skill, until the registry is redeployed.
Case 08 attacked the registry as data and reported that radius. It explicitly
did **not** claim the registry is trustworthy, and left that to this case.

This case must not overclaim in the other direction either. It covers the
**skill registry** — the type-level declaration of what a skill may read. It
does **not** cover the artifact map, the record binding a declared type to a
concrete key, which case 08 measured as the cheaper surface of the two and
which has no administrative lifecycle to appeal to. That is case 10.

> Case 09 may conclude the registry is or is not defensible. It may not
> conclude that the type-to-key trust root is secured, because it addresses
> half of it.

## Threat

**Level 1 — a worker executing a skill.** It uses the interfaces the execution
plane offers. This is the adversary §16 is about: the execution plane must not
expose `create_skill`, `edit_skill`, `publish_skill`,
`change_skill_permissions` or `disable_review`.

**Level 2 — hostile code sharing the interpreter.** It reaches private module
state directly. Case 01 established that this adversary is not contained
in-process and nothing here changes that.

## Existing assumption

**"Skills are an allowlist, so the executable vocabulary is fixed."** True of
the *names*: case 08 measured that a queue item naming an unregistered skill is
refused, and that an object type restricts which skills it may run. What was
never established is that the *contents* of an approved entry are fixed. An
allowlist whose entries can be rewritten is a list of names, not a list of
approved transformations.

## Attack

```bash
python cases/09-skill-registry/attack.py
```

### A — Create, through the execution plane

```text
      REGISTRY[name] = skill    : AttributeError
      REGISTRY.update({...})    : AttributeError
      REGISTRY.setdefault(...)  : AttributeError
      skill created             : no
```

There is also no `create_skill`, `publish_skill`, `edit_skill`,
`change_skill_permissions` or `disable_review` anywhere on the execution path.
Absent, not denied — a denied operation is still an operation something can be
talked into reaching.

### B — Modify, through the execution plane

Case 08's winning edit, attempted through the interface a worker actually holds
rather than by direct module access.

```text
      blocked: TypeError: 'mappingproxy' object does not support item assignment
      widened contract in effect : no
      grant: reads ['artifact.raw_input'] writes 'artifact.schema_profile'
```

### C — Replace, between workflow steps

The operation §16 warns about: *running workflows should remain tied to the
skill versions with which they started.*

```text
   !! baseline, no version pin  OBTAINED
      with version pin          no
      detected: skill 'infer_schema' failed version verification: run pinned
                a55968b4... and the registry now holds 5be295af... - the
                definition was replaced after the run started
```

The baseline arm is what makes this a measurement. Without it, C2's value would
be an assertion about a control nobody watched fail.

### D — Select an unapproved definition

Not mutation at all.

```text
      unregistered name       : refused: no approved skill named 'exfiltrate'
      registered, wrong state : refused: queue item names 'validate_chain' but
                                'orders_table' in state 'ingested' requires
                                'infer_schema'
```

Selection was already sound — case 08 measured it. Re-measured here because
§16 lists it as a separate verb, and a case that assumed it would be assuming
the interesting half.

### E — Level 2, and the independent-authority question

```text
   !! rewritten before the run pins   OBTAINED
      rewritten mid-run               no
   !! rewritten with the pin updated  OBTAINED
```

Three placements, two of which the pin cannot speak to.

## Observed unsafe result — `undetected`

Without a version pin, a definition replaced between steps takes effect
silently: the run resolves a grant from a contract it never approved, and
nothing compares what it is using against what it started with.

## Control

### C1 — The execution plane holds a read-only registry

`REGISTRY` is a `MappingProxyType` over a private dict of frozen `Skill`
records, and no mutation operation exists on the execution path.

> **Guarantee:** a worker using the interfaces it is given cannot add, remove
> or alter a skill definition. Prevention at the interface, as in case 03.

### C2 — A run is bound to the skill versions it started with

Each `Skill` carries a version and a content digest over its declared
behaviour. At run start the evaluator pins the digest of every skill the object
type permits, and re-verifies before deriving any grant. A mismatch raises
`SkillRegistryError` naming the skill and both digests.

> **Guarantee:** a definition replaced after the run started is detected before
> the run acts on it, whether the replacement came through the interface or
> around it.

## Observed protected result — `prevented`

```text
  A create : blocked at the interface
  B modify : blocked at the interface
  C replace: baseline OBTAINED -> detected, named, with both digests
  D select : refused, both forms
```

`prevented` for a Level 1 worker, on all four verbs. The scope of that word is
the execution plane's interfaces and nothing beyond them.

## The independent-authority question, answered

§16 asks what independent authority says a skill version is legitimate.

**There is none, and this case did not build one.**

What C2 provides is *continuity*, not authority: it can say the definition in
use differs from the one this run started with. It cannot say either of them is
legitimate. The placement table makes the boundary exact — the pin covers the
window between run start and use, and says nothing on either side of it.

An independent authority would need the approved set attested somewhere the
execution plane cannot reach, and verified by something it cannot bypass. Every
in-process version of that fails the same way: a signed manifest needs a
verification key, and a Level 2 adversary that reaches the registry reaches the
key. This is the fifth appearance of the repository's cross-cutting finding and
it is not closable at this phase.

The honest form: **the registry is not trustworthy. It is tamper-continuous
within a run, and that is a smaller claim.**

## Residual limitation

**Replacement before the run pins is undetected.** The pin records what was
there, not what should have been — case 03's residual in a new place. An
integrity value taken over already-tampered state certifies the tampering.

**Updating the pin alongside the registry passes.** The pin lives in the run's
own memory. Fifth instance of the cross-cutting finding.

**`MappingProxyType` is a view, not a freeze.** The public registry reflects
the private dict, which is why C1 stops a worker and not Level 2 code.

**Removal mid-run is misreported.** Deleting a pinned skill surfaces as *no
approved skill named X* — the same message a queue item naming something that
never existed produces. `verify_pins` has the right message and `validate` runs
first and shadows it, so an operator cannot distinguish registry tampering from
a malformed queue item. Recorded rather than fixed: reordering the checks
degrades the selection message case 08 depends on, and getting both right is a
change to the evaluator's error model rather than to this case's claim.

**No administrative lifecycle exists.** `reset_registry()` stands in for §16's
proposal, review, approval, signing and versioned release. None of that is
implemented and none of it may be claimed.

## Containment response

A version mismatch raises `SkillRegistryError`, distinct from
`AuthorizationError`. The run refuses to derive a grant from a definition it
did not start with rather than deriving one and flagging it — there is no sound
conclusion available from an unapproved contract, so this fails closed.

The two errors are kept apart because they need different operator responses:
one means a workflow asked for something it should not have, the other means
the vocabulary changed underneath a running workflow.

## Recovery requirement

Restart the run. The pin is taken at run start, so a fresh run over an
untampered registry is clean — and unlike cases 02, 03 and 05 there is nothing
to reconstruct, because a skill definition is not run state.

Restoring the registry itself is out of scope and would be unsound anyway: the
process holds no record of what the approved set was, only of what this run
found. That is the same gap the independent-authority section describes.

## Blast radius

**A successful registry edit reaches every object that runs the skill, until
the registry is redeployed** — the widest scope measured anywhere in this
repository, and case 08's headline finding.

C2 narrows that to *runs that start after the edit*. Runs already in flight
detect it and stop. That is a real reduction and it is not containment: the
edit is still there, and every subsequent run picks it up silently.

---

## What this proves

That an allowlist of names is not an allowlist of transformations. Selection
was already sound — an unregistered name and a name the object type does not
permit were both refused before this case existed — while the *contents* of an
approved entry could be rewritten and the run would use them without comment.
With the control, a worker cannot create, modify or select through any
interface it holds, and a definition replaced after the run started is detected
before a grant is derived from it, with both digests named.

It also establishes precisely what a version pin is worth, which is less than
it looks: continuity across one window, not legitimacy.

## What this does not prove

It does not prove the registry is trustworthy. There is no independent account
of what the approved set should be, so tampering before a run pins is
undetected, and tampering with the pin alongside the registry passes.

It does not implement any part of §16's administrative lifecycle. A
`reset_registry()` call is not an admin plane.

It does not secure the type-to-key binding. The artifact-map edit case 08
measured still works with every control in this case active, pinned by
`test_this_case_does_not_secure_the_artifact_map`. Case 10 owns that surface,
and it is the cheaper of the two.

---

## Tests

`tests/adversarial/test_case_09_skill_registry.py`

| Test | Asserts |
|---|---|
| `test_the_registry_rejects_every_mutation` | C1 — create, update, setdefault, remove, clear |
| `test_there_is_no_skill_mutation_operation_on_the_execution_path` | §16 — absent, not denied |
| `test_skill_records_are_frozen` | An entry cannot be edited in place |
| `test_a_worker_cannot_widen_a_contract_through_the_interface` | Attack B end to end |
| `test_replacement_between_steps_is_detected` | C2 — named, with both digests |
| `test_without_the_pin_the_replacement_is_undetected` | The baseline arm |
| `test_a_skill_added_after_run_start_cannot_be_used` | Pinning bounds the usable set |
| `test_verify_pins_reports_a_removed_skill_distinctly` | The branch says the right thing |
| `test_finding_removal_mid_run_is_reported_as_a_selection_failure` | …and `validate` shadows it |
| `test_the_digest_covers_every_declared_field` | No field escapes the digest |
| `test_an_untampered_run_is_unaffected` | No false positives |
| `test_selecting_an_unregistered_skill_is_refused` | Attack D |
| `test_selecting_a_registered_skill_the_state_does_not_require` | Attack D |
| `test_residual_replacement_before_the_run_pins_is_undetected` | Residual |
| `test_residual_updating_the_pin_alongside_the_registry_passes` | Residual |
| `test_residual_level_2_reaches_the_private_registry` | Residual |
| `test_this_case_does_not_secure_the_artifact_map` | Scope guard for case 10 |
