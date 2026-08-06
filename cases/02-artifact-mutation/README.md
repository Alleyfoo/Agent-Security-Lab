# Case 02 — In-place mutation of a registered artifact

**Phase:** 2 (in-process attack cases)
**Baseline finding:** L3
**Ladder level:** 2 (see *Classification* below)
**Baseline result:** `undetected`
**Controlled result:** `detected_after_occurrence`

---

## Research question

> Can a misbehaving same-process agent modify an existing artifact without
> creating a new key, and can the trusted runner detect that modification?

Answers: **yes**, and **not at the baseline** — but detection is achievable
in-process, which is what separates this case from
[case 01](../01-ungranted-read/README.md).

## Classification — a deviation, recorded

The manager direction's example metadata suggested `Level 1: malicious agent`.
Measured, it is **Level 2**. Every route into stored state requires reaching a
private attribute:

* `view.get()` returns a `deepcopy`, so editing the returned object is inert.
* `view.register()` deep-copies its argument on the way in.
* `register()` returns a `deepcopy`, so the writer keeps no alias to its own
  artifact.
* Re-registering the key with different content raises `DuplicateKeyError`.

There is no Level 1 path to in-place mutation. Recording the deviation rather
than adopting the label, per the rule that an honest red beats a cosmetic green
— the same rule applies to threat classification, not just results.

This matters operationally: case 02's control raises the cost of *undetected*
corruption, but the adversary who can perform the mutation at all is the same
one case 01 shows cannot be contained in-process.

## Threat

A hostile agent that does its legitimate work and additionally edits an
artifact it was granted **read** access to. Starting authority: a `StoreView`
granting read on `artifact.raw_input`, write on `artifact.schema_profile`, plus
in-process code execution.

## Existing assumption

Baseline controls **B14** (immutability) and **B7** (outbound store diff) were
read together as "an agent cannot change artifacts it does not own". Each is
true about the thing it checks, and the conjunction is false:

* B14 prevents *rebinding a key* to different content. It says nothing about
  editing the dict already stored under that key.
* B7 compares the *set of keys* before and after the step. A mutation adds no
  key, so the set is unchanged.

The gap between "no new key" and "no change" is the whole case.

## Attack

```bash
python cases/02-artifact-mutation/attack.py
```

A hostile schema stage writes its legitimate schema profile, then rewrites one
cell of `artifact.raw_input`:

```python
stored = view._store._artifacts[KEY_RAW_INPUT]
stored["rows_data"][0]["Total"] = "999999.00"
```

Deliberately chosen to survive every existing check: row count unchanged,
columns unchanged, so `ValidationAgent`'s `row_counts_consistent` and
`schema_matches_output` both still pass.

## Observed unsafe result — `undetected`

```text
  original Total (row 0)   : 42.50
  Total after tampering    : 999999.00
  new keys created by step : ['artifact.schema_profile']
    -> exactly the granted output; the mutation is not a new
       key, so the diff has nothing to notice
  runner receipt status    : ok
  stored source_hash       : 16879f037b6a2832...
  recomputed source_hash   : 8194315c08fe6c3a...
  hashes match             : False
  cleaned_output row 0 Total: 999999.0  <- corruption propagated
  final verdict             : ok
```

The run completed clean. An honest `TransformAgent` consumed the tampered
`raw_input` and produced a `cleaned_output` containing the forged value, and
`ValidationAgent` returned `ok`.

**The evidence to catch this already existed.** `source_hash` stopped
recomputing the moment the dict changed. Nothing on the live path looked —
`from_snapshot` was the only verifier, and it only runs during hydration
([artifact_store.py](../../agent_network_demo/artifact_store.py)). The baseline
had a detection primitive it never wired in.

## Control

Two checks, in trusted code, each stating an independent guarantee. Neither
asks the agent to verify anything.

### C1 — Read-boundary verification (`ArtifactStore.get`)

Every read recomputes the stored artifact's hash and raises
`ArtifactIntegrityError` on divergence.

> **Guarantee:** no consumer receives artifact content that does not match the
> hash registered for it.

### C2 — Post-step sweep (`RunSession.step`)

After each agent runs, the runner calls `ArtifactStore.verify_all()` over every
artifact.

> **Guarantee:** an in-place mutation is detected at the end of the step in
> which it occurred, whether or not anything subsequently reads the artifact.

C2 is not redundant. A hostile agent that mutates an artifact nothing reads
again — the last stage tampering with `raw_input`, say — would never trip C1.
C1 alone would make detection depend on the workflow's read pattern, which the
attacker partly controls.

### Cost — measured, not assumed

| | |
|---|---|
| Full 4-stage run with verification | 3.8 ms |
| One verified `get()` (20-row artifact) | 71 µs |
| `verify_all()` over 4 artifacts | 69 µs |

Free at fixture scale. It is **not** free asymptotically: C1 is O(artifact
size) per read and C2 is O(total store size) per step, both re-serialising
canonical JSON. A workflow with large artifacts or many stages would need
either cached hashes with explicit invalidation, or verification at stage
boundaries only. Recorded here so the trade-off is not rediscovered as a
surprise.

### Fail-closed on detection

A detected mutation sets a quarantine flag on the session. Further `step()`
calls are refused, because the existing error path leaves `_current` unchanged
and would otherwise retry the stage **against a store already known to be
corrupt**. The workflow stops rather than continuing on untrusted state.

`ArtifactIntegrityError` is distinct from `ContractError` and from
`ReceiptIntegrityError`: a contract breach, an attack on the audit plane, and
corruption of the data plane are three different incidents and must not be
conflated in triage.

## Observed protected result — `detected_after_occurrence`

Same attack, unchanged:

```text
  runner receipt status    : error
  hashes match             : False
  DETECTED: ArtifactIntegrityError: artifact 'artifact.raw_input' failed
  integrity verification: stored hash 16879f03... does not match recomputed
  8194315c... - the artifact was modified in place after registration
```

The workflow halts. `cleaned_output` is never produced, so the corruption does
not propagate.

## Why this is not prevention

Per the required vocabulary, this is **detected after occurrence**, not
prevented and not rejected before commitment:

* The mutation **did** happen. The bytes in the trusted store changed, and for
  the window between mutation and check, the corrupted value was live.
* Hash verification observes divergence. It cannot stop a write to memory the
  adversary can already reach.
* Detection lands before the altered state is *consumed by a downstream stage*,
  which is what makes it useful — but "not yet consumed" is not "never
  occurred".

Do not describe this control as preventing artifact tampering.

## Residual limitation

> Same-process hostile code may still mutate memory. Hash verification detects
> divergence but does not create memory isolation or undo confidentiality loss.

Specifically still open:

* The adversary can mutate an artifact, read the result of its own tampering,
  and restore the original bytes before the sweep runs — the check is at step
  boundaries, not continuous. Detection assumes the attacker does not clean up.
* The adversary can mutate `source_hash` *and* the content together, so both
  recompute consistently. Nothing in-process can prevent this: the hash lives
  in the same dict as the data it protects. Closing it needs the expected hash
  held outside the adversary's reach — a different trust boundary, not a
  different check.
* `as_dict()` / `to_snapshot()` / `summary()` do not verify. The step sweep
  covers the workflow path; direct UI reads of store state are not individually
  verified.
* This is detection only. No artifact is restored, and none of it constrains
  the reads from case 01.

## Containment response

Deterministic, from the ladder's table — *agent contract violation → reject the
operation and stop the workflow*, extended with the quarantine flag so a
corrupt store is never retried.

## Recovery requirement

Recovery is **distinct from detection and is not implemented in this slice.**
Assessed, per the manager direction:

| Option | Safe here? |
|---|---|
| Abort the step | **Yes — implemented.** The runner already halts on error. |
| Quarantine the workflow | **Yes — implemented.** Refuses further steps rather than retrying against a corrupt store. |
| Discard the modified in-memory store | Possible, but pointless alone — the run cannot continue without its artifacts, and discarding destroys the evidence an investigator needs. |
| Restore from a verified snapshot | **Not implemented, and not safe to add here.** `from_snapshot` verifies hashes, so a snapshot taken *before* the mutation would restore correctly — but nothing currently takes one, and a snapshot taken after is corrupt-but-consistent if the adversary updated the hash. Restoration needs its own specification and its own tests. |

Operationally today: treat the run as failed, treat every artifact in it as
suspect, and re-run from intake in a clean session.

## Blast radius

One workflow's artifacts. Without the control, any artifact derived from the
tampered one afterwards — demonstrated: `cleaned_output` inherited the forged
value, and the verdict certified it.

There is no provenance graph yet, so *identifying* derived outputs after the
fact is not possible. That is Phase 8's job, and this case is a concrete
argument for it.

---

## What this proves

That the baseline's immutability guarantee covered key rebinding but not
content mutation, and that the gap was silently exploitable end to end. With
the control, unauthorized in-place mutation of registered artifacts is detected
before the workflow accepts or consumes the altered state, by trusted code that
never asks the agent to vouch for the artifact it may have modified.

## What this does not prove

It does not prove prevention. The mutation occurs; the control observes it
afterwards. It does not create memory isolation — the adversary that can mutate
the artifact can also reach the hash beside it, and an attacker who updates
both passes verification. It does not undo any confidentiality loss from
[case 01](../01-ungranted-read/README.md), and it restores nothing.

---

## Tests

`tests/adversarial/test_case_02_artifact_mutation.py`

| Test | Asserts |
|---|---|
| `test_baseline_diff_does_not_see_in_place_mutation` | The new-key diff is structurally blind to mutation |
| `test_read_boundary_detects_mutation` | C1 — `get()` raises with a specific reason |
| `test_post_step_sweep_detects_unread_mutation` | C2 — detection without any subsequent read |
| `test_mutation_halts_the_workflow` | Corruption does not propagate to `cleaned_output` |
| `test_quarantined_session_refuses_further_steps` | Fail-closed; no retry against a corrupt store |
| `test_verify_all_reports_every_corrupted_key` | The sweep names all affected artifacts |
| `test_untampered_run_is_unaffected` | No false positives on the honest path |
| `test_residual_matching_hash_and_content_passes_verification` | Residual limitation is real and executable |
