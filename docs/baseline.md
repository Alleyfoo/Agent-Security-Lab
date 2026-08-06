# Baseline architecture and limitations

**Tag:** `v0-baseline-inprocess` (commit `ae46595`)
**Source:** snapshot of `Agent-payload-demo@fdf6b42`
**Test status at tag:** 72 passed

This document records what the baseline *is* before the laboratory starts
attacking it. It is the reference point every later case measures against.
Do not amend it to make later results look better — record drift in the case
READMEs instead.

---

## 1. What the baseline does

A four-stage deterministic pipeline over a CSV payload. No LLM, no network,
no randomness. One process.

```text
intake_agent      reads a fixture file      -> artifact.raw_input
schema_agent      reads raw_input           -> artifact.schema_profile
transform_agent   reads raw_input + schema  -> artifact.cleaned_output
validation_agent  reads all three           -> artifact.validation_verdict
```

Stages are driven by `RunSession.step()` in
[demo_runner.py:125](../agent_network_demo/demo_runner.py:125). Each call runs
exactly one agent and emits one trusted-runner receipt.

## 2. Controls that exist at the baseline

These are real, enforced, and covered by tests. Each maps to a standard
security concept in [security-concepts.md](security-concepts.md).

| # | Control | Where | Enforces |
|---|---------|-------|----------|
| B1 | Closed action vocabulary | [contracts.py:39](../agent_network_demo/contracts.py:39) | An agent's powers come from a finite set, not from strings it invents |
| B2 | Contract-to-action binding | [contracts.py:162](../agent_network_demo/contracts.py:162) | `allowed_actions` must contain the write action its `output_contract` requires — the grant is not decorative |
| B3 | Read-grant declaration | [contracts.py:152](../agent_network_demo/contracts.py:152) | Declaring `input_keys` requires holding `read_artifact` |
| B4 | Capability-scoped read | [artifact_store.py:125](../agent_network_demo/artifact_store.py:125) | `StoreView.get` denies any key not in the grant |
| B5 | Capability-scoped write | [artifact_store.py:136](../agent_network_demo/artifact_store.py:136) | `StoreView.register` denies any key except the single granted output |
| B6 | Non-probeable existence | [artifact_store.py:133](../agent_network_demo/artifact_store.py:133) | `has()` returns False for ungranted keys, so the view is not an enumeration oracle |
| B7 | Outbound write diff | [demo_runner.py:144](../agent_network_demo/demo_runner.py:144) | Store-keys before/after comparison catches writes that bypassed the view |
| B8 | Read-grant reconciliation | [demo_runner.py:151](../agent_network_demo/demo_runner.py:151) | Actual reads must be a subset of the runner's grant |
| B9 | Declared-vs-actual output check | [demo_runner.py:153](../agent_network_demo/demo_runner.py:153) | An agent's self-reported `output_keys` must match what really appeared |
| B10 | Runner-owned routing | [demo_runner.py:42](../agent_network_demo/demo_runner.py:42) | `WORKFLOW_ROUTES` is the only source of grants; agents return `AgentResult`, which carries no routing or permissions |
| B11 | Key files cannot grant | [demo_runner.py:118](../agent_network_demo/demo_runner.py:118) | Actions named in an untrusted key file are ignored |
| B12 | Path confinement | [agents.py:46](../agent_network_demo/agents.py:46) | `source_ref` is resolved with `realpath` and must stay inside the fixtures dir |
| B13 | Content-addressed artifacts | [artifact_store.py:16](../agent_network_demo/artifact_store.py:16) | Every artifact carries a `source_hash` over its canonical JSON |
| B14 | Immutable-by-rebinding | [artifact_store.py:39](../agent_network_demo/artifact_store.py:39) | Re-registering a key with different content raises `DuplicateKeyError` |
| B15 | Copy-on-read/write | [artifact_store.py:37](../agent_network_demo/artifact_store.py:37) | `deepcopy` on register, get, `as_dict`, and `receipts()` — callers cannot reach stored state through a returned object |
| B16 | Snapshot hash verification | [artifact_store.py:85](../agent_network_demo/artifact_store.py:85) | Hydration rejects any artifact whose `source_hash` does not recompute |
| B17 | Receipts separate from agent claims | [demo_runner.py:178](../agent_network_demo/demo_runner.py:178) | The runner records what actually happened, independent of what the agent said |
| B18 | Verdict derived from receipts | [agents.py:375](../agent_network_demo/agents.py:375) | `ValidationAgent` reads runner receipts, not agent-authored log events |
| B19 | Append-only log API | [event_log.py:36](../agent_network_demo/event_log.py:36) | No update or delete operation on the application interface |
| B20 | Read-only receipt handle | [receipts.py](../agent_network_demo/receipts.py) | The audited agent cannot mutate the runner's evidence (added by case 00, not present at the tag) |
| B21 | Live-path integrity verification | [artifact_store.py](../agent_network_demo/artifact_store.py) | `get()` verifies at the read boundary and `verify_all()` sweeps after every step; in-place mutation is detected, not prevented (added by case 02) |
| B22 | Read-only, pinned routing policy | [demo_runner.py](../agent_network_demo/demo_runner.py) | Public route table is a `MappingProxyType`; each run pins a private copy and verifies its fingerprint every step (added by case 03) |

## 3. Baseline limitations — verified, not assumed

The following were **executed against the tagged baseline**, not inferred.
They are the starting inventory for Phase 2 and define the honest scope of
every baseline claim.

### L1 — `StoreView` is an interface, not an isolation boundary

> Documented as [case 01](../cases/01-ungranted-read/README.md). **Open** — no
> control at Phase 2; control is process isolation, Phase 5.

Same-process code holding a view reaches the full store through
`view._store`. Verified: an ungranted read denied through `view.get()`
succeeded through `view._store.get()`, returning all 20 rows.

Case 01 escalates this to two further paths that never touch the view at all —
walking `sys._getframe()` and scanning `gc.get_objects()` — establishing that
the three paths share no mechanism. Removing the private attribute closes
exactly one of them, which is why that patch is demonstrated and refused rather
than shipped.

**Consequence:** B4 constrains code that goes through the interface. It does
not constrain code that can read the Python object graph. A boundary enforced
by the absence of a reference is not a boundary in a runtime with reflection.

### L2 — Bypassed reads are invisible

`StoreView._read_log` only records reads made through the view, so the
reach-around in L1 left `view.read_keys == []`. B8 reconciles the read log
against the grant, so a bypassed read passes reconciliation by being absent.

**Consequence:** the baseline detects *over-declared* reads, not *hidden*
ones. This asymmetry does not apply to writes, which B7 catches via the store
diff regardless of path.

The transferable form of the lesson, from case 01:

```text
Writes  are checked against observed store state  -> bypass is caught
Reads   are checked against a log the reader owns -> bypass is invisible
```

A control that reconciles against evidence the adversary produces is not a
control.

### L3 — Artifact immutability is interface-level only

> **DETECTED** as of [case 02](../cases/02-artifact-mutation/README.md) — not
> prevented. The mutation still occurs; trusted code now notices it. The tag
> still exhibits the undetected form.

Direct mutation of `view._store._artifacts[key]` succeeded and changed a
registered artifact in place. B14 prevents *re-registration* with different
content; it does not prevent in-place mutation of the stored dict.

**The detection primitive existed but was not wired in.** The tampered
artifact's stored `source_hash` no longer recomputes (`16879f03…` vs
`f6434f29…`). Nothing on the live path checked this — B16 verified hashes only
during `from_snapshot` hydration.

Case 02 measured the consequence end to end: a hostile stage changed one cell
of `raw_input`, no new key appeared, every structural check still passed, the
forged value propagated into `cleaned_output`, and the run returned verdict
`ok`. Now `ArtifactStore.get()` verifies at the read boundary and the runner
sweeps every artifact after each step, with a fail-closed quarantine so a store
known to be corrupt is never retried.

Still open, and not closable in-process: `source_hash` lives in the same dict
as the data it protects, so an adversary who updates both passes verification.

### L4 — The audit log accepts forged runner identity

`EventLog.append` performs no authentication of `Event.agent`. Hostile
in-process code appended an event claiming `agent="trusted_runner"`,
`action="step_receipt"`, `contract_result="passed"`.

**Bounded by B18:** the verdict is computed from the runner's receipt list,
not from log events, so the forged event did not change the outcome — this is
what `test_forged_agent_permission_event_cannot_change_verdict` locks in. The
damage is to the *human-readable audit record*, not to the decision. State
this distinction precisely; do not describe the log as trustworthy evidence of
authorization.

### L5 — The on-disk log is rewritable

The JSONL file was truncated to zero bytes by ordinary file I/O. Append-only
is a property of the *application API* (B19), not of the storage. There is no
hash chain, no sequence binding, and no external replica, so deletion and
reordering are neither prevented nor detectable.

**Terminology:** the baseline log is append-only *by API*. It is **not**
tamper-evident. Do not use the stronger term until a chain exists (Phase 7).

### L6 — The route table is mutable at runtime

> **PREVENTED** through the interface as of
> [case 03](../cases/03-mutable-route-table/README.md). A Level 2 adversary
> reaching the private table before `start_run` remains undetected. The tag
> exhibits the fully open form.

`demo_runner.WORKFLOW_ROUTES` was a module-level dict. Hostile code rewrote the
`schema` entry to grant itself `artifact.cleaned_output` plus a broader output
contract. `Route` is a frozen dataclass — including its tuple fields — but the
dict holding the routes was not, and the module object is reachable from any
agent by ordinary import.

**Consequence:** B10 says routing is runner-owned. That is true of the
*control flow*, but the routing *data* sat in the same mutable namespace as
the agents it governs.

Case 03 measured three effects, the third found by accident and then
deliberately: the runner **issued** grants the policy never contained; a
hostile agent **deleted the validation stage** and the run still reported
completion with no error and no quarantine; and the tampering **outlived the
run**, so a later, entirely honest session in the same process inherited it.
Blast radius was process lifetime, not run lifetime.

Now: `WORKFLOW_ROUTES` is a `MappingProxyType` over a private table, each run
pins its own copy at `start_run`, and a fingerprint over that copy is verified
before and after every step with fail-closed quarantine on mismatch.

### L7 — The audited component holds a live handle to its own evidence

> **FIXED** by [case 00](../cases/00-receipt-handle/README.md). Described below
> as it stood at `v0-baseline-inprocess`; the tag still exhibits it.

`ValidationAgent` was constructed with the runner's actual receipt list, not a
copy (`demo_runner.py:112` at the tag): `va.receipts is runner._receipts` was
`True`.

A compromised validator could filter failing receipts out of the list it was
supposed to be checking. Verified end to end: a run whose schema stage failed
its contract once reported verdict `ok` with zero failing receipts, against
`warn` with one for the honest run. The corruption reached
`RunSession.receipts()` — the accessor `report()` and the UI read — so the
exposure was not confined to the agent-side handle as first assessed.

**This was the anti-pattern the project charter forbids** ("logs written by the
same untrusted component being audited"), and it undermined B18.

Now: the runner owns a `ReceiptLedger` and hands agents a read-only
`ReceiptView` ([receipts.py](../agent_network_demo/receipts.py)). Editing the
evidence requires Level 2 in-process reach-around rather than a merely hostile
agent implementation. The verdict itself remains agent-authored — see the
case's residual-limitation section.

### L8 — Structural limits inherited by design

* One OS process, one uid, one filesystem view, no resource limits.
* Grants are plain key lists: no expiry, no use count, no audience, no
  workflow binding, no revocation, no signature.
* Artifacts carry no classification or provenance beyond `source_hash`, so
  there is no basis for information-flow decisions or blast-radius tracing.
* There is no policy engine distinct from the runner; decision, issuance, and
  enforcement are one component.

## 4. What the baseline legitimately proves

> Within a single trusted process, an agent that goes through the provided
> interfaces can only read the keys it was granted and write the single key
> its contract licenses. Routing and grants come from a trusted table that
> agent return values cannot influence. Every stage produces a runner-owned
> receipt recording the reads and writes that actually occurred.

## 5. What the baseline does not prove

> It does not prove containment of hostile code executing inside the same
> process. Such code can read ungranted artifacts undetected, mutate stored
> artifacts in place, forge audit events attributed to the runner, delete the
> on-disk log, and rewrite the route table. Nothing here is evidence about
> process, host, identity, or data-authority compromise.

## 6. Reproducing the limitation inventory

Phase 2 converts each of L1–L7 into an executable case under `cases/` with an
adversarial test that fails without the control and passes with it. Until
then, these findings are recorded observations from a scratch probe run
against `v0-baseline-inprocess`, not regression-guarded behaviour.
