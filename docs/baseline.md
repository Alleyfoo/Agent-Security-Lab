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

## 3. Baseline limitations — verified, not assumed

The following were **executed against the tagged baseline**, not inferred.
They are the starting inventory for Phase 2 and define the honest scope of
every baseline claim.

### L1 — `StoreView` is an interface, not an isolation boundary

Same-process code holding a view reaches the full store through
`view._store`. Verified: an ungranted read denied through `view.get()`
succeeded through `view._store.get()`, returning all 20 rows.

**Consequence:** B4 constrains code that goes through the interface. It does
not constrain code that can read the Python object graph.

### L2 — Bypassed reads are invisible

`StoreView._read_log` only records reads made through the view, so the
reach-around in L1 left `view.read_keys == []`. B8 reconciles the read log
against the grant, so a bypassed read passes reconciliation by being absent.

**Consequence:** the baseline detects *over-declared* reads, not *hidden*
ones. This asymmetry does not apply to writes, which B7 catches via the store
diff regardless of path.

### L3 — Artifact immutability is interface-level only

Direct mutation of `view._store._artifacts[key]` succeeded and changed a
registered artifact in place. B14 prevents *re-registration* with different
content; it does not prevent in-place mutation of the stored dict.

**Detection primitive exists but is not wired in.** The tampered artifact's
stored `source_hash` no longer recomputes (`16879f03…` vs `f6434f29…`).
Nothing on the live path checks this — B16 verifies hashes only during
`from_snapshot` hydration. A recompute-on-read check is a cheap Phase 2 win.

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

`demo_runner.WORKFLOW_ROUTES` is a module-level dict. Hostile code rewrote the
`schema` entry to grant itself `artifact.cleaned_output` plus a broader output
contract. `Route` is a frozen dataclass, but the dict holding the routes is
not, and the module object is reachable from any agent.

**Consequence:** B10 says routing is runner-owned. That is true of the
*control flow*, but the routing *data* sits in the same mutable namespace as
the agents it governs.

### L7 — The audited component holds a live handle to its own evidence

`ValidationAgent` is constructed with the runner's actual receipt list, not a
copy ([demo_runner.py:112](../agent_network_demo/demo_runner.py:112)):
`va.receipts is runner._receipts` is `True`.

A compromised validator can filter failing receipts out of the list it is
supposed to be checking. Note that `RunSession.receipts()` *does* deep-copy on
the way out, so external readers are safe — the exposure is specifically the
agent-side handle.

**This is the anti-pattern the project charter forbids** ("logs written by the
same untrusted component being audited"). It is the highest-value Phase 2
target because it is cheap to fix and currently undermines B18.

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
