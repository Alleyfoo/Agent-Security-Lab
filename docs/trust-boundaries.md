# Trust boundaries

Where authority changes hands, what checks it, and what is *not* a boundary
despite looking like one.

---

## 1. Security planes

The architecture is modelled as five planes. A compromise in one plane must
not silently compromise the others.

```text
Execution plane   Agents and deterministic task services.
Control plane     Runner, workflow state machine, policy decisions.
Data plane        Artifact storage, databases, output destinations.
Identity plane    Service identities, capability signing, authentication.
Audit plane       Receipts, event logs, provenance, independent verification.
```

### Plane separation at the baseline

This is the honest picture, not the target picture:

| Plane | Baseline realization | Separated from execution? |
|---|---|---|
| Execution | `IntakeAgent`, `SchemaAgent`, `TransformAgent`, `ValidationAgent` | — |
| Control | `RunSession` + `WORKFLOW_ROUTES` | **No** — same process, same namespace (L6) |
| Data | `ArtifactStore` (in-memory dict) | **No** — reachable via `view._store` (L1) |
| Identity | *Does not exist.* Agents are identified by a `name` string with no authentication | **No** |
| Audit | `EventLog` + runner receipt list | **No** — log accepts forged identity (L4), receipts handle shared with the validator (L7) |

Four of five planes are currently collapsed into one process. The lab's job is
to pull them apart one at a time and measure what each separation actually
buys.

## 2. Boundary inventory

Each row is a place authority changes hands. "Enforced by" names the code that
actually checks; "Bypassable by" names who can walk around it *today*.

### TB-1 — Untrusted file → Intake

```text
key_file.json / sample_payload.csv  ==>  IntakeAgent
```

* **Crossing:** untrusted path and content enter the system.
* **Enforced by:** `confine_path` ([agents.py:46](../agent_network_demo/agents.py:46)) — `realpath` + containment check; key-file `actions` ignored ([demo_runner.py:118](../agent_network_demo/demo_runner.py:118)).
* **Holds against:** `..` traversal, absolute paths outside the root, other drives, self-granted actions.
* **Bypassable by:** anything at Level 2+. Also note confinement is checked at `start_run`, and `IntakeAgent` re-opens `self.source_ref` at run time — a TOCTOU gap that is currently unreachable only because nothing mutates the attribute between those points.

### TB-2 — Runner → Agent (the grant)

```text
WORKFLOW_ROUTES  ==>  HandoffEnvelope + StoreView  ==>  agent.run()
```

* **Crossing:** authority is issued.
* **Enforced by:** `validate_inbound` ([contracts.py:126](../agent_network_demo/contracts.py:126)) and view construction ([demo_runner.py:139](../agent_network_demo/demo_runner.py:139)).
* **Holds against:** unknown actions, grants inconsistent with the declared contract, input keys the agent invented.
* **Bypassable by:** rewriting `WORKFLOW_ROUTES` (L6).

### TB-3 — Agent → Store (read)

```text
agent  ==>  StoreView.get()  ==>  ArtifactStore
```

* **Enforced by:** [artifact_store.py:125](../agent_network_demo/artifact_store.py:125); non-probeable `has()` at :133.
* **Holds against:** reading any key outside the grant *through the view*.
* **Bypassable by:** `view._store.get()` — succeeds and is **not logged** (L1, L2). This is the single most important honest caveat in the repository.

### TB-4 — Agent → Store (write)

```text
agent  ==>  StoreView.register()  ==>  ArtifactStore
```

* **Enforced by:** [artifact_store.py:136](../agent_network_demo/artifact_store.py:136), plus the runner's store-diff at [demo_runner.py:144](../agent_network_demo/demo_runner.py:144).
* **Holds against:** writing any key but the granted one — including via a bypass path, because the diff compares actual store contents rather than trusting the view.
* **Bypassable by:** in-place mutation of an existing artifact, which is not a new key and so does not appear in the diff (L3).

> **Asymmetry worth internalizing:** writes are checked against observed state,
> reads are checked against a log the reader controls. That is why bypassed
> writes are caught and bypassed reads are not.

### TB-5 — Agent → Runner (the return value)

```text
AgentResult  ==>  RunSession.step()
```

* **Crossing:** the agent tries to influence what happens next.
* **Enforced by:** `AgentResult` carries no routing or permission fields; the runner recomputes the next envelope from the route table and cross-checks `result.output_keys` against reality ([demo_runner.py:153](../agent_network_demo/demo_runner.py:153)).
* **Holds against:** an agent choosing its successor, its grants, or lying about what it wrote.
* **Bypassable by:** L6/L7 (mutating the route table or the receipt list).

### TB-6 — Agent → Audit

```text
agent._emit()  ==>  EventLog  ==>  events_<run>.jsonl
```

* **Enforced by:** nothing authenticates `Event.agent`.
* **Holds against:** nothing.
* **Contained by:** `ValidationAgent` deriving authorization from runner receipts rather than log events (B18) — so a forged event corrupts the *record*, not the *decision* (L4).

### TB-7 — Runner → Audit (receipts)

```text
RunSession.step()  ==>  self._receipts  ==>  ValidationAgent
```

* **Intended as:** trusted evidence, produced by the runner, consumed by an independent checker.
* **Actually:** the same list object is handed to the validator (L7). `receipts()` deep-copies for *external* callers, but the agent-side handle is live.
* **Status:** the weakest link in the audit plane and the first Phase 2 fix.

## 3. Things that are not boundaries

Recording these explicitly, because each one is easy to mistake for a control.

| Looks like a boundary | Actually |
|---|---|
| The leading underscore in `_store`, `_artifacts`, `_receipts` | A naming convention. CPython enforces nothing. |
| `@dataclass(frozen=True)` on `Route` | Freezes an individual route object. The dict holding them is mutable, and rebinding the dict entry is unrestricted. |
| `deepcopy` on artifact reads | Prevents *accidental* aliasing and protects external callers. Does not stop deliberate access to the original. |
| "Append-only" `EventLog` | A property of the API surface. The file underneath is an ordinary writable file. |
| The `allowed_actions` list | Real, because `validate_inbound` ties it to the contract (B2). Would be decorative without that check — the distinction is the point. |
| Agent `name` strings | Labels. There is no identity plane, so no name is authenticated anywhere. |

## 4. Boundary strength ledger

Maintained per phase. A boundary is only promoted when an adversarial test
demonstrates the attack failing *for that specific reason*.

| Boundary | v0 | Target phase |
|---|---|---|
| TB-1 path confinement | Enforced (interface) | — |
| TB-2 grant issuance | Enforced (in-process) | P4: separate issuance from decision |
| TB-3 scoped read | **Interface only** | P5: process isolation |
| TB-4 scoped write | Enforced + state-diff | P2: extend diff to detect mutation |
| TB-5 no self-authorization | Enforced (in-process) | P3: bind capabilities to workflow + audience |
| TB-6 agent audit claims | **None** | P7: identity-bound events |
| TB-7 receipt integrity | **Shared handle** | P2 (fix), P7 (hash chain) |
| Flow / sink policy | **Absent** | P6 |
| Provenance / blast radius | **Absent** | P8 |

## 5. Rule for changing this document

When a phase adds a control, update the ledger in the *same* commit as the
control and its adversarial test. A boundary is never described as enforced on
the strength of an intention, a comment, or an unenforced metadata field.
