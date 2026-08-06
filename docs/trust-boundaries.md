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
| Identity | *Assigned, not authenticated.* The runner takes an agent's identity from the routing table rather than from `agent.name` (case 04), but nothing proves who is executing | **No** |
| Audit | `EventLog` + `ReceiptLedger` | **Partly** — receipts are read-only for agents (case 00) and log attribution is runner-assigned (case 04), but nothing is chained and the file is rewritable (L5) |

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
* **Bypassable by:** rewriting the routing table (L6) — now **prevented** through the interface and **detected** mid-run ([case 03](../cases/03-mutable-route-table/README.md)). A Level 2 adversary rewriting the private table before `start_run` remains undetected.

### TB-3 — Agent → Store (read)

```text
agent  ==>  StoreView.get()  ==>  ArtifactStore
```

* **Enforced by:** [artifact_store.py:125](../agent_network_demo/artifact_store.py:125); non-probeable `has()` at :133.
* **Holds against:** reading any key outside the grant *through the view*.
* **Bypassable by:** `view._store.get()`, a `sys._getframe()` walk, or a `gc.get_objects()` scan — all succeed and none are logged (L1, L2). This is the single most important honest caveat in the repository. See [case 01](../cases/01-ungranted-read/README.md), which also records why removing the private attribute is refused as a fix.

### TB-4 — Agent → Store (write)

```text
agent  ==>  StoreView.register()  ==>  ArtifactStore
```

* **Enforced by:** [artifact_store.py:136](../agent_network_demo/artifact_store.py:136), plus the runner's store-diff at [demo_runner.py:144](../agent_network_demo/demo_runner.py:144).
* **Holds against:** writing any key but the granted one — including via a bypass path, because the diff compares actual store contents rather than trusting the view.
* **Bypassable by:** in-place mutation of an existing artifact, which is not a new key and so does not appear in the diff (L3). Now **detected** — not prevented — by hash verification at the read boundary and a runner post-step sweep ([case 02](../cases/02-artifact-mutation/README.md)).

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
* **Bypassable by:** nothing at Level 1. Both L6 (route table) and L7 (receipt list) now require Level 2 reach-around rather than a hostile agent implementation.

### TB-6 — Agent → Audit

```text
agent._emit()  ==>  EventLog  ==>  events_<run>.jsonl
```

* **Enforced by:** `EventLogView`, an author-bound handle minted by the runner from the routing table; the runner also tallies its own label and verifies it after every step (case 04).
* **Holds against:** Level 1 — an agent using the handle it is given cannot append under another identity. Not against Level 2 reaching the `EventLog` itself, where only the runner's own label is tallied.
* **Contained by:** `ValidationAgent` deriving authorization from runner receipts rather than log events (B18) — so a forged event corrupts the *record*, not the *decision* (L4). Measured in case 04b, not assumed.

### TB-7 — Runner → Audit (receipts)

```text
RunSession.step()  ==>  self._receipts  ==>  ValidationAgent
```

* **Intended as:** trusted evidence, produced by the runner, consumed by an independent checker.
* **At the tag:** the same list object was handed to the validator (L7), and scrubbing it corrupted `RunSession.receipts()` itself.
* **Enforced by (now):** `ReceiptLedger` / `ReceiptView` ([receipts.py](../agent_network_demo/receipts.py)) — read-only handle, deep copy per item, `ReceiptIntegrityError` on every mutation. See [case 00](../cases/00-receipt-handle/README.md).
* **Holds against:** a hostile agent implementation (Level 1) editing the evidence it is audited against.
* **Bypassable by:** Level 2 reach-around to `view._ledger._receipts` (L1 applies here too).

### TB-8 — Agent → the run's conclusion

```text
ValidationAgent  ==>  artifact.validation_verdict  ==>  report()["verdict"]
```

* **Intended as:** an independent check on the chain, published as the run's answer.
* **At the tag:** the same untrusted component read the evidence, drew the conclusion and published it. `report()` returned the agent's artifact verbatim.
* **Enforced by (now):** `derive_verdict()` in [verdict.py](../agent_network_demo/verdict.py), called by the runner over its own store and ledger. The agent's artifact is `report()["recommendation"]`; disagreement on the decision fields sets `review_required`. See [case 05](../cases/05-false-verdict/README.md).
* **Holds against:** a hostile validator (Level 1) publishing a conclusion the evidence does not support, in either direction.
* **Bypassable by:** Level 2 rewriting `_derived_verdict` or patching the derivation — though patching only one side surfaces as disagreement with the other. The derivation also trusts artifact metadata the agents wrote.

## 3. Things that are not boundaries

Recording these explicitly, because each one is easy to mistake for a control.

| Looks like a boundary | Actually |
|---|---|
| The leading underscore in `_store`, `_artifacts`, `_receipts` | A naming convention. CPython enforces nothing. |
| Holding a reference in a closure instead of an attribute | Closes one reach-around path. The frame stack and the GC are unaffected — demonstrated and refused in case 01. |
| `@dataclass(frozen=True)` on `Route` | Freezes an individual route object. At the baseline the dict holding them was mutable, so rebinding an entry was unrestricted — freezing the element is not freezing the collection (case 03). |
| `MappingProxyType` over a dict | A read-only *view*, not a freeze. It removes write methods from one object; the underlying mapping stays writable to anything that reaches it. |
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
| TB-2 grant issuance | Enforced; policy read-only + pinned per run (case 03) | Expected policy held outside the process |
| TB-3 scoped read | **Interface only** in-process; a real boundary for an isolated stage, resolved per read (case 06) | Isolate the remaining three stages; ambient authority still unbounded |
| TB-4 scoped write | Enforced + state-diff + integrity verification (case 02) | Hash held outside the store's reach — needs a different trust boundary |
| TB-5 no self-authorization | Enforced (in-process) | P3: bind capabilities to workflow + audience |
| TB-6 agent audit claims | **None** | P7: identity-bound events |
| TB-7 receipt integrity | Read-only vs. Level 1 (case 00) | P7 (hash chain) |
| TB-8 the run's conclusion | Runner-derived, recommendation compared (case 05) | Derivation and its reference value both in-process — needs a different trust boundary |
| Flow / sink policy | **Absent** | P6 |
| Provenance / blast radius | **Absent** | P8 |

## 5. Rule for changing this document

When a phase adds a control, update the ledger in the *same* commit as the
control and its adversarial test. A boundary is never described as enforced on
the strength of an intention, a comment, or an unenforced metadata field.
