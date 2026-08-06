# Agent Security Lab

A laboratory for demonstrating what happens when an AI agent, agent process,
service boundary, orchestrator, capability broker, audit system, or data
authority is **compromised** — and exactly how much authority each compromise
does and does not grant.

The working assumption is not that agents behave:

> Any agent may become confused, manipulated, malicious, or fully compromised.

Controls therefore live outside the agents, and every security claim in this
repository states its assumptions and scope. The project does not claim to
build an unhackable AI system. Its defensible claim is that failures become
*incremental, observable, containable, traceable, and recoverable* rather than
one uninterrupted path from manipulated input to production authority.

## Start here

| Document | What it covers |
|---|---|
| [docs/threat-model.md](docs/threat-model.md) | Central assumption, trusted computing base, adversary levels, non-claims |
| [docs/trust-boundaries.md](docs/trust-boundaries.md) | The five planes, every boundary, and what only *looks* like a boundary |
| [docs/compromise-ladder.md](docs/compromise-ladder.md) | Levels 1–7, blast radius, detection, containment, recovery |
| [docs/security-concepts.md](docs/security-concepts.md) | Mapping to standard terminology, and where the mapping is partial |
| [docs/baseline.md](docs/baseline.md) | The preserved baseline's controls (B1–B19) and verified limitations (L1–L8) |
| [cases/README.md](cases/README.md) | Case contract, adversarial-test-first rule, acceptance criteria |

## Cases so far

| Case | Result |
|---|---|
| [00 — audited component edits its own evidence](cases/00-receipt-handle/README.md) | ✅ **Blocked.** A hostile validator could delete failing receipts through the handle it was given, flipping a run's verdict from `warn` to `ok`. The runner now owns an append-only ledger and agents get a read-only view, so the attack needs Level 2 rather than Level 1. |
| [01 — reading artifacts the grant excludes](cases/01-ungranted-read/README.md) | ⚠️ **Open, by design.** Three unrelated reach-around paths all succeed and none appear in the read log. No in-process control exists; the obvious patch is demonstrated to close one path of three and is refused. Control is process isolation, Phase 5. |

Each case ships an executable attack you can run yourself, e.g.:

```bash
python cases/01-ungranted-read/attack.py
```

The clean architectural baseline is preserved at tag
`v0-baseline-inprocess` and mirrored in the reference repository
[Agent-payload-demo](https://github.com/Alleyfoo/Agent-payload-demo). This
repository is the deliberately attacked, analysed, and hardened copy.

---

## The baseline under test

A small, deterministic, in-process architecture demo. Agents exchange artifact
keys rather than payload content. A trusted runner constructs every
runner-enforced scoped handoff, grants a capability-scoped store view, validates
actual reads and writes, and records an authorization receipt after each stage.

This is deliberately free of LLM, network, database, and distributed-execution
dependencies. It demonstrates an architecture, not a cryptographic security
boundary.

```
Key file (intent + bounded source selection)
  -> trusted runner grants IntakeAgent
  -> trusted runner grants SchemaAgent
  -> trusted runner grants TransformAgent
  -> trusted runner grants ValidationAgent
  -> human-readable verdict
```

## How the boundary works

- `ArtifactStore` owns immutable artifacts. Public reads and snapshots return
  deep copies, and snapshot hydration verifies every `source_hash`.
- `StoreView` permits only the runner-granted input keys and one contracted
  output key. It records actual reads and writes for the runner receipt.
- `IntakeAgent` is the only component in the agent chain that opens the source
  file. It stores the complete rows at `artifact.raw_input`; UI panels show only
  a preview.
- Schema and Transform read complete source content from granted artifacts.
  They never receive or reopen a filesystem path as operational input.
- Agents return output keys, a summary, and operational details. They do not
  construct the next permission-bearing envelope.
- `WORKFLOW_ROUTES` in `demo_runner.py` fixes each receiving agent, input grant,
  output contract, allowed action, and next stage. Key-file action fields cannot
  grant runtime permissions.
- The JSONL event log is append-only through the application API. It is not
  described as tamper-proof or tamper-evident.
- UUID-based run IDs avoid collisions between concurrent or deleted runs.

## What the baseline proves

Scope: code that reaches the store **through the interfaces it is given**.

- Handoffs carry keys rather than artifact content.
- Runtime grants restrict reads and writes.
- Only Intake accesses the source file.
- Agents cannot choose their successors' permissions — `AgentResult` carries no
  routing or permission fields, and the runner rebuilds each envelope from the
  trusted route table.
- A write outside the contracted key is caught even if the scoped view is
  bypassed, because the runner diffs actual store contents rather than trusting
  the agent's self-report.
- A final ValidationAgent checks the artifact chain and runner-owned receipts.

## What the baseline does not prove

- **Containment of hostile code in the same process.** Verified against the
  tagged baseline: such code reads ungranted artifacts undetected, mutates
  stored artifacts in place, forges audit events attributed to the runner,
  deletes the on-disk log, and rewrites the route table. See
  [docs/baseline.md](docs/baseline.md) §3 for the reproduction and the exact
  scope of each finding.
- Security between separate processes or machines.
- Cryptographic identity or authorization.
- Tamper evidence. The event log is append-only *through the application API*;
  the file underneath is an ordinary writable file.
- Any information-flow property. Artifacts carry no classification, so a chain
  of individually valid steps is not evaluated as a whole.
- Any blast-radius property. Artifacts record content hashes but not producers,
  so dependent outputs cannot be traced after a compromise.
- LLM reliability.
- Lower token usage at production scale.
- Self-healing or adaptive retry.
- Protection against a compromised trusted runner.

## Handoff example

```json
{
  "run_id": "run_7e2a...",
  "from_agent": "intake_agent",
  "to_agent": "schema_agent",
  "handoff_type": "schema_request",
  "input_keys": ["artifact.raw_input"],
  "output_contract": "schema_profile.v1",
  "context_summary": "Loaded 20 source rows.",
  "allowed_actions": ["read_artifact", "write_schema_profile"]
}
```

The envelope contains a key and summary, not table rows. The complete raw rows
remain in the artifact store.

## Project layout

```
agent_network_demo/
  streamlit_app.py      # Streamlit click-through UI
  demo_runner.py        # trusted route table, envelopes, grants, receipts
  agents.py             # deterministic Intake/Schema/Transform/Validation
  contracts.py          # closed actions and output contracts
  artifact_store.py     # immutable store and scoped StoreView
  event_log.py          # application-API append-only JSONL log
  fixtures/             # bounded key file and sample payloads
tests/                  # unit, end-to-end, smoke, and adversarial tests
```

## Run

```bash
pip install -r requirements.txt
pytest -q
streamlit run agent_network_demo/streamlit_app.py
```

In the UI, click **Start run**, then **Step next agent** four times. Each step
adds the agent's work event and the trusted runner's authorization receipt. The
fourth step runs ValidationAgent and displays the final verdict.

## Artifact keys

- `artifact.raw_input`
- `artifact.schema_profile`
- `artifact.cleaned_output`
- `artifact.validation_verdict`
