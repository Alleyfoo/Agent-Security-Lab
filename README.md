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

**Picking this up in a new session? [HANDOUT.md](HANDOUT.md)** — scope, working
rules, canonical sources, gotchas.

| Document | What it covers |
|---|---|
| [docs/threat-model.md](docs/threat-model.md) | Central assumption, trusted computing base, adversary levels, non-claims |
| [docs/trust-boundaries.md](docs/trust-boundaries.md) | The five planes, every boundary, and what only *looks* like a boundary |
| [docs/compromise-ladder.md](docs/compromise-ladder.md) | Levels 1–7, blast radius, detection, containment, recovery |
| [docs/security-concepts.md](docs/security-concepts.md) | Mapping to standard terminology, and where the mapping is partial |
| [docs/baseline.md](docs/baseline.md) | The preserved baseline's controls (B1–B19) and verified limitations (L1–L8) |
| [cases/README.md](cases/README.md) | Case contract, adversarial-test-first rule, acceptance criteria |

## Current research question

> Can an agent be restricted to its assigned function when it is manipulated,
> malicious, or fully captured?

The near-term milestone is not a secure multi-agent platform. It is **a
verified map of what a malicious agent can and cannot do inside the baseline
process** — which effects are prevented or detected, and which remaining
failures require an actual process boundary.

## Cases so far

Full results: **[cases/REPORT.md](cases/REPORT.md)**, generated from the
canonical registry so a claim cannot be true in one place and stale in another.

| Case | Baseline | Controlled |
|---|---|---|
| [00 — audited component edits its own evidence](cases/00-receipt-handle/README.md) | 🔴 Undetected | 🟢 Prevented |
| [01 — reading artifacts the grant excludes](cases/01-ungranted-read/README.md) | 🔴 Undetected | 🔴 Undetected — open by design |
| [02 — in-place mutation of a registered artifact](cases/02-artifact-mutation/README.md) | 🔴 Undetected | 🟠 Detected after occurrence |
| [03 — altering runner-owned routing data](cases/03-mutable-route-table/README.md) | 🔴 Undetected | 🟢 Prevented |
| [04a — forged runner-labelled audit event: the record](cases/04-forged-runner-event/README.md) | 🔴 Undetected | 🟢 Prevented |
| [04b — forged runner-labelled audit event: the decision](cases/04-forged-runner-event/README.md) | 🟢 Prevented | 🟢 Prevented |
| [05 — a conclusion the agent authors is not evidence](cases/05-false-verdict/README.md) | 🔴 Undetected | 🟡 Rejected before commitment |
| [06 — what process separation actually buys](cases/06-process-isolation/README.md) | 🔴 Undetected | 🟢 Prevented — one stage, one attack class |
| [07 — corrupting downstream artifacts through your own](cases/07-poisoned-chain/README.md) | 🔴 Undetected | 🟠 Detected after occurrence |
| [08 — stored grant vs. grant derived at use time](cases/08-derived-authority/README.md) | 🔴 Undetected | 🔴 Undetected — a comparison, no control applied |
| [09 — can the execution plane mint a transformation?](cases/09-skill-registry/README.md) | 🔴 Undetected | 🟢 Prevented — for a worker; the registry is not trustworthy |
| [10 — the type-to-key binding](cases/10-type-to-key-binding/README.md) | 🔴 Undetected | 🟠 Detected after occurrence |
| [11 — contain a contradiction the moment it appears](cases/11-conflict-containment/README.md) | 🟠 Detected after occurrence | 🟢 Prevented — the object stops; the read the overwrite obtains is untouched |

Every outcome is exactly one of **prevented**, **rejected before commitment**,
**detected after occurrence**, or **undetected**. Vague terms — "handled",
"protected", "secure" — are not results. For confidentiality attacks,
detection after the read is not prevention: once secret content reaches the
compromised agent, the loss has already occurred.

Case 01 stays red because it is genuinely open. An open case is never shown as
green, and a patch that closes one path of a class is refused rather than
shipped.

Case 04 is registered as two rows because forging the audit record and
corrupting the authorization decision are different effects with different
results. 04b is green at the baseline: the decision was already contained by
existing architecture, and the case measured that rather than claiming credit
for it.

Each case ships an executable attack you can run yourself:

```bash
python cases/02-artifact-mutation/attack.py
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
