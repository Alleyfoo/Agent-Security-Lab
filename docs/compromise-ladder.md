# Compromise ladder

Each level assumes the level below it has already fallen. For every level the
project must be able to state: what authority the attacker gained, what
remains denied, the maximum blast radius, how it is detected, what containment
runs automatically, and what recovery requires.

The governing idea the showcase must communicate:

> Crossing one boundary grants a specific amount of authority. Further damage
> requires crossing another separately enforced and separately observable
> boundary.

**Baseline status column:** `survives` = the tagged baseline already holds this
line; `open` = the laboratory must build it.

---

## Level 1 — Manipulated agent — *survives*

The attacker controls what the agent *requests*: prompt injection, a hostile
document, poisoned input, bad planning, a malicious tool call.

```text
Gained    Full control of the agent's requested operations and outputs.
Denied    The runner, the route table, and the grant issuer.
```

| | |
|---|---|
| **Blast radius** | One stage's declared inputs and its single contracted output key. |
| **Detection** | `ContractError` from `validate_inbound` / `validate_outbound`; a receipt with `contract_result: failed`. |
| **Containment** | The step raises, `status` becomes `error`, and the workflow does not advance — `self._current` is only incremented on the success path ([demo_runner.py:157](../agent_network_demo/demo_runner.py:157)). No new envelope is issued. |
| **Recovery** | Re-run the stage with corrected input. No artifact was written, so nothing downstream is tainted. |
| **Residual** | The agent's *summary text* still propagates into the next envelope's `context_summary`. It is never parsed into a decision, but a human reading the UI sees attacker-influenced prose. |

Required behaviour, all present at baseline: forbidden operations rejected;
workflow halted on contract violation; no new authority issued; agent-authored
claims excluded from authorization; suspicious output quarantined or routed to
review.

> The last one — quarantine/review routing — is **partially** present. Failures
> stop the chain, but there is no quarantine *state* for an output that was
> written and later becomes suspect. That arrives in Phase 8.

## Level 2 — Fully compromised agent process — *open*

Arbitrary code execution inside one agent.

```text
Gained    That process's memory, its active capability, its output,
          its permitted interfaces, its resource allocation.
Denied    (target) Unrelated artifacts, other workflows, broad filesystem,
          network, policy, DB credentials, audit deletion, capability minting.
```

At the baseline **none of the "denied" column holds**, because the agent shares
a process with the runner and the store. Verified consequences: ungranted
reads succeed unlogged (L1/L2), artifacts mutate in place (L3), runner-attributed
events are forgeable (L4), the log file is deletable (L5), the route table is
rewritable (L6), and the receipt list was editable by the validator (L7 —
fixed against Level 1 by [case 00](../cases/00-receipt-handle/README.md), still
reachable at Level 2 through private attributes).

Target statement once Phase 5 lands, for the Schema stage:

```text
Compromised Schema process
May:      read one raw-input artifact
          write one schema artifact
May not:  read cleaned output
          open arbitrary files
          contact the public internet
          update workflow policy
          access another run
```

| | |
|---|---|
| **Blast radius (target)** | One stage of one workflow; artifacts it legitimately touched. |
| **Detection (target)** | Broker-side denial records; capability use outside grant; receipt-chain gap. |
| **Containment** | Revoke active capabilities; invalidate current output. |
| **Recovery** | Replay the stage under a fresh capability from a clean image; quarantine outputs produced in the suspect window. |

## Level 3 — Agent host or container compromised — *open*

The attacker escapes one sandbox and controls its host.

```text
Gained    Neighbouring processes, local IPC, active local capabilities,
          temp files, local logs, impersonation of co-hosted services.
Denied    (target) Identity roots, policy-signing keys, independent audit
          storage, hosts in other trust zones.
```

| | |
|---|---|
| **Blast radius** | Every workflow scheduled on that host during the suspect window. |
| **Detection** | Host-identity anomalies; receipts signed by a host after its suspected compromise time. |
| **Containment** | Revoke capabilities bound to the host identity; suspend that host's workflows; quarantine outputs produced after the suspected compromise time. |
| **Recovery** | Rebuild from a trusted image. In-place cleanup is not accepted. |

The project must explicitly show that **multiple containers on one host do not
automatically create independent trust zones.** Co-tenancy is a scheduling
property, not a security property.

## Level 4 — Capability broker or artifact service compromised — *open*

```text
Gained    Issue broader access, ignore expiry, permit cross-workflow access,
          substitute artifacts, hide unauthorized reads, impersonate services.
Denied    (target) Whatever the *other two* of the three functions still check.
```

The required split, which the baseline does not have — `RunSession` performs
all three:

```text
Policy decision       Should this access be allowed?
Capability issuance   Create the narrow permission.
Artifact enforcement  Verify the permission at use time.
```

| | |
|---|---|
| **Blast radius** | Every workflow issued or enforced during the compromise window. |
| **Detection** | Reconciliation between issued capabilities and enforced uses; independent audit disagreeing with broker records. |
| **Containment** | Stop new issuance; enter restricted mode. |
| **Recovery** | Re-derive the set of valid capabilities from policy; revalidate affected workflows. |

## Level 5 — Orchestrator or policy engine compromised — *open*

The attacker composes a malicious sequence **entirely out of individually valid
operations**.

```text
Read confidential customer data
  -> summarise it            (valid)
  -> save the summary        (valid)
  -> to a public destination (valid in isolation, forbidden as a chain)
```

Per-step authorization cannot catch this. The control must be an independent
information-flow policy: source classification, destination classification,
allowed-sink rules, explicit declassification, and whole-chain validation.

| | |
|---|---|
| **Blast radius** | Any data reachable by any composition of permitted steps. |
| **Detection** | Sink policy evaluated over the whole chain, not per step. |
| **Containment** | Freeze new workflows; require external approval. |
| **Recovery** | Re-approve workflow definitions against the flow policy. |
| **Hard rule** | The orchestrator must not have unilateral power to remove confidentiality labels. |

## Level 6 — Identity or signing infrastructure compromised — *open*

```text
Gained    Mint apparently valid authority, approve malicious policy changes,
          impersonate trusted agents, create legitimate-looking receipts.
```

The project must distinguish **ordinary token theft** (one credential, bounded
by its scope and expiry) from **compromise of the authority that creates
trusted identities** (every credential is now suspect, including past ones).

| | |
|---|---|
| **Blast radius** | Every credential and receipt in the compromise window; retroactively, anything trusted on their basis. |
| **Detection** | Out-of-band trust-root monitoring. Nothing signed by the compromised root can be self-evidencing. |
| **Containment** | Rotate trust roots; invalidate active credentials. |
| **Recovery** | Rebuild trust relationships; revalidate every workflow executed in the window. |

## Level 7 — Database or final data authority compromised — *open*

At this level the agent controls are bypassed entirely. The required statement:

> The agent execution layer cannot guarantee integrity or confidentiality
> against a fully compromised authority beneath its own trust assumptions.

Remaining controls are **detection only**: independent audit records,
replicated data, externally held hashes, signed receipts, reconciliation
against another system, detection of unexplained historical change.

| | |
|---|---|
| **Blast radius** | The entire data plane and everything derived from it. |
| **Containment** | Isolate the data plane; begin the recovery procedure. |
| **Recovery** | Restore from independently held evidence; reconcile. |
| **Hard rule** | **Do not claim prevention where only detection is possible.** |

---

## Automatic containment policy

Deterministic responses. An LLM is never asked to improvise containment. Each
row must be independently testable.

| Compromise signal | Required response |
|---|---|
| Agent contract violation | Reject operation and stop the workflow |
| Suspicious agent output | Quarantine output and request review |
| Agent process compromise | Revoke active capabilities and invalidate current output |
| Host compromise | Revoke host identity and suspend its workflows |
| Capability broker anomaly | Stop new issuance and enter restricted mode |
| Orchestrator compromise | Freeze new workflows and require external approval |
| Identity-root compromise | Rotate trust roots and invalidate active credentials |
| Database compromise | Isolate data plane and begin recovery procedure |
| Audit verification failure | Freeze affected workflow evidence and investigate |

Baseline coverage: **row 1 only.** Every other row is an unimplemented target,
and the UI must not imply otherwise.

## Fail-closed rule

Unknown actions, missing evidence, invalid capabilities, ambiguous policy, and
broken provenance result in denial or review — never silent continuation.

The baseline is fail-closed on unknown actions and missing input keys. It is
**fail-open on missing evidence**: `ValidationAgent`'s `all_writes_allowed`
requires a non-empty receipt list, but no check ties the receipt count to the
number of stages that actually ran, so a *removed* receipt reduces evidence
without raising an alarm. Phase 7's hash chain closes this.
