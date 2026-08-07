# Security concepts — mapping this codebase to standard terminology

The baseline was built as an architecture demo, not a security artifact, so its
mechanisms carry project-specific names. This maps them to the established
concepts a security reviewer will look for, and — more importantly — records
where the mapping is *partial*.

---

## 0. The layer model, and a framing error it corrects

Cases 12–15 compared an identity model, a workflow model and an object model.
The framing implied they compete. **They do not — they sit at different
layers**, and a workflow engine can perfectly well run on top of conventional
OS security while an object/skill system runs on top of both:

```text
Application authority model      object / skill / artifact relationships
        ↓
Workflow / orchestration model   steps / connectors / credentials / state
        ↓
Execution isolation              process / container / service boundaries
        ↓
Operating-system enforcement     users / ACLs / MAC / capabilities / kernel
        ↓
Hardware / physical trust
```

**The measurements stand; the framing was wrong.** Cases 12–15 are recorded
here as three *idioms for expressing the same protection principles*, not three
competitors, and no result in them should be read as "model X beats model Y".
Case 12's own registry entry already refused that reading; this states the
reason structurally. The useful question is not which layer wins but:

> How does each layer implement the same underlying protection principles, and
> what happens when the layer below or above it is compromised?

A corollary worth keeping: **if one layer is the only thing keeping the system
safe, the system is brittle.** The layers are supposed to reinforce each other —
the OS stops the worker escaping its process, the workflow layer controls
credentials, the object layer controls which transformation is valid, and the
artifact layer controls what data resolves.

## 0.05 The analysis subsystem, and what it may not conclude

Separate from the agent runtime above: cases 16 to 18 and 24 built a
reachability view, and the one sentence they amount to is

> **Exposure is derived from the authority graph; severity is supplied from an
> independent source.**

The graph answers *which authority is reachable, through which intermediaries,
which endpoints are exposed, and how many paths lead there*. It does not answer
*how important that authority is*. Case 24 measured what happens when it is
asked to: a severity computed from the graph is not a weaker input than none —
it is the same input, and it changes no ordering.

Full argument, the report-length criterion from case 18, and the −0.995
anti-correlation: **The reachability subsystem's contract** in
[`cases/REPORT.md`](../cases/REPORT.md).

## 0.1 Principles matrix

The comparison this project should be running is not architecture against
architecture. It is **one principle across layers**, asking whether the higher
layer preserves it, weakens it, or expresses it differently.

| Principle | OS layer | Workflow layer | Object/agent layer |
|---|---|---|---|
| Least privilege | process and user rights | connector credentials | task-scoped skill + artifacts |
| Complete mediation | kernel reference monitor | workflow runtime | artifact resolver / manager |
| Separation of privilege | DAC + MAC, separate credentials | independent connection + step policy | skill + object/artifact premises |
| Fail-safe defaults | deny by default | a failed step stops the run | unresolved or conflicting transition rejected |
| Isolation | processes and users | separate services and connections | disposable workers |
| Provenance / integrity | filesystem and audit mechanisms | run history | artifact lineage and receipts |
| Authority scope | subject and resource | workflow and action | object and transformation |

## 0.2 Where the cases landed on established principles

The findings were reached by measurement and then recognised, which is worth
saying plainly: this project did not set out to re-derive Saltzer & Schroeder.

| Measured finding | Established principle |
|---|---|
| Workers should get only what the task needs | least privilege |
| Resolving a reference must go through enforcement | complete mediation |
| Two genuinely independent premises raise tamper cost (case 13) | separation of privilege |
| Unknown or conflicting state stops or quarantines (cases 09, 11) | fail-safe defaults |
| Shared mutable structures become pivots (cases 03, 13, 14) | least common mechanism |
| Removing authority beats adding another colocated check (the review's design rule) | economy of mechanism, least privilege |
| Security cannot rest on hiding worker names or internals (case 01) | open design |

**Two refinements this project can claim**, both measured rather than asserted,
and both stated as implementation conditions on classic principles rather than
as replacements for them:

> **On separation of privilege.** Multiple premises only buy independence if no
> single attacker-controlled selector can move them all together. (Case 13,
> mapped in case 14.)

> **On the reference monitor.** The classic requirements are *always invoked*,
> *tamper-resistant*, and *small enough to analyse*. Every Level 2 residual in
> this repository is the same failure of the second one: an enforcement point
> that shares a writable boundary with the adversary is not tamper-resistant,
> which is why adding another checksum inside that boundary keeps failing. It
> is not that hashes are bad; it is that the enforcement point has to sit
> somewhere the attacker cannot rewrite.

**Relatives worth naming so the model is not oversold as novel:**

* deciding access from subject, object, requested operation, state and policy
  is close to **ABAC**, and the object model is a constrained instance of it;
* **capability security** — an unforgeable reference binding an object to
  permitted operations — is where target-bound grants would eventually lead.
  The current grants are deliberately *not* capabilities and §3 below keeps the
  weaker word.

So the honest description of what is being investigated is not a new
architecture with a new name:

> How established principles — least privilege, complete mediation, separation
> of privilege, fail-safe defaults, and attribute/object-based authorization —
> behave when applied to agent workflows with canonical artifacts and
> disposable workers.

---

## 1. Concept map

| Standard concept | Realized here as | Fidelity |
|---|---|---|
| **Capability / object-capability** | `StoreView` + the envelope's `input_keys` and `output_contract` | **Partial.** A real capability is unforgeable and transfer-controlled. These are plain strings in a mutable process — unforgeable only because nothing forges them yet. |
| **Least privilege** | Per-stage grants in `WORKFLOW_ROUTES`; exactly one writable key per stage | **Good.** Grants are genuinely minimal and stage-scoped. |
| **Complete mediation** | `StoreView.get` / `.register` on every access | **Broken at Level 2.** Mediation is bypassable in-process (L1); the reference monitor is not tamper-proof. |
| **Reference monitor** | `RunSession.step()` | Satisfies *always-invoked* and *small enough to verify*; fails *tamper-proof*. Two of three. |
| **Separation of duties** | — | **Absent.** Policy decision, capability issuance, and enforcement are all `RunSession`. Phase 4. |
| **Confused deputy** | — | **Absent.** No component currently holds authority on behalf of a requester, so the pattern cannot yet arise. Phase 4 introduces it deliberately. |
| **Ambient authority** | The filesystem, the module namespace, the process's uid | **Present and unmitigated.** This is exactly what Level 2 exploits. |
| **Provenance / content addressing** | `source_hash` over canonical JSON ([artifact_store.py:16](../agent_network_demo/artifact_store.py:16)) | **Partial.** Content is addressed; *producer* is not recorded. No identity, host, policy version, or input-hash lineage. Phase 8. |
| **Immutability / write-once** | `DuplicateKeyError` on differing content | **Partial.** Prevents rebinding, not in-place mutation (L3). |
| **Taint tracking / information-flow control** | — | **Absent.** No labels, no propagation, no sink policy. Phase 6. |
| **Tamper-evident log** | `EventLog` | **Not achieved.** Append-only by API only. No chaining, no sequence binding, no external anchor. Use "append-only by API" until Phase 7. |
| **Non-repudiation** | — | **Absent.** Attribution is now *assigned* by the runner rather than claimed by the agent (case 04), which stops a Level 1 forgery but proves nothing: no keys, no signatures, and same-process code can still write under any label. |
| **Defence in depth** | Contract validation + view scoping + outbound store diff | **Genuine.** Three independent checks on the write path; the diff catches what the view misses. |
| **Fail-closed / default-deny** | Closed action vocabulary; unknown key → deny | **Good on the request path**, fail-open on missing evidence (see ladder). |
| **TOCTOU** | `confine_path` at `start_run` vs. `open()` at run time | **Latent.** Currently unreachable; would become real the moment `source_ref` is settable between the two points. |
| **Blast radius / dependency tracing** | — | **Absent.** The artifact graph exists implicitly but is not recorded or queryable. Phase 8. |
| **Revocation** | — | **Absent.** A grant lives exactly as long as one `step()` call and cannot be withdrawn early or reused. Short-lived by construction, not by policy. |

## 2. Where the baseline is genuinely strong

Worth stating plainly, because the rest of this repository is about attacking it.

1. **Authority does not flow through return values.** `AgentResult` has no
   routing or permission fields, and the runner rebuilds each envelope from
   the route table. This eliminates a whole class of self-escalation that
   agent frameworks routinely permit.
2. **The write path is checked against observed state, not self-report.** The
   store-key diff at [demo_runner.py:144](../agent_network_demo/demo_runner.py:144)
   means an agent cannot lie about what it wrote, even by bypassing the view.
3. **Grants are tied to obligations.** `validate_inbound` requires that the
   action backing an `output_contract` actually be granted, so
   `allowed_actions` cannot decay into decorative metadata — the failure mode
   §15 of the charter calls "metadata fields that are never enforced".
4. **The verdict is computed from runner evidence, not agent testimony.**
   The distinction between an agent-authored *work event* and a runner-owned
   *receipt* is the correct one, and it is already implemented.

   Read precisely, this was true of the *inputs* only. The validator computed
   the verdict from runner evidence and then published its own answer, which
   nothing compared to anything ([case 05](../cases/05-false-verdict/README.md)).
   Protecting the input to a computation is not the same as protecting its
   output when the adversary owns the computation. The runner now derives the
   conclusion itself.

Points 1–4 are what makes the baseline a defensible starting point rather than
a strawman. The laboratory's value comes from attacking a design that is
already better than average.

## 3. Vocabulary rules for this repository

Terms are used in their strict sense. When the implementation does not meet
the strict sense, the weaker term is used.

| Use | Not | Because |
|---|---|---|
| tamper-evident | tamper-proof | Evidence of change ≠ prevention of change |
| append-only by API | append-only | The file is writable |
| scoped view | sandbox / isolation | No process, memory, or syscall boundary |
| detected | prevented | Different guarantees, different response |
| bounded blast radius | contained | Bounded means measurable, not zero |
| grant | capability | Until it is unforgeable and audience-bound (Phase 3) |
| deterministic containment | automatic remediation | The response is a fixed table, not a judgement |

## 4. Anti-patterns this project must not exhibit

From the charter, restated as review criteria. A slice is rejected if it:

* adds a comment or field asserting security without an enforcing check;
* prompts an agent not to misbehave and calls that a control;
* introduces metadata that no runtime path reads;
* defines an allowlist not connected to a runtime check;
* has the audited component write its own audit record;
* presents post-hoc detection as prevention;
* presents a container as a magical security boundary;
* bundles several independent security claims into one change.

> The baseline violated one of these — **the audited component held a live
> handle to its own evidence** (L7). Fixed by
> [case 00](../cases/00-receipt-handle/README.md); the `v0-baseline-inprocess`
> tag still exhibits it. The related weakness that the validator's *conclusion*
> is still agent-authored is recorded as that case's residual limitation, not
> as a fixed item.

## 5. Required framing on every case and UI result

```text
What this proves
What this does not prove
```

Both sections are mandatory. A case with a passing test and a vague claim is
not complete — see the acceptance criteria in [../cases/README.md](../cases/README.md).
