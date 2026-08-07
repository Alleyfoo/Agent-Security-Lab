# Threat model

Scope: the agent execution architecture in this repository, as of
`v0-baseline-inprocess`. This document is versioned alongside the controls —
when a phase changes what is trusted, amend the tables here in the same slice.

---

## 1. Central assumption

> Any agent may become confused, manipulated, malicious, or fully compromised.

The architecture is therefore not designed to make agents behave. It is
designed so that an agent which does not behave gains a bounded, observable,
recoverable amount of authority.

Two things are kept categorically distinct:

```text
Agent output      A proposal, result, summary, or piece of evidence.
                  Never self-executing. Never authorizing.

Authority         A permission issued and enforced by trusted infrastructure,
                  independent of anything the agent returned.
```

An agent must not be able to obtain authority by returning a specially shaped
object. In the baseline this holds because `AgentResult`
([agents.py:158](../agent_network_demo/agents.py:158)) has no routing or
permission fields, and the runner builds every envelope from `WORKFLOW_ROUTES`
without consulting the previous agent's return value.

## 2. Trusted computing base (baseline)

Compromise of anything in this list invalidates the baseline's claims.

| Trusted | Why it must be, at this stage |
|---|---|
| Operating system, filesystem, CPython interpreter | Everything runs in one unprivileged process with no sandbox |
| `RunSession` (trusted runner) | Constructs every envelope, computes every receipt, owns the step loop |
| `WORKFLOW_ROUTES` | The sole source of grants and stage ordering |
| `ArtifactStore` implementation | Enforces immutability, hashing, and scoping |
| Contract module constants | Define the closed action and contract vocabulary |
| The Python module namespace itself | Route table and store internals are reachable from it (see L6, L1) |

The last row is the uncomfortable one and is stated deliberately. Because
agents execute in the same interpreter, the TCB includes *every object
reachable from any agent*, which in CPython is effectively all of them.

## 3. Untrusted inputs

| Untrusted | Baseline handling |
|---|---|
| Agent implementation code | Constrained only through the interfaces it chooses to use (L1) |
| Model output / summaries | Carried as `context_summary`; never parsed into a decision |
| Key files | Parsed as data; `actions` fields ignored (B11); `source_ref` confined (B12) |
| Source payload files | Confined to the fixtures directory; parsed as CSV/JSON only |
| Agent-authored log events | Descriptive only; excluded from authorization (B18) |
| Requested operations and routing | Not honoured — the runner does not read them |
| Artifact content produced by an agent | Hashed on registration; content itself is not validated |
| User input in the UI | Key file is a selectbox over bundled fixtures, never free text |

## 4. Explicit statement of the in-process limitation

> Arbitrary hostile Python running in the same process is not contained by
> Python naming conventions or a scoped wrapper alone.

`StoreView` is an enforcement mechanism **for access through its interface**.
It is not a process-isolation boundary against code that can inspect the
complete Python runtime. This was verified against the tagged baseline, not
assumed — see [baseline.md](baseline.md) §3, L1–L3.

This limitation must remain visible in the README, the UI, and every case
result until process separation lands in Phase 5. Removing the caveat before
the boundary exists is the failure mode this project is meant to avoid.

## 5. Adversary capabilities by level

Full ladder detail lives in [compromise-ladder.md](compromise-ladder.md). In
brief, the adversary is assumed to control, at each level:

| Level | Adversary controls | Baseline survives? |
|---|---|---|
| 1 | What an agent *requests* (injection, poisoned input, bad planning) | **Yes** — the routine design case |
| 2 | Arbitrary code inside one agent process | **No** — same process as the runner |
| 3 | The agent's host or container | No — not modelled yet |
| 4 | Capability issuance / artifact authorization | No — not separated yet |
| 5 | Workflow construction (orchestrator, policy) | No — no independent flow policy |
| 6 | Identity and signing infrastructure | No — no identities exist |
| 7 | The database or final data authority | No — and prevention is not achievable here |

Level 1 is the minimum the architecture must survive routinely, and the
baseline does survive it. Levels 2–7 are the laboratory's work programme.

## 6. Assets

| Asset | Compromise means |
|---|---|
| Artifact confidentiality | An agent reads data outside its stage's grant |
| Artifact integrity | A stored artifact's content changes after registration |
| Authorization integrity | Authority is exercised that the route table never granted |
| Audit integrity | The recorded history diverges from what happened |
| Flow integrity | A sequence of individually valid steps produces a forbidden end-to-end effect |
| Recoverability | After a compromise, affected outputs cannot be identified |

Note that flow integrity and recoverability have **no baseline control at
all** — artifacts carry no classification and no producer provenance. They are
not weakly defended; they are undefended, by design, until Phases 6 and 8.

## 7. Out of scope

* Availability and denial of service.
* Side channels: timing, cache, power, memory-pressure inference.
* Supply-chain compromise of Python packages or the interpreter build.
* Physical access and hardware attack.
* Attacks on the human reviewing the demo output.

These are excluded because the project cannot demonstrate them honestly at its
current scale, not because they are unimportant. Say so rather than implying
coverage.

> **Open direction question, raised by the review in `cases/REPORT.md`.**
> Availability is excluded here as an *attack target*, and the cases have
> meanwhile been spending it as a *control currency*: quarantine stops a run
> (cases 02, 03, 04a), fail-closed refuses a grant (case 09), a produced-once
> invariant blocks a legitimate producer permanently and unintentionally
> (case 10), and containment on a contradiction widens that surface on purpose
> (case 11). Three of those are cheap for an attacker to trigger deliberately.
>
> The two meanings are different and this section currently covers only one, so
> the project has nowhere to record what a control costs in availability, and
> no rule about how much it may spend. Recorded rather than resolved: which
> meaning §7 excludes is a direction decision, not a measurement.

## 8. Non-claims

The project does not claim, and no case README may claim:

* that an AI system is "secure" without a stated assumption set;
* that containers are an absolute security boundary;
* prevention where only detection is implemented;
* tamper-*proof* where only tamper-*evident* is implemented;
* that a passing test alone establishes a security property.

Every security claim in this repository states its assumptions and its scope,
or it is a bug.
