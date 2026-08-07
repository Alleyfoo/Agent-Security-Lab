# Agent Security Lab — orientation handout

Read this first if you are picking up this work in a new session. It is
orientation only: **it deliberately does not restate any security result.**
Results live in one canonical place (§4) and restating them elsewhere is how
claims drift.

---

## 1. Where things are

| | |
|---|---|
| **This repo** | `C:\Users\pertt\Agent-Security-Lab` → `github.com/Alleyfoo/Agent-Security-Lab` (private) |
| **Preserved baseline** | `C:\Users\pertt\Agent-payload-demo` → `github.com/Alleyfoo/Agent-payload-demo`, pinned at `fdf6b42` |
| **Baseline tag here** | `v0-baseline-inprocess` = commit `ae46595`. **Never rewrite it** — every case's before/after reproduces against it |
| **Streamlit main file** | `agent_network_demo/streamlit_app.py` — must stay at this path |

The two repos have different jobs. `Agent-payload-demo` is the clean
architectural reference and is **not** to be turned into the laboratory. This
repo is the deliberately attacked copy. They share no git history.

Start sessions with the working directory set to this repo. If a shell is
rooted in `Agent-payload-demo`, commands silently operate on the baseline.

## 2. Scope — one research question

> Can an agent be restricted to its assigned function when it is manipulated,
> malicious, or fully captured?

**Deferred, and must not influence current slices** unless required to expose
or enforce the agent boundary: production customer-service architecture,
multiple-LLM topology, external logging design, information-flow control,
capability signing, orchestrator compromise, full deployment architecture.

They are documented future questions in `cases/README.md` under *Deferred*.
Listing them is not permission to start them.

The near-term milestone is **not** a secure multi-agent platform. It is a
verified map of what a malicious agent can and cannot do inside the baseline
process — which effects are prevented or detected, and which remaining failures
require an actual process boundary.

### What the project may not claim — one dead hypothesis

Case 12 compared three architectures and refuted this outright:

> ~~The object model is safer than an identity model or a workflow model.~~

For the one property family measured — authority structure and tampering — the
object model has the *most* authority-bearing records, the same minimum tamper
set as the identity model, and a one-edit route wider in scope than either
other arm. The competent workflow arm did best, and did it by accident of
ordinary configuration.

The honest form of the claim, and the one to use in any write-up:

> Different orchestration models attach authority and state differently. This
> laboratory is experimentally identifying which properties actually improve
> under each model, and at which threat level.

The principle that survived is **architecture-neutral** and belongs to no arm:

> Authority is harder to forge when it must be derived from independent
> premises than when it is read from one writable conclusion.

Measured bound, which must travel with it: the number of independent premises
sets the *cost* (2 premises → 2 edits), not the *possibility* — both of arm B's
records sat inside the same adversary's reach. Only a premise outside that
reach has ever bought more than a price increase.

Full argument and evidence: the **What the cases add up to** section of
[`cases/REPORT.md`](cases/REPORT.md).

## 3. Non-negotiable working rules

### Result vocabulary — closed set

Every attack outcome is exactly one of:

| Value | Meaning |
|---|---|
| `prevented` | The unauthorized effect never occurred |
| `rejected_before_commitment` | Hostile output produced but never accepted into trusted state |
| `detected_after_occurrence` | The effect occurred and was noticed later |
| `undetected` | The effect occurred and no trusted observation identified it |

"Handled", "protected", "secure", "mitigated" are not results. Enforced in
`CaseResult.__post_init__`.

For confidentiality attacks, **detection after the read is not prevention** —
once secret content reaches the compromised agent, the loss has occurred.

### Case sequence — contract before code

1. Write the case contract first. No production change before it exists.
2. Write the attack and **prove it succeeds** against the current code. A
   control whose attack was never demonstrated is unfalsifiable.
3. Implement the control **outside** the component assumed compromised.
4. Run the *same attack, unchanged* against the control.
5. Assert on the **specific denial reason**, not merely that something raised.
6. Preserve every existing test. The count only goes up.
7. Document the residual limitation, and pin it with an executable test where
   possible.

### One claim per slice

Do not bundle independent security claims. A slice's central claim must pass or
fail on its own.

### Reject cosmetic confinement

A change is rejected if it only improves the *appearance* of confinement:

- renaming private attributes, adding underscores
- hiding references in closures
- freezing a wrapper while the underlying state stays mutable
- telling an agent in a prompt not to misbehave
- treating a read log controlled by the reader as complete evidence
- calling subprocess separation a complete sandbox
- marking an open negative case as passed

**Prefer an honest red result over a cosmetic green one.** `ClosureStoreView`
in `cases/01-ungranted-read/` is the recorded example of a patch demonstrated
and then refused.

### Tripwires

Open cases assert that the attack **succeeds**, and carry a `TRIPWIRE` message
naming the phase that should break them. When that control lands the tests
fail, and the failure is the instruction to rewrite the case. **Never relax a
tripwire to green a suite.**

### Record deviations, don't adopt them

If measurement disagrees with a direction or an assumption — including threat
*classification* — record the deviation with evidence rather than adopting the
label. There is precedent in the case notes.

## 4. Canonical sources — do not duplicate

| What | Where |
|---|---|
| **All case results and claims** | `cases/registry.py` — the single source |
| Rendered report (acceptance criterion 7) | `cases/REPORT.md` — generated; a test fails if stale |
| Case contracts and detail | `cases/NN-*/README.md` |
| Executable attacks | `cases/NN-*/attack.py` |
| Adversarial tests | `tests/adversarial/` |
| Threat model, boundaries, ladder, concepts | `docs/` |
| Baseline controls (B*) and limitations (L*) | `docs/baseline.md` |
| Session state and next task | `.handoff.md` (gitignored) |

Security claims are written **once**, in `registry.py`, and rendered from
there. Do not restate a result in test code, README prose, report code or UI
code independently.

When a case closes a finding, update `docs/baseline.md`, `docs/trust-boundaries.md`
and the ladder **in the same commit**. A fixed finding must never stay
described as open.

## 5. Current status

Do not read status from this file — it goes stale. Read:

```bash
cat cases/REPORT.md          # results + the in-process boundary map
cat .handoff.md              # session state, next task, open decisions
python -m pytest -q          # the regression floor
```

`cases/REPORT.md` also carries the **boundary map** that gates the move to
process isolation, and the cross-cutting finding that has emerged from the
cases so far.

## 6. Transition gate to process isolation

Phase 5 does not begin until the boundary map in `REPORT.md` answers all seven
questions: which interface controls genuinely work, which attacks remain
possible through shared memory, which unauthorized writes can be detected,
which unauthorized reads remain invisible, which runner-owned structures agents
can affect, which conclusions remain agent-authored, and which evidence remains
trustworthy.

The transition statement, when it is earned:

> The remaining attacks cannot be closed honestly while agent and trusted
> infrastructure share a Python process. The next control changes the trust
> boundary rather than hiding references inside the same boundary.

The first isolation experiment moves **one** hostile agent into a subprocess
and runs the same attack suite against both architectures. Its initial claim
must stay narrow — a separate process prevents direct inspection and
modification of the runner's Python memory and object graph — and must not
imply filesystem confinement, network confinement, host isolation, capability
security, correctness of permitted output, or resistance to OS compromise.

## 7. UI work — when it happens

Do **not** hand-build a Streamlit panel per case. Build one data-driven case
comparison surface rendering `cases/registry.py`, the same structure the report
and tests use. An open case renders with its real (unimproved) result — never
artificially green.

## 8. Practical gotchas

- **Windows file handles.** `EventLog` keeps the JSONL file open. Call
  `session.log.close()` before a `TemporaryDirectory` unwinds, or cleanup
  raises `PermissionError`. Attack scripts and test fixtures already do this.
- **`RunSession.report()` can raise.** On a store that failed integrity
  verification it raises rather than returning. That is fail-closed and
  intended, but the Streamlit app calls it unguarded — a UI that can drive a
  hostile case needs to handle the quarantine state.
- **Streamlit Cloud caches stale modules.** After a push, **reboot** the app;
  a refresh is not enough.
- **Regenerate the report** after touching `cases/registry.py`:
  `python cases/report.py`. A test enforces it.
- **Tests may reach past private attributes.** In `tests/adversarial/` that is
  the point — they model an adversary inside the process, and the reach-around
  is the thing being measured.

## 9. Commands

```bash
python -m pytest -q
```

```bash
python cases/report.py
```

```bash
streamlit run agent_network_demo/streamlit_app.py
```

Run any case's attack directly to watch it work:

```bash
python cases/03-mutable-route-table/attack.py
```

## 10. Global conventions that apply here

From the user's own instructions:

- Conventional commit messages (`feat:`, `fix:`, `docs:`, `test:`, `chore:`).
  Commit at each logical milestone, not in one batch at the end.
- Write `.handoff.md` at the end of every session; read it at the start.
- Python-first; prefer local/self-hosted tooling over cloud APIs.
- Feedback should focus on code quality and logic — not git health,
  infrastructure or workflow, unless asked.
