# Case 06 — What process separation actually buys

**Phase:** 5 (first isolation experiment)
**Baseline finding:** L1, L2 — case 01's open finding
**Ladder level:** 2 (arbitrary hostile code inside one agent)
**Baseline result:** `undetected`
**Controlled result:** `prevented` — for the isolated stage only, and for one
class of attack only

---

## Research question

> What does moving one agent into a separate process actually prevent, measured
> rather than asserted?

## The claim, stated before any measurement

> A stage running in a separate interpreter cannot inspect or modify the
> runner's Python memory or object graph.

That is the whole claim. It is deliberately narrow, and the following are **not
claimed** and are not measured here: filesystem confinement, network
confinement, host isolation, capability security, correctness of the stage's
permitted output, or resistance to OS compromise. Several of those are measured
below and found **absent** — that is the point of measuring them.

Two commitments follow from the project's posture, and they are design
decisions rather than observations:

1. **The process boundary is a containment boundary, not a trust boundary.**
   The isolated stage is assumed captured. Everything crossing back — the
   artifacts it wrote, the events it emitted, its declared identity, its
   declared result — remains untrusted input, validated on the runner's side by
   the controls cases 00–05 already built.
2. **No existing control is removed because isolation "handles it" now.** Hash
   verification, the pinned route table, attribution binding and the derived
   verdict all still run against the isolated stage's output. They are what
   bounds the loss when this boundary fails, and deleting them would be the
   best-case design in its purest form.

## Threat

Ladder Level 2: arbitrary hostile Python executing as the schema stage. This is
the adversary case 01 demonstrated and could not contain — it reached
`artifact.cleaned_output` by three independent paths (`view._store`, a
`sys._getframe()` walk, and a `gc.get_objects()` scan) while
`view.read_keys` stayed empty.

## Existing assumption

**"Process isolation will fix case 01."** Written into case 01's own README as
the deferred control, and into the transition statement earned at the end of
Phase 2. It has never been measured, and the phrase hides two different
claims — that the isolated stage is contained, and that *the system* is. This
case separates them, and they get different answers.

## Mechanism

The stage runs in a spawned interpreter. The only channel is line-delimited
JSON over pipes.

```text
runner process                    │  isolated stage
                                  │
StoreView (grant: raw_input)      │
  ▲ resolve request               │  view.get("artifact.raw_input")
  │                               │    → {"op":"read","key":...}  ─┐
  └─ decide, then answer  ────────┼──  {"ok":true,"value":{...}}  ◄┘
                                  │
register(key, value) ◄────────────┼──  {"op":"result","artifacts":{...},
  contract + hash + attribution   │                    "events":[...]}
```

The parent is a **trusted resolver**. It does not ship the granted artifacts
eagerly: the child asks for a key, the parent checks the grant, and only then
does content cross. Two reasons, both from the concept note's §6 —

* the enforcement point survives the boundary, per read rather than per run;
* `view.read_keys` keeps meaning what it meant in-process, so the runner's
  reconciliation of actual reads against the grant still works. Eager shipping
  would have made that check pass vacuously.

What crosses the boundary is **artifact content for keys already granted**, in
response to a resolved reference. Agent-to-agent handoffs remain
reference-based; this is the resolver step, not a payload handoff.

Returned artifacts are registered through the real `StoreView` and returned
events appended through the real `EventLogView`, so the write contract, the
hash registration and the attribution binding all apply to output that came
from a captured process.

## Attack

```bash
python cases/06-process-isolation/attack.py
```

### A — Case 01's paths, from both placements

The same class, two places to run. The in-process arm is the control: without
demonstrated exposure there is nothing for the boundary to remove.

```text
  In the runner's process:
   !! memory  path 1   view._store                REACHED a store (2 keys)
   !! memory  path 2   call-stack walk            REACHED a store (2 keys)
   !! memory  path 3   gc.get_objects()           REACHED 2 store(s) with no reference path
   !! memory  path 4   the RunSession itself      REACHED (run run_000a87de…)
   !! memory  path 5   ungranted artifact content REACHED ungranted artifact.cleaned_output (20 rows)

  In a spawned interpreter:
      memory  path 1   view._store                nothing found: the view holds no store
      memory  path 2   call-stack walk            nothing found: no ArtifactStore on the call stack
      memory  path 3   gc.get_objects()           nothing found: no ArtifactStore in this interpreter
      memory  path 4   the RunSession itself      nothing found: no RunSession in this interpreter
      memory  path 5   ungranted artifact content nothing found: … is not in this interpreter
```

Five to zero, and the workflow still completed with verdict `ok` and a truthful
read log (`['artifact.raw_input']`).

**Read the failure messages, not the count.** Every path reports *nothing
found*, not *access denied*. The techniques still work perfectly; they run in
an interpreter that contains no runner objects to find. Isolation empties the
room rather than locking the door — which is why it cannot be defeated by a
better reach-around, and equally why it protects nothing that happens to be in
the room already.

Path 5 needed a prior completed run held alive in the process to have anything
ungranted to find. That is not a contrivance: case 01's recorded blast radius
is the process, not the run, and a long-lived host holding finished sessions is
the realistic shape — the Streamlit app keeps them in session state.

### B — What the isolated stage still does

Isolation is not a grant, not a sandbox, and not a validator. Measured:

```text
   !! ambient  repository filesystem   READ (9586 bytes of README.md)
   !! ambient  every run's event log   LISTED (216 event log files)
```

Same uid, same filesystem, same network. It also read exactly what it was
granted — `keys_actually_read == granted_input_keys` — because **isolation
narrows a grant by exactly nothing**. And it still authors its own output; a
process boundary does not make a stage's content honest.

### C — Partial isolation, which is the system's actual state

```text
  The transform stage, still in-process:
   !! memory  path 1..5  all reached, including the isolated stage's own output
  isolated stages in this run                : ['schema']
  stages still sharing the runner's process  : 3 of 4
```

## Observed unsafe result — `undetected`

Case 01's finding, unchanged where it still applies: hostile code in the
runner's process reads any artifact in the process, from any run it has
handled, and `view.read_keys` stays empty.

## Observed protected result — `prevented`, for the isolated stage only

For a stage that is isolated, every demonstrated memory path finds nothing, and
the reads it does make are recorded truthfully. The runner's reconciliation of
actual reads against the grant keeps working across the boundary because the
parent resolves reads one at a time rather than shipping the grant up front.

The scope of that word matters: `prevented` here covers **one class of attack
against one stage**. The system's exposure is measured in part C and is
unchanged.

## A finding this case did not go looking for

An isolated stage wrote a fabricated schema — `columns: ["fabricated"]`. The
honest transform stage then did its job perfectly: it built the cleaned output
*from that schema*. Result:

```text
  raw columns     : ['Order ID', 'Customer', 'Date', 'Total']
  cleaned columns : ['fabricated']
  every row       : {'fabricated': None}
  verdict         : ok    (all four checks passing, no review flag)
```

Every column of real data is gone and the run certifies itself clean.

Isolation is not implicated — the same attack works in-process. Nor is this
case 05 failing on its own terms: it derives the conclusion from the runner's
own evidence, and the evidence agrees. The gap is in what the evidence covers.
Every check compares derived artifacts **to each other**, so a poisoned
upstream stage is laundered by an honest downstream one into a chain that is
internally consistent. Nothing compares the output back to the source artifact
the chain started from.

> **Closed by [case 07](../07-poisoned-chain/README.md)**, which added the
> missing comparison. The test that pinned the behaviour above was a tripwire;
> it fired and was rewritten as
> `test_a_poisoned_upstream_stage_is_caught_across_the_boundary`. Isolation was
> never what caught it — the attack works in-process too — but the control does
> apply to output that came from a captured process, which is worth having
> measured.

## Residual limitation

**Ambient authority is untouched.** Same uid, same filesystem, same network,
no resource limits. The child can read the repository, list every run's event
log, and open anything the runner could. A process boundary is not a sandbox,
and nothing here should be read as claiming otherwise.

**The grant is untouched.** An isolated stage reads everything it was granted.
If the grant is too wide, isolation does not narrow it by one key.

**Output honesty is untouched.** The stage authors its own artifact, and the
finding above shows how far that goes.

**Three of four stages are still in-process**, so the system's exposure is what
case 01 measured. This is the residual that matters most, and it is the one an
"isolation landed" headline would hide.

**The boundary is only as good as the channel.** The parent trusts nothing the
child says, but it does parse the child's JSON, and the resolver answers reads
for granted keys. A child that asks for its whole grant gets its whole grant.

**Not measured, and therefore not claimed:** whether a subprocess resists a
determined escape, what happens under resource exhaustion, whether the same
result holds on a platform using `fork` rather than a fresh interpreter.

## Containment response

Two failure modes, deliberately distinguished:

* the stage breaks its contract — a `ContractError` raised in the child is
  re-raised on the parent side as a contract violation, the ordinary Level 1
  path: the step fails and the workflow halts;
* the boundary breaks — a crash, a timeout, or a protocol violation raises
  `IsolationError`, reported as `isolated stage failure`. An operator needs to
  know that the infrastructure failed rather than that the agent misbehaved,
  and conflating them would send them to the wrong place.

Neither quarantines: nothing is known corrupt in either case.

## Recovery requirement

Re-run the stage. This is the first case where recovery is genuinely cheap: the
child holds no state, the artifacts it wrote either registered or did not, and
a fresh interpreter is a clean one by construction. Nothing has to be restored
from a place the adversary could also reach — the failure mode cases 02, 03, 04
and 05 all hit.

## Blast radius

**For the isolated stage:** its own grant, its own output, and whatever the
uid can reach on the host. Not the runner's memory, and not other runs'
artifacts — the interpreter is new per invocation, so there is no cross-run
residue of the kind case 01 measured.

**For the system:** unchanged. Three stages share the runner's process, and any
one of them still reaches every artifact of every run the process has handled.

---

## What this proves

That process separation removes exactly one thing, and removes it completely:
a stage in another interpreter has no path to the runner's Python objects,
because there are none there to find. Five demonstrated paths — the three case
01 recorded, plus the runner object itself, plus ungranted artifact content
from an earlier run — all return nothing, while the workflow completes normally
and the read log stays truthful.

It also proves the boundary can be crossed without giving up the enforcement
point. Resolving reads one at a time keeps `view.read_keys` meaningful, which
an eager payload handoff would have reduced to "everything granted" and made
the runner's reconciliation vacuous.

## What this does not prove

It does not prove the isolated stage is contained: its ambient authority, its
grant and its authorship are all unchanged, and each is measured above rather
than assumed. It does not prove *the system* is isolated — three stages of four
still share the runner's process, so case 01's finding stands. It says nothing
about host compromise, resource exhaustion, or a determined sandbox escape,
none of which were tested. And the poisoned-chain finding shows that removing
an adversary's reach into memory does nothing about what it can accomplish
through its own legitimate output.

---

## Tests

`tests/adversarial/test_case_06_process_isolation.py`
