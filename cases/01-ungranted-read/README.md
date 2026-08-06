# Case 01 — Reading artifacts the grant excludes

**Phase:** 2 (in-process attack cases)
**Baseline findings:** L1, L2
**Ladder level:** 2 (fully compromised agent process)
**Status:** ⚠️ **open — no control at this phase.** Control is process
isolation, Phase 5.

This case exists to establish a negative result precisely, and to make it
expensive to paper over. It does not meet acceptance criteria 4 and 5, and it
is not supposed to yet.

---

## Threat

Hostile code executing inside an agent. Unlike [case 00](../00-receipt-handle/README.md),
this adversary needs code execution — a merely hostile agent *implementation*
using the interfaces it was handed is not enough.

Starting authority: a `StoreView` granting read access to one key
(`artifact.raw_input`) and write access to one key
(`artifact.schema_profile`), plus everything the CPython runtime makes
reachable from inside the process.

## Existing assumption

That `StoreView` is a capability-scoped handle, and therefore that an agent
"reads only the keys it was handed". The word doing the unearned work in that
sentence is *only*.

## Attack

Read `artifact.cleaned_output` from a stage never granted it. Three paths,
chosen because they share no mechanism:

| Path | Mechanism | Touches the view? |
|---|---|---|
| 1 | `view._store.get(key)` | Yes — private attribute |
| 2 | Walk `sys._getframe()` until a frame holds an `ArtifactStore` | **No** |
| 3 | Scan `gc.get_objects()` for any `ArtifactStore` | **No** |

Paths 2 and 3 reach the store with no reference path from the agent at all.

```bash
python cases/01-ungranted-read/attack.py
```

## Observed unsafe result

```text
  Production StoreView:
    0. view.get()            [sanctioned]     -> denied: ContractError
    1. view._store           [private attr]   -> READ OK (20 rows)
    2. call-stack walk       [no view use]    -> READ OK (20 rows)
    3. gc.get_objects()      [no references]  -> READ OK (20 rows)
    view.read_keys recorded: []
```

The last line is the important one. Every bypass left the read log **empty**,
so the runner's reconciliation of actual reads against the grant
(`demo_runner.py:151`) sees nothing to object to. The bypass is not merely
unlogged — it is affirmatively undetected.

### The asymmetry

Baseline finding L2, stated as the design lesson:

```text
Writes  are checked against observed store state  -> bypass is caught
Reads   are checked against a log the reader owns -> bypass is invisible
```

A control that reconciles against evidence the adversary produces is not a
control. This is the single most transferable finding in the repository, and
case 02 demonstrates the write side, where the same architecture gets it right.

## Control

**None at Phase 2.** No in-process mechanism addresses this, and the case's
value lies in saying so rather than shipping something that looks like one.

### The refused patch

The obvious response to path 1 is to remove the private attribute — keep the
store in a closure so the view has nothing to reach through. `ClosureStoreView`
in `attack.py` implements exactly that. Measured:

```text
  ClosureStoreView (the 'fix' for path 1):
    0. view.get()            [sanctioned]     -> denied: PermissionError
    1. view._store           [private attr]   -> denied: AttributeError
    2. call-stack walk       [no view use]    -> READ OK (20 rows)
    3. gc.get_objects()      [no references]  -> READ OK (20 rows)
```

One path closed. The class untouched. Shipping it would let the repository
describe a boundary it does not have — the charter's definition of cosmetic
security — so it is demonstrated and refused rather than merged. It stays in
the case directory as a test, never in `agent_network_demo/`.

The general principle: **a boundary enforced by the absence of a reference is
not a boundary in a runtime with reflection.** Closures, name mangling,
`__slots__`, and private conventions all fall to paths 2 and 3.

### What would actually work

Per charter §10, the isolated stage must not receive the `ArtifactStore` at
all. It receives a typed operation request, one redeemable scoped capability or
brokered artifact response, and a constrained output channel. The store lives
in a different address space, so there is no object graph to walk. That is
Phase 5, and case 01 is its motivation.

## Status after case 06 — still open, and here is exactly why

[Case 06](../06-process-isolation/README.md) built the control this case has
pointed at since Phase 2, and measured it: a stage running in a spawned
interpreter finds nothing by any of the three paths below, plus two more.

**This case's tripwire tests did not fail, and that is correct.** They assert
the attack succeeds against a stage in the runner's process, and case 06
isolates one stage of four. Nothing about the schema stage moving out of the
process changes what the transform stage reaches — case 06 part C measures the
un-isolated stage still reaching every path, including the isolated stage's own
output. Case 01 closes when every stage is isolated, not before, and the tests
below hold that line.

What case 06 did establish, for a stage that is isolated: the prediction in
*What would actually work* was right, and the mechanism is not the one the
prose implies. The paths are not blocked — they run and find nothing, because
the interpreter contains no `ArtifactStore`. Isolation empties the room; it
does not lock the door.

## Residual limitation

The whole case is a residual limitation. Confirmed by measurement rather than
predicted, now that case 06 exists: process isolation bounds this to *one
stage's granted artifacts within one workflow*, and does not make it zero — an
isolated stage read exactly what it was granted, because isolation narrows a
grant by nothing.

## Containment response

None automatic, because there is no detection. Once Phase 5 lands, the ladder's
Level 2 row applies: **revoke active capabilities and invalidate current
output.**

Until then the honest operational posture is: a compromised agent process is
assumed to have read every artifact in its run.

## Recovery requirement

Treat every artifact in the affected run as disclosed to the adversary. Nothing
narrower is defensible, because nothing narrower is evidenced — there is no
record distinguishing what was read from what was reachable.

## Blast radius

Every artifact in the process, for every run the process has handled. In the
current single-process design that is the entire store.

Note this is strictly larger than the run: `ArtifactStore` instances from
earlier sessions remain reachable via `gc` until collected.

---

## What this proves

That the scoped view enforces exactly one thing — reads that go through its
interface — and that this is worth having but must not be described as
isolation. It also proves that closing individual reach-around paths is not
progress, because the three demonstrated paths share no mechanism and only the
first involves the view.

## What this does not prove

It proves nothing about a Level 1 adversary, who is genuinely constrained by
the view and has no way to execute the code above. It does not show the store
is *easy* to reach in a hardened deployment, since it assumes arbitrary
execution already achieved. And it says nothing about whether process isolation
will hold — that claim belongs to Phase 5 and must be measured there, not
assumed here.

---

## Tests

`tests/adversarial/test_case_01_ungranted_read.py` — 10 tests.

Three are regression guards on what genuinely works: the sanctioned read is
denied and the denial names the grant; `has()` is not an existence oracle;
granted reads are recorded.

The rest assert the attack **succeeds**. They are tripwires — when Phase 5
lands they must fail, and that failure is the signal to rewrite this case with
its control section filled in. Each carries a `TRIPWIRE` message saying so. Do
not relax them.
