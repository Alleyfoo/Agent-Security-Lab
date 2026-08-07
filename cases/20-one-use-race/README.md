# Case 20 — Two executors racing one one-use approval

**Phase:** 3 (authority model) — second sign-off slice
**Baseline finding:** case 19's R4, and the atomicity it did not measure
**Ladder level:** Level 1 — a compromised worker that can start two executions
**Baseline result:** `undetected`
**Controlled result:** `prevented` — for concurrent acquisition, and nothing
more

---

## What this case may claim

Fixed before measuring, and the limit is the point:

```text
provable      a single approval cannot be concurrently acquired by two
              executions - an atomicity property around the approval itself
NOT provable  exactly-once execution of an arbitrary external effect
```

Exactly-once is not available for free when the side effect is not in the same
transaction as the approval record. A test enforces this scope, because the
predictable failure mode of this case is somebody reading `state == 'executed'`
and writing *exactly once* in a README.

## Four gates

```text
G0  check -> execute -> mark        case 19's R4, as built
G1  check -> mark -> execute        the tempting fix
G2  atomic claim -> execute -> done exclusive execution ownership
G3  G2 + an idempotent sink         keyed on execution id
```

## Results

```bash
python cases/20-one-use-race/attack.py
```

| Gate | Race | Crash before the effect | Crash after, then retry |
|---|---|---|---|
| G0 check-execute-mark | **2 effects** | `unused` — nothing lost | **2 effects** |
| G1 check-mark-execute | **2 effects** | `executed` — **action LOST** | 1 |
| G2 atomic claim | 1 | `claimed` — **action LOST, stuck** | 1 |
| G3 + idempotent sink | 1 | `claimed` — **action LOST, stuck** | 1 |

**Prediction confirmed.** Case 19's R4 performs the external effect twice from
one approval.

### G1 is the trap, and it takes two measurements to see it

Reordering the mark before the effect looks like the fix. Forced at the worst
moment it **still performs the effect twice**. What it changes is how hard the
failure is to reach:

| Unforced, 25 rounds | G0 | G1 |
|---|---|---|
| instantaneous sink | 1 | 1 |
| sink with real latency | **2** | 1 |

G0's window spans the external call and reproduces the moment the sink takes
the time a real one takes. G1's window is a couple of bytecodes and never
reproduced at all.

> **Both are racy; only one is findable by running the tests.** A race that
> ordinary testing cannot reach is still a race, and an adversary who can
> influence timing does not need the luck a test suite is waiting for.

That is worse than an obvious bug, and it is the reason the interleaving hook
exists: with an instantaneous sink even G0 survives 200 rounds, so a suite
measuring only that would report the naive gate as correct.

### The cost every fix pays

G0's failure mode is duplication and *only* duplication — it writes nothing
before the effect, so a crash leaves the approval spendable and nothing is
lost. Every gate that writes first can lose the action instead:

* **G1** — approval spent, effect never happened;
* **G2/G3** — approval stuck in `claimed`, no double effect, no execution, and
  no automatic way back.

Whether stuck-and-visible beats lost-and-silent is a policy question this case
does not answer. It measures that the choice exists and that no ordering
avoids it.

### Where exactly-once actually comes from

G3 differs from G2 **only** in the sink refusing a repeated execution id. It is
not a property of the approval record, and a test pins that:

```text
idempotent sink:  perform(d, exec-1) -> performed
                  perform(d, exec-1) -> deduplicated
plain sink:       perform(d, exec-1) x2 -> 2 effects
```

The sink keys on the **execution id, not the action digest** — two legitimately
identical payments must both go through, and a sink deduplicating on content
would silently drop the second real one.

## The lineage this completes

```text
action -> hash -> proposal -> approval -> one-use claim -> execution_id
       -> external effect -> receipt
```

Case 19 built `action → approval`. This builds `approval → claim →
execution_id`, and shows the last hop out to the external effect is where the
approval record's authority stops.

## Residual limitation

**The lock is in one process.** `_LOCK` is a `threading.Lock`, so exclusivity
holds for executors in one interpreter and says nothing about two processes or
two hosts. That is the same boundary case 19 hit and the reason gate
independence is the next case rather than this one.

**The stuck state has no resolution path.** A crash after the claim leaves the
approval unusable and nothing here reclaims it. A lease with an expiry is the
obvious answer and introduces its own race, unmeasured.

**Crashes are simulated by an exception at a named point**, which models a
process dying between two statements and does not model partial writes, torn
records, or a sink that succeeded while the caller saw a timeout — the last of
which is the realistic and nastiest version.

**One approval, one action, two executors.** No quorum, no distributed claim,
no clock.

---

## What this proves

That case 19's one-use rung was not one-use under concurrency, that the obvious
reordering narrows the window rather than closing it, and that only a claim
joined to the state test is exclusive. It also shows the price: every gate that
writes before acting can lose the action instead of duplicating it, and the
atomic ones leave a stuck approval with no way back.

And it locates exactly-once precisely — in the sink, keyed on the execution id,
not in the approval record.

## What this does not prove

It does not prove exactly-once execution of anything. It proves single
acquisition of an approval, which is a different and much smaller claim.

It does not extend past one interpreter, does not resolve the stuck state, and
does not model the crash that matters most: the sink succeeding while the
caller believes it failed.

---

## Tests

`tests/adversarial/test_case_20_one_use_race.py`
