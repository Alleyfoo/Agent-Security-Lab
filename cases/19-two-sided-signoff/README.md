# Case 19 — Two-sided sign-off

**Phase:** 3 (authority model) — first slice of the target architecture
**Baseline finding:** `docs/target-architecture.md` claim 6, and the warning
cases 13–15 attached to it
**Ladder level:** Level 1 *and* Level 1.5, measured separately
**Baseline result:** `undetected`
**Controlled result:** `prevented` — against Level 1, and only against Level 1

---

## Built naively on purpose

The design document already knew the right answer. Building it directly would
have produced a working mechanism and no evidence for why any piece of it
exists — so this starts with the version that *looks* correct:

```text
propose(request_id)
approve(request_id)
execute_if_both_exist(request_id)
```

and then adds one condition per rung, measuring what each one buys.

| Rung | Adds | Independence |
|---|---|---|
| R0 naive | both records exist under one request id | decision |
| R1 +bind action | gate compares `H(actual action)` to both attestations | decision |
| R2 +credential | only a reviewer identity may approve | decision + credential |
| R3 +append-only | a digest may be approved at most once | decision + credential + state |
| R4 +one-use | an approval authorises one execution and is spent | *(a lifecycle rule, not a layer)* |

Two adversaries, kept apart because the answer differs: **Level 1**, a
compromised worker using only its own interfaces, and **Level 1.5**, the
configuration adversary.

## Results

```bash
python cases/19-two-sided-signoff/attack.py
```

| Rung | Level 1 | Level 1.5 |
|---|---|---|
| R0 naive | **1** | **1** |
| R1 +bind action | **1** | **1** |
| R2 +credential | **1** | **1** |
| R3 +append-only | **1** | **1** |
| R4 +one-use | **refused** | **1** |

**The pre-registered prediction held.** The naive version measures 1, by two
independent routes: the worker signs its own approval, and the worker changes
what the request points at after an honest reviewer approved something else.

### What each rung actually bought

**R1 — closed one class and opened another.** Swapping the action after review
stops working. And because approvals now match by *content* rather than by
request, **any past approval of the same action matches by construction** —
replay did not work at R0 and does at R1. The route count did not move; the
routes changed. A review counting defects rather than naming them would have
called that progress.

This is the case's most useful finding, and it is an argument *against* the
design document's own most confident recommendation being adopted alone.

**R2 — closed self-approval, moved nothing.** A Level 1 worker can no longer
forge an approval through any interface it holds. Replay still works, so the
minimum stays 1.

**R3 — closed nothing measurable here.** Cases 10 and 11's append-only,
produced-once record refuses a *second* approval of a digest. Replay reuses the
*first*. The record shape that was decisive on the artifact plane does not help
on the approval plane, and a first draft of this case's summary claimed it did
until the measurement said otherwise.

**R4 — moved the result.** A lifecycle rule, not an independence layer. Three
rungs of independence did not do what one rule about spending did.

### The staircase is the finding

Each of the first three rungs looks like the important one and closes exactly
one thing, while the minimum tamper set sits at 1 until the last route is gone.
**A design review that stopped after R2 would have shipped a mechanism that
still executes an unapproved payment.**

## The bottom line no rung changes

> **Two-sided sign-off is a Level 1 control.**

Level 1.5 stays at 1 commit at every rung. The configuration adversary appends
an approval record past the API, or adds the worker to the reviewer list — one
commit either way. No arrangement of records *inside the same writable
boundary* raises that, which is the cross-cutting finding arriving at the
approval plane for the seventh time.

It is worth building: R4 genuinely stops a compromised worker, which is claim
6's actual job. It must not be described as protecting against anyone who can
write the approval store.

**No rung has gate independence.** The gate is ordinary in-process code
throughout — deliberately, and asserted by a test so a reader cannot infer
otherwise from the independence column.

## Residual limitation

**Gate independence is absent and is the obvious next boundary.** Every result
here assumes the gate itself is honest. Nothing measures what happens when it
is not, and the repository's own answer — an absence rather than a check —
would mean the gate is not reachable from either party's process.

**Replay is closed by spending, not by freshness.** R4 consumes an approval, so
an action legitimately approved twice can execute twice. A nonce or validity
window is a different rule and is not measured here.

**One protected action, one object, one reviewer.** No quorum, no delegation,
no reviewer unavailability, and no escalation — which is claim 5 and
deliberately a separate case, so that a failure is not ambiguous between the
two mechanisms.

**Object version is in the digest and nothing advances it.** The stale-approval
class the design document predicts is therefore claimed by construction rather
than measured.

---

## What this proves

That the obvious implementation of two-sided sign-off proves almost nothing,
and that the conditions which fix it do not fix it in the order they look most
important. Binding authority to action content — the recommendation the design
document states most confidently — closes swapping and simultaneously opens
replay. Credential independence closes self-approval and moves no number. The
record shape that was decisive in cases 10 and 11 does nothing on this plane.
What finally moves the Level 1 result is a lifecycle rule about spending an
approval.

And that the mechanism's honest scope is one adversary: it stops a compromised
worker and does not stop anyone who can write the approval store.

## What this does not prove

It does not prove the gate is trustworthy — no rung has gate independence, and
every result assumes an honest gate.

It does not close replay in general, only reuse of a spent approval.

It says nothing about escalation, quorum, delegation, or reviewer availability,
and nothing about whether a reviewer's *decision* is correct — case 05's
finding applies unchanged to the reviewer's judgement.

---

## Tests

`tests/adversarial/test_case_19_two_sided_signoff.py`
