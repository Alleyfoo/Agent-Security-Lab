# Demo: the reservation queue

A deliberately simple world in which to measure **operational** value alongside
the security properties. Contract first; nothing is built.

Structured objects only — no email, no natural language. Every request arrives
already valid. The point is to test the agent network, its skills, escalation
and recovery, not whether a model can parse a sentence.

---

## 1. The two hypotheses

Both falsifiable, and neither assumed:

> **Operational.** A restricted agent network can handle routine work and
> absorb ordinary disruptions locally, escalating only the cases that exceed
> its available skills, evidence or authority.

> **Security.** Compromise or failure of one agent does not enlarge its
> authority beyond the functions made available to it.

This is the first thing in the repository that measures the operational one at
all, and it is the first exercise of the object model as a *system* rather than
as a comparison arm.

It also finally measures target-architecture claims 4 and 5 — *routine work
stays local* and *errors, ambiguity and higher-risk decisions escalate upward*
— which have stood at "not measured" since they were written.

## 2. The world

A month of practice spaces. Rooms with capacity, opening hours, equipment;
existing reservations; a queue of structured requests:

```text
reserve Hall A, Friday 19:00-20:30, boxing, 20 people
```

Small enough to reason about by hand, which is a requirement rather than a
convenience: every measurement below must be checkable against a schedule a
person can read.

## 3. The skill set *is* the authority boundary

```text
check_availability(reservation)
create_reservation(reservation)
find_alternative(reservation)
cancel_reservation(reservation)
raise_exception(reservation)
```

An agent has no arbitrary system access. Its authority is exactly this set,
which is target-architecture claim 1's **application claim** — and the
isolation claim underneath it remains false, so the security hypothesis must be
stated at Level 1 and not beyond.

## 4. Disruptions, and the rule that makes them evidence

Hall closes for a week; capacity reduced; equipment unavailable; opening hours
change; a priority reservation inserted; two displaced bookings competing for
one slot; an agent or path stops responding.

> **The disruption generator is defined independently of what the skills can
> resolve, and is written before the resolution logic.**

This is not pedantry. Case 17 measured a beautiful reduction that turned out to
be a generator parameter, and case 18 had to unpick it. A disruption set chosen
because the agents cope with it measures the author, not the architecture. The
generator is fixed and published first; the resolution rate is whatever it
turns out to be.

## 5. Escalation is not pre-decided

Deliberately. The taxonomy is an **output** of the simulation, not an input:
run it, see which failures actually occur, and record which ones the lower
level could resolve safely. A taxonomy invented up front would be a hypothesis
wearing the costume of a result.

The intended shape, to be confirmed or refuted:

```text
routine work                  handled locally
resolvable disruption         handled locally
unresolved conflict           review level
needs new authority/policy    higher review or human
```

## 6. Consequential actions use two-sided sign-off

Displacing an already-confirmed reservation is not something a worker does
alone. It proposes; an independent reviewer approves the exact action; the gate
executes only on both.

Cases 19–22 already measured what that mechanism is worth, and the demo
inherits every limit rather than re-litigating them:

* it binds to **action content**, not request identity (case 19);
* the approval is **one-use**, and one-use is not exactly-once (case 20);
* it is a **Level 1 control** — a configuration adversary still wins (19–22);
* the store and gate boundaries are **modelled, not enforced** until case 23
  can run.

The demo may show the mechanism working. It may not upgrade the claim.

## 7. The monitor, and why it gets no authority

A shadow layer, independent of reservation decisions, recording communication,
traces and graph state. Then break a path — `reservation agent → availability
agent` stops responding — and ask two questions in order:

1. **detection:** does the monitor identify the failed path?
2. **recovery:** can it restore or reroute using a *predefined bounded skill*?

```text
detect_missing_response(connection_17)
  -> restart_worker(worker_4)
  -> reroute_queue(queue_2, backup_worker_7)
```

> **The monitor does not receive general system-control authority because it
> observes everything.** Any recovery it performs is itself a bounded skill.

That is case 09's question — *can the execution plane mint a transformation?* —
asked of the observability plane, and it is the part of this demo most likely
to go wrong quietly. A monitor that can restart anything is an administrator
with good manners.

## 8. Measurement, and the oracle problem

Most of the proposed metrics have a trap, and the repository has already paid
for the lesson twice: **a system may not grade its own homework** (case 24),
and **a scalar without routes hides what changed** (case 19).

| Metric | How it is computed honestly |
|---|---|
| completed locally | fraction of requests reaching a confirmed reservation with no escalation |
| disruptions introduced | from the generator's own log, fixed in advance |
| affected reservations auto-recovered | recovered ÷ affected, where *affected* comes from the world state, not the agents' opinion |
| escalation rate | escalations ÷ requests |
| **false escalations** | escalations for which an **independent exhaustive search** finds a valid resolution under the rules |
| unresolved conflicts | escalations for which the same search finds none — genuinely out of solution space |
| skill calls per completed reservation | counted by the runtime, not self-reported |
| sign-off frequency | proposals ÷ consequential actions |
| comms failures detected / recovered | injected ÷ detected ÷ recovered, all from the injector's log |
| failures needing higher authority | recovery skill refused or exhausted |

**The oracle is the load-bearing piece.** *False escalation* and *unresolved
conflict* are the two most interesting numbers and both require ground truth
about whether a solution existed. That ground truth must come from a **separate
exhaustive search over the allowed slot space**, written independently of the
agents' resolution logic and sharing no code with it. If the agents' own
`find_alternative` decides whether an alternative existed, the escalation
metrics are self-graded and worth nothing — case 24 measured exactly that
failure in another guise.

Two more rules, inherited:

* **correctness before rate.** A resolution counts only if the resulting
  schedule satisfies every invariant — no double booking, capacity, opening
  hours, equipment — checked independently. A high local-resolution rate that
  produces an invalid schedule is a worse result than escalating.
* **report the kinds, not only the counts.** Escalations are enumerated by
  cause, exactly as tamper costs are reported with their routes.

## 9. What this demo may not claim

* nothing about natural language — there is none;
* nothing about isolation — the skill boundary is the application claim, and
  the isolation claim is still false (case 06) and blocked (case 23);
* nothing about the sign-off mechanism beyond what cases 19–22 measured;
* nothing about scale — a month of one venue is not a deployment, and case 18
  is the standing reminder of what distribution assumptions cost.

## 10. Sequencing

Each step is a case with its own contract, and each is measurable alone:

```text
A  the world, the queue, the skill set        does routine work complete, and
                                              is the schedule valid?
B  the disruption generator, fixed first      what actually breaks?
C  local resolution + the independent oracle  how much absorbs locally, and how
                                              many escalations were false?
D  sign-off on displacement                   does the mechanism hold in a
                                              system rather than a harness?
E  the monitor: detection                     is a broken path identified?
F  bounded recovery                           and can it be repaired without
                                              the monitor gaining authority?
```

**A and B before C.** The generator must exist and be published before any
resolution logic is written, or C measures the author.

**E before F**, and both after C, so a detection failure is never confused with
a resolution failure.
