# Design philosophy — intelligence should compile into automation

**Status: FROZEN, pre-study.** Recorded 2026-08-08, before any formal
cybersecurity study. It is deliberately written in the vocabulary the author had
at the time.

**Do not retrofit this note with terminology learned later.** When formal study
happens, compare against this document — do not edit it into agreement. A
prediction rewritten after the result is not a prediction, and this repository
exists because that distinction matters. Corrections, contradictions and
vocabulary learned afterwards belong in a separate appendix that cites this one.
A test in `tests/test_design_philosophy_frozen.py` fails if the body changes,
which is the same reason every other rule here is enforced structurally rather
than by a sentence asking nicely.

---

## Core idea

Do not assume that a mature agentic system should contain many permanent agents.

Use high intelligence initially where the process is not yet understood. Let the
agent handle real or simulated work, observe its decisions, exceptions,
dependencies and repeated patterns, then progressively replace stable reasoning
with deterministic software.

The desired lifecycle is:

```text
UNKNOWN -> REASON -> MODEL -> AUTOMATE -> OBSERVE -> REMODEL WHEN REALITY CHANGES
```

A successful system should generally become **less** agentic over time, not more.

## 1. Intelligence is for discovering the process

At the beginning, a strong model may handle a large share of the workflow
because we do not yet know which parts are deterministic.

Its job is partly operational, but more importantly it reveals:

* what information actually matters;
* which decisions repeat;
* which exceptions recur;
* which transformations are stable;
* which parts genuinely require judgement;
* where authority is needed.

The traces are therefore process-discovery evidence.

## 2. Compile repeated reasoning into automation

When the agent has processed enough examples, ask:

> Which parts of this work are now understood well enough that intelligence is
> unnecessary?

Repeated behaviour should become:

* parsers;
* schemas;
* regex/structural gates;
* Python functions;
* deterministic rules;
* bounded skills;
* conventional services.

Generated automation must be proposed, tested against historical cases and
independently verified before entering production. **The agent does not silently
install its own replacement.**

Broad reasoning discovers a narrow repeatable transformation.

## 3. Mature outside-facing paths should contain as little AI as practical

Every externally influenceable field is an attack surface:

* chat;
* names;
* reservation fields;
* email;
* PDFs;
* OCR;
* filenames;
* web content;
* APIs;
* imported data.

Assume hostile instructions can appear anywhere the system can perceive
language.

First define the outside-facing surface. Then reduce it deterministically before
exposing anything to reasoning. If a task can be completed safely with a parser
or ordinary software, do not expose an agent merely because an agent could do
it.

Successful automation therefore reduces both cost and AI attack surface.

## 4. The permanent high intelligence belongs primarily in Shadow

Once normal work has been compiled into deterministic or narrowly bounded
components, retain strong intelligence as an independent observer.

Shadow watches:

* traces;
* receipts;
* behavioural changes;
* unusual sequences;
* rising exception rates;
* drift;
* repeated new patterns;
* apparent control failures.

Shadow asks: *Does what just happened still make sense?*

Shadow should be **highly informed but weakly authorised**.

> Intelligence lives in Shadow. Authority lives in boundaries.

Shadow may produce:

* observations;
* anomalies;
* hypotheses;
* proposed controls;
* proposed deterministic skills;
* escalation objects.

Shadow must not quietly become the administrator of everything it observes.

## 5. When automation stops fitting reality, reasoning returns temporarily

If Shadow discovers a new recurring exception class or meaningful drift:

```text
AUTOMATION -> NOVELTY -> REASONING -> NEW MODEL -> TESTED AUTOMATION
```

The strong reasoning layer comes back to understand the new situation, then
retreats again once the new behaviour can be encoded safely. This creates a
continuous cycle rather than permanent agent autonomy.

## 6. Agents may be modeling tools rather than the final product

The reservation demo and other simple agent systems should not be interpreted as
proposals that real production systems need a society of agents.

The agents are useful because they let us model:

* work;
* authority;
* failure;
* recovery;
* escalation;
* observation;
* conversion into deterministic mechanisms.

A mature implementation may contain very few agents. **That is a success
condition, not a failure of the agentic architecture.**

## 7. Security implication

Do not make the primary security goal *prevent the model from ever being
prompt-injected*.

Assume the worst: anything possible through an exposed surface will eventually
be attempted, and the reasoning component may eventually be influenced
incorrectly.

Instead ensure that **compromise does not enlarge authority**.

As repeated reasoning is compiled out of externally exposed paths, the number of
places where hostile semantic input can influence a powerful model should
decrease.

## 8. Toy "box" experiment

A useful minimal demonstration:

External input is constrained first by a deterministic structural gate, e.g. an
exact `Firstname Lastname` format with bounded length. Anything outside that
format is flagged without reaching the agent.

A fresh sealed agent sees only structurally permitted input. Its only positive
external capability is approving the current object. Anything except the exact
permitted approval fails closed and is flagged.

The important experiment is not whether the model remains mentally obedient. It
is:

> If the model becomes completely persuaded by hostile input, can that
> persuasion create authority that the surrounding system did not provide?

Later experiments can widen the permitted input language and measure what
changes.

## 9. Current architectural summary

* Map the surface.
* Reduce the surface.
* Use intelligence where the process is unknown.
* Observe what intelligence actually does.
* Compile stable reasoning into deterministic automation.
* Restrict every remaining consequential function.
* Keep strong intelligence in an independent Shadow.
* Bring reasoning back only when reality stops matching the encoded model.
