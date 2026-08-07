# Case 18 — Gate 1: distribution validity

**Phase:** 3 (authority model)
**Baseline finding:** case 17's reduction result, and the parameter in its
generator
**Ladder level:** Level 1.5, the configuration adversary (inherited; this case
measures a report, not an attack)
**Baseline result:** `undetected`
**Controlled result:** `undetected` — a validity measurement, not a control

---

## The defect this case corrects

Case 17 reported *320,000 paths reduce to 16 causes*. Its generator signature
was:

```python
generate(n_work, n_intermediaries, n_sensitive, n_causes=16)
```

**The cause count was a parameter.** Case 17 grew the deployment along the work
axis — which is provably the one that cannot matter — and held fixed the axis
that does. So it partly measured that it could count what it had planted.

This case removes the parameter. Deployments are sampled from distributions,
nothing is told how many causes to produce, and a test asserts `sample()` has
no `n_causes`.

## Three answers, and case 17 reported only the flattering one

```bash
python cases/18-distribution/attack.py
```

### 1. Survives — estate size is irrelevant

| Work items | Paths | Causes |
|---|---|---|
| 200 | 2,000 | 10 |
| 2,000 | 20,000 | 10 |
| 20,000 | 200,000 | 10 |
| 200,000 | 2,000,000 | 10 |

Unmoved across a 1,000× change. This is structural rather than a generator
artefact: a cause is a fact about *authority*, and work items only multiply
paths. It is the half of case 17's result that holds.

### 2. Failed as built — the grouping key is linear in fan-out

Case 17's key is `(authority, intermediary)`. One over-scoped credential
holding forty secrets therefore becomes **forty rows**.

| Shape | Unreadable at density | Causes there |
|---|---|---|
| uniform — holders spread by chance, one thing each | 0.16 | 51 |
| broad — few holders, each holding many | 0.10 | 60 |
| **heavy-tailed — a few hold a great deal, the tail holds nothing** | **0.01** | **73** |

The heavy-tailed shape is the one real entitlement data has, and it is
**unreadable at the lowest density sampled** — three holders producing
seventy-three causes. Case 17's number was not wrong; it was measured on a
distribution that does not occur.

### 3. Fixed — and the failure forced the fix

Case 17 had already shown that grouping by intermediary *alone* hides
endpoints, which is why the authority went into the key. Both requirements are
satisfiable at once by making the endpoint set an **attribute** of a
per-intermediary finding rather than part of its key:

| Shape | Density | Causes | Findings | Endpoints kept |
|---|---|---|---|---|
| heavy-tailed | 0.01 | 73 | **3** | all |
| heavy-tailed | 0.10 | 148 | **30** | all |
| broad | 1.00 | 600 | **15** | all |
| uniform | 0.10 | 25 | 25 | all |

A finding reads *"this credential reaches 40 sensitive authorities"* — one row,
one decision, nothing lost. Case 17 had measured a trade-off between hiding and
readability; there was a third option, and only the failure at realistic
distribution made it necessary to find.

## The floor that remains

Under the fix, `uniform` is unchanged — each holder holds one thing, so causes
and findings coincide. That is not a defect of the grouping; it is the real
limit:

> **Report length = the number of intermediaries that hold sensitive
> authority.**

Not paths. Not causes. No amount of graph work reduces it, because each such
intermediary is a separate thing somebody has to decide about.

That is the useful output of this gate, because it is **checkable on a real
estate before anyone adopts any of this**: count the identities, credentials
and skills that hold something sensitive. That number is the report, and if it
is four thousand, the approach does not help.

## Residual limitation

**Still synthetic.** Four shapes, argued from what entitlement data is usually
like, and none sampled from a real estate. This case narrows the assumption
from *"sensitive authority is rare"* to *"few intermediaries hold it"* and
measures what happens when that is false — but it does not establish which is
true anywhere.

**`READABLE = 50` is declared, not measured.** It is stated once so it can be
argued with. Nothing here establishes what a person will actually read.

**Uniform bindability throughout.** Every work item may bind to every
intermediary, the worst case. A real estate constrains bindings, which reduces
paths but not findings — so the criterion above is unaffected.

**The pathological shape is honestly unreadable** and no fix rescues it. A test
asserts that, so the case cannot be read as claiming the approach always works.

---

## What this proves

That case 17's headline was half a result. Estate size genuinely does not
matter — that part is structural and survives every distribution. The cause
count genuinely does depend on how sensitive authority is spread, case 17's
number came from a parameter rather than a measurement, and on the shape real
entitlement data has its grouping key fails at the lowest density worth
testing.

And that the failure was fixable without giving up what case 17 protected: the
endpoint set belongs in the finding, not in its key. Report length then tracks
the number of holders and nothing else, which is a criterion an operator can
evaluate before adopting the approach rather than after.

## What this does not prove

It does not show the reduction works on any real deployment. It replaces one
untested assumption with a narrower untested assumption and measures the
consequences of the assumption failing.

It does not establish a readability threshold, and it does not measure whether
findings are comprehensible — only how many of them there are.

It adds no control, no detection and no containment, and changes nothing about
what any adversary can do.

---

## Tests

`tests/adversarial/test_case_18_distribution.py`
