# Case 24 — Gate 2: where does severity come from?

**Phase:** 3 (authority model) — the reachability line
**Baseline finding:** case 17 left the view usable *given* a severity map and
unusable without one
**Ladder level:** not an attack case — a measurement of an input
**Baseline result:** `undetected`
**Controlled result:** `undetected` — a measurement, not a control

---

## The gate

> Severity should be knowledge supplied **independently** of the reachability
> calculation — classification, policy, asset inventory, business criticality —
> otherwise the graph starts grading its own homework.

So this case does not build a classifier. It measures three things:

1. **independence** — the engine must not read severity when computing
   reachability;
2. **whether topology predicts severity** — if it did, an independent source
   would be unnecessary, so this is the load-bearing measurement;
3. **whether self-grading works** — a severity derived from the graph, built
   deliberately, because *the graph grades its own homework* is an argument
   until somebody runs it.

## Three sources

```text
absent       no severity at all              case 17's failure mode
topological  severity computed from the graph (path count)
declared     an independent classification of the authority itself
```

## Results

```bash
python cases/24-severity-source/attack.py
```

| Severity source | Needles in top 10 | top 20 |
|---|---|---|
| absent | **0%** | 100% |
| topological | **0%** | 100% |
| declared | **100%** | 100% |

### Self-grading does not merely work badly — it changes nothing

The finding is sharper than "a derived severity is a weaker source". It is
**the same source**:

> Severity computed from the graph is not a weaker input than none. Path count
> is what the fallback ordering already used, so supplying it as "severity"
> looks like knowledge and moves no cell.

Every figure in the `topological` row equals the `absent` row. A team that
built this would believe they had added prioritisation and would have added a
rename.

### Why: topology is not uninformative, it is inverted

| Graph proxy | ρ against declared severity |
|---|---|
| paths reaching it | **−0.995** |
| largest single cause | **−0.995** |
| intermediaries holding it | +0.000 |

Not weak correlation — **strong negative** correlation. As a proxy, path count
is worse than random, because the rarest paths lead to the most valuable
things.

**Stated as conditional, not as a law.** The inversion follows from the
scenario: the needles were planted rare *and* valuable. But that is exactly the
assumption case 17 established as the one that matters, and it is what an
over-broad service identity with a route to a signing key actually looks like.

The one genuinely uncorrelated proxy — how many intermediaries hold an
authority — is case 18's report length. **Useful for sizing the report, useless
for ranking it.**

### Independence holds in the other direction too

Causes and findings are byte-identical under all three severity maps, so the
answer never shapes the question. A structural test pins the narrower version
of this: `by_sensitivity` legitimately *takes* a severity map — ranking is
where supplied knowledge belongs — while `causes`, `findings`,
`endpoints_exposed` and `path_count` may not mention it at all.

## Residual limitation

**The declared source is a stand-in.** A registry of three authorities with
hand-written severities models asset inventory or data classification exactly
as case 12's arms modelled architectures. Whether a real organisation can
produce such a map, keep it current, and agree on it is the actual difficulty
and is untouched here.

**One scenario.** Rare-and-valuable is the assumption case 17 identified and
case 18 stress-tested, and the inversion result depends on it. A deployment
where the most-reachable authority is also the most valuable would give the
opposite correlation and make a topological proxy look excellent — for that
deployment.

**Severity is treated as a scalar per authority.** No context, no aggregation
across authorities an intermediary reaches together, no notion that two
medium-value things in combination are worse than either alone.

**This is a measurement, not a control.** Nothing here detects, prevents or
contains anything.

---

## What this proves

That Gate 2 is answered and the answer is no: the graph cannot supply its own
severity. A derived severity is not a cheaper approximation of the real thing —
it is the fallback ordering wearing a different name, and it moves no cell.

And that the reason is stronger than "topology is uninformative". Under the
scenario the reachability line exists to address, topology is *inverted*
against severity, so a topological proxy is worse than having none while
looking like progress.

## What this does not prove

It does not produce a severity source. It shows what one must not be derived
from, and models the alternative with a hand-written registry.

It does not establish the inversion as a general property — it is conditional
on rare-and-valuable, which is stated rather than assumed.

---

## Tests

`tests/adversarial/test_case_24_severity_source.py`
