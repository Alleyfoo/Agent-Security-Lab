# Case 17 — Does the reachability view survive a messy deployment?

**Phase:** 3 (authority model)
**Baseline finding:** case 16's own residual — the view was measured on four
stages and two credentials
**Ladder level:** Level 1.5, the configuration adversary
**Baseline result:** `undetected`
**Controlled result:** `undetected` — a usability measurement, not a control

---

## The gate

Case 16 built the reachability view and reported 4, 4 and 1 paths. That is a
laboratory. Before any of it can be called useful:

> Can a large reachability graph be reduced to a small number of actionable
> causes **without hiding dangerous paths**?

If ten thousand paths become "here are the six bindings that matter", the view
is a tool. If the operator gets a forty-page graph, it is mathematically
correct wallpaper.

**This case is written so it can fail.** If reduction did not hold, or the
planted needles disappeared, that would be the result.

## Paths are not findings; causes are

The unit an operator can act on is not a path. There is nothing to do about
*"stage 4,812 could use conn_ops"* except fix `conn_ops`. So:

```text
path   (work, intermediary, authority)   what the graph contains
cause  (authority, intermediary)         one fact someone can act on
```

A cause is a fact about the deployment — *this credential holds that secret* —
and it generates however many paths the estate's size implies.

The model is layer-neutral, because case 16 established the three layers
express one structure. `parity_checks()` reproduces case 16's per-arm numbers
exactly, so the scale experiment measures the same thing:

| Arm | Case 16 | Generic model |
|---|---|---|
| A | 4 | 4 |
| B | 4 | 4 |
| C | 1 | 1 |

## Results

```bash
python cases/17-scale/attack.py
```

### Reduction holds

| Deployment | Paths | Causes | Endpoints |
|---|---|---|---|
| 50 work × 20 intermediaries | 200 | 4 | 4 |
| 500 × 100 | 4,000 | 8 | 8 |
| 5,000 × 400 | 60,000 | 12 | 12 |
| 20,000 × 800 | 320,000 | 16 | 16 |

**Causes track the amount of sensitive authority that exists, not the size of
the estate.** The reading load stays flat while the graph grows by three orders
of magnitude. Every path is explained by exactly one cause — a reduction that
dropped paths would be a filter, not a summary, and a test asserts the totals
reconcile.

Every generated deployment binds every work item to every intermediary, which
is the worst case. A real deployment constrains bindings and produces fewer
paths per cause, not more causes.

### The needles survive grouping — and the obvious ranking buries them

Three rare dangerous relationships planted among 320,000 paths, each reachable
by one or two work items and generating **4 paths between them**:

```text
artifact.root_signing_key  <- inter_rare_1
artifact.customer_pii      <- inter_rare_2
artifact.payment_token     <- inter_rare_3
```

| | Needles found |
|---|---|
| every needle survives grouping | **yes, 3 of 3** |
| top 10 ranked by blast radius | **0%** |
| top 10 ranked by severity first | **100%** |

**This is the finding.** Grouping does not lose them — but the obvious way to
present the result does. A needle generates one path, so any report ordered by
blast radius sorts it last, and the operator reading the top of the list sees
the three biggest boring credentials and none of the three that matter.

> **Severity is not derivable from the graph.** It is a property of the
> authority that an operator supplies. With no severity map the ranking
> collapses back to blast radius and needle recall returns to 0% — which a test
> asserts, so the requirement is recorded as a requirement rather than an
> apology.

### The grouping key is load-bearing

The obvious key — group by intermediary — reports one row per credential and
silently loses how many distinct sensitive authorities it reaches:

```text
grouping by (authority, intermediary):  4 findings for inter_0
grouping by intermediary alone:         1 finding  for inter_0
-> the naive key hides 3 distinct sensitive authorities behind one row
```

Endpoints exposed is reported as its own number for the same reason.

## Residual limitation

**Synthetic deployments.** The shape is argued, not sampled: mostly boring
intermediaries, a few holding something sensitive, uniform bindability. A real
estate's distribution could be worse in ways this does not model — most
obviously if sensitive authority is not rare, in which case causes grow and the
reduction claim weakens.

**Severity must come from outside.** The measurement shows the view is usable
*given* a severity map. Producing one is real work this case does not do, and
an operator without it gets blast-ranked output with the needles at the bottom.

**One hop, one target class.** Inherited from case 16 unchanged. A path needing
two binding changes is still not modelled, and nothing here improves that.

**Reading load is measured as a count, not as comprehension.** Sixteen causes
is a short list; whether sixteen *well-written* findings are actionable is a
question about presentation that no test here answers.

---

## What this proves

That the reduction survives scale on the axis that matters: the operator's
reading load tracks how much sensitive authority exists rather than how large
the deployment is, and 320,000 paths become 16 findings without dropping a
single path.

And that the reduction is not the hard part — **the presentation is**. Grouping
kept every planted needle; the obvious ranking hid all three of them. A correct
reduction presented by blast radius is still wallpaper, with the dangerous
findings underneath it.

## What this does not prove

It does not show the view works on a real deployment. The distributions are
argued rather than sampled, and the case names the shape that would break it.

It does not show sixteen findings are *actionable* — only that there are
sixteen of them.

It does not add any control, detection or containment, and it changes nothing
about what any adversary can do.

---

## Tests

`tests/adversarial/test_case_17_scale.py` — parity with case 16, reduction at
three sizes, path conservation, needle survival, both rankings, the empty
severity map, and the cost of the naive grouping key.
