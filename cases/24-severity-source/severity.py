"""Case 24 - Gate 2: where does severity come from?

Case 17 measured the reachability view as usable *given* a severity map and
unusable without one: ranked by blast radius, none of the planted needles
reached the top ten; ranked by severity, all of them did. It left the source of
that map unbuilt, and the manager's condition on it was precise:

    Severity should be knowledge supplied independently of the reachability
    calculation - classification, policy, asset inventory, business
    criticality - otherwise the graph starts grading its own homework.

So this case measures three things rather than building a classifier:

  1. **independence** - the engine must not read severity when computing
     reachability, asserted by computing both with and without a map;
  2. **topology does not predict severity** - if it did, an independent source
     would be unnecessary, so this is the load-bearing measurement;
  3. **self-grading fails** - a severity derived from the graph is built
     deliberately and measured, because "the graph grades its own homework" is
     an argument until somebody runs it.

Three sources, and the middle one is the trap:

    absent       no severity at all - case 17's failure mode
    topological  severity computed from the graph (path count)
    declared     an independent classification of the authority itself
"""

from __future__ import annotations

import importlib.util
import os
import sys
from dataclasses import dataclass
from typing import Callable, Dict, List, Tuple

CASE_24 = os.path.dirname(os.path.abspath(__file__))
CASES = os.path.dirname(CASE_24)
CASE_18 = os.path.join(CASES, "18-distribution")

for path in (CASE_18, os.path.dirname(CASES)):
    if path not in sys.path:
        sys.path.insert(0, path)


def _load18(name: str):
    spec = importlib.util.spec_from_file_location(
        f"case18_{name}", os.path.join(CASE_18, f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[f"case18_{name}"] = module
    spec.loader.exec_module(module)
    return module


d = _load18("distribution")
g = d.g                                   # case 17's graph module

NEEDLES = {
    "artifact.root_signing_key": 10,
    "artifact.customer_pii": 9,
    "artifact.payment_token": 9,
}


# ---------------------------------------------------------------------------
# The deployment under test: many boring causes, three rare dangerous ones.
# ---------------------------------------------------------------------------

def deployment_with_needles():
    dep = g.generate(5000, 400, 20, 12)
    planted = [
        g.plant_needle(dep, "artifact.root_signing_key", "inter_rare_1", 1),
        g.plant_needle(dep, "artifact.customer_pii", "inter_rare_2", 2),
        g.plant_needle(dep, "artifact.payment_token", "inter_rare_3", 1),
    ]
    return dep, planted


# ---------------------------------------------------------------------------
# The three sources.
# ---------------------------------------------------------------------------

def source_absent(dep, causes) -> Dict[str, int]:
    """Case 17's failure mode, kept as the baseline."""
    return {}


def source_topological(dep, causes) -> Dict[str, int]:
    """THE TRAP. Severity derived from the graph itself - here, how many paths
    reach an authority. Plausible, cheap, requires no external knowledge, and
    it is the graph grading its own homework."""
    by_authority: Dict[str, int] = {}
    for c in causes:
        by_authority[c.authority] = by_authority.get(c.authority, 0) + c.paths
    return by_authority


def source_declared(dep, causes) -> Dict[str, int]:
    """An independent classification of the authority itself.

    Not derived from the graph and not derivable from it: what a signing key
    is worth is a fact about the business, supplied by asset inventory, data
    classification or policy. The registry here stands in for that, exactly as
    case 12's arms stood in for architectures.
    """
    declared = dict(NEEDLES)
    for authority in dep.sensitive:
        declared.setdefault(authority, 1)
    return declared


SOURCES: Dict[str, Callable] = {
    "absent": source_absent,
    "topological": source_topological,
    "declared": source_declared,
}


# ---------------------------------------------------------------------------
# Measurement.
# ---------------------------------------------------------------------------

@dataclass
class Reading:
    source: str
    recall_top_10: float
    recall_top_20: float
    note: str


def measure() -> List[Reading]:
    dep, planted = deployment_with_needles()
    causes = g.causes(dep)
    out: List[Reading] = []
    for name, fn in SOURCES.items():
        severity = fn(dep, causes)
        ranked = g.by_sensitivity(causes, severity)
        out.append(Reading(
            name,
            g.recall_in_top(ranked, planted, 10),
            g.recall_in_top(ranked, planted, 20),
            {"absent": "no severity: the ordering collapses to blast radius",
             "topological": "severity computed from the graph",
             "declared": "severity supplied about the authority itself",
             }[name]))
    return out


def independence_check() -> Tuple[bool, str]:
    """The engine must not read severity when computing reachability.

    Computed with three different severity maps, the causes and findings must
    be identical - otherwise the graph is grading its own homework in the
    other direction, by letting the answer shape the question.
    """
    dep, _planted = deployment_with_needles()
    causes = g.causes(dep)
    signatures = set()
    for name, fn in SOURCES.items():
        severity = fn(dep, causes)
        recomputed = g.causes(dep)
        findings = d.findings(dep)
        signatures.add((
            tuple(sorted((c.authority, c.intermediary, c.paths)
                         for c in recomputed)),
            tuple(sorted((f.intermediary, f.endpoints, f.paths)
                         for f in findings)),
            len(severity) >= 0,
        ))
    ok = len({s[:2] for s in signatures}) == 1
    return ok, ("reachability is identical under every severity map"
                if ok else "the severity map changed the reachability result")


# ---------------------------------------------------------------------------
# Does topology predict severity? If it did, Gate 2 would not exist.
# ---------------------------------------------------------------------------

def _ranks(values: List[float]) -> List[float]:
    order = sorted(range(len(values)), key=lambda i: values[i])
    ranks = [0.0] * len(values)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and values[order[j + 1]] == values[order[i]]:
            j += 1
        shared = (i + j) / 2 + 1
        for k in range(i, j + 1):
            ranks[order[k]] = shared
        i = j + 1
    return ranks


def spearman(xs: List[float], ys: List[float]) -> float:
    """Rank correlation, implemented here rather than imported so the case has
    no dependency it does not need."""
    if len(xs) < 2:
        return 0.0
    rx, ry = _ranks(xs), _ranks(ys)
    n = len(xs)
    mx, my = sum(rx) / n, sum(ry) / n
    num = sum((a - mx) * (b - my) for a, b in zip(rx, ry))
    dx = sum((a - mx) ** 2 for a in rx) ** 0.5
    dy = sum((b - my) ** 2 for b in ry) ** 0.5
    return num / (dx * dy) if dx and dy else 0.0


def topology_vs_severity() -> Dict[str, float]:
    """Correlate each graph-derived proxy against declared severity."""
    dep, _planted = deployment_with_needles()
    causes = g.causes(dep)
    declared = source_declared(dep, causes)

    by_authority: Dict[str, List[int]] = {}
    for c in causes:
        by_authority.setdefault(c.authority, []).append(c.paths)

    authorities = sorted(by_authority)
    severity = [declared.get(a, 1) for a in authorities]
    return {
        "paths reaching it": spearman(
            [sum(by_authority[a]) for a in authorities], severity),
        "intermediaries holding it": spearman(
            [len(by_authority[a]) for a in authorities], severity),
        "largest single cause": spearman(
            [max(by_authority[a]) for a in authorities], severity),
    }
