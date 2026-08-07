"""Case 18 - is the reduction a property of the approach or of the generator?

Gate 1 on the reachability hypothesis. Case 17 reported 320,000 paths reducing
to 16 causes, and there is a problem with that number:

    `generate(..., n_causes=16)` took the cause count as a **parameter**.

So case 17 partly measured that it could count what it had planted. The work
axis it grew is provably the one that does not matter, and the axis that does -
how much sensitive authority is spread across intermediaries - it held fixed
and named directly.

This case removes the parameter. Deployments are **sampled from a
distribution**, nothing is told how many causes to produce, and the question is
where the reduction stops working.

    cause  = (authority, intermediary) - one actionable fact
    causes = Σ over intermediaries holding sensitive authority
                 of how many distinct sensitive authorities each holds

Written down that way the structural claim is visible before any measurement:
**the cause count cannot depend on the number of work items at all.** That is
tested rather than assumed, because it is the half of case 17's result that
survives.
"""

from __future__ import annotations

import importlib.util
import os
import random
import sys
from dataclasses import dataclass
from typing import Dict, List, Set, Tuple

CASE_18 = os.path.dirname(os.path.abspath(__file__))
CASES = os.path.dirname(CASE_18)
CASE_17 = os.path.join(CASES, "17-scale")

for path in (CASE_17, os.path.dirname(CASES)):
    if path not in sys.path:
        sys.path.insert(0, path)


def _load17(name: str):
    spec = importlib.util.spec_from_file_location(
        f"case17_{name}", os.path.join(CASE_17, f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[f"case17_{name}"] = module
    spec.loader.exec_module(module)
    return module


g = _load17("graph")
Deployment, causes, endpoints_exposed = g.Deployment, g.causes, g.endpoints_exposed

# What a person will actually read before giving up. Not measured, declared -
# and declared once here so the threshold is arguable rather than buried.
READABLE = 50


# ---------------------------------------------------------------------------
# Distributions. None of them is told how many causes to produce.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Shape:
    name: str
    note: str


# Report length is the product of two independent things, and the shapes below
# exist to move them one at a time:
#
#     causes = (how many intermediaries hold sensitive authority)
#              x (how many distinct sensitive authorities each holds)
#
# An earlier draft had "sparse" and "dense" as separate shapes; they sampled
# identically and differed only in the density parameter, which measured one
# factor twice and the other never.

UNIFORM = Shape("uniform",
                "holders are spread by chance and each holds one thing - "
                "density moves the *number* of holders")
BROAD = Shape("broad",
              "the same number of holders, but each holds many sensitive "
              "authorities - density moves the *fan-out*")
HEAVY_TAILED = Shape(
    "heavy-tailed",
    "a few intermediaries hold a great deal and the tail holds nothing - "
    "the shape real entitlement data actually has")
PATHOLOGICAL = Shape("pathological", "every intermediary holds everything")


def sample(shape: Shape, n_work: int, n_intermediaries: int,
           n_sensitive: int, density: float, seed: int = 7) -> Deployment:
    """Build a deployment by sampling. Nothing here sets the cause count."""
    rng = random.Random(seed)
    work = [f"work_{i}" for i in range(n_work)]
    sensitive = {f"secret_{i}" for i in range(n_sensitive)}
    ordered = sorted(sensitive)
    holds: Dict[str, Set[str]] = {}

    # For the heavy tail the holders are the *front* of the list rather than a
    # random draw, or the shape is not heavy-tailed - it is uniform with an
    # odd fan-out.
    n_holders = max(1, int(n_intermediaries * density))

    for i in range(n_intermediaries):
        name = f"inter_{i}"
        held = {f"ordinary_{i % 7}"}
        if shape is PATHOLOGICAL:
            held |= sensitive
        elif shape is HEAVY_TAILED:
            if i < n_holders:
                take = max(1, int(n_sensitive / (i + 1)))
                held |= set(ordered[:take])
        elif shape is BROAD:
            # A fixed, small number of holders; density controls how much each
            # one holds.
            if i < max(1, n_intermediaries // 20):
                take = max(1, int(n_sensitive * density))
                held |= set(ordered[:take])
        else:                                             # UNIFORM
            if rng.random() < density:
                held.add(rng.choice(ordered))
        holds[name] = held

    return Deployment(
        work=work, holds=holds,
        bindable={w: set(holds) for w in work},
        sensitive=sensitive,
        label=f"{shape.name} d={density:g}")


# ---------------------------------------------------------------------------
# Measurement.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Finding:
    """One row an operator reads: *this intermediary is over-scoped, and here
    is everything sensitive it reaches.*

    The resolution of a real tension between the two earlier cases. Case 17
    showed that grouping by intermediary alone **hides endpoints**, so the
    authority had to be in the key. But keying on the authority makes one
    over-scoped credential holding forty secrets into forty rows, which is what
    breaks the heavy-tailed shape below.

    Both requirements are satisfied by making the endpoint set an *attribute*
    of a per-intermediary finding rather than part of its key: report length
    tracks the number of holders, and no endpoint is lost.
    """

    intermediary: str
    endpoints: Tuple[str, ...]
    paths: int

    def describe(self) -> str:
        return (f"{self.intermediary!r} reaches {len(self.endpoints)} "
                f"sensitive authorities ({self.paths} paths): "
                f"{', '.join(self.endpoints[:3])}"
                f"{' ...' if len(self.endpoints) > 3 else ''}")


def findings(dep: Deployment) -> List[Finding]:
    grouped: Dict[str, Tuple[Set[str], int]] = {}
    for c in causes(dep):
        ends, paths = grouped.get(c.intermediary, (set(), 0))
        ends.add(c.authority)
        grouped[c.intermediary] = (ends, paths + c.paths)
    return [Finding(i, tuple(sorted(e)), n) for i, (e, n) in grouped.items()]


@dataclass
class Reading:
    shape: str
    density: float
    n_work: int
    paths: int
    causes: int
    endpoints: int
    readable: bool
    top_share: float          # fraction of paths the 5 biggest causes explain


def read(dep: Deployment, shape: Shape, density: float) -> Reading:
    cs = causes(dep)
    total = sum(c.paths for c in cs) or 1
    top = sorted(cs, key=lambda c: -c.paths)[:5]
    return Reading(
        shape=shape.name, density=density, n_work=len(dep.work),
        paths=dep.path_count(), causes=len(cs),
        endpoints=len(endpoints_exposed(dep)),
        readable=len(cs) <= READABLE,
        top_share=sum(c.paths for c in top) / total)


def sweep_density(shape: Shape, densities: List[float], n_work: int = 2000,
                  n_intermediaries: int = 300,
                  n_sensitive: int = 40) -> List[Reading]:
    out = []
    for d in densities:
        dep = sample(shape, n_work, n_intermediaries, n_sensitive, d)
        out.append(read(dep, shape, d))
    return out


def sweep_work(shape: Shape, works: List[int], density: float = 0.05,
               n_intermediaries: int = 300,
               n_sensitive: int = 40) -> List[Reading]:
    """The structural claim: cause count must not move when only the number of
    work items changes."""
    out = []
    for n_work in works:
        dep = sample(shape, n_work, n_intermediaries, n_sensitive, density)
        out.append(read(dep, shape, density))
    return out


def breaking_density(shape: Shape, n_work: int = 2000,
                     n_intermediaries: int = 300,
                     n_sensitive: int = 40) -> Tuple[float, int]:
    """The lowest sampled density at which the report stops being readable,
    and the cause count there. This is the operational criterion: an estate
    can be checked against it *before* anyone adopts the approach."""
    for d in [x / 100 for x in range(1, 101)]:
        dep = sample(shape, n_work, n_intermediaries, n_sensitive, d)
        cs = len(causes(dep))
        if cs > READABLE:
            return d, cs
    return 1.0, len(causes(sample(shape, n_work, n_intermediaries,
                                  n_sensitive, 1.0)))
