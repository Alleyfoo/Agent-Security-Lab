"""Case 17 - does the reachability view survive a messy deployment?

Case 16 built the view and reported 4, 4 and 1 paths against deployments with
four stages and two credentials. That is a laboratory. The gate before any of
it can be called useful:

    Can a large reachability graph be reduced to a small number of actionable
    causes **without hiding dangerous paths**?

If ten thousand paths become "here are the six bindings that matter", the view
is a tool. If the operator gets a forty-page graph, it is mathematically
correct wallpaper.

The generic model
-----------------

Case 16 established that the three layers express one structure in three
idioms. So the graph here is generic, over a triple:

    work  --(bindable to)-->  intermediary  --(holds)-->  authority

    layer A   stage   ->  subject     ->  key
    layer B   step    ->  connection  ->  key
    layer C   object  ->  skill       ->  artifact type/key

A **potential path** is `(work, intermediary, authority)` where the work could
be bound to that intermediary and the intermediary holds sensitive authority -
the same definition case 16 used, and `from_arm()` below reproduces case 16's
numbers exactly so the scale experiment is measuring the same thing.

A **cause** is `(authority, intermediary)` - one fact about the deployment that
generates however many paths. Causes are what an operator can act on: revoke
the credential, narrow the identity, unapprove the skill. Paths are not
actionable; there is nothing to do about "stage 4,812 could use conn_ops"
except fix conn_ops.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Set, Tuple

CASE_17 = os.path.dirname(os.path.abspath(__file__))
CASES = os.path.dirname(CASE_17)
CASE_16 = os.path.join(CASES, "16-reachability")

for path in (CASE_16, os.path.dirname(CASES)):
    if path not in sys.path:
        sys.path.insert(0, path)


def _load16(name: str):
    spec = importlib.util.spec_from_file_location(
        f"case16_{name}", os.path.join(CASE_16, f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[f"case16_{name}"] = module
    spec.loader.exec_module(module)
    return module


reach = _load16("reach")


@dataclass
class Deployment:
    """One deployment, in the layer-neutral form."""

    work: List[str]
    holds: Dict[str, Set[str]]            # intermediary -> authorities held
    bindable: Dict[str, Set[str]]         # work -> intermediaries it may use
    sensitive: Set[str]                   # authorities that matter
    label: str = ""
    # Authorities an operator has explicitly accepted. Everything else is a
    # finding; this is what keeps a report from re-reporting known facts.
    accepted: Set[Tuple[str, str]] = field(default_factory=set)

    def path_count(self) -> int:
        return sum(
            1
            for w in self.work
            for i in self.bindable.get(w, ())
            for a in self.holds.get(i, ())
            if a in self.sensitive
        )

    def paths(self) -> Iterable[Tuple[str, str, str]]:
        for w in self.work:
            for i in self.bindable.get(w, ()):
                for a in self.holds.get(i, ()):
                    if a in self.sensitive:
                        yield (w, i, a)


# ---------------------------------------------------------------------------
# Reduction.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Cause:
    """One actionable fact. `paths` is how much of the graph it explains."""

    authority: str
    intermediary: str
    paths: int

    def describe(self) -> str:
        return (f"{self.intermediary!r} holds {self.authority!r} "
                f"({self.paths} paths)")


def causes(dep: Deployment) -> List[Cause]:
    """Group by (authority, intermediary). The authority is in the key on
    purpose - see `naive_causes` for what dropping it costs."""
    counts: Dict[Tuple[str, str], int] = {}
    for _work, intermediary, authority in dep.paths():
        if (authority, intermediary) in dep.accepted:
            continue
        counts[(authority, intermediary)] = \
            counts.get((authority, intermediary), 0) + 1
    return [Cause(a, i, n) for (a, i), n in counts.items()]


def naive_causes(dep: Deployment) -> List[Cause]:
    """The obvious grouping - by intermediary alone - kept so the cost of
    getting the key wrong is measured rather than asserted. It reports one
    finding per credential and silently loses how many distinct sensitive
    authorities that credential reaches."""
    counts: Dict[str, int] = {}
    for _work, intermediary, _authority in dep.paths():
        counts[intermediary] = counts.get(intermediary, 0) + 1
    return [Cause("(all)", i, n) for i, n in counts.items()]


def endpoints_exposed(dep: Deployment) -> Set[str]:
    return {a for _w, _i, a in dep.paths()}


# ---------------------------------------------------------------------------
# Ranking. What the operator actually reads is the top of a list.
# ---------------------------------------------------------------------------

def by_blast(cs: List[Cause]) -> List[Cause]:
    """The obvious ranking: biggest first."""
    return sorted(cs, key=lambda c: (-c.paths, c.intermediary))


def by_sensitivity(cs: List[Cause], severity: Dict[str, int]) -> List[Cause]:
    """Severity first, blast second. Severity is a property of the authority,
    which an operator supplies - it is not derivable from the graph."""
    return sorted(cs, key=lambda c: (-severity.get(c.authority, 1), -c.paths,
                                     c.intermediary))


# ---------------------------------------------------------------------------
# Parity with case 16. The scale experiment must measure the same thing.
# ---------------------------------------------------------------------------

def from_arm_a() -> Deployment:
    a = reach.arm_a
    a.reset()
    holds = {subject: {k for k, ops in grants.items() if a.READ in ops}
             for subject, grants in a.PERMISSIONS.items()}
    stages = list(a.SUBJECT_OF_STAGE)
    return Deployment(
        work=stages, holds=holds,
        bindable={s: set(holds) for s in stages},
        sensitive={reach.TARGET}, label="arm A (case 16)")


def from_arm_b() -> Deployment:
    b = reach.arm_b
    b.reset()
    b.CONNECTIONS[reach.sel.OVERSCOPED] = set(
        b.CONNECTIONS[b.CONN_ORDERS]) | {reach.TARGET}
    holds = {name: set(scope) for name, scope in b.CONNECTIONS.items()}
    bindable: Dict[str, Set[str]] = {}
    for name, step in b.WORKFLOW.items():
        needed = set(step.inputs) | ({step.output} if step.output else set())
        bindable[name] = {c for c, scope in holds.items() if needed <= scope}
    # Deliberately left installed: the Deployment describes the arm *as it
    # stands*, so a caller comparing against case 16's own count must read it
    # before resetting. `parity_checks` does that; getting it wrong reported a
    # mismatch that was an artefact of ordering rather than of the model.
    return Deployment(work=list(b.WORKFLOW), holds=holds, bindable=bindable,
                      sensitive={reach.TARGET}, label="arm B (case 16)")


def from_arm_c(store_dir: str) -> Deployment:
    from object_model import evaluator, skills
    c = reach.arm_c
    c.reset(store_dir)
    reach.inv._install_rotation_skill()
    bound = reach._types_bound_to(reach.TARGET)
    holds = {name: {reach.TARGET} if set(skill.reads) & bound else set()
             for name, skill in skills.REGISTRY.items()}
    reachable_skills = {s for (_t, _st), s in evaluator.TRANSITIONS.items()}
    obj = c._state["obj"].object_id
    return Deployment(
        work=[obj], holds=holds, bindable={obj: reachable_skills},
        sensitive={reach.TARGET}, label="arm C (case 16)")


def parity_checks(store_dir: str) -> List[Tuple[str, int, int]]:
    """(arm, case-16 count, generic-model count), each read in one state.

    The two numbers must be taken while the arm is in the same configuration
    the Deployment describes. Reading them either side of a reset compares two
    different deployments and reports a mismatch that is not there.
    """
    out: List[Tuple[str, int, int]] = []

    dep = from_arm_a()
    out.append(("A", len(reach.potential_a()), dep.path_count()))

    dep = from_arm_b()
    out.append(("B", len(reach.potential_b()), dep.path_count()))
    reach.arm_b.reset()

    dep = from_arm_c(store_dir)
    out.append(("C", len(reach.potential_c()), dep.path_count()))

    reach.arm_a.reset()
    return out


# ---------------------------------------------------------------------------
# The synthetic messy deployment.
# ---------------------------------------------------------------------------

BENIGN = "artifact.ordinary"


def generate(n_work: int, n_intermediaries: int, n_sensitive: int,
             n_causes: int, seed_label: str = "") -> Deployment:
    """A deployment that is mostly boring.

    `n_causes` intermediaries hold something sensitive; the rest hold only
    ordinary authority. Every work item may bind to every intermediary, which
    is the worst case for the view and the honest one to measure - a real
    deployment constrains bindings and would produce fewer paths.
    """
    work = [f"work_{i}" for i in range(n_work)]
    sensitive = {f"artifact.secret_{i}" for i in range(n_sensitive)}
    holds: Dict[str, Set[str]] = {}
    for i in range(n_intermediaries):
        name = f"inter_{i}"
        holds[name] = {f"{BENIGN}_{i % 7}"}
    for i in range(n_causes):
        holds[f"inter_{i}"].add(f"artifact.secret_{i % max(n_sensitive, 1)}")
    return Deployment(
        work=work, holds=holds,
        bindable={w: set(holds) for w in work},
        sensitive=sensitive,
        label=seed_label or f"{n_work} work x {n_intermediaries} intermediaries")


def plant_needle(dep: Deployment, authority: str, intermediary: str,
                 reachable_by: int = 1) -> Tuple[str, str]:
    """A rare dangerous relationship: one intermediary holding one very
    sensitive authority, bindable by only a few work items.

    This is the thing a reduction must not lose. It generates almost no paths,
    so any report ordered by blast radius buries it.
    """
    dep.holds.setdefault(intermediary, set()).add(authority)
    dep.sensitive.add(authority)
    for w in dep.work:
        dep.bindable.setdefault(w, set()).discard(intermediary)
    for w in dep.work[:reachable_by]:
        dep.bindable.setdefault(w, set()).add(intermediary)
    return (authority, intermediary)


def recall_in_top(ranked: List[Cause], needles: Iterable[Tuple[str, str]],
                  top: int) -> float:
    head = {(c.authority, c.intermediary) for c in ranked[:top]}
    needles = list(needles)
    if not needles:
        return 1.0
    return sum(1 for n in needles if n in head) / len(needles)
