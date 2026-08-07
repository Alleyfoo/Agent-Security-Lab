"""Case 17 - does the reachability view survive a messy deployment?

The gate before case 16's view can be called useful. Written so it can fail:
if reduction does not hold, or planted needles disappear, that is the result.

Three things pinned here, and the second is the finding:

  1. reduction holds - causes track the number of intermediaries holding
     something sensitive, not the size of the deployment;
  2. the obvious ranking is exactly wrong for the findings that matter most;
  3. the obvious grouping key silently loses endpoints.
"""

from __future__ import annotations

import importlib.util
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
CASE_DIR = os.path.join(REPO_ROOT, "cases", "17-scale")

if CASE_DIR not in sys.path:
    sys.path.insert(0, CASE_DIR)


def _load(name: str):
    spec = importlib.util.spec_from_file_location(
        f"case17_{name}", os.path.join(CASE_DIR, f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[f"case17_{name}"] = module
    spec.loader.exec_module(module)
    return module


g = _load("graph")

NEEDLES = {"artifact.root_signing_key": 10, "artifact.customer_pii": 9,
           "artifact.payment_token": 9}


# ---------------------------------------------------------------------------
# Parity. Without it the scale experiment measures a different thing.
# ---------------------------------------------------------------------------

def test_the_generic_model_reproduces_case_16(tmp_path):
    """The layer-neutral graph must agree with case 16's own per-arm views.

    Both numbers have to be read while the arm is in one state - reading them
    either side of a reset compares two deployments, which reported a
    mismatch that was not there while this case was being written.
    """
    for arm, expected, got in g.parity_checks(str(tmp_path)):
        assert got == expected, (
            f"arm {arm}: case 16 says {expected}, the generic model says {got}"
        )


# ---------------------------------------------------------------------------
# Claim 1 - reduction.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("n_work,n_inter,n_sens,n_cause", [
    (50, 20, 5, 4),
    (500, 100, 10, 8),
    (5000, 400, 20, 12),
])
def test_causes_do_not_grow_with_the_deployment(n_work, n_inter, n_sens,
                                                n_cause):
    """The whole gate in one assertion: the operator's reading load is a
    property of how much sensitive authority exists, not of how big the
    estate is."""
    dep = g.generate(n_work, n_inter, n_sens, n_cause)
    causes = g.causes(dep)

    assert dep.path_count() >= n_work, "the graph really is large"
    assert len(causes) <= n_cause, (
        "causes must track the intermediaries holding something sensitive"
    )


def test_the_reduction_ratio_improves_with_scale():
    """The claim stated properly. A fixed ratio is the wrong assertion - at
    50 work items 4 causes explain 200 paths, which is only 50x. What matters
    is that the operator's reading load stays flat while the graph does not.
    """
    ratios = []
    counts = []
    for n_work, n_inter, n_sens, n_cause in [(50, 20, 5, 4),
                                             (500, 100, 10, 8),
                                             (5000, 400, 20, 12)]:
        dep = g.generate(n_work, n_inter, n_sens, n_cause)
        ratios.append(dep.path_count() / max(len(g.causes(dep)), 1))
        counts.append(len(g.causes(dep)))

    assert ratios == sorted(ratios), "reduction must get better, not worse"
    assert ratios[-1] > 1000, "and reach orders of magnitude at scale"
    assert counts[-1] < 50, "while the operator still reads a short list"


def test_reduction_loses_no_path():
    """Every path must be explained by exactly one cause. A reduction that
    drops paths is not a summary, it is a filter."""
    dep = g.generate(200, 40, 6, 6)
    assert sum(c.paths for c in g.causes(dep)) == dep.path_count()


def test_accepted_causes_are_not_re_reported():
    """An operator who has accepted a fact should stop seeing it, or the
    report is unusable on the second run."""
    dep = g.generate(100, 20, 4, 4)
    first = g.causes(dep)
    assert first

    dep.accepted.add((first[0].authority, first[0].intermediary))
    second = g.causes(dep)
    assert len(second) == len(first) - 1
    assert sum(c.paths for c in second) < dep.path_count()


# ---------------------------------------------------------------------------
# Claim 2 - the needles, and the ranking that buries them.
# ---------------------------------------------------------------------------

@pytest.fixture
def planted():
    dep = g.generate(5000, 400, 20, 12)
    needles = [
        g.plant_needle(dep, "artifact.root_signing_key", "inter_rare_1", 1),
        g.plant_needle(dep, "artifact.customer_pii", "inter_rare_2", 2),
        g.plant_needle(dep, "artifact.payment_token", "inter_rare_3", 1),
    ]
    return dep, needles, g.causes(dep)


def test_every_needle_survives_grouping(planted):
    """The failure this case exists to look for. A rare dangerous
    relationship must not be absorbed into a large benign group."""
    _dep, needles, causes = planted
    found = {(c.authority, c.intermediary) for c in causes}
    for needle in needles:
        assert needle in found, f"{needle} was lost by the reduction"


def test_needles_generate_almost_no_paths(planted):
    """Which is why they are the hard case: they are invisible to any measure
    of blast radius."""
    _dep, needles, causes = planted
    needle_paths = sum(c.paths for c in causes
                       if (c.authority, c.intermediary) in needles)
    assert needle_paths <= 4


def test_ranking_by_blast_radius_buries_the_needles(planted):
    """THE FINDING. The obvious ranking - biggest first - is exactly wrong for
    the findings that matter most."""
    _dep, needles, causes = planted
    assert g.recall_in_top(g.by_blast(causes), needles, 10) == 0.0, (
        "if this ever passes, blast-ranking stopped burying rare findings and "
        "the case's recommendation needs re-measuring"
    )


def test_ranking_by_severity_finds_them_all(planted):
    _dep, needles, causes = planted
    assert g.recall_in_top(g.by_sensitivity(causes, NEEDLES), needles, 10) == 1.0


def test_severity_is_not_derivable_from_the_graph(planted):
    """Stated as a requirement on anyone deploying this rather than a
    limitation to apologise for.

    With no severity supplied, every authority ranks alike and the ordering
    collapses back to blast radius - which buries the needles again.
    """
    _dep, needles, causes = planted
    assert g.recall_in_top(g.by_sensitivity(causes, {}), needles, 10) == 0.0


# ---------------------------------------------------------------------------
# Claim 3 - the grouping key.
# ---------------------------------------------------------------------------

def test_grouping_by_intermediary_alone_hides_endpoints():
    """The obvious grouping key reports one row per credential and loses how
    many distinct sensitive authorities it reaches."""
    dep = g.generate(200, 40, 6, 6)
    dep.holds["inter_0"].update({"artifact.secret_1", "artifact.secret_2",
                                 "artifact.secret_3"})

    proper = [c for c in g.causes(dep) if c.intermediary == "inter_0"]
    naive = [c for c in g.naive_causes(dep) if c.intermediary == "inter_0"]

    assert len(naive) == 1
    assert len(proper) > len(naive), (
        "the authority must be in the grouping key or endpoints vanish"
    )


def test_endpoints_exposed_is_reported_separately():
    """How many distinct sensitive things are reachable is its own number and
    must not be inferable only from the cause count."""
    dep = g.generate(100, 20, 5, 5)
    assert len(g.endpoints_exposed(dep)) <= 5
    assert g.endpoints_exposed(dep) <= dep.sensitive
