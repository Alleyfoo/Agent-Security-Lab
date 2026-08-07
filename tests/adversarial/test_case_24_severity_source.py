"""Case 24 - Gate 2: where does severity come from?

Case 17 measured the reachability view as usable given a severity map and
unusable without one, and left the source unbuilt. The condition on it was
that severity be supplied independently, or the graph grades its own homework.

Three claims:

  1. the engine does not read severity when computing reachability;
  2. graph topology does not predict severity - and is worse than that;
  3. a severity derived from the graph is not a weaker source than none, it is
     the same source.
"""

from __future__ import annotations

import importlib.util
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
CASE_DIR = os.path.join(REPO_ROOT, "cases", "24-severity-source")

if CASE_DIR not in sys.path:
    sys.path.insert(0, CASE_DIR)


def _load(name: str):
    spec = importlib.util.spec_from_file_location(
        f"case24_{name}", os.path.join(CASE_DIR, f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[f"case24_{name}"] = module
    spec.loader.exec_module(module)
    return module


s = _load("severity")


@pytest.fixture(scope="module")
def readings():
    return s.measure()


def _by(readings, name):
    return next(r for r in readings if r.source == name)


# ---------------------------------------------------------------------------
# Claim 1 - the answer must not shape the question.
# ---------------------------------------------------------------------------

def test_reachability_is_identical_under_every_severity_map():
    """The engine must not read severity. If it did, the graph would be
    grading its own homework in the other direction."""
    ok, note = s.independence_check()
    assert ok, note


def test_the_reachability_computation_never_mentions_severity():
    """Structural, and narrower than it first looks.

    `by_sensitivity` legitimately *takes* a severity map - that is the
    ranking, and ranking is where supplied knowledge belongs. What must be
    free of it is the computation of what reaches what: `causes`, `findings`
    and `path_count` decide the facts, and a severity map may not touch them.
    """
    import inspect
    for fn in (s.g.causes, s.g.naive_causes, s.g.endpoints_exposed,
               s.d.findings, s.g.Deployment.path_count):
        source = inspect.getsource(fn)
        assert "severity" not in source and "sensitivity" not in source, (
            f"{fn.__name__} consults severity while computing reachability"
        )

    assert "severity" in inspect.getsource(s.g.by_sensitivity), (
        "ranking is exactly where supplied knowledge belongs"
    )


# ---------------------------------------------------------------------------
# Claim 2 - topology does not predict severity, and is worse than useless.
# ---------------------------------------------------------------------------

def test_no_graph_proxy_positively_predicts_severity():
    """A strong positive correlation would make Gate 2 unnecessary."""
    for proxy, rho in s.topology_vs_severity().items():
        assert rho <= 0.5, f"{proxy} predicts severity (rho={rho:+.3f})"


def test_path_count_is_strongly_inverted_against_severity():
    """THE SHARPER FINDING. Not merely uninformative - inverted, so using path
    count as a proxy is worse than random.

    Conditional on the scenario rather than a law: the needles were planted
    rare AND valuable. That is exactly the assumption case 17 established as
    the one that matters, and it is what an over-broad service identity to a
    signing key looks like.
    """
    rho = s.topology_vs_severity()["paths reaching it"]
    assert rho < -0.5


def test_the_holder_count_is_genuinely_uncorrelated():
    """Useful for sizing the report - it is case 18's report length - and
    useless for ranking it."""
    rho = s.topology_vs_severity()["intermediaries holding it"]
    assert abs(rho) < 0.2


# ---------------------------------------------------------------------------
# Claim 3 - self-grading measured rather than argued.
# ---------------------------------------------------------------------------

def test_no_severity_reproduces_case_17s_failure(readings):
    assert _by(readings, "absent").recall_top_10 == 0.0


def test_severity_derived_from_the_graph_adds_nothing(readings):
    """THE FINDING. A topological severity is not a weaker source than none;
    it is the SAME source, because path count is what the fallback ordering
    already used. It looks like knowledge and changes no cell."""
    absent = _by(readings, "absent")
    topological = _by(readings, "topological")
    assert topological.recall_top_10 == absent.recall_top_10 == 0.0
    assert topological.recall_top_20 == absent.recall_top_20


def test_an_independent_classification_finds_every_needle(readings):
    assert _by(readings, "declared").recall_top_10 == 1.0


def test_the_declared_source_is_not_derivable_from_the_deployment():
    """The severity map must be knowledge about the authority, not a function
    of the graph. Asserted by construction: the needle severities are stated
    outright and cannot be recomputed from paths, holders or fan-out."""
    dep, _planted = s.deployment_with_needles()
    causes = s.g.causes(dep)
    declared = s.source_declared(dep, causes)
    topological = s.source_topological(dep, causes)

    for authority, value in s.NEEDLES.items():
        assert declared[authority] == value
        assert topological.get(authority, 0) != value, (
            "if the graph could reproduce the declared value, Gate 2 would "
            "not exist"
        )


# ---------------------------------------------------------------------------
# The gate itself.
# ---------------------------------------------------------------------------

def test_gate_2_is_answered_and_the_answer_is_no():
    """The graph cannot supply its own severity - stated as the one-line
    result so a reader cannot take the opposite from the table."""
    readings = s.measure()
    assert _by(readings, "topological").recall_top_10 == 0.0
    assert _by(readings, "declared").recall_top_10 == 1.0
