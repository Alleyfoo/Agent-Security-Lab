"""Case 18 - Gate 1: is the reduction a property of the approach or the generator?

Case 17 passed `n_causes` into its generator and then reported the cause count,
which measured that it could count what it had planted. This samples from
distributions instead and asks where the reduction stops working.

Three claims, and the middle one is a failure:

  1. estate size is irrelevant - structural, and the half of case 17 that holds;
  2. case 17's grouping key is linear in fan-out and breaks on the shape real
     entitlement data has;
  3. moving the endpoint set out of the key and into an attribute fixes it
     without losing any endpoint.
"""

from __future__ import annotations

import importlib.util
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
CASE_DIR = os.path.join(REPO_ROOT, "cases", "18-distribution")

if CASE_DIR not in sys.path:
    sys.path.insert(0, CASE_DIR)


def _load(name: str):
    spec = importlib.util.spec_from_file_location(
        f"case18_{name}", os.path.join(CASE_DIR, f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[f"case18_{name}"] = module
    spec.loader.exec_module(module)
    return module


d = _load("distribution")


# ---------------------------------------------------------------------------
# Claim 1 - the half of case 17 that survives.
# ---------------------------------------------------------------------------

def test_cause_count_does_not_move_with_estate_size():
    """Structural: a cause is a fact about authority, and work items only
    multiply paths. This is what case 17 should have claimed."""
    readings = d.sweep_work(d.UNIFORM, [200, 2000, 20000])
    assert len({r.causes for r in readings}) == 1, (
        "cause count must be independent of how much work exists"
    )
    assert readings[-1].paths > readings[0].paths * 50, "paths really do grow"


def test_nothing_tells_the_sampler_how_many_causes_to_make():
    """The defect this case exists to correct. `sample()` takes a density, not
    a cause count, so the reduction is measured rather than assumed."""
    import inspect
    source = inspect.signature(d.sample)
    assert "n_causes" not in source.parameters
    assert "density" in source.parameters


# ---------------------------------------------------------------------------
# Claim 2 - case 17's grouping key breaks on a realistic shape.
# ---------------------------------------------------------------------------

def test_case_17s_key_is_linear_in_fan_out():
    """One over-scoped credential holding many secrets becomes many rows."""
    dep = d.sample(d.BROAD, 500, 300, 40, 1.0)
    causes = d.causes(dep)
    findings = d.findings(dep)
    assert len(causes) > len(findings) * 10, (
        "the (authority, intermediary) key multiplies one holder into many rows"
    )


def test_the_realistic_shape_is_unreadable_under_case_17s_key():
    """THE FAILURE. Heavy-tailed is the shape real entitlement data has, and
    it is unreadable at the lowest density sampled - three holders producing
    seventy-odd causes."""
    density, count = d.breaking_density(d.HEAVY_TAILED)
    assert density <= 0.01
    assert count > d.READABLE


def test_uniform_survives_further_than_the_realistic_shape():
    """Recorded so the failure is attributed to fan-out rather than to
    density in general."""
    uniform_at, _ = d.breaking_density(d.UNIFORM)
    heavy_at, _ = d.breaking_density(d.HEAVY_TAILED)
    assert uniform_at > heavy_at


# ---------------------------------------------------------------------------
# Claim 3 - the fix, and that it costs no information.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("shape", [d.UNIFORM, d.BROAD, d.HEAVY_TAILED])
@pytest.mark.parametrize("density", [0.01, 0.1, 1.0])
def test_findings_never_lose_an_endpoint(shape, density):
    """Case 17's requirement, which is why the authority was in the key at
    all. Making it an attribute must not reintroduce the hiding."""
    dep = d.sample(shape, 500, 300, 40, density)
    kept = set().union(*(set(f.endpoints) for f in d.findings(dep))) \
        if d.findings(dep) else set()
    assert kept == d.endpoints_exposed(dep)


def test_findings_never_lose_a_path():
    dep = d.sample(d.HEAVY_TAILED, 500, 300, 40, 0.1)
    assert sum(f.paths for f in d.findings(dep)) == dep.path_count()


def test_the_fix_makes_the_realistic_shape_readable():
    """73 causes become 3 findings at the density that broke case 17's key."""
    dep = d.sample(d.HEAVY_TAILED, 2000, 300, 40, 0.01)
    assert len(d.causes(dep)) > d.READABLE
    assert len(d.findings(dep)) <= d.READABLE


def test_fan_out_no_longer_drives_report_length():
    """BROAD moves fan-out while holding the number of holders fixed. Under
    the fix the report length must not move with it."""
    lengths = {len(d.findings(d.sample(d.BROAD, 500, 300, 40, x)))
               for x in (0.05, 0.25, 1.0)}
    assert len(lengths) == 1, (
        "report length must track holders, not how much each one holds"
    )


# ---------------------------------------------------------------------------
# The floor that remains.
# ---------------------------------------------------------------------------

def test_report_length_equals_the_number_of_holders():
    """The honest operational criterion, and it is irreducible: each
    intermediary holding sensitive authority is a separate thing somebody has
    to decide about."""
    for density in (0.02, 0.1, 0.3):
        dep = d.sample(d.UNIFORM, 500, 300, 40, density)
        holders = {i for i, held in dep.holds.items() if held & dep.sensitive}
        assert len(d.findings(dep)) == len(holders)


def test_the_pathological_shape_is_honestly_unreadable():
    """No fix rescues an estate where everything holds everything, and the
    case must not pretend otherwise."""
    dep = d.sample(d.PATHOLOGICAL, 200, 300, 40, 1.0)
    assert len(d.findings(dep)) > d.READABLE
