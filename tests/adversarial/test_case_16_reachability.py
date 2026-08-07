"""Case 16 - authority reachability.

Case 15 measured that an inventory diff is blind to the attack all three models
converge on. This builds the missing view and measures whether it sees what the
inventory could not.

Two claims, and the second is the more useful one:

  1. a reachability diff detects the attack in every arm;
  2. the exposure is visible **at rest**, before any attack, in a deployment
     an inventory audit calls clean.

Adversary: Level 1.5, the configuration adversary, unchanged.
"""

from __future__ import annotations

import importlib.util
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
CASE_DIR = os.path.join(REPO_ROOT, "cases", "16-reachability")

if CASE_DIR not in sys.path:
    sys.path.insert(0, CASE_DIR)


def _load(name: str):
    spec = importlib.util.spec_from_file_location(
        f"case16_{name}", os.path.join(CASE_DIR, f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[f"case16_{name}"] = module
    spec.loader.exec_module(module)
    return module


reach = _load("reach")
TARGET = reach.TARGET


@pytest.fixture
def detections(tmp_path):
    return {d.arm: d for d in reach.measure(str(tmp_path))}


# ---------------------------------------------------------------------------
# Claim 1 - the diff sees what the inventory could not.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("arm", ["A", "B", "C"])
def test_reachability_detects_what_the_inventory_diff_missed(detections, arm):
    det = detections[arm]
    assert det.inventory_changed is False, (
        "case 15's finding, reproduced: the standing inventory does not move"
    )
    assert det.reachability_changed is True, (
        f"arm {arm}: the reachability view must see the new path"
    )
    assert det.new_paths, "and must be able to name it"


def test_the_named_paths_identify_the_actual_route(detections):
    """A detection that cannot say *which* path appeared is an alarm, not an
    audit. Each arm names the binding that was changed."""
    assert any("svc_keys" in p for p in detections["A"].new_paths)
    assert any("conn_ops" in p for p in detections["B"].new_paths)
    assert any("rotate_keys" in p for p in detections["C"].new_paths)
    for arm in ("A", "B", "C"):
        assert all(TARGET in p for p in detections[arm].new_paths)


# ---------------------------------------------------------------------------
# Claim 2 - the exposure is visible before anything is attacked.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("arm", ["A", "B", "C"])
def test_the_exposure_is_visible_at_rest(tmp_path, arm):
    """THE USEFUL HALF. In a deployment where nothing has happened and an
    inventory audit reports a legitimate identity, credential or skill, the
    reachability view already says how much ordinary work is one configuration
    change away from it."""
    report = reach.exposure_report(str(tmp_path))
    potential, actual = report[arm]
    assert actual == 0, f"arm {arm}: nothing reaches it yet"
    assert potential > 0, (
        f"arm {arm}: and the view must still flag the exposure"
    )


def test_removing_the_pre_existing_authority_removes_the_exposure(tmp_path):
    """The view tracks the deployment rather than reporting a constant.

    With no identity holding the authority, arm A's potential set is empty -
    so a non-empty result is a fact about this deployment and not an artefact
    of the query.
    """
    reach.arm_a.reset()
    assert reach.potential_a(TARGET), "the identity is there"

    del reach.arm_a.PERMISSIONS[reach.arm_a.KEY_OWNER]
    assert reach.potential_a(TARGET) == [], "and now it is not"
    reach.arm_a.reset()


# ---------------------------------------------------------------------------
# The view has to be honest, or it is an alarm generator.
# ---------------------------------------------------------------------------

def test_arm_b_does_not_count_a_credential_that_would_break_the_step():
    """`conn_keys` holds the target and covers nothing else, so rebinding a
    step to it breaks that step - case 15 measured exactly this. Counting it
    as a path would inflate every report with routes that do not work."""
    reach.arm_b.reset()
    assert TARGET in reach.arm_b.CONNECTIONS[reach.arm_b.CONN_KEYS]
    assert reach.potential_b(TARGET) == [], (
        "a credential that cannot carry the step's own inputs is not a path"
    )


def test_an_honest_deployment_reports_no_paths(tmp_path):
    """No pre-existing authority, no exposure, in every arm. A view that
    reported paths here would be useless."""
    reach.arm_a.reset()
    del reach.arm_a.PERMISSIONS[reach.arm_a.KEY_OWNER]
    assert reach.potential_a(TARGET) == []
    reach.arm_a.reset()

    reach.arm_b.reset()
    assert reach.potential_b(TARGET) == []

    reach.arm_c.reset(str(tmp_path / "honest"))
    assert reach.potential_c(TARGET) == [], (
        "no approved skill reads key material until one is installed"
    )


def test_potential_is_a_superset_of_actual(tmp_path):
    """Anything reachable now is reachable by definition. If this ever fails
    the two views are measuring different things and the diff is meaningless."""
    reach.arm_a.reset()
    reach.arm_a.mutate_subject_assignment(TARGET)
    actual = {(p.work, p.authority) for p in reach.actual_a(TARGET)}
    potential = {(p.work, p.authority) for p in reach.potential_a(TARGET)}
    assert actual <= potential
    reach.arm_a.reset()


# ---------------------------------------------------------------------------
# The property the manager asked to keep separate.
# ---------------------------------------------------------------------------

def test_blast_radius_and_detectability_are_independent(detections):
    """Arm C has the smallest blast radius measured anywhere in this series -
    one object - and case 15 measured its attack as the quietest. Both remain
    true, and this case adds detection to it.

    So a small blast radius did not bring detectability with it, and did not
    prevent it either. They are separate properties and the series should stop
    treating a narrow scope as if it implied visibility.
    """
    assert detections["C"].inventory_changed is False, "still quiet by inventory"
    assert detections["C"].reachability_changed is True, "and now detectable"
    assert detections["C"].exposure_at_rest < detections["A"].exposure_at_rest, (
        "arm C's exposure is genuinely narrower, which is a different fact "
        "from whether anyone can see it"
    )
