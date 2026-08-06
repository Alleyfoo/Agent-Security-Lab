"""Case 08 - stored grant versus grant derived at use time.

A comparison, not a control. These tests pin each measured cell so the result
cannot quietly change, and pin the fairness conditions so the comparison cannot
quietly stop being like for like.

Attacker, narrowly: may alter persisted policy or workflow records before
execution; may not modify evaluator code or the administrative trust root.
"""

from __future__ import annotations

import importlib.util
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
CASE_DIR = os.path.join(REPO_ROOT, "cases", "08-derived-authority")


if CASE_DIR not in sys.path:
    sys.path.insert(0, CASE_DIR)


def _load(name: str):
    """The case directory is not an importable package."""
    spec = importlib.util.spec_from_file_location(
        f"case08_{name}", os.path.join(CASE_DIR, f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[f"case08_{name}"] = module
    spec.loader.exec_module(module)
    return module


# Imported by name, not by path: the arms do ``from common import ...`` through
# sys.path, and a second module object would give a second exception class that
# pytest.raises would not match.
import common  # noqa: E402

arm_a = _load("arm_a")
arm_b = _load("arm_b")

GRANTED = "artifact.raw_input"
C1 = "artifact.cleaned_output"      # future - absent at this position
C2 = "artifact.key_material"        # existing, granted to no stage
PRESENT = [GRANTED, C2]


@pytest.fixture
def obj(tmp_path):
    arm_b.reset()
    o = arm_b.WorkObject(
        object_id="obj_812", object_type="orders_table", state="ingested",
        artifacts={arm_b.T_TABLE_PREVIEW: GRANTED,
                   arm_b.T_KEY_MATERIAL: C2},
    )
    arm_b.save_object(o, str(tmp_path))
    return o


def _resolve_b(o, store_dir, skill=None):
    """Persist the tampering, then evaluate what was persisted."""
    arm_b.save_object(o, store_dir)
    proposed = skill or arm_b.required_skill(o)
    item = arm_b.QueueItem(object_id=o.object_id, skill=proposed)
    reloaded = arm_b.load_object(o.object_id, store_dir)
    return arm_b.resolve(item, reloaded)


@pytest.fixture(autouse=True)
def _clean_arm_a():
    arm_a.reset()
    yield
    arm_a.reset()


# ---------------------------------------------------------------------------
# Fairness. If these stop holding, the comparison means nothing.
# ---------------------------------------------------------------------------

def test_both_arms_resolve_the_same_grant_for_the_legitimate_task(obj, tmp_path):
    a = arm_a.resolve("schema", PRESENT)
    b = _resolve_b(obj, str(tmp_path))

    assert a.read_keys == b.read_keys == [GRANTED]
    assert a.write_key == b.write_key == "artifact.schema_profile"


@pytest.mark.parametrize("target", [C1, C2])
def test_neither_arm_grants_the_target_untampered(obj, tmp_path, target):
    assert not arm_a.resolve("schema", PRESENT).permits_read(target)
    assert not _resolve_b(obj, str(tmp_path)).permits_read(target)


def test_arm_a_is_built_from_the_production_types(obj):
    """Not a strawman: same Route record, same write-key mapping."""
    from agent_network_demo.contracts import write_key_for
    from agent_network_demo.demo_runner import Route

    assert isinstance(arm_a.GRANT_TABLE["schema"], Route)
    assert arm_a.resolve("schema", PRESENT).write_key == write_key_for(
        arm_a.GRANT_TABLE["schema"].output_contract)


# ---------------------------------------------------------------------------
# Arm A: one surface, and it yields both capabilities.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("target", [C1, C2])
def test_arm_a_one_edit_obtains_either_capability(target):
    arm_a.MUTATIONS["route or grant definition"](target)
    grant = arm_a.resolve("schema", PRESENT)

    assert grant.permits_read(target)
    assert grant.permits_read(GRANTED), "the edit is additive - nothing is lost"


def test_arm_a_has_exactly_one_authority_bearing_surface():
    assert arm_a.surfaces() == ["route or grant definition"]


# ---------------------------------------------------------------------------
# Arm B: the three surfaces that yield nothing.
# ---------------------------------------------------------------------------

def test_arm_b_transition_edit_yields_no_key_authority(obj, tmp_path):
    """Repointing at a skill that legitimately reads cleaned_output gives a
    grant of raw_input, because the wider contract resolves through the
    object's own artifact map."""
    arm_b.MUTATIONS["route or grant definition"](obj, C1)
    grant = _resolve_b(obj, str(tmp_path))

    assert grant.read_keys == [GRANTED]
    assert not grant.permits_read(C1)


def test_arm_b_object_state_edit_yields_no_key_authority(obj, tmp_path):
    arm_b.MUTATIONS["object type / state"](obj, C1)
    grant = _resolve_b(obj, str(tmp_path))

    assert grant.read_keys == [GRANTED]
    assert not grant.permits_read(C1)


def test_arm_b_queue_record_edit_is_refused_by_name(obj, tmp_path):
    with pytest.raises(common.AuthorizationError) as exc:
        _resolve_b(obj, str(tmp_path), skill="validate_chain")

    assert "requires 'infer_schema'" in str(exc.value)


def test_arm_b_refuses_an_unapproved_skill(obj, tmp_path):
    with pytest.raises(common.AuthorizationError) as exc:
        _resolve_b(obj, str(tmp_path), skill="exfiltrate")
    assert "no approved skill" in str(exc.value)


# ---------------------------------------------------------------------------
# Arm B: the two surfaces that do yield, and what they buy.
# ---------------------------------------------------------------------------

def test_arm_b_skill_contract_edit_obtains_the_existing_artifact(obj, tmp_path):
    arm_b.MUTATIONS["skill contract"](obj, C2)
    grant = _resolve_b(obj, str(tmp_path))

    assert grant.permits_read(C2)
    assert grant.permits_read(GRANTED), "additive, like arm A's route edit"


def test_arm_b_skill_contract_edit_still_cannot_reach_a_future_artifact(
        obj, tmp_path):
    """The contract may declare it; the object's map has to resolve it."""
    arm_b.MUTATIONS["skill contract"](obj, C1)
    grant = _resolve_b(obj, str(tmp_path))

    assert not grant.permits_read(C1)


@pytest.mark.parametrize("target", [C1, C2])
def test_arm_b_artifact_map_edit_obtains_either_capability(obj, tmp_path, target):
    """The map is the binding from declared type to concrete key, which makes
    it the authority-bearing record - including for a key that does not exist
    yet."""
    arm_b.MUTATIONS["artifact relationship / map"](obj, target)
    grant = _resolve_b(obj, str(tmp_path))

    assert grant.permits_read(target)
    assert not grant.permits_read(GRANTED), (
        "this mutation replaces rather than adds, so the legitimate read is "
        "lost - a property of the indirection, not a boundary"
    )


def test_the_map_edit_survives_reload(obj, tmp_path):
    """Scope: current object lifetime, including retries and resume."""
    arm_b.MUTATIONS["artifact relationship / map"](obj, C1)
    arm_b.save_object(obj, str(tmp_path))

    reloaded = arm_b.load_object("obj_812", str(tmp_path))
    assert reloaded.artifacts[arm_b.T_TABLE_PREVIEW] == C1


# ---------------------------------------------------------------------------
# The headline, pinned.
# ---------------------------------------------------------------------------

def test_minimum_tamper_set_is_one_in_both_arms(obj, tmp_path):
    """The hypothesis this case was written to test, and it is refuted.

    If this ever starts failing because arm B needs two edits, the win is real
    and the case README's conclusion must be rewritten - do not simply relax
    the assertion.
    """
    arm_a.MUTATIONS["route or grant definition"](C2)
    assert arm_a.resolve("schema", PRESENT).permits_read(C2)

    arm_b.MUTATIONS["artifact relationship / map"](obj, C2)
    assert _resolve_b(obj, str(tmp_path)).permits_read(C2)


def test_arm_b_has_more_stored_surfaces_than_arm_a():
    """More records to protect, not fewer. Recorded because it is the opposite
    of what the design intuition suggests."""
    assert len(arm_b.surfaces()) > len(arm_a.surfaces())
    assert set(arm_b.MUTATIONS) == set(arm_b.surfaces())
    assert set(arm_a.MUTATIONS) == set(arm_a.surfaces())


def test_every_surface_has_a_recorded_scope_and_detection_note():
    for arm in (arm_a, arm_b):
        for surface in arm.surfaces():
            assert arm.SCOPES.get(surface), f"{surface}: no scope recorded"
            assert arm.DETECTION.get(surface), f"{surface}: no detection note"
