"""Case 12 - three models, one workflow.

A comparison, not a control. These tests pin every measured cell so a result
cannot quietly change, and pin the fairness conditions so the comparison cannot
quietly stop being like for like - the discipline case 08 established.

Attacker, identical in all three arms: may alter persisted configuration or
workflow records; may not modify executable code or the administrative trust
root.

Two pre-registered predictions were refuted and the tests below are what
refuted them. Do not "fix" a failing competence assertion by weakening the arm
it protects; an arm that stops being competent makes its own numbers void.
"""

from __future__ import annotations

import importlib.util
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
CASE_DIR = os.path.join(REPO_ROOT, "cases", "12-three-models")

if CASE_DIR not in sys.path:
    sys.path.insert(0, CASE_DIR)


def _load(name: str):
    """The case directory is not an importable package."""
    spec = importlib.util.spec_from_file_location(
        f"case12_{name}", os.path.join(CASE_DIR, f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[f"case12_{name}"] = module
    spec.loader.exec_module(module)
    return module


# Imported by name so the arms and these tests share one exception class - the
# arms do `from case12_common import ...` through sys.path, and a second module
# object would give a second AuthorizationError that pytest.raises would miss.
#
# The name is case-qualified on purpose. Case 08 owns the bare name `common`,
# and when the whole suite runs its test module imports first, so a plain
# `import common` here silently binds case 08's module and this file fails to
# collect. It did, once. Any future case sharing a helper module must qualify
# the name the same way.
import case12_common as common  # noqa: E402

arm_a = _load("arm_a")
arm_b = _load("arm_b")
arm_c = _load("arm_c")

TARGET = common.TARGET
STAGE = common.ATTACK_STAGE


@pytest.fixture(autouse=True)
def _fresh(tmp_path):
    arm_a.reset()
    arm_b.reset()
    arm_c.reset(str(tmp_path / "c"))
    yield
    arm_a.reset()
    arm_b.reset()


# ---------------------------------------------------------------------------
# Fairness. Without these the numbers below mean nothing.
# ---------------------------------------------------------------------------

def test_all_three_arms_do_the_same_work(tmp_path):
    """The precondition. Case 10 built map maintenance before attacking the
    map for the same reason: an arm that cannot do the work is not an arm."""
    produced = []
    for index, arm in enumerate((arm_a, arm_b, arm_c)):
        store = common.fresh_store()
        if arm is arm_c:
            arm.reset(str(tmp_path / f"eq{index}"))
        else:
            arm.reset()
        arm.run_workflow(store)
        produced.append([k for k in store.keys()
                         if k not in ("artifact.source_payload", TARGET)])

    assert produced[0] == produced[1] == produced[2]
    assert common.KEY_CLEANED in produced[0]


def test_all_three_arms_resolve_the_same_schema_grant(tmp_path):
    for index, arm in enumerate((arm_a, arm_b, arm_c)):
        if arm is arm_c:
            arm.reset(str(tmp_path / f"g{index}"))
        else:
            arm.reset()
        grant = arm.resolve(STAGE)
        assert sorted(grant.read_keys) == [common.KEY_RAW], arm.NAME
        assert not grant.permits_read(TARGET), arm.NAME


def test_arm_a_is_not_a_strawman():
    """Competence checklist: own subject per stage, least privilege, no
    superuser, revocable. A violated checklist voids arm A's result."""
    subjects = set(arm_a.SUBJECT_OF_STAGE.values())
    assert len(subjects) == len(arm_a.SUBJECT_OF_STAGE), "one subject per stage"

    schema_subject = arm_a.SUBJECT_OF_STAGE["schema"]
    reads = {k for k, ops in arm_a.PERMISSIONS[schema_subject].items()
             if arm_a.READ in ops}
    assert reads == {common.KEY_RAW}, "least privilege"

    for subject, grants in arm_a.PERMISSIONS.items():
        assert "*" not in grants, f"{subject} is a superuser"
        assert TARGET not in grants or subject == arm_a.KEY_OWNER

    arm_a.revoke(schema_subject, common.KEY_RAW)
    assert not arm_a.may(schema_subject, common.KEY_RAW, arm_a.READ)


def test_arm_b_is_not_a_strawman():
    """Competence checklist: scoped per-connection credentials, no credential
    with access to everything, references rather than payloads."""
    everything = {common.KEY_RAW, common.KEY_SCHEMA, common.KEY_CLEANED,
                  TARGET}
    for name, scope in arm_b.CONNECTIONS.items():
        assert not everything.issubset(scope), f"{name} is a god credential"

    for step in arm_b.WORKFLOW.values():
        for ref in step.inputs:
            assert ref.startswith("artifact."), (
                "steps must pass references, not payloads - the direction is "
                "explicit and key_vs_paste.py is the counter-example"
            )


def test_arm_b_fails_closed_on_an_unreachable_reference():
    """Load-bearing for arm B's minimum tamper set of 2. If a step that
    references data its connection cannot reach silently proceeded with the
    subset it can reach, one edit would obtain the capability."""
    arm_b.mutate_step_configuration(TARGET)
    with pytest.raises(common.AuthorizationError) as exc:
        arm_b.resolve(STAGE)
    assert TARGET in str(exc.value)
    assert "cannot reach" in str(exc.value)


def test_arm_c_does_not_modify_the_object_model():
    """Cases 10 and 11 published tables taken against object_model. This case
    adapts to it and must never retrofit into it."""
    from object_model import evaluator, skills
    assert len(evaluator.TRANSITIONS) == 3
    assert skills.REGISTRY["validate_chain"].effects == "read_only"
    assert skills.REGISTRY["infer_schema"].reads == (skills.T_TABLE_PREVIEW,)


# ---------------------------------------------------------------------------
# Arm A - authority follows the subject.
# ---------------------------------------------------------------------------

def test_arm_a_widening_the_permission_table_obtains_it():
    arm_a.mutate_permission_table(TARGET)
    assert arm_a.resolve(STAGE).permits_read(TARGET)


def test_arm_a_becoming_another_subject_obtains_it():
    """No new authority is created anywhere - the edit redirects the work to
    an identity that already held it. This is why the identity model's blast
    radius is not bounded by the workflow."""
    arm_a.mutate_subject_assignment(TARGET)
    assert arm_a.resolve(STAGE).permits_read(TARGET)
    assert arm_a.PERMISSIONS[arm_a.KEY_OWNER][TARGET] == {arm_a.READ}, (
        "the permission itself was never edited"
    )


def test_arm_a_minimum_tamper_set_is_one():
    for surface in arm_a.surfaces():
        arm_a.reset()
        arm_a.MUTATIONS[surface](TARGET)
        assert arm_a.resolve(STAGE).permits_read(TARGET), surface
        assert arm_a.EDITS[surface] == 1


# ---------------------------------------------------------------------------
# Arm B - authority follows the configured workflow.
# ---------------------------------------------------------------------------

def test_arm_b_no_single_edit_obtains_it():
    """REFUTES the pre-registered hypothesis. Both existing comparisons
    measured a minimum tamper set of 1 in every arm; a competently configured
    workflow needs two, because what a step names and what its credential may
    reach are separate records."""
    for surface in ("step configuration", "connection scope",
                    "connection binding"):
        arm_b.reset()
        arm_b.MUTATIONS[surface](TARGET)
        try:
            obtained = arm_b.resolve(STAGE).permits_read(TARGET)
        except common.AuthorizationError:
            obtained = False
        assert not obtained, f"{surface} obtained the capability alone"


def test_arm_b_two_edits_obtain_it():
    arm_b.mutate_step_configuration(TARGET)
    arm_b.mutate_connection_scope(TARGET)
    assert arm_b.resolve(STAGE).permits_read(TARGET)


def test_arm_b_rebinding_the_connection_breaks_the_step_instead():
    """Availability loss rather than a capability. Worth recording: the
    cheapest thing an attacker can do to this arm is stop it working."""
    arm_b.mutate_step_configuration(TARGET)
    arm_b.mutate_connection_binding(TARGET)
    with pytest.raises(common.AuthorizationError) as exc:
        arm_b.resolve(STAGE)
    assert common.KEY_RAW in str(exc.value)


# ---------------------------------------------------------------------------
# Arm C - authority derived for one transformation.
# ---------------------------------------------------------------------------

def test_arm_c_overwriting_the_binding_obtains_it(tmp_path):
    """Case 10's surviving route, unchanged by case 11's containment because
    an overwrite leaves no contradiction to contain."""
    arm_c.reset(str(tmp_path / "bind"))
    arm_c.mutate_artifact_binding(TARGET)
    assert arm_c.resolve(STAGE).permits_read(TARGET)


def test_arm_c_widening_the_skill_contract_obtains_it(tmp_path):
    """One edit, placed before the run pins - case 09's undetected placement.
    Its scope is the widest measured anywhere in this case."""
    arm_c.reset(str(tmp_path / "skill"))
    arm_c.mutate_skill_contract(TARGET)
    assert arm_c.resolve(STAGE).permits_read(TARGET)
    assert arm_c.SCOPES["skill contract"] == common.SCOPE_DEPLOYMENT


@pytest.mark.parametrize("surface",
                         ["object state", "transition table", "queue item"])
def test_arm_c_the_other_surfaces_yield_no_key_authority(surface, tmp_path):
    """Case 08's finding, reproduced here: the grant still has to resolve
    through the artifact binding and none of these touches it."""
    arm_c.reset(str(tmp_path / surface.replace(" ", "_")))
    arm_c.MUTATIONS[surface](TARGET)
    try:
        obtained = arm_c.resolve(STAGE).permits_read(TARGET)
    except Exception:                                     # noqa: BLE001
        obtained = False
    assert not obtained


# ---------------------------------------------------------------------------
# The comparison itself.
# ---------------------------------------------------------------------------

def test_the_measured_minimum_tamper_sets(tmp_path):
    """The headline cell of the case. A=1, B=2, C=1."""
    assert min(arm_a.EDITS.values()) == 1

    arm_b_min = None
    for label, steps in arm_b.COMBINATIONS.items():
        arm_b.reset()
        for step in steps:
            arm_b.MUTATIONS[step](TARGET)
        try:
            if arm_b.resolve(STAGE).permits_read(TARGET):
                arm_b_min = min(arm_b_min or 99, len(steps))
        except common.AuthorizationError:
            pass
    assert arm_b_min == 2

    arm_c.reset(str(tmp_path / "mts"))
    arm_c.mutate_artifact_binding(TARGET)
    assert arm_c.resolve(STAGE).permits_read(TARGET)


def test_scope_at_minimum_cost_is_not_narrowest_in_arm_c():
    """REFUTES the secondary prediction.

    Arm C was predicted to have the narrowest blast radius. It does - but only
    if you pick the artifact-binding surface. Its *other* one-edit route is
    the skill contract, whose scope is the whole deployment, wider than arm
    B's workflow scope and wider than arm A's subject scope. Reporting the
    narrower one would flatter the arm this laboratory is investigating.
    """
    order = common.SCOPE_ORDER
    cheapest_c = max((arm_c.SCOPES[s] for s in
                      ("artifact binding record", "skill contract")),
                     key=order.index)
    assert cheapest_c == common.SCOPE_DEPLOYMENT
    assert common.wider(cheapest_c, common.SCOPE_WORKFLOW)
    assert common.wider(cheapest_c, common.SCOPE_SUBJECT)


def test_version_pinning_is_not_architecture_specific(tmp_path):
    """The fairness adjudication, made executable.

    The contract gave pinning to all three arms because it is not an
    architectural feature of any of them. The same function pins all three
    arms' records and detects the same mid-run edit in each - so pinning
    equalizes rather than differentiates, and none of it helps against an edit
    made before the run pins.
    """
    from object_model import skills

    records = {
        "A": lambda: arm_a.PERMISSIONS,
        "B": lambda: arm_b.CONNECTIONS,
        "C": lambda: skills.manifest(),
    }
    mutate = {
        "A": lambda: arm_a.mutate_permission_table(TARGET),
        "B": lambda: arm_b.mutate_connection_scope(TARGET),
        "C": lambda: arm_c.mutate_skill_contract(TARGET),
    }

    for arm_label, read in records.items():
        arm_a.reset()
        arm_b.reset()
        arm_c.reset(str(tmp_path / f"pin{arm_label}"))

        pinned = common.digest_of(read())                 # run starts
        mutate[arm_label]()                               # edited mid-run
        with pytest.raises(common.PinMismatch):
            common.verify(pinned, read(), f"arm {arm_label}")
