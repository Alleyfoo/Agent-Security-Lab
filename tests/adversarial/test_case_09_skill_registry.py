"""Case 09 - can the execution plane mint a transformation?

Adversary: **Level 1**, a worker using the interfaces the execution plane
offers, for the control claim. **Level 2** for the residuals.

Central claim under test:

    The execution plane has no operation to create, modify, replace or select
    an unapproved skill definition, and a run is bound to the definitions it
    started with.

Scope, and the case must not exceed it: this covers the skill registry, the
type-level declaration of what a skill may read. It does **not** cover the
artifact map, which case 08 measured as the cheaper of the two surfaces. Case
10 owns that, and nothing here may be read as securing the type-to-key
binding.
"""

from __future__ import annotations

import pytest

from object_model import (
    AuthorizationError, QueueItem, Skill, SkillRegistryError, WorkObject,
    digest_of, pin_versions, reset_registry, resolve, save_object,
)
from object_model import evaluator, skills

TARGET = "artifact.key_material"
GRANTED = "artifact.raw_input"


@pytest.fixture
def run(tmp_path):
    """A pinned run, set up the way the evaluator intends."""
    reset_registry()
    evaluator.reset_workflow()
    obj = WorkObject("obj_812", "orders_table", "ingested",
                     {skills.T_TABLE_PREVIEW: GRANTED,
                      skills.T_KEY_MATERIAL: TARGET})
    save_object(obj, str(tmp_path))
    pins = pin_versions(evaluator.OBJECT_TYPES["orders_table"])
    yield obj, pins
    reset_registry()
    evaluator.reset_workflow()


def _resolve(obj, pins, skill="infer_schema"):
    return resolve(QueueItem(obj.object_id, skill), obj, pins)


def _widened(name: str = "infer_schema") -> Skill:
    s = skills.REGISTRY[name]
    return Skill(s.name, s.version, tuple(s.reads) + (skills.T_KEY_MATERIAL,),
                 s.produces, s.effects)


# ---------------------------------------------------------------------------
# C1 - the execution plane holds a read-only registry.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("operation", [
    pytest.param(lambda s: s.REGISTRY.__setitem__("evil", None), id="create"),
    pytest.param(lambda s: s.REGISTRY.update({"evil": None}), id="update"),
    pytest.param(lambda s: s.REGISTRY.setdefault("evil", None), id="setdefault"),
    pytest.param(lambda s: s.REGISTRY.pop("infer_schema"), id="remove"),
    pytest.param(lambda s: s.REGISTRY.clear(), id="clear"),
])
def test_the_registry_rejects_every_mutation(run, operation):
    with pytest.raises((TypeError, AttributeError)):
        operation(skills)
    assert "evil" not in skills.REGISTRY
    assert "infer_schema" in skills.REGISTRY


def test_there_is_no_skill_mutation_operation_on_the_execution_path():
    """§16: the execution plane must not expose these at all. Absent, not
    denied - a denied operation is still an operation someone can be tricked
    into reaching."""
    for forbidden in ("create_skill", "edit_skill", "publish_skill",
                      "change_skill_permissions", "disable_review"):
        assert not hasattr(skills, forbidden), forbidden
        assert not hasattr(evaluator, forbidden), forbidden


def test_skill_records_are_frozen(run):
    skill = skills.REGISTRY["infer_schema"]
    with pytest.raises(Exception):
        skill.reads = (skills.T_KEY_MATERIAL,)
    assert isinstance(skill.reads, tuple)


def test_a_worker_cannot_widen_a_contract_through_the_interface(run):
    obj, pins = run
    with pytest.raises(TypeError):
        skills.REGISTRY["infer_schema"] = _widened()

    assert not _resolve(obj, pins).permits_read(TARGET)


# ---------------------------------------------------------------------------
# C2 - a run is bound to the versions it started with.
# ---------------------------------------------------------------------------

def test_replacement_between_steps_is_detected(run):
    """The operation §16 warns about, reached around the read-only view."""
    obj, pins = run
    assert _resolve(obj, pins).describe()          # first step is fine

    skills._REGISTRY["infer_schema"] = _widened()

    with pytest.raises(SkillRegistryError) as exc:
        _resolve(obj, pins)
    assert "failed version verification" in str(exc.value)
    assert "replaced after the run started" in str(exc.value)


def test_without_the_pin_the_replacement_is_undetected(run):
    """The baseline, measured rather than assumed - otherwise C2's value is
    an assertion."""
    obj, _ = run
    skills._REGISTRY["infer_schema"] = _widened()

    grant = _resolve(obj, None)
    assert grant.permits_read(TARGET)


def test_a_skill_added_after_run_start_cannot_be_used(run):
    obj, pins = run
    skills._REGISTRY["exfiltrate"] = Skill(
        "exfiltrate", "1.0", (skills.T_KEY_MATERIAL,), "leak")
    evaluator._OBJECT_TYPES["orders_table"] += ("exfiltrate",)
    evaluator._TRANSITIONS[("orders_table", "ingested")] = "exfiltrate"

    with pytest.raises(SkillRegistryError) as exc:
        _resolve(obj, pins, "exfiltrate")
    assert "was not pinned at run start" in str(exc.value)


def test_verify_pins_reports_a_removed_skill_distinctly():
    """The branch exists and says the right thing when it is reached."""
    reset_registry()
    pinned = pin_versions(["infer_schema"])
    del skills._REGISTRY["infer_schema"]

    with pytest.raises(SkillRegistryError) as exc:
        skills.verify_pins(pinned, "infer_schema")
    assert "no longer registered" in str(exc.value)
    reset_registry()


def test_finding_removal_mid_run_is_reported_as_a_selection_failure(run):
    """RECORDED FINDING, not a control.

    Deleting a pinned skill mid-run surfaces through ``validate`` as *no
    approved skill named 'infer_schema'* - the same message a queue item
    naming something that never existed would produce. The distinct incident,
    "the vocabulary changed underneath a running workflow", is reachable in
    ``verify_pins`` but ``validate`` runs first and shadows it.

    An operator cannot tell registry tampering from a malformed queue item.
    Recorded rather than fixed: reordering the checks would degrade the
    selection message, which case 08 relies on, and getting both right is a
    change to the evaluator's error model rather than to this case's claim.
    """
    obj, pins = run
    del skills._REGISTRY["infer_schema"]

    with pytest.raises(AuthorizationError) as exc:
        _resolve(obj, pins)
    assert "no approved skill" in str(exc.value), (
        "if this now reports a registry incident, the error model was fixed - "
        "update case 09's findings and this test"
    )


def test_the_digest_covers_every_declared_field():
    base = Skill("s", "1.0", ("a",), "out", "derive")
    for changed in (Skill("s2", "1.0", ("a",), "out", "derive"),
                    Skill("s", "2.0", ("a",), "out", "derive"),
                    Skill("s", "1.0", ("a", "b"), "out", "derive"),
                    Skill("s", "1.0", ("a",), "other", "derive"),
                    Skill("s", "1.0", ("a",), "out", "read_only")):
        assert digest_of(changed) != digest_of(base)


def test_an_untampered_run_is_unaffected(run):
    """No false positives."""
    obj, pins = run
    grant = _resolve(obj, pins)

    assert grant.read_keys == [GRANTED]
    assert not grant.permits_read(TARGET)


# ---------------------------------------------------------------------------
# Selection. Not mutation at all.
# ---------------------------------------------------------------------------

def test_selecting_an_unregistered_skill_is_refused(run):
    obj, pins = run
    with pytest.raises(AuthorizationError) as exc:
        _resolve(obj, pins, "exfiltrate")
    assert "no approved skill" in str(exc.value)


def test_selecting_a_registered_skill_the_state_does_not_require(run):
    obj, pins = run
    with pytest.raises(AuthorizationError) as exc:
        _resolve(obj, pins, "validate_chain")
    assert "requires 'infer_schema'" in str(exc.value)


# ---------------------------------------------------------------------------
# Residual limitations - executable. These decide what the pin is worth.
# ---------------------------------------------------------------------------

def test_residual_replacement_before_the_run_pins_is_undetected(tmp_path):
    """RESIDUAL. The pin records what was there, not what should have been.

    Case 03's residual in a new place: an integrity value taken over
    already-tampered state certifies the tampering.
    """
    reset_registry()
    evaluator.reset_workflow()
    skills._REGISTRY["infer_schema"] = _widened()

    obj = WorkObject("obj_812", "orders_table", "ingested",
                     {skills.T_TABLE_PREVIEW: GRANTED,
                      skills.T_KEY_MATERIAL: TARGET})
    save_object(obj, str(tmp_path))
    pins = pin_versions(evaluator.OBJECT_TYPES["orders_table"])

    grant = _resolve(obj, pins)
    assert grant.permits_read(TARGET), (
        "if this now fails, an independent account of the approved registry "
        "exists - update case 09's residual-limitation section and this test"
    )
    reset_registry()


def test_residual_updating_the_pin_alongside_the_registry_passes(run):
    """RESIDUAL. Fifth instance of the cross-cutting finding."""
    obj, pins = run
    skills._REGISTRY["infer_schema"] = _widened()
    pins["infer_schema"] = digest_of(skills._REGISTRY["infer_schema"])

    assert _resolve(obj, pins).permits_read(TARGET), (
        "if this now fails, the pin moved outside the adversary's reach - "
        "update case 09's residual-limitation section and this test"
    )


def test_residual_level_2_reaches_the_private_registry(run):
    """RESIDUAL. MappingProxyType is a view, not a freeze."""
    obj, pins = run
    skills._REGISTRY["infer_schema"] = _widened()

    assert skills.REGISTRY["infer_schema"].reads == (
        skills.T_TABLE_PREVIEW, skills.T_KEY_MATERIAL), (
        "the public view reflects the private dict, which is the point"
    )


def test_this_case_does_not_secure_the_artifact_map(run):
    """SCOPE GUARD. Case 09 addresses the registry only.

    The map edit case 08 measured still works with every control in this case
    active. If this ever starts failing, case 10 landed and this test should be
    rewritten to point at it - not deleted.
    """
    obj, pins = run
    obj.artifacts[skills.T_TABLE_PREVIEW] = TARGET

    grant = _resolve(obj, pins)
    assert grant.permits_read(TARGET), (
        "case 09 must not be read as securing the type-to-key binding"
    )
