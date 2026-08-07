"""Case 11 - contain a contradiction the moment it appears.

Case 10 left `conflicts_for()` reporting contradictions that nothing acted on:
an appended rebinding was inert, the object carried on working, and the
contradiction sat in the record until something looked. This case closes
exactly that and nothing else. No new surfaces, no new records, no new arms -
the step lifecycle checks the record it already has.

Central claim under test:

    An object whose production record contradicts itself runs no further step,
    and the refusal survives a retry, a reload and a resume without anything
    having to remember it.

Not claimed: that the surface is closed. The one attack that works - see case
10 - destroys the evidence, and a containment that reads the evidence cannot
see it. That blind spot is measured here, not asserted away.

The cost is measured too, and it is real: an append that was harmless in case
10 is now a permanent stop.
"""

from __future__ import annotations

import json
import os

import pytest

from object_model import (
    ObjectContainedError, QueueItem, WorkObject, load_object, pin_versions,
    reset_registry, save_object,
)
from object_model import evaluator, skills
from object_model.ledger import (
    LedgerIntegrityError, ProductionLedger, ProductionRecord,
)

OBJ = "obj_812"
OTHER = "obj_900"
TARGET = "artifact.key_material"
SOURCE = "artifact.raw_input"
SEED = {skills.T_TABLE_PREVIEW: SOURCE, skills.T_KEY_MATERIAL: TARGET}


@pytest.fixture(autouse=True)
def _fresh():
    reset_registry()
    evaluator.reset_workflow()
    yield
    reset_registry()
    evaluator.reset_workflow()


def _arm(tmp_path, object_id: str = OBJ):
    store = str(tmp_path)
    obj = WorkObject(object_id, "orders_table", "ingested", {})
    ledger = ProductionLedger(path=os.path.join(store, "ledger.jsonl"))
    ledger.seed(object_id, SEED)
    save_object(obj, store)
    pins = pin_versions(evaluator.OBJECT_TYPES["orders_table"])
    return obj, ledger, pins, store


def _step(obj, store, pins, ledger, contain=True):
    item = QueueItem(obj.object_id, evaluator.required_skill(obj))
    return evaluator.run_step(obj, item, store, pins, ledger, contain)


def _forge(ledger, obj, artifact_type=skills.T_TABLE_PREVIEW, key=TARGET,
           object_id=OBJ):
    """Case 10's attack A-append: reach past the API and add a record that
    contradicts one already there. Inert for the derivation - that is the
    whole point of case 10 - and the starting position for this case."""
    ledger._records.append(
        ProductionRecord(object_id, obj.state, "attacker", artifact_type, key))


def _forge_on_disk(store, at_state="profiled",
                   artifact_type=skills.T_TABLE_PREVIEW, key=TARGET,
                   object_id=OBJ):
    """Case 10's attack C: the same forgery from an attacker with file access.
    Reaching `_records` tampers with this process; writing the file tampers
    with every process that loads it afterwards."""
    with open(os.path.join(store, "ledger.jsonl"), "a", encoding="utf-8") as fh:
        fh.write(json.dumps({
            "object_id": object_id, "at_state": at_state, "skill": "attacker",
            "artifact_type": artifact_type, "key": key}, sort_keys=True) + "\n")


# ---------------------------------------------------------------------------
# A - the unsafe result. Without this the control's value is an assertion.
# ---------------------------------------------------------------------------

def test_baseline_the_object_keeps_working_on_a_contradicted_record(tmp_path):
    """Case 10's endpoint, reproduced: the contradiction changes nothing and
    nothing stops the object."""
    obj, ledger, pins, store = _arm(tmp_path)
    _step(obj, store, pins, ledger)                      # infer_schema
    _forge(ledger, obj)
    assert ledger.conflicts_for(OBJ)

    steps = evaluator.run_to_completion(obj, store, pins, ledger,
                                        contain=False)

    assert [s.skill for s in steps] == ["clean_table", "validate_chain"]
    assert obj.state == evaluator.TERMINAL_STATE
    assert ledger.conflicts_for(OBJ), "and the contradiction is still there"


def test_the_contained_object_runs_no_further_step(tmp_path):
    obj, ledger, pins, store = _arm(tmp_path)
    _step(obj, store, pins, ledger)                      # infer_schema
    state_before = obj.state
    _forge(ledger, obj)
    records_before = len(ledger.records_for(OBJ))

    with pytest.raises(ObjectContainedError) as exc:
        _step(obj, store, pins, ledger)                  # clean_table

    message = str(exc.value)
    assert OBJ in message
    assert "table_preview" in message, "the refusal names the contradiction"
    assert SOURCE in message and TARGET in message, "and both bindings"
    assert obj.state == state_before, "the object did not advance"
    assert len(ledger.records_for(OBJ)) == records_before, "and produced nothing"
    assert obj.state != evaluator.TERMINAL_STATE


def test_containment_precedes_authorization(tmp_path):
    """A contained object never resolves a grant at all.

    Ordering is the claim: the check runs before validate() and before any
    grant is derived, so the lifecycle does not compute authority from a
    record it has already found untrustworthy.
    """
    obj, ledger, pins, store = _arm(tmp_path)
    _step(obj, store, pins, ledger)
    _forge(ledger, obj)

    # A queue item naming the wrong skill would normally fail validation with
    # AuthorizationError. Containment must win, because it is checked first.
    bogus = QueueItem(OBJ, "validate_chain")             # not required yet
    with pytest.raises(ObjectContainedError):
        evaluator.run_step(obj, bogus, store, pins, ledger)


# ---------------------------------------------------------------------------
# B - quarantine with no new state. The record is its own marker.
# ---------------------------------------------------------------------------

def test_containment_holds_on_retry(tmp_path):
    obj, ledger, pins, store = _arm(tmp_path)
    _step(obj, store, pins, ledger)
    _forge(ledger, obj)

    for _ in range(3):
        with pytest.raises(ObjectContainedError):
            _step(obj, store, pins, ledger)
    assert obj.state != evaluator.TERMINAL_STATE


def test_containment_survives_reload_and_resume_without_a_flag(tmp_path):
    """The point of doing this with no new record.

    Case 02 needed a quarantine flag because the corruption it found lived in
    data the flag was separate from. Here the contradiction is *in* the
    persisted record, so a reloaded ledger re-detects it and a resumed object
    is contained again - nothing had to remember the incident.
    """
    obj, ledger, pins, store = _arm(tmp_path)
    _step(obj, store, pins, ledger)
    _forge_on_disk(store)

    reloaded_ledger = ProductionLedger.load(os.path.join(store, "ledger.jsonl"))
    resumed = load_object(OBJ, store)
    resumed.state = "profiled"

    with pytest.raises(ObjectContainedError):
        _step(resumed, store, pins, reloaded_ledger)


# ---------------------------------------------------------------------------
# C - the blind spot. The one attack that works is the one this cannot see.
# ---------------------------------------------------------------------------

def test_an_overwritten_record_leaves_nothing_to_contain(tmp_path):
    """RESIDUAL, and the honest limit of the whole control.

    Case 10 measured overwriting as the only route that still obtains the
    capability, and recorded that it destroys the evidence rather than adding
    to it. Containment reads that evidence. So the cheap attack is now stopped
    and the working attack is untouched - it does not even trip the check.
    """
    obj, ledger, pins, store = _arm(tmp_path)
    _step(obj, store, pins, ledger)

    for index, entry in enumerate(ledger._records):
        if entry.artifact_type == skills.T_TABLE_PREVIEW:
            ledger._records[index] = ProductionRecord(
                OBJ, entry.at_state, entry.skill, entry.artifact_type, TARGET)
            break

    assert ledger.conflicts_for(OBJ) == [], "no contradiction to find"
    evaluator.check_containment(obj, ledger)             # does not raise

    record = _step(obj, store, pins, ledger)             # clean_table proceeds
    assert record.grant.permits_read(TARGET), (
        "if this now fails, the overwrite route closed - update case 10's "
        "residual, case 11's blind-spot section and this test"
    )
    evaluator.run_to_completion(obj, store, pins, ledger)
    assert obj.state == evaluator.TERMINAL_STATE, (
        "the object completes normally: containment never fired"
    )


# ---------------------------------------------------------------------------
# D - what it costs. Measured, not assumed either way.
# ---------------------------------------------------------------------------

def test_cost_one_forged_append_is_now_a_permanent_denial_of_service(tmp_path):
    """The trade, stated as a measurement.

    The same single appended line that case 10 measured as *inert* now stops
    the object for good. Case 10 already found a denial of service in the
    produced-once invariant, for a type not yet produced; containment widens
    it to any type in the record, and makes it the designed response rather
    than an accident.
    """
    obj, ledger, pins, store = _arm(tmp_path)
    _step(obj, store, pins, ledger)
    _forge_on_disk(store)
    ledger = ProductionLedger.load(os.path.join(store, "ledger.jsonl"))

    with pytest.raises(ObjectContainedError):
        evaluator.run_to_completion(obj, store, pins, ledger)
    assert obj.state == "profiled", "stopped where the forgery found it"

    # And there is no route back through the lifecycle: the record is
    # persisted, so this object is finished until an operator intervenes
    # outside the model.
    reloaded_ledger = ProductionLedger.load(os.path.join(store, "ledger.jsonl"))
    resumed = load_object(OBJ, store)
    with pytest.raises(ObjectContainedError):
        evaluator.run_to_completion(resumed, store, pins, reloaded_ledger)


def test_cost_a_conflict_on_a_type_no_step_reads_still_stops_the_object(tmp_path):
    """Object-scoped by choice. key_material is not read by any skill in this
    workflow, and a contradiction about it still contains the object - so the
    denial-of-service surface is every type in the record, not only the ones
    the remaining steps need."""
    obj, ledger, pins, store = _arm(tmp_path)
    _step(obj, store, pins, ledger)
    _forge(ledger, obj, artifact_type=skills.T_KEY_MATERIAL, key=SOURCE)

    with pytest.raises(ObjectContainedError) as exc:
        _step(obj, store, pins, ledger)
    assert "key_material" in str(exc.value)


def test_containment_does_not_spread_to_other_objects(tmp_path):
    """Blast radius: one object, in a ledger that holds several."""
    obj, ledger, pins, store = _arm(tmp_path)
    other = WorkObject(OTHER, "orders_table", "ingested", {})
    ledger.seed(OTHER, SEED)
    save_object(other, store)

    _step(obj, store, pins, ledger)
    _forge(ledger, obj)

    with pytest.raises(ObjectContainedError):
        _step(obj, store, pins, ledger)

    evaluator.run_to_completion(other, store, pins, ledger)
    assert other.state == evaluator.TERMINAL_STATE


# ---------------------------------------------------------------------------
# E - no false positives, and what the stored map cannot have.
# ---------------------------------------------------------------------------

def test_an_untampered_run_is_unaffected(tmp_path):
    obj, ledger, pins, store = _arm(tmp_path)
    steps = evaluator.run_to_completion(obj, store, pins, ledger)

    assert [s.skill for s in steps] == ["infer_schema", "clean_table",
                                        "validate_chain"]
    assert obj.state == evaluator.TERMINAL_STATE
    assert ledger.conflicts_for(OBJ) == []


def test_containment_changes_nothing_on_a_clean_run(tmp_path):
    """Parity: contained and uncontained resolve identical grants when there
    is no contradiction, so the delta this case measures is the containment
    and not a side effect of it."""
    a_obj, a_ledger, a_pins, a_store = _arm(tmp_path / "a")
    b_obj, b_ledger, b_pins, b_store = _arm(tmp_path / "b")

    contained = evaluator.run_to_completion(a_obj, a_store, a_pins, a_ledger)
    uncontained = evaluator.run_to_completion(b_obj, b_store, b_pins, b_ledger,
                                              contain=False)

    assert [s.skill for s in contained] == [s.skill for s in uncontained]
    for x, y in zip(contained, uncontained):
        assert sorted(x.grant.read_keys) == sorted(y.grant.read_keys)
        assert x.grant.write_key == y.grant.write_key


def test_the_stored_map_cannot_have_this_control(tmp_path):
    """The comparison finding, made executable.

    Containment needs a contradiction to find. The stored map keeps none: a
    write is total, the previous binding is gone, and the object is left
    holding a map that is internally consistent and wrong. The derived model
    is not merely better protected here - it is the only one of the two where
    this control can exist at all.
    """
    store = str(tmp_path)
    obj = WorkObject(OBJ, "orders_table", "ingested", {})
    obj.artifacts.update(SEED)
    save_object(obj, store)
    pins = pin_versions(evaluator.OBJECT_TYPES["orders_table"])

    _step(obj, store, pins, None)                        # infer_schema
    obj.artifacts[skills.T_TABLE_PREVIEW] = TARGET       # total, silent
    save_object(obj, store)

    assert list(obj.artifacts.values()).count(SOURCE) == 0, "nothing survives"
    evaluator.check_containment(obj, None)               # nothing to read
    record = _step(obj, store, pins, None)               # and it runs on
    assert record.grant.permits_read(TARGET)
    assert obj.state != "profiled"


# ---------------------------------------------------------------------------
# Scope guards. Neither neighbouring case's measurement moved.
# ---------------------------------------------------------------------------

def test_case_10s_derivation_is_unchanged(tmp_path):
    """This case adds a response, not a derivation. An appended rebinding is
    still inert where case 10 measured it - at derive_grant, which has no
    containment and must not grow one, or case 10's published table changes."""
    obj, ledger, pins, store = _arm(tmp_path)
    _step(obj, store, pins, ledger)
    _forge(ledger, obj)

    grant = evaluator.derive_grant(obj, "clean_table", pins, ledger)
    assert not grant.permits_read(TARGET)
    assert grant.permits_read(SOURCE), "first production still wins"


def test_case_10s_produced_once_refusal_is_still_the_ledgers_own(tmp_path):
    """Pre-seeding a type that has *not* been produced is not a contradiction,
    so containment does not fire and the failure is still case 10's: the
    ledger refusing to record. Two incidents, two classes, one hierarchy."""
    obj, ledger, pins, store = _arm(tmp_path)
    _step(obj, store, pins, ledger)
    _forge(ledger, obj, artifact_type=skills.T_CLEANED_OUTPUT)

    assert ledger.conflicts_for(OBJ) == []
    with pytest.raises(LedgerIntegrityError) as exc:
        _step(obj, store, pins, ledger)                  # clean_table
    assert not isinstance(exc.value, ObjectContainedError)
    assert "cleaned_output" in str(exc.value)


def test_this_case_does_not_secure_the_skill_registry(tmp_path):
    """Case 09's half of the trust root is untouched, asserted from this side
    as case 10 asserts it from its own."""
    obj, ledger, pins, store = _arm(tmp_path)
    with pytest.raises(TypeError):
        skills.REGISTRY["infer_schema"] = None
    _step(obj, store, pins, ledger)
    assert evaluator.artifact_map(obj, ledger)[skills.T_SCHEMA_PROFILE]
