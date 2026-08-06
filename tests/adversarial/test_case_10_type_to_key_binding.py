"""Case 10 - the type-to-key binding.

Case 08 measured the artifact map as the cheapest authority surface in the
object model. Case 09 left it alone on purpose. This case attacks it against a
workflow that actually maintains it, and compares storing the binding with
deriving it from an append-only record of what completed steps produced.

Central claim under test:

    Rebinding a type that has already been produced is refused through the
    interface, inert if appended past it, and visible as a conflict
    afterwards.

Not claimed: that the surface is closed. Overwriting a production record still
works, at the same cost as writing the stored map.
"""

from __future__ import annotations

import json
import os

import pytest

from object_model import (
    QueueItem, WorkObject, load_object, pin_versions, reset_registry,
    save_object,
)
from object_model import evaluator, skills
from object_model.ledger import (
    LedgerIntegrityError, ProductionLedger, ProductionRecord,
)

OBJ = "obj_812"
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


def _arm(tmp_path, derived: bool):
    store = str(tmp_path)
    obj = WorkObject(OBJ, "orders_table", "ingested", {})
    ledger = (ProductionLedger(path=os.path.join(store, "ledger.jsonl"))
              if derived else None)
    if ledger is not None:
        ledger.seed(OBJ, SEED)
    else:
        obj.artifacts.update(SEED)
    save_object(obj, store)
    pins = pin_versions(evaluator.OBJECT_TYPES["orders_table"])
    return obj, ledger, pins, store


def _step(obj, store, pins, ledger):
    item = QueueItem(obj.object_id, evaluator.required_skill(obj))
    return evaluator.run_step(obj, item, store, pins, ledger)


def _grant_for(obj, skill, pins, ledger):
    return evaluator.derive_grant(obj, skill, pins, ledger)


# ---------------------------------------------------------------------------
# Map maintenance. Without this the case measures nothing.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("derived", [False, True], ids=["stored", "derived"])
def test_the_workflow_actually_writes_the_map(tmp_path, derived):
    obj, ledger, pins, store = _arm(tmp_path, derived)
    before = evaluator.artifact_map(obj, ledger)
    assert skills.T_SCHEMA_PROFILE not in before

    _step(obj, store, pins, ledger)

    after = evaluator.artifact_map(obj, ledger)
    assert after[skills.T_SCHEMA_PROFILE] == "artifact.schema_profile"


def test_both_arms_resolve_identically_untampered(tmp_path):
    """Parity is the precondition for the comparison."""
    stored_obj, _, stored_pins, stored_store = _arm(tmp_path / "a", False)
    derived_obj, ledger, derived_pins, derived_store = _arm(tmp_path / "b", True)

    stored = evaluator.run_to_completion(stored_obj, stored_store, stored_pins)
    derived = evaluator.run_to_completion(derived_obj, derived_store,
                                          derived_pins, ledger)

    assert [s.skill for s in stored] == [s.skill for s in derived]
    for a, b in zip(stored, derived):
        assert sorted(a.grant.read_keys) == sorted(b.grant.read_keys)
        assert a.grant.write_key == b.grant.write_key
    assert stored_obj.state == derived_obj.state == evaluator.TERMINAL_STATE


# ---------------------------------------------------------------------------
# A - rebinding an existing binding.
# ---------------------------------------------------------------------------

def test_stored_map_rebinding_succeeds_silently(tmp_path):
    """The baseline. Without it the control's value is an assertion."""
    obj, ledger, pins, store = _arm(tmp_path, derived=False)
    _step(obj, store, pins, ledger)

    obj.artifacts[skills.T_TABLE_PREVIEW] = TARGET
    save_object(obj, store)

    assert _grant_for(obj, "clean_table", pins, ledger).permits_read(TARGET)


def test_derived_map_refuses_rebinding_through_the_api(tmp_path):
    obj, ledger, pins, store = _arm(tmp_path, derived=True)
    _step(obj, store, pins, ledger)

    with pytest.raises(LedgerIntegrityError) as exc:
        ledger.record(OBJ, obj.state, "attacker", skills.T_TABLE_PREVIEW, TARGET)
    assert "was already produced" in str(exc.value)
    assert not _grant_for(obj, "clean_table", pins, ledger).permits_read(TARGET)


def test_derived_map_makes_an_appended_rebinding_inert(tmp_path):
    """Level 2 append. First production wins, so the forged record does
    nothing - and the contradiction stays in the record."""
    obj, ledger, pins, store = _arm(tmp_path, derived=True)
    _step(obj, store, pins, ledger)

    ledger._records.append(
        ProductionRecord(OBJ, obj.state, "attacker", skills.T_TABLE_PREVIEW,
                         TARGET))

    grant = _grant_for(obj, "clean_table", pins, ledger)
    assert not grant.permits_read(TARGET)
    assert grant.permits_read(SOURCE), "the legitimate binding still wins"
    assert ledger.conflicts_for(OBJ), "the contradiction must remain visible"


def test_derived_map_overwriting_the_record_still_works(tmp_path):
    """RESIDUAL. The surface is not closed - it costs a different edit."""
    obj, ledger, pins, store = _arm(tmp_path, derived=True)
    _step(obj, store, pins, ledger)

    for index, entry in enumerate(ledger._records):
        if entry.artifact_type == skills.T_TABLE_PREVIEW:
            ledger._records[index] = ProductionRecord(
                OBJ, entry.at_state, entry.skill, entry.artifact_type, TARGET)
            break

    assert _grant_for(obj, "clean_table", pins, ledger).permits_read(TARGET), (
        "if this now fails, the ledger became tamper-evident - update case "
        "10's residual-limitation section and this test"
    )
    assert not ledger.conflicts_for(OBJ), "overwriting destroys the evidence"


# ---------------------------------------------------------------------------
# B - pre-seeding, and the liability it exposed.
# ---------------------------------------------------------------------------

def test_stored_map_preseeding_is_overwritten_by_the_producer(tmp_path):
    obj, ledger, pins, store = _arm(tmp_path, derived=False)
    _step(obj, store, pins, ledger)

    obj.artifacts[skills.T_CLEANED_OUTPUT] = TARGET
    save_object(obj, store)
    _step(obj, store, pins, ledger)                      # clean_table

    assert obj.artifacts[skills.T_CLEANED_OUTPUT] == "artifact.cleaned_output"
    assert not _grant_for(obj, "validate_chain", pins, ledger).permits_read(TARGET)


def test_finding_preseeding_denies_service_in_the_derived_arm(tmp_path):
    """NEW FINDING, not predicted by the design.

    The produced-once invariant that makes rebinding hard also means one forged
    append for a type that has not been produced yet permanently prevents its
    legitimate producer from recording. The object cannot complete. The stored
    map has no equivalent weakness.

    A control that trades silent corruption for loud unavailability may be the
    right trade; it is a trade, and it is recorded as one.
    """
    obj, ledger, pins, store = _arm(tmp_path, derived=True)
    _step(obj, store, pins, ledger)

    ledger._records.append(
        ProductionRecord(OBJ, obj.state, "attacker", skills.T_CLEANED_OUTPUT,
                         TARGET))

    with pytest.raises(LedgerIntegrityError) as exc:
        _step(obj, store, pins, ledger)                  # clean_table
    assert "cleaned_output" in str(exc.value)
    assert obj.state != evaluator.TERMINAL_STATE


# ---------------------------------------------------------------------------
# C - surviving resume, the map's worst property per case 08.
# ---------------------------------------------------------------------------

def test_stored_map_tampering_survives_resume(tmp_path):
    obj, ledger, pins, store = _arm(tmp_path, derived=False)
    evaluator.run_to_completion(obj, store, pins, ledger)

    obj.artifacts[skills.T_TABLE_PREVIEW] = TARGET
    save_object(obj, store)

    resumed = load_object(OBJ, store)
    resumed.state = "profiled"
    assert _grant_for(resumed, "clean_table", pins, None).permits_read(TARGET)


def test_derived_map_tampering_is_inert_across_resume(tmp_path):
    """Reloaded from the JSONL file, conflicts and all, so this is a property
    of the record rather than of in-memory state."""
    obj, ledger, pins, store = _arm(tmp_path, derived=True)
    evaluator.run_to_completion(obj, store, pins, ledger)

    path = os.path.join(store, "ledger.jsonl")
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps({
            "object_id": OBJ, "at_state": "profiled", "skill": "attacker",
            "artifact_type": skills.T_TABLE_PREVIEW, "key": TARGET},
            sort_keys=True) + "\n")

    reloaded_ledger = ProductionLedger.load(path)
    resumed = load_object(OBJ, store)
    resumed.state = "profiled"

    grant = _grant_for(resumed, "clean_table", pins, reloaded_ledger)
    assert not grant.permits_read(TARGET)
    assert reloaded_ledger.conflicts_for(OBJ)


# ---------------------------------------------------------------------------
# Properties of the ledger itself.
# ---------------------------------------------------------------------------

def test_an_empty_ledger_is_truthy():
    """__len__ without __bool__ made a fresh ledger falsy, and the first run of
    this case's harness silently measured the stored arm twice."""
    assert bool(ProductionLedger()) is True
    assert len(ProductionLedger()) == 0


def test_first_production_wins():
    ledger = ProductionLedger()
    ledger.record(OBJ, "s", "intake", skills.T_TABLE_PREVIEW, SOURCE)
    ledger._records.append(
        ProductionRecord(OBJ, "s", "attacker", skills.T_TABLE_PREVIEW, TARGET))

    assert ledger.map_for(OBJ)[skills.T_TABLE_PREVIEW] == SOURCE


def test_records_are_scoped_per_object():
    ledger = ProductionLedger()
    ledger.record("a", "s", "intake", skills.T_TABLE_PREVIEW, SOURCE)
    ledger.record("b", "s", "intake", skills.T_TABLE_PREVIEW, TARGET)

    assert ledger.map_for("a")[skills.T_TABLE_PREVIEW] == SOURCE
    assert ledger.map_for("b")[skills.T_TABLE_PREVIEW] == TARGET
    assert ledger.conflicts_for("a") == []


def test_case_09s_registry_controls_still_hold_here(tmp_path):
    """The two halves of the trust root are independent, and both are now
    measured. Neither case's control substitutes for the other's."""
    obj, ledger, pins, store = _arm(tmp_path, derived=True)

    with pytest.raises(TypeError):
        skills.REGISTRY["infer_schema"] = None

    _step(obj, store, pins, ledger)
    assert evaluator.artifact_map(obj, ledger)[skills.T_SCHEMA_PROFILE]
