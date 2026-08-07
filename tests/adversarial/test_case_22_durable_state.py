"""Case 22 - durable-state independence.

Case 21 moved the gate's code and left its persisted authority on a filesystem
the worker could write. This tests the part that did not move, and attacks
deletion as hard as insertion.

    Compromise of the worker boundary cannot create, modify or DELETE durable
    gate authority except through the gate's exposed protocol.

The finding is that moving the store is necessary and not sufficient: a
protocol that can forget is a protocol that can forge.
"""

from __future__ import annotations

import importlib.util
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
CASE_DIR = os.path.join(REPO_ROOT, "cases", "22-durable-state")

if CASE_DIR not in sys.path:
    sys.path.insert(0, CASE_DIR)


def _load(name: str):
    spec = importlib.util.spec_from_file_location(
        f"case22_{name}", os.path.join(CASE_DIR, f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[f"case22_{name}"] = module
    spec.loader.exec_module(module)
    return module


s = _load("store")


@pytest.fixture
def results(tmp_path):
    return s.measure(str(tmp_path))


# ---------------------------------------------------------------------------
# D0 - case 21's residual, measured.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("attack", [
    "forge an approval", "resurrect a spent approval",
    "destroy the durable record"])
def test_a_writable_store_loses_everything(results, attack):
    assert s.get(results, s.D0, attack).succeeded is True


def test_deleting_a_consumption_record_resurrects_a_spent_approval(results):
    """THE ATTACK CASE 21 DID NOT RUN, and the reason deletion matters.

    After cases 19 and 20 the store holds security state: the consumption
    record is what makes a spent approval spent. Remove it and one legitimate
    review authorises a second execution - and neither case 19 nor case 20
    detects it, because both trusted the record.
    """
    probe = s.get(results, s.D0, "resurrect a spent approval")
    assert probe.succeeded is True
    assert "executed a second time" in probe.note


# ---------------------------------------------------------------------------
# D1 - the store behind the protocol.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("attack", list(s.ATTACK_NAMES))
def test_the_protocol_only_store_refuses_everything(results, attack):
    assert s.get(results, s.D1, attack).succeeded is False


def test_d1_refuses_by_naming_the_reason(results):
    for attack in ("forge an approval", "resurrect via maintenance"):
        note = s.get(results, s.D1, attack).note
        assert "REFUSED" in note or "no protocol operation" in note


# ---------------------------------------------------------------------------
# D2 - the finding.
# ---------------------------------------------------------------------------

def test_one_maintenance_operation_reopens_the_whole_thing(results):
    """THE FINDING. Moving the store behind a protocol moves the attack to the
    protocol's vocabulary.

    D2 differs from D1 by a single ordinary operation - the kind every
    persistent store eventually grows - and it drops the consumption records,
    so the approval is live again.
    """
    assert s.get(results, s.D2, "forge an approval").succeeded is False
    assert s.get(results, s.D2, "resurrect via maintenance").succeeded is True


def test_d2_still_refuses_direct_insertion(results):
    """The maintenance hole is not a general collapse - insertion and
    destruction are still refused, which is why it is easy to miss."""
    assert s.get(results, s.D2, "forge an approval").succeeded is False
    assert s.get(results, s.D2, "destroy the durable record").succeeded is False


def test_the_only_difference_between_d1_and_d2_is_one_operation():
    assert s.D1.worker_can_write_the_file == s.D2.worker_can_write_the_file
    assert s.D1.offers_maintenance is False
    assert s.D2.offers_maintenance is True


# ---------------------------------------------------------------------------
# The store still works.
# ---------------------------------------------------------------------------

def test_the_gate_still_does_its_job_in_every_arm(tmp_path):
    """A store nobody can write is not a control if the gate cannot record an
    approval either."""
    for arm in s.ARMS:
        store = s.DurableStore(str(tmp_path / f"ok-{arm.name.split()[0]}.jsonl"))
        store.load()
        gate = s.Gate(store, arm)
        assert gate.approve(s.REVIEWER, s.DIGEST)["ok"] is True
        assert gate.execute(s.DIGEST)["ok"] is True
        with pytest.raises(s.Refused):
            gate.execute(s.DIGEST)


def test_a_non_reviewer_is_refused_in_every_arm(tmp_path):
    for arm in s.ARMS:
        store = s.DurableStore(str(tmp_path / f"nr-{arm.name.split()[0]}.jsonl"))
        store.load()
        gate = s.Gate(store, arm)
        with pytest.raises(s.Refused):
            gate.approve(s.WORKER, s.DIGEST)


# ---------------------------------------------------------------------------
# Scope.
# ---------------------------------------------------------------------------

def test_the_case_states_what_is_modelled_rather_than_enforced():
    """D1/D2 model the store being unreachable; this platform cannot enforce
    it with separate OS users. Recorded in the module, exactly as case 12's
    arm A recorded that it was not Unix."""
    text = open(os.path.join(CASE_DIR, "store.py"), encoding="utf-8").read()
    assert "modelled" in text and "measured" in text
    assert "cannot enforce" in text
