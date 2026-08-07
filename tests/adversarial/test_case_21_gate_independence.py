"""Case 21 - gate independence.

Cases 19 and 20 both ended on the same sentence: the mechanism is a Level 1
control because a Level 1.5 adversary writes the approval store. This tests the
boundary itself, with a claim kept deliberately small:

    Compromise of the worker's execution boundary cannot modify or invoke the
    approval gate except through its exposed protocol.

Not "secure isolation". Six probes, two arms, and a seventh probe that fails -
which is the result worth keeping.
"""

from __future__ import annotations

import importlib.util
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
CASE_DIR = os.path.join(REPO_ROOT, "cases", "21-gate-independence")

if CASE_DIR not in sys.path:
    sys.path.insert(0, CASE_DIR)


def _load(name: str):
    spec = importlib.util.spec_from_file_location(
        f"case21_{name}", os.path.join(CASE_DIR, f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[f"case21_{name}"] = module
    spec.loader.exec_module(module)
    return module


b = _load("boundary")

PERSISTED = "manipulate the gate's datastore (persisted)"


@pytest.fixture(scope="module")
def probes(tmp_path_factory):
    tmp = str(tmp_path_factory.mktemp("case21"))
    return b.measure(tmp)


# ---------------------------------------------------------------------------
# Arm A - there is no boundary, so every probe lands.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", b.PROBE_NAMES)
def test_every_probe_succeeds_when_the_boundary_is_shared(probes, name):
    """The baseline, and it is unanimous. A gate that is an ordinary object in
    the worker's process is furniture: the attributes are simply there."""
    assert b.get(probes, "A", name).succeeded is True


# ---------------------------------------------------------------------------
# Arm B - the claim, exactly as written and no further.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", b.PROBE_NAMES)
def test_no_in_memory_probe_reaches_the_isolated_gate(probes, name):
    assert b.get(probes, "B", name).succeeded is False


def test_patching_the_module_does_not_reach_the_running_gate(probes):
    """The probe that most looks like it should work. Loading the gate's own
    source and rebinding a function patches *this* process's copy; the gate
    has its own and never consulted ours."""
    probe = b.get(probes, "B", "replace the gate's code")
    assert probe.succeeded is False
    assert "own" in probe.note


def test_the_gate_refuses_a_forged_reviewer_by_name(probes):
    """Assert on the denial reason, not that something failed."""
    probe = b.get(probes, "B", "forge reviewer membership")
    assert probe.succeeded is False
    assert "not a reviewer" in probe.note


def test_unknown_operations_and_extra_fields_are_both_refused(probes):
    """A protocol that honoured fields it did not ask for would be a bypass
    with extra steps."""
    probe = b.get(probes, "B", "bypass the protocol")
    assert probe.succeeded is False
    assert "unknown op" in probe.note
    assert "ignored" in probe.note


def test_the_protocol_does_not_leak_the_credential(probes):
    probe = b.get(probes, "B", "read the gate's credential")
    assert probe.succeeded is False

    gate = b.IsolatedGate()
    try:
        state = gate.state()
        assert state["ok"] is True
        flat = " ".join(str(v) for v in state.values())
        assert "signing" not in flat
    finally:
        gate.close()


def test_the_isolated_gate_still_does_its_job():
    """A boundary that refuses everything is an outage, not a control."""
    gate = b.IsolatedGate()
    try:
        assert gate.approve(b.REVIEWER, b.DIGEST)["ok"] is True
        assert gate.execute(b.DIGEST)["ok"] is True
        assert gate.execute(b.DIGEST)["ok"] is False, "one-use still holds"
    finally:
        gate.close()


# ---------------------------------------------------------------------------
# The probe that fails, and it is the result.
# ---------------------------------------------------------------------------

def test_a_persisted_store_on_a_shared_filesystem_is_still_writable(probes):
    """THE FINDING. Process separation separated the code and not the storage.

    Case 06 measured that isolation leaves ambient authority untouched - same
    uid, same filesystem. This is that finding arriving at the approval plane:
    a gate that persists its approvals to a file the worker can write is
    isolated in memory only, and Level 1.5 still wins.

    If this ever passes, the store has moved outside the worker's reach and
    the case's conclusion needs rewriting - not this assertion.
    """
    probe = b.get(probes, "B", PERSISTED)
    assert probe.succeeded is True
    assert "did not separate storage" in probe.note


def test_the_case_does_not_claim_secure_isolation():
    """A naming guard. The claim is one sentence about one boundary, and the
    repository's history says this is exactly where overclaiming starts."""
    text = open(os.path.join(CASE_DIR, "boundary.py"), encoding="utf-8").read()
    assert "secure isolation" not in text.lower().replace('not "secure isolation"', "")
    assert "exposed protocol" in text
