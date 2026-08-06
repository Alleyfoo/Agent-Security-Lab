"""Case 01 - a scoped view is not an isolation boundary.

Adversary: hostile code executing inside an agent process - ladder **Level 2**.
Unlike case 00, this adversary needs code execution, not merely a hostile agent
implementation.

Central claim under test:

    StoreView constrains reads that go through its interface. It does not
    constrain code that can read the Python object graph, and such reads leave
    no trace in the read log the runner reconciles against the grant.

**This case has no control at Phase 2.** The tests below therefore assert that
the attack SUCCEEDS. They are tripwires: when process isolation lands in Phase
5, they must fail, and that failure is the signal to rewrite this case with its
control section filled in. Do not "fix" them by weakening the assertions.
"""

from __future__ import annotations

import gc
import sys

import pytest

from agent_network_demo.agents import KEY_CLEANED, KEY_RAW_INPUT
from agent_network_demo.artifact_store import ArtifactStore
from agent_network_demo.contracts import ContractError
from agent_network_demo.demo_runner import RunSession

TARGET = KEY_CLEANED

TRIPWIRE = (
    "This asserts an UNFIXED weakness (case 01). If it now fails, process "
    "isolation or an equivalent control has landed - update "
    "cases/01-ungranted-read/README.md and docs/baseline.md L1/L2 instead of "
    "relaxing this test."
)


@pytest.fixture
def loaded_session(data_dir, key_file_path):
    """A session run far enough that ``artifact.cleaned_output`` exists."""
    session = RunSession(data_dir=str(data_dir))
    session.start_run(key_file_path)
    for _ in range(3):  # intake, schema, transform
        session.step()
    assert session.store.has(TARGET)
    yield session
    session.log.close()


@pytest.fixture
def scoped_view(loaded_session):
    """A schema-stage view: read access to raw_input only."""
    return loaded_session.store.view([KEY_RAW_INPUT], "artifact.schema_profile")


# ---------------------------------------------------------------------------
# What the view genuinely enforces (regression guards on B4 and B6).
# ---------------------------------------------------------------------------

def test_sanctioned_read_of_an_ungranted_key_is_denied(scoped_view):
    with pytest.raises(ContractError) as exc:
        scoped_view.get(TARGET)
    assert "denied" in str(exc.value)
    assert KEY_RAW_INPUT in str(exc.value), "the denial should name the grant"


def test_view_is_not_an_existence_oracle(scoped_view):
    """``has()`` must not reveal that an ungranted artifact exists."""
    assert scoped_view.has(KEY_RAW_INPUT) is True
    assert scoped_view.has(TARGET) is False


def test_granted_read_is_recorded(scoped_view):
    scoped_view.get(KEY_RAW_INPUT)
    assert scoped_view.read_keys == [KEY_RAW_INPUT]


# ---------------------------------------------------------------------------
# What it does not enforce. These assert the attack succeeds.
# ---------------------------------------------------------------------------

def test_bypass_via_private_attribute_succeeds(scoped_view):
    artifact = scoped_view._store.get(TARGET)
    assert artifact["row_count"] == 20, TRIPWIRE


def test_bypass_via_call_stack_succeeds(loaded_session, scoped_view):
    """Reaches the store without touching the view at all."""
    found = None
    frame = sys._getframe()
    while frame is not None and found is None:
        for value in frame.f_locals.values():
            if isinstance(value, ArtifactStore):
                found = value
                break
            store = getattr(value, "store", None)
            if isinstance(store, ArtifactStore):
                found = store
                break
        frame = frame.f_back

    assert found is not None, TRIPWIRE
    assert found.get(TARGET)["row_count"] == 20, TRIPWIRE


def test_bypass_via_garbage_collector_succeeds(loaded_session, scoped_view):
    """Reaches a store with no reference path from the agent."""
    stores = [o for o in gc.get_objects()
              if isinstance(o, ArtifactStore) and o.has(TARGET)]
    assert stores, TRIPWIRE
    assert stores[0].get(TARGET)["row_count"] == 20, TRIPWIRE


@pytest.mark.parametrize("bypass", [
    pytest.param(lambda view: view._store.get(TARGET), id="private_attribute"),
    pytest.param(
        lambda view: [o for o in gc.get_objects()
                      if isinstance(o, ArtifactStore) and o.has(TARGET)][0].get(TARGET),
        id="garbage_collector"),
])
def test_bypassed_reads_leave_no_trace_in_the_read_log(scoped_view, bypass):
    """Baseline finding L2 - the asymmetry that makes this case matter.

    The runner reconciles ``view.read_keys`` against the grant
    (demo_runner.py). A bypassed read is absent from that log, so it passes
    reconciliation by never appearing.
    """
    bypass(scoped_view)
    assert scoped_view.read_keys == [], TRIPWIRE


def test_runner_reconciliation_accepts_a_run_containing_a_bypassed_read(
        scoped_view):
    """The bypass is not merely unlogged - it is affirmatively undetected."""
    scoped_view._store.get(TARGET)
    granted = [KEY_RAW_INPUT]
    assert set(scoped_view.read_keys).issubset(granted), TRIPWIRE


# ---------------------------------------------------------------------------
# Why the obvious patch is refused.
# ---------------------------------------------------------------------------

class ClosureStoreView:
    """A view holding no store attribute - only closures. Not shipped."""

    def __init__(self, store, read_keys, write_key=""):
        grants = set(read_keys)
        self._read_log = []

        def _get(key):
            if key not in grants:
                raise PermissionError(f"read of {key!r} denied")
            self._read_log.append(key)
            return store.get(key)

        self.get = _get

    @property
    def read_keys(self):
        return list(self._read_log)


def test_closure_view_closes_only_the_private_attribute_path(loaded_session):
    """Removing ``_store`` closes exactly one path and no others.

    This is why the patch is documented and refused rather than shipped: it
    would let the repository claim a boundary it does not have, which the
    charter classifies as cosmetic security.
    """
    view = ClosureStoreView(loaded_session.store, [KEY_RAW_INPUT])

    with pytest.raises(PermissionError):
        view.get(TARGET)
    with pytest.raises(AttributeError):
        view._store.get(TARGET)

    # ... and the other two paths are entirely unaffected.
    stores = [o for o in gc.get_objects()
              if isinstance(o, ArtifactStore) and o.has(TARGET)]
    assert stores, TRIPWIRE
    assert stores[0].get(TARGET)["row_count"] == 20, TRIPWIRE
    assert view.read_keys == []
