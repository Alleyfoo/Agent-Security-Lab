"""Case 02 - in-place mutation of a registered artifact.

Adversary: hostile code inside an agent - ladder **Level 2**. In-place mutation
has no Level 1 path: reads return deep copies, writes deep-copy on the way in,
and rebinding a key with different content raises DuplicateKeyError. Reaching
``_artifacts`` is required, and that is a private-attribute reach-around.

Central claim under test:

    Unauthorized in-place mutation of registered artifacts is detected before
    the workflow accepts or consumes the altered state.

Result vocabulary: baseline ``undetected`` -> controlled
``detected_after_occurrence``. Not prevention - the mutation happens, and the
control observes it afterwards.
"""

from __future__ import annotations

import pytest

from agent_network_demo.agents import (
    KEY_CLEANED, KEY_RAW_INPUT, KEY_SCHEMA, SchemaAgent, ValidationAgent,
)
from agent_network_demo.artifact_store import (
    ArtifactIntegrityError, ArtifactStore, compute_source_hash,
)
from agent_network_demo.demo_runner import RunSession

FORGED_TOTAL = "999999.00"


def _tamper(store: ArtifactStore, key: str = KEY_RAW_INPUT) -> None:
    """Edit one cell in place. No new key, no row-count change, no column
    change - so every existing structural check still passes."""
    store._artifacts[key]["rows_data"][0]["Total"] = FORGED_TOTAL


class TamperingSchemaAgent(SchemaAgent):
    """Does its real job, then rewrites a cell of an artifact it only reads."""

    def run(self, envelope, view, log):
        result = super().run(envelope, view, log)
        _tamper(view._store)
        return result


class TamperingValidationAgent(ValidationAgent):
    """Mutates an artifact at the last stage, which nothing reads afterwards.

    Defeats a read-boundary check on its own; only the post-step sweep sees it.
    """

    def run(self, envelope, view, log):
        result = super().run(envelope, view, log)
        view._store._artifacts[KEY_SCHEMA]["row_count"] = 9999
        return result


@pytest.fixture
def session(data_dir, key_file_path):
    s = RunSession(data_dir=str(data_dir))
    s.start_run(key_file_path)
    yield s
    if s.log is not None:
        s.log.close()


# ---------------------------------------------------------------------------
# Why the baseline missed it.
# ---------------------------------------------------------------------------

def test_baseline_diff_does_not_see_in_place_mutation(session):
    """The runner's new-key diff compares key *sets*. A mutation adds no key,
    so it contributes nothing to the comparison - structurally, not by
    oversight."""
    session.step()                                  # intake
    keys_before = set(session.store.keys())

    _tamper(session.store)

    keys_after = set(session.store.keys())
    assert keys_after == keys_before, (
        "the mutation must not change the key set - that is the whole point"
    )


def test_mutation_breaks_the_hash_that_was_never_checked(session):
    """The detection primitive existed at the baseline; nothing consulted it."""
    session.step()
    _tamper(session.store)

    stored = session.store._artifacts[KEY_RAW_INPUT]
    recomputed = compute_source_hash(
        {k: v for k, v in stored.items() if k != "source_hash"})
    assert stored["source_hash"] != recomputed


# ---------------------------------------------------------------------------
# C1 - read-boundary verification.
# ---------------------------------------------------------------------------

def test_read_boundary_detects_mutation(session):
    """Guarantee: no consumer receives content that does not match its hash."""
    session.step()
    _tamper(session.store)

    with pytest.raises(ArtifactIntegrityError) as exc:
        session.store.get(KEY_RAW_INPUT)

    message = str(exc.value)
    assert KEY_RAW_INPUT in message
    assert "modified in place after registration" in message


def test_read_boundary_applies_through_the_scoped_view(session):
    """The view delegates to the store, so a granted read is verified too."""
    session.step()
    _tamper(session.store)
    view = session.store.view([KEY_RAW_INPUT])

    with pytest.raises(ArtifactIntegrityError):
        view.get(KEY_RAW_INPUT)


# ---------------------------------------------------------------------------
# C2 - post-step sweep.
# ---------------------------------------------------------------------------

def test_post_step_sweep_detects_unread_mutation(session):
    """C2 is not redundant with C1.

    The last stage mutates an artifact nothing reads again, so a read-boundary
    check alone would never fire. Detection must not depend on the workflow's
    read pattern, which the attacker partly controls.
    """
    session._agents[3] = TamperingValidationAgent(session._receipts.view())
    for _ in range(4):
        if session.quarantined:
            break
        session.step()

    assert session.quarantined is True
    assert KEY_SCHEMA in session.error
    assert session.done is False, "a corrupted run must not report completion"


def test_verify_all_reports_every_corrupted_key(session):
    session.step()
    session.step()
    _tamper(session.store, KEY_RAW_INPUT)
    session.store._artifacts[KEY_SCHEMA]["row_count"] = 9999

    corrupted = session.store.verify_all()
    assert sorted(corrupted) == sorted([KEY_RAW_INPUT, KEY_SCHEMA])


def test_verify_all_is_clean_on_an_untampered_store(session):
    session.step()
    session.step()
    assert session.store.verify_all() == []


# ---------------------------------------------------------------------------
# End to end.
# ---------------------------------------------------------------------------

def test_mutation_halts_the_workflow_before_corruption_propagates(session):
    """Without the control this run completed with verdict 'ok' and a
    cleaned_output containing the forged value."""
    session._agents[1] = TamperingSchemaAgent()
    session.step()                                  # intake
    session.step()                                  # schema + tamper

    assert session.quarantined is True
    assert "integrity" in session.error.lower()
    assert not session.store.has(KEY_CLEANED), "corruption reached downstream"


def test_quarantined_session_refuses_further_steps(session):
    """Fail-closed. The ordinary error path leaves _current unchanged, so
    without quarantine the stage would be retried against a corrupt store."""
    session._agents[1] = TamperingSchemaAgent()
    session.step()
    session.step()

    with pytest.raises(RuntimeError) as exc:
        session.step()
    assert "quarantined" in str(exc.value)
    assert "re-run from intake" in str(exc.value)


def test_the_failure_is_recorded_as_a_receipt(session):
    """Detection must leave trusted evidence, not just an exception."""
    session._agents[1] = TamperingSchemaAgent()
    session.step()
    session.step()

    receipt = session.receipts()[-1]
    assert receipt["status"] == "error"
    assert receipt["contract_result"] == "failed"
    assert receipt["agent"] == "schema_agent"


def test_untampered_run_is_unaffected(session):
    """No false positives on the honest path."""
    while not session.done:
        session.step()

    assert session.quarantined is False
    assert session.error is None
    assert session.report()["verdict"]["verdict"] == "ok"


# ---------------------------------------------------------------------------
# Residual limitation - executable.
# ---------------------------------------------------------------------------

def test_residual_attacker_who_updates_the_hash_passes_verification(session):
    """RESIDUAL LIMITATION (case 02 does not fix this, and cannot in-process).

    ``source_hash`` lives in the same dict as the data it protects. An adversary
    that can mutate the content can mutate the hash beside it. Closing this
    needs the expected hash held outside the adversary's reach - a different
    trust boundary, not a different check.
    """
    session.step()
    stored = session.store._artifacts[KEY_RAW_INPUT]
    stored["rows_data"][0]["Total"] = FORGED_TOTAL
    stored["source_hash"] = compute_source_hash(
        {k: v for k, v in stored.items() if k != "source_hash"})

    assert session.store.verify_all() == [], (
        "if this now fails, the expected hash moved outside the store - "
        "update case 02's residual-limitation section and this test"
    )
    assert session.store.get(KEY_RAW_INPUT)["rows_data"][0]["Total"] == FORGED_TOTAL


def test_residual_detection_is_not_prevention(session):
    """The mutation occurs and is observable in memory before any check runs."""
    session.step()
    _tamper(session.store)

    # The corrupted value is live in the store right now. Nothing undid it.
    assert (session.store._artifacts[KEY_RAW_INPUT]["rows_data"][0]["Total"]
            == FORGED_TOTAL)
    # Detection happens only when something looks.
    with pytest.raises(ArtifactIntegrityError):
        session.store.get(KEY_RAW_INPUT)
