"""Case 05 - a conclusion the agent authors is not evidence.

Adversary: a hostile ``ValidationAgent`` implementation. **Level 1** - it uses
only its granted write, ``artifact.validation_verdict``, and puts whatever dict
it likes there. The residual tests use Level 2.

Central claim under test:

    The run's conclusion is derived by the runner from evidence the validator
    does not control, and the validator's conclusion is a recommendation that
    is never adopted without agreement - in either direction.

This closes the residual case 00 recorded. It does NOT make the derived verdict
correct: it is four structural checks over metadata the pipeline's own agents
wrote, and the residual tests below hold that line.
"""

from __future__ import annotations

import pytest

from agent_network_demo import demo_runner
from agent_network_demo.agents import (
    AgentResult, KEY_CLEANED, KEY_RAW_INPUT, KEY_SCHEMA, KEY_VERDICT,
    SchemaAgent, TransformAgent, ValidationAgent,
)
from agent_network_demo.demo_runner import RunSession
from agent_network_demo.event_log import RUNNER_IDENTITY
from agent_network_demo.verdict import (
    CHECK_ALL_WRITES_ALLOWED, CHECK_CHAIN_COMPLETE,
    CHECK_ROW_COUNTS_CONSISTENT, CHECK_SCHEMA_MATCHES_OUTPUT,
    derive_verdict, verdict_disagreement,
)

ALL_PASSED = {CHECK_CHAIN_COMPLETE: True, CHECK_ALL_WRITES_ALLOWED: True,
              CHECK_SCHEMA_MATCHES_OUTPUT: True,
              CHECK_ROW_COUNTS_CONSISTENT: True}

PASSING_RECEIPT = {"agent": "schema_agent", "status": "ok",
                   "contract_result": "passed"}
FAILED_RECEIPT = {"agent": "schema_agent", "status": "error",
                  "contract_result": "failed"}


def _chain(raw_rows: int = 20, cleaned_rows: int = 20,
           cleaned_cols=None) -> dict:
    columns = ["a", "b"]
    return {
        KEY_RAW_INPUT: {"row_count": raw_rows, "columns": columns},
        KEY_SCHEMA: {"columns": columns},
        KEY_CLEANED: {"row_count": cleaned_rows,
                      "columns": columns if cleaned_cols is None else cleaned_cols},
    }


def _derive(artifacts, receipts):
    return derive_verdict(artifacts, receipts,
                          KEY_RAW_INPUT, KEY_SCHEMA, KEY_CLEANED)


# ---------------------------------------------------------------------------
# Hostile components.
# ---------------------------------------------------------------------------

class LyingValidationAgent(ValidationAgent):
    """Writes whatever conclusion it was told to, ignoring the evidence."""

    def __init__(self, receipts, claim="ok", checks=None, reasons=None):
        super().__init__(receipts)
        self.claim = claim
        self.claim_checks = ALL_PASSED if checks is None else checks
        self.claim_reasons = reasons

    def run(self, envelope, view, log):
        verdict = {
            "type": "validation_verdict", "status": self.claim,
            "verdict": self.claim, "checks": dict(self.claim_checks),
            "reasons": (self.claim_reasons if self.claim_reasons is not None
                        else ["all checks passed"]),
        }
        view.register(KEY_VERDICT, verdict)
        self._emit(log, action="validate",
                   input_keys=[KEY_RAW_INPUT, KEY_SCHEMA, KEY_CLEANED],
                   output_keys=[KEY_VERDICT], status=self.claim,
                   checks=verdict["checks"], message="Chain validated.")
        return AgentResult([KEY_VERDICT], "Validated artifacts and runner receipts.",
                           {"verdict": self.claim})


class FlakySchemaAgent(SchemaAgent):
    """Violates its write contract once, so a failed receipt exists while the
    run still reaches validation."""

    def __init__(self) -> None:
        self.attempts = 0

    def run(self, envelope, view, log):
        self.attempts += 1
        if self.attempts == 1:
            view.register(KEY_CLEANED, {"type": "cleaned_output"})
        return super().run(envelope, view, log)


class _RewritingTransformAgent(TransformAgent):
    """Base for transforms that publish a chain the receipts cannot see."""

    drop_rows = 0
    declare_full_count = False

    def run(self, envelope, view, log):
        preview = view.get(KEY_RAW_INPUT)
        schema = view.get(KEY_SCHEMA)
        rows = preview["rows_data"]
        kept = rows[:len(rows) - self.drop_rows] if self.drop_rows else rows
        declared = len(rows) if self.declare_full_count else len(kept)
        view.register(KEY_CLEANED, {
            "type": "cleaned_output", "status": "ok", "row_count": declared,
            "columns": schema["columns"], "preview_rows": kept[:5],
            "rows_data": kept, "coerced_cells": 0,
        })
        self._emit(log, action="write_artifact",
                   input_keys=[KEY_RAW_INPUT, KEY_SCHEMA],
                   output_keys=[KEY_CLEANED], status="ok",
                   checks={"rows": len(kept)},
                   message=f"Cleaned {len(kept)} rows.")
        return AgentResult([KEY_CLEANED], "Normalized rows from granted artifacts.",
                           {"rows": len(kept)})


class RowDroppingTransformAgent(_RewritingTransformAgent):
    """Drops a row and says so - the chain is visibly inconsistent."""

    drop_rows = 1


class SelfConsistentLyingTransformAgent(_RewritingTransformAgent):
    """Drops a row and declares the original count - the metadata agrees."""

    drop_rows = 1
    declare_full_count = True


def _run_to_completion(session: RunSession, max_steps: int = 8) -> None:
    for _ in range(max_steps):
        if session.done or session.quarantined:
            break
        session.step()


@pytest.fixture
def session(data_dir, key_file_path):
    s = RunSession(data_dir=str(data_dir))
    s.start_run(key_file_path)
    yield s
    if s.log is not None:
        s.log.close()


# ---------------------------------------------------------------------------
# C1 - the derivation is a pure function of the evidence.
# ---------------------------------------------------------------------------

def test_derivation_is_a_pure_function_of_the_evidence():
    artifacts, receipts = _chain(), [PASSING_RECEIPT]
    first = _derive(artifacts, receipts)
    second = _derive(artifacts, receipts)

    assert first == second
    assert first["verdict"] == "ok"
    assert set(first["checks"]) == set(ALL_PASSED)


@pytest.mark.parametrize("artifacts, receipts, failing_check", [
    pytest.param({k: v for k, v in _chain().items() if k != KEY_SCHEMA},
                 [PASSING_RECEIPT], CHECK_CHAIN_COMPLETE, id="missing-artifact"),
    pytest.param(_chain(), [PASSING_RECEIPT, FAILED_RECEIPT],
                 CHECK_ALL_WRITES_ALLOWED, id="failed-receipt"),
    pytest.param(_chain(cleaned_cols=["a"]), [PASSING_RECEIPT],
                 CHECK_SCHEMA_MATCHES_OUTPUT, id="column-mismatch"),
    pytest.param(_chain(cleaned_rows=19), [PASSING_RECEIPT],
                 CHECK_ROW_COUNTS_CONSISTENT, id="row-count-mismatch"),
])
def test_each_failure_mode_is_derived(artifacts, receipts, failing_check):
    derived = _derive(artifacts, receipts)

    assert derived["checks"][failing_check] is False
    assert derived["verdict"] == "warn"


def test_no_receipts_is_not_treated_as_authorized():
    """Fail-closed on absent evidence, which is the pre-existing semantics."""
    derived = _derive(_chain(), [])

    assert derived["checks"][CHECK_ALL_WRITES_ALLOWED] is False


def test_disagreement_is_empty_when_the_two_conclusions_match():
    derived = _derive(_chain(), [PASSING_RECEIPT])

    assert verdict_disagreement(derived, derived) == []


def test_a_missing_recommendation_is_itself_a_disagreement():
    derived = _derive(_chain(), [PASSING_RECEIPT])

    assert verdict_disagreement(derived, None) == [
        "no recommendation was produced"]


# ---------------------------------------------------------------------------
# C2 - the runner derives the conclusion; the agent recommends.
# ---------------------------------------------------------------------------

def test_the_published_verdict_is_runner_derived(session):
    _run_to_completion(session)
    report = session.report()

    assert report["verdict_source"] == "runner_derived"
    assert report["verdict"] is not None
    assert report["verdict"] is not report["recommendation"]


def test_the_recommendation_is_the_agents_artifact(session):
    _run_to_completion(session)
    report = session.report()

    assert report["recommendation"] == session.store.get(KEY_VERDICT)


def test_the_derived_verdict_is_not_reachable_through_the_store(session):
    """The conclusion is not an artifact, so no write grant can reach it."""
    _run_to_completion(session)

    assert session.store.has(KEY_VERDICT), "the recommendation is an artifact"
    assert session._derived_verdict is not session.store.get(KEY_VERDICT)


# ---------------------------------------------------------------------------
# The four attacks.
# ---------------------------------------------------------------------------

def test_false_clean_verdict_over_a_failed_receipt_is_rejected(session):
    """A1 - the evidence is runner-owned and contradicts the recommendation."""
    session._agents[1] = FlakySchemaAgent()
    session._agents[3] = LyingValidationAgent(session._receipts.view(), "ok")
    _run_to_completion(session)

    report = session.report()
    assert report["recommendation"]["verdict"] == "ok"
    assert report["verdict"]["verdict"] == "warn"
    assert report["checks"][CHECK_ALL_WRITES_ALLOWED] is False
    assert report["review_required"] is True


def test_false_clean_verdict_over_a_broken_chain_is_rejected(session):
    """A2 - every receipt passes; only comparing artifacts finds this."""
    session._agents[2] = RowDroppingTransformAgent()
    session._agents[3] = LyingValidationAgent(session._receipts.view(), "ok")
    _run_to_completion(session)

    report = session.report()
    assert not [r for r in report["receipts"]
                if r["contract_result"] != "passed"], (
        "A2 must not depend on a failed receipt, or it duplicates A1"
    )
    assert report["verdict"]["verdict"] == "warn"
    assert report["checks"][CHECK_ROW_COUNTS_CONSISTENT] is False
    assert report["review_required"] is True


def test_a_conclusion_with_no_evidence_is_rejected(session):
    """B - a positive conclusion resting on no checks at all."""
    session._agents[3] = LyingValidationAgent(
        session._receipts.view(), "ok", checks={})
    _run_to_completion(session)

    report = session.report()
    assert report["recommendation"]["checks"] == {}
    assert set(report["checks"]) == set(ALL_PASSED)
    assert report["review_required"] is True
    assert len(report["verdict_differences"]) == 4, (
        "every unsupported check must be named individually"
    )


def test_a_false_alarm_on_a_healthy_run_is_rejected(session):
    """C - the symmetric direction. Disagreement is not resolved by pessimism."""
    session._agents[3] = LyingValidationAgent(
        session._receipts.view(), "warn",
        checks=dict(ALL_PASSED, row_counts_consistent=False))
    _run_to_completion(session)

    report = session.report()
    assert report["recommendation"]["verdict"] == "warn"
    assert report["verdict"]["verdict"] == "ok", (
        "a compromised validator must not be able to condemn a healthy run"
    )
    assert report["review_required"] is True


# ---------------------------------------------------------------------------
# C3 - disagreement is recorded, never silently resolved.
# ---------------------------------------------------------------------------

def test_disagreement_names_every_differing_field(session):
    session._agents[1] = FlakySchemaAgent()
    session._agents[3] = LyingValidationAgent(session._receipts.view(), "ok")
    _run_to_completion(session)

    differences = session.report()["verdict_differences"]
    assert "verdict: recommended 'ok', derived 'warn'" in differences
    assert (f"check {CHECK_ALL_WRITES_ALLOWED}: recommended True, derived False"
            in differences)


def test_disagreement_emits_a_runner_labelled_event(session):
    session._agents[3] = LyingValidationAgent(
        session._receipts.view(), "ok", checks={})
    _run_to_completion(session)

    events = [e for e in session.events()
              if e["action"] == "verdict_disagreement"]
    assert len(events) == 1
    assert events[0]["agent"] == RUNNER_IDENTITY
    assert events[0]["status"] == "warn"
    assert events[0]["checks"]["differences"]
    assert events[0]["checks"]["derived"]["verdict"] == "ok"
    assert events[0]["checks"]["recommended"]["checks"] == {}


def test_the_disagreement_event_keeps_case_04s_tally_consistent(session):
    """The runner's own event must go through its own append path."""
    session._agents[3] = LyingValidationAgent(
        session._receipts.view(), "warn")
    _run_to_completion(session)

    labelled = [e for e in session.events() if e["agent"] == RUNNER_IDENTITY]
    assert len(labelled) == session._runner_event_count
    assert session.quarantined is False


def test_disagreement_does_not_quarantine(session):
    """Nothing is corrupt: the derived conclusion is sound and usable."""
    session._agents[3] = LyingValidationAgent(session._receipts.view(), "warn")
    _run_to_completion(session)

    assert session.quarantined is False
    assert session.error is None
    assert session.done is True
    assert session.report()["verdict"]["verdict"] == "ok"


def test_untampered_run_agrees_and_is_not_flagged(session):
    """No false positives - the flag has to mean something."""
    _run_to_completion(session)
    report = session.report()

    assert report["review_required"] is False
    assert report["verdict_differences"] == []
    assert report["verdict"]["verdict"] == "ok"
    assert report["recommendation"]["verdict"] == "ok"


def test_a_genuinely_failing_run_agrees_on_warn(session):
    """The flag means disagreement, not badness."""
    session._agents[1] = FlakySchemaAgent()
    _run_to_completion(session)
    report = session.report()

    assert report["verdict"]["verdict"] == "warn"
    assert report["recommendation"]["verdict"] == "warn"
    assert report["review_required"] is False


def test_reset_clears_the_review_state(session, key_file_path):
    session._agents[3] = LyingValidationAgent(session._receipts.view(), "warn")
    _run_to_completion(session)
    assert session.review_required is True

    session.reset()
    session.start_run(key_file_path)

    assert session.review_required is False
    assert session.verdict_differences == []
    assert session.report()["verdict"] is None


# ---------------------------------------------------------------------------
# Residual limitations - executable.
# ---------------------------------------------------------------------------

def test_residual_a_self_consistent_data_lie_passes_both(session):
    """RESIDUAL. The derivation trusts metadata the agents wrote.

    A transform that drops a row and declares the original count is
    self-consistent: the recommendation and the derivation agree, and both are
    wrong. Case 02's hash proves the artifact is unchanged since registration,
    not that it was truthful then.
    """
    session._agents[2] = SelfConsistentLyingTransformAgent()
    _run_to_completion(session)

    report = session.report()
    raw = session.store.get(KEY_RAW_INPUT)
    cleaned = session.store.get(KEY_CLEANED)

    assert len(cleaned["rows_data"]) < len(raw["rows_data"]), (
        "the row must actually be missing, or this proves nothing"
    )
    assert cleaned["row_count"] == raw["row_count"], "the metadata agrees"
    assert report["verdict"]["verdict"] == "ok", (
        "if this now fails, the derivation reads the rows themselves - "
        "update case 05's residual-limitation section and this test"
    )
    assert report["review_required"] is False


def test_residual_prose_is_not_compared(session):
    """RESIDUAL. The decision is bound; the story around it is not."""
    session._agents[3] = LyingValidationAgent(
        session._receipts.view(), "ok",
        reasons=["audited by hand", "signed off by the compliance team"])
    _run_to_completion(session)

    report = session.report()
    assert report["recommendation"]["reasons"] != report["verdict"]["reasons"]
    assert report["review_required"] is False, (
        "if this now fails, prose became part of the comparison - update "
        "case 05's residual-limitation section and this test"
    )


def test_residual_level_2_can_rewrite_the_derived_verdict(session):
    """RESIDUAL. The reference value lives inside the adversary's reach.

    Fourth instance of the cross-cutting finding, after cases 02, 03 and 04.
    """
    session._agents[1] = FlakySchemaAgent()
    _run_to_completion(session)
    assert session.report()["verdict"]["verdict"] == "warn"

    session._derived_verdict["verdict"] = "ok"
    session._derived_verdict["checks"][CHECK_ALL_WRITES_ALLOWED] = True
    session.review_required = False

    assert session.report()["verdict"]["verdict"] == "ok", (
        "if this now fails, the conclusion moved outside the runner's reach - "
        "update case 05's residual-limitation section and this test"
    )


def _always_ok(*_a, **_k):
    return {"type": "validation_verdict", "status": "ok", "verdict": "ok",
            "checks": dict(ALL_PASSED), "reasons": ["all checks passed"]}


def test_residual_level_2_can_patch_the_runners_derivation(session, monkeypatch):
    """RESIDUAL. Patching the name the runner calls corrupts the conclusion.

    Note what the flag does here, and what that is worth. The honest validator
    still derives 'warn' from the unpatched function, so the comparison fires
    and the run is flagged - the two-sided comparison retains some value even
    when one side is compromised. It cannot be relied on: an adversary at this
    level replaces the validator too, which is the next test.
    """
    monkeypatch.setattr(demo_runner, "derive_verdict", _always_ok)

    session._agents[1] = FlakySchemaAgent()
    _run_to_completion(session)

    report = session.report()
    assert [r for r in report["receipts"] if r["contract_result"] != "passed"]
    assert report["verdict"]["verdict"] == "ok", (
        "if this now fails, the derivation moved outside the process - "
        "update case 05's residual-limitation section and this test"
    )
    assert report["review_required"] is True, (
        "the honest agent's disagreement is the only thing that surfaced this"
    )


def test_residual_patching_both_sides_is_silent(session, monkeypatch):
    """RESIDUAL. The same adversary owns both sides, and then nothing fires."""
    monkeypatch.setattr(demo_runner, "derive_verdict", _always_ok)

    session._agents[1] = FlakySchemaAgent()
    session._agents[3] = LyingValidationAgent(session._receipts.view(), "ok")
    _run_to_completion(session)

    report = session.report()
    assert [r for r in report["receipts"] if r["contract_result"] != "passed"]
    assert report["verdict"]["verdict"] == "ok"
    assert report["review_required"] is False, (
        "if this now fails, the derivation moved outside the process - "
        "update case 05's residual-limitation section and this test"
    )
