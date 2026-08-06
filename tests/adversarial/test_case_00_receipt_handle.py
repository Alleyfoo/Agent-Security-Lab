"""Case 00 - the audited component must not be able to edit its own evidence.

Adversary: a hostile ``ValidationAgent`` implementation. Per the threat model,
agent implementation code is untrusted, so this is a **Level 1** adversary. It
touches no private attribute and needs no memory access — it uses only the
object the runner handed to its constructor.

Central claim under test:

    The runner's receipt record is read-only for the agent that audits it, so
    corrupting that evidence requires full in-process compromise (Level 2)
    rather than merely a hostile agent implementation (Level 1).
"""

from __future__ import annotations

import pytest

from agent_network_demo.agents import (
    KEY_CLEANED, SchemaAgent, ValidationAgent,
)
from agent_network_demo.demo_runner import RunSession
from agent_network_demo.receipts import (
    ReceiptIntegrityError, ReceiptLedger, ReceiptView,
)


# ---------------------------------------------------------------------------
# Hostile components.
# ---------------------------------------------------------------------------

class FlakySchemaAgent(SchemaAgent):
    """Violates its write contract once, then behaves.

    Produces a genuine ``contract_result: failed`` receipt while still letting
    the workflow reach validation on retry.
    """

    def __init__(self) -> None:
        self.attempts = 0

    def run(self, envelope, view, log):
        self.attempts += 1
        if self.attempts == 1:
            view.register(KEY_CLEANED, {"type": "cleaned_output"})
        return super().run(envelope, view, log)


class ScrubbingValidationAgent(ValidationAgent):
    """Deletes every non-passing receipt before auditing."""

    def __init__(self, receipts):
        super().__init__(receipts)
        self.scrub_error: Exception | None = None

    def run(self, envelope, view, log):
        try:
            self.receipts[:] = [
                r for r in self.receipts
                if r.get("status") == "ok" and r.get("contract_result") == "passed"
            ]
        except Exception as exc:  # noqa: BLE001
            self.scrub_error = exc
        return super().run(envelope, view, log)


def _run_to_completion(session: RunSession, max_steps: int = 8) -> None:
    for _ in range(max_steps):
        if session.done:
            break
        session.step()


@pytest.fixture
def flaky_session(data_dir, key_file_path):
    """A run whose schema stage fails once, so a failing receipt exists."""
    session = RunSession(data_dir=str(data_dir))
    session.start_run(key_file_path)
    session._agents[1] = FlakySchemaAgent()
    yield session
    if session.log is not None:
        session.log.close()  # Windows holds the JSONL handle open.


# ---------------------------------------------------------------------------
# The control.
# ---------------------------------------------------------------------------

def test_runner_does_not_hand_the_validator_its_own_receipt_record(
        data_dir, key_file_path):
    """Regression guard on baseline finding L7."""
    session = RunSession(data_dir=str(data_dir))
    session.start_run(key_file_path)
    try:
        validator = session._agents[3]
        assert validator.receipts is not session._receipts
        assert isinstance(validator.receipts, ReceiptView)
        assert isinstance(session._receipts, ReceiptLedger)
    finally:
        session.log.close()


def test_hostile_validator_cannot_scrub_failing_receipts(flaky_session):
    """The attack, blocked for a specific and observable reason."""
    flaky_session._agents[3] = ScrubbingValidationAgent(
        flaky_session._receipts.view()
    )
    _run_to_completion(flaky_session)

    validator = flaky_session._agents[3]
    assert isinstance(validator.scrub_error, ReceiptIntegrityError)
    # Assert on the reason, not merely that something was raised.
    assert "receipt assignment denied" in str(validator.scrub_error)
    assert "audited component" in str(validator.scrub_error)


def test_runner_evidence_survives_a_hostile_validator(flaky_session):
    """End-to-end: the failing receipt is still in the record, and the verdict
    still reflects it."""
    flaky_session._agents[3] = ScrubbingValidationAgent(
        flaky_session._receipts.view()
    )
    _run_to_completion(flaky_session)

    receipts = flaky_session.receipts()
    failed = [r for r in receipts if r.get("contract_result") != "passed"]
    assert len(failed) == 1, "the runner's record of the failure was erased"

    report = flaky_session.report()
    assert report["verdict"]["verdict"] == "warn"
    assert "runner receipts contain authorization failures" in report["reasons"]


@pytest.mark.parametrize("operation, expected", [
    (lambda v: v.append({"status": "ok"}), "append"),
    (lambda v: v.extend([{"status": "ok"}]), "extend"),
    (lambda v: v.insert(0, {"status": "ok"}), "insert"),
    (lambda v: v.clear(), "clear"),
    (lambda v: v.pop(), "pop"),
    (lambda v: v.remove(v[0]), "remove"),
    (lambda v: v.sort(), "reordering"),
    (lambda v: v.reverse(), "reordering"),
    (lambda v: v.__setitem__(0, {"status": "ok"}), "assignment"),
    (lambda v: v.__delitem__(0), "deletion"),
    (lambda v: v.__iadd__([{"status": "ok"}]), "in-place extension"),
])
def test_every_mutation_path_on_the_view_is_denied(operation, expected):
    ledger = ReceiptLedger()
    ledger.append({"agent": "schema_agent", "status": "error",
                   "contract_result": "failed"})
    view = ledger.view()

    with pytest.raises(ReceiptIntegrityError) as exc:
        operation(view)
    assert expected in str(exc.value)
    # The record is untouched.
    assert len(ledger) == 1
    assert ledger.snapshot()[0]["contract_result"] == "failed"


def test_view_yields_copies_so_receipts_cannot_be_edited_in_place():
    ledger = ReceiptLedger()
    ledger.append({"agent": "schema_agent", "status": "error",
                   "contract_result": "failed"})
    view = ledger.view()

    for receipt in view:
        receipt["contract_result"] = "passed"
    view[0]["status"] = "ok"

    assert ledger.snapshot()[0]["contract_result"] == "failed"
    assert ledger.snapshot()[0]["status"] == "error"


def test_ledger_copies_on_append_so_later_caller_edits_do_not_apply():
    ledger = ReceiptLedger()
    receipt = {"agent": "schema_agent", "status": "error",
               "contract_result": "failed"}
    ledger.append(receipt)
    receipt["contract_result"] = "passed"

    assert ledger.snapshot()[0]["contract_result"] == "failed"


# ---------------------------------------------------------------------------
# Residual limitations - executable, so they cannot quietly stop being true.
# ---------------------------------------------------------------------------

class LyingValidationAgent(ValidationAgent):
    """Ignores the real evidence and audits a fabricated list instead."""

    def run(self, envelope, view, log):
        # Rebinding its own attribute is not blocked, and cannot be: the
        # attacker controls its own process-local names.
        self.receipts = [{"agent": "schema_agent", "status": "ok",
                          "contract_result": "passed"}]
        return super().run(envelope, view, log)


def test_case_00_still_cannot_stop_a_false_recommendation(flaky_session):
    """The limit of case 00's control, stated exactly.

    Until case 05 this test asserted that the false verdict became the run's
    conclusion, and carried a tripwire message naming the change that should
    break it. Case 05 landed, it broke, and this is the rewrite the message
    asked for.

    What did not change: case 00 protects the *evidence*, not the *authorship*.
    A hostile validator still writes whatever it likes to its granted key, and
    nothing here prevents that. What changed is that the artifact is a
    recommendation, and the run's conclusion is derived by the runner - so the
    lie is rejected before commitment rather than published. See
    cases/05-false-verdict/README.md.
    """
    flaky_session._agents[3] = LyingValidationAgent(
        flaky_session._receipts.view()
    )
    _run_to_completion(flaky_session)

    report = flaky_session.report()
    assert report["recommendation"]["verdict"] == "ok", (
        "case 00 does not constrain what the validator writes, and a control "
        "that appeared to would be constraining something else"
    )
    assert report["verdict"]["verdict"] == "warn", (
        "the run's conclusion is the runner's derivation, not the agent's"
    )
    assert report["review_required"] is True


def test_residual_but_the_runner_record_still_shows_the_failure(flaky_session):
    """The lie is detectable: the runner's own receipts contradict the verdict.

    This is what keeps the residual limitation bounded - the false verdict is
    contradicted by evidence the attacker could not reach.
    """
    flaky_session._agents[3] = LyingValidationAgent(
        flaky_session._receipts.view()
    )
    _run_to_completion(flaky_session)

    failed = [r for r in flaky_session.receipts()
              if r.get("contract_result") != "passed"]
    assert len(failed) == 1
    assert failed[0]["agent"] == "schema_agent"
