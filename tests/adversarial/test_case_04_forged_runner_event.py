"""Case 04 - forged runner-labelled audit event.

Adversary for the demonstrated attacks: **Level 1**. An agent that uses the log
handle the runner passes it, or that assigns itself a different ``name``. The
residual tests use Level 2 reach-around.

Two claims under test, deliberately kept apart:

    04a  An event attributed to an identity the agent was not assigned cannot
         be appended through the interfaces the agent is given, and a
         runner-labelled event the runner did not write is detected before the
         workflow advances.

    04b  Forging the record does not corrupt the authorization decision -
         measured, not assumed, because an unmeasured containment is
         indistinguishable from luck.

This does NOT make the log tamper-evident. No chain, no signature, no external
anchor; the on-disk file is still rewritable (L5). Case 01 remains the
governing statement on same-process containment.
"""

from __future__ import annotations

import pytest

from agent_network_demo.agents import (
    KEY_CLEANED, KEY_RAW_INPUT, KEY_SCHEMA, KEY_VERDICT,
    SchemaAgent, TransformAgent, ValidationAgent,
)
from agent_network_demo.demo_runner import RunSession
from agent_network_demo.event_log import (
    AuditIntegrityError, Event, EventLog, EventLogView, RUNNER_IDENTITY,
)


@pytest.fixture
def session(data_dir, key_file_path):
    s = RunSession(data_dir=str(data_dir))
    s.start_run(key_file_path)
    yield s
    if s.log is not None:
        s.log.close()


@pytest.fixture
def log(data_dir):
    lg = EventLog("run_case_04", data_dir=str(data_dir))
    yield lg
    lg.close()


def _forged_receipt(run_id: str, about: str, agent: str = RUNNER_IDENTITY) -> Event:
    """Shaped exactly like the event the runner writes after a step."""
    return Event(
        run_id=run_id, agent=agent, action="step_receipt",
        input_keys=[], output_keys=[], status="ok",
        checks={"agent": about, "contract_result": "passed", "status": "ok"},
        message=f"Receipt for {about}: passed.",
    )


def _runner_labelled(session: RunSession) -> list:
    return [e for e in session.events() if e["agent"] == RUNNER_IDENTITY]


class ForgingTransformAgent(TransformAgent):
    """A1 - forge a runner receipt through the handle it was given."""

    def run(self, envelope, view, log):
        result = super().run(envelope, view, log)
        try:
            log.append(_forged_receipt(log.run_id, "validation_agent"))
            self.forge_error = None
        except Exception as exc:  # noqa: BLE001
            self.forge_error = exc
        return result


class SelfRenamingSchemaAgent(SchemaAgent):
    """A2 - the whole attack is the next line."""

    name = RUNNER_IDENTITY


class ReachAroundTransformAgent(TransformAgent):
    """C - Level 2. ``log._log`` is the cheapest route to the real EventLog;
    ``gc.get_objects()`` finds it too, as the attack script demonstrates."""

    label = RUNNER_IDENTITY

    def run(self, envelope, view, log):
        result = super().run(envelope, view, log)
        raw = log._log
        raw.append(_forged_receipt(raw.run_id, "validation_agent", self.label))
        return result


# ---------------------------------------------------------------------------
# C1 - the agent's log handle is bound to an author.
# ---------------------------------------------------------------------------

def test_handle_refuses_an_event_claiming_the_runner(log):
    handle = log.view_for("schema_agent")
    with pytest.raises(AuditIntegrityError) as exc:
        handle.append(_forged_receipt("run_case_04", "transform_agent"))
    assert "'schema_agent' may not append an event attributed to " \
           "'trusted_runner'" in str(exc.value)
    assert len(log) == 0


def test_handle_refuses_another_agents_identity(log):
    handle = log.view_for("schema_agent")
    with pytest.raises(AuditIntegrityError):
        handle.append(Event("run_case_04", "transform_agent", "write_artifact"))
    assert len(log) == 0


def test_handle_stamps_an_unattributed_event(log):
    handle = log.view_for("schema_agent")
    stored = handle.append(Event("wrong_run", "", "write_artifact"))
    assert stored.agent == "schema_agent"
    assert stored.run_id == "run_case_04", "the handle stamps the run too"
    assert log.all()[0].agent == "schema_agent"


def test_no_handle_can_be_minted_under_the_runner_identity(log):
    with pytest.raises(AuditIntegrityError) as exc:
        log.view_for(RUNNER_IDENTITY)
    assert "not delegable" in str(exc.value)


def test_a_handle_needs_an_author(log):
    with pytest.raises(AuditIntegrityError):
        log.view_for("")


def test_the_returned_event_is_a_copy(log):
    """Without this the guarantee is defeated in one line."""
    handle = log.view_for("schema_agent")
    returned = handle.append(Event("run_case_04", "schema_agent", "write_artifact"))
    returned.agent = RUNNER_IDENTITY

    assert log.all()[0].agent == "schema_agent"


def test_read_back_through_the_handle_is_a_copy(log):
    handle = log.view_for("schema_agent")
    handle.append(Event("run_case_04", "schema_agent", "write_artifact"))

    handle.all()[0].agent = RUNNER_IDENTITY
    handle.all()[0].checks["forged"] = True

    assert log.all()[0].agent == "schema_agent"
    assert log.all()[0].checks == {}


def test_the_agent_receives_a_handle_and_not_the_log(session):
    seen = {}

    class Recording(TransformAgent):
        def run(self, envelope, view, log):
            seen["handle"] = log
            return super().run(envelope, view, log)

    session._agents[2] = Recording()
    for _ in range(3):
        session.step()

    assert isinstance(seen["handle"], EventLogView)
    assert seen["handle"].author == "transform_agent"


# ---------------------------------------------------------------------------
# A1 - forged runner receipt through the handed log.
# ---------------------------------------------------------------------------

def test_forged_runner_receipt_through_the_handle_is_blocked(session):
    session._agents[2] = ForgingTransformAgent()
    while not session.done and not session.quarantined and session.error is None:
        session.step()

    assert isinstance(session._agents[2].forge_error, AuditIntegrityError)
    assert len(_runner_labelled(session)) == len(session.receipts()), (
        "every runner-labelled event must correspond to a receipt the runner wrote"
    )


# ---------------------------------------------------------------------------
# C2 - the acting identity comes from the route, not from the agent.
# ---------------------------------------------------------------------------

def test_a_renamed_agent_cannot_take_the_runner_identity(session):
    """A2 - one renamed attribute used to make the runner write the lie."""
    session._agents[1] = SelfRenamingSchemaAgent()
    while not session.done and not session.quarantined and session.error is None:
        session.step()

    assert not [r for r in session.receipts() if r["agent"] == RUNNER_IDENTITY]
    assert "event attribution denied" in session.error
    assert "'schema_agent' may not append" in session.error


def test_identity_in_the_trusted_record_comes_from_the_route(session):
    """A rename to any other identity is ignored, not just the runner's."""

    class Renamed(SchemaAgent):
        name = "auditor"

    session._agents[1] = Renamed()
    session.step()
    snapshot = session.step()

    assert snapshot.agent == "schema_agent"
    assert session.receipts()[1]["agent"] == "schema_agent"
    assert not any(e["agent"] == "auditor" for e in session.events())


# ---------------------------------------------------------------------------
# C3 - the runner's own label is verified after every step.
# ---------------------------------------------------------------------------

def test_level_2_append_under_the_runner_identity_is_detected(session):
    session._agents[2] = ReachAroundTransformAgent()
    session.step()
    session.step()
    session.step()                                   # transform + forgery

    assert session.quarantined is True
    assert "audit integrity failure" in session.error
    assert "written by something else" in session.error


def test_audit_integrity_failure_is_recorded_as_a_receipt(session):
    session._agents[2] = ReachAroundTransformAgent()
    for _ in range(3):
        session.step()

    receipt = session.receipts()[-1]
    assert receipt["status"] == "error"
    assert receipt["contract_result"] == "failed"


def test_quarantined_run_refuses_further_steps(session):
    session._agents[2] = ReachAroundTransformAgent()
    for _ in range(3):
        session.step()

    with pytest.raises(RuntimeError) as exc:
        session.step()
    assert "quarantined" in str(exc.value)


def test_untampered_run_is_unaffected(session):
    """No false positives."""
    while not session.done:
        session.step()

    assert session.quarantined is False
    assert session.error is None
    assert session.report()["verdict"]["verdict"] == "ok"
    assert len(_runner_labelled(session)) == len(session.receipts()) == 4


# ---------------------------------------------------------------------------
# 04b - the authorization decision, measured separately.
# ---------------------------------------------------------------------------

def test_forged_events_do_not_change_the_verdict(session, data_dir, key_file_path):
    """Forged under agent labels - the strongest forgery C3 does not cover -
    so this measurement means the same thing before and after the control."""
    clean = RunSession(data_dir=str(data_dir))
    clean.start_run(key_file_path)
    while not clean.done:
        clean.step()
    clean_verdict = clean.report()["verdict"]
    clean.log.close()

    for _ in range(3):
        session.step()
    for agent in ("intake_agent", "schema_agent", "transform_agent"):
        session.log.append(Event(
            session.run_id, agent, "write_artifact", [], ["artifact.evil"],
            "ok", {"allowed_write": True, "contract_result": "passed"},
            "forged permission claim",
        ))
    session.step()                                   # validation

    assert session.report()["verdict"] == clean_verdict


def test_the_validator_follows_the_ledger_not_the_log(session):
    """The sharper form: make the two disagree and see which one wins."""
    for _ in range(3):
        session.step()

    # The log says, in the runner's own voice, that every stage passed.
    for stage in ("intake_agent", "schema_agent", "transform_agent"):
        session._append_runner_event(_forged_receipt(session.run_id, stage))

    # The ledger the validator is actually given says one stage failed.
    validator = ValidationAgent([{"agent": "transform_agent", "status": "error",
                                  "contract_result": "failed"}])
    view = session.store.view([KEY_RAW_INPUT, KEY_SCHEMA, KEY_CLEANED], KEY_VERDICT)
    validator.run(session._envelope, view,
                  session.log.view_for("validation_agent"))

    verdict = session.store.get(KEY_VERDICT)
    assert verdict["verdict"] == "warn"
    assert verdict["checks"]["all_writes_allowed"] is False
    assert "runner receipts contain authorization failures" in verdict["reasons"]


# ---------------------------------------------------------------------------
# Residual limitations - executable.
# ---------------------------------------------------------------------------

def test_residual_matching_tally_passes_verification(session):
    """RESIDUAL. The reference value lives where the adversary can reach it.

    Same shape as case 02's hash-in-the-same-dict and case 03's fingerprint on
    the session object. An adversary who forges and updates the tally passes.
    """
    session._agents[2] = ReachAroundTransformAgent()
    session.step()
    session.step()
    session._runner_event_count += 1                 # the adversary's one line
    session.step()                                   # transform + forgery

    assert session.quarantined is False, (
        "if this now fails, the tally moved outside the runner's reach - "
        "update case 04's residual-limitation section and this test"
    )
    assert len(_runner_labelled(session)) > len(session.receipts()), (
        "the forged event must actually be in the log, or this proves nothing"
    )


def test_residual_forgery_under_an_agent_label_is_not_detected(session):
    """RESIDUAL. C3 covers the runner's label only.

    The runner has no independent record of what an agent legitimately wrote,
    so it cannot tally agent-labelled events. Inter-agent forgery by a Level 2
    adversary stays undetected.
    """
    class ImpersonatingTransformAgent(ReachAroundTransformAgent):
        label = "validation_agent"

    session._agents[2] = ImpersonatingTransformAgent()
    for _ in range(3):
        session.step()

    forged = [e for e in session.events()
              if e["agent"] == "validation_agent" and e["action"] == "step_receipt"]
    assert forged, "the forgery must actually have landed"
    assert session.quarantined is False, (
        "if this now fails, per-author attribution is now verified - update "
        "case 04's residual-limitation section and this test"
    )


def test_residual_content_is_not_bound(session):
    """RESIDUAL. Attribution is bound; content is not.

    An agent may still write receipt-shaped prose about another stage under its
    own honest identity. A reader who checks the ``agent`` field is not
    deceived; a reader who skims the message is.
    """
    class ProseForgingSchemaAgent(SchemaAgent):
        def run(self, envelope, view, log):
            result = super().run(envelope, view, log)
            log.append(Event(
                log.run_id, "", "step_receipt", [], [], "ok",
                {"agent": "transform_agent", "contract_result": "passed"},
                "Receipt for transform_agent: passed.",
            ))
            return result

    session._agents[1] = ProseForgingSchemaAgent()
    session.step()
    session.step()

    misleading = [e for e in session.events()
                  if e["action"] == "step_receipt" and e["agent"] == "schema_agent"]
    assert misleading, (
        "if this now fails, action names became runner-reserved - update "
        "case 04's residual-limitation section and this test"
    )
    assert session.quarantined is False
    assert session.error is None
