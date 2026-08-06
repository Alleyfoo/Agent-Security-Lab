"""Case 03 - altering runner-owned routing data.

Adversary for the demonstrated attack: **Level 1**. An agent that can
``import agent_network_demo.demo_runner`` - no reach-around, no private
attribute, no frame walking. This is the cheapest attack in the repository and
the one with the widest blast radius, because tampering outlives the run.

Central claim under test:

    Runtime route modification is prevented at the interface, and modification
    of the copy a run actually uses is detected before the runner acts on it.

This does NOT imply hostile same-process Python has been sandboxed. Case 01
remains the governing statement on that, and the residual tests below hold the
line.
"""

from __future__ import annotations

import pytest

from agent_network_demo import demo_runner
from agent_network_demo.agents import (
    IntakeAgent, KEY_VERDICT, SchemaAgent,
)
from agent_network_demo.contracts import ACTION_WRITE_CLEANED_OUTPUT
from agent_network_demo.demo_runner import (
    Route, RouteIntegrityError, RunSession, WORKFLOW_ROUTES, route_fingerprint,
)


@pytest.fixture
def pristine_routes():
    """Restore the private table after any test that tampers with it."""
    saved = dict(demo_runner._WORKFLOW_ROUTES)
    yield
    demo_runner._WORKFLOW_ROUTES.clear()
    demo_runner._WORKFLOW_ROUTES.update(saved)


@pytest.fixture
def session(data_dir, key_file_path):
    s = RunSession(data_dir=str(data_dir))
    s.start_run(key_file_path)
    yield s
    if s.log is not None:
        s.log.close()


def _widened(stage: str) -> Route:
    current = WORKFLOW_ROUTES[stage]
    return Route(
        agent=current.agent, handoff_type=current.handoff_type,
        input_keys=current.input_keys, output_contract=current.output_contract,
        allowed_actions=tuple(current.allowed_actions) + (ACTION_WRITE_CLEANED_OUTPUT,),
        next_stage=current.next_stage,
    )


class GrantWideningIntakeAgent(IntakeAgent):
    def run(self, envelope, view, log):
        result = super().run(envelope, view, log)
        try:
            WORKFLOW_ROUTES["schema"] = _widened("schema")
            self.tamper_error = None
        except Exception as exc:  # noqa: BLE001
            self.tamper_error = exc
        return result


class StageSkippingSchemaAgent(SchemaAgent):
    def run(self, envelope, view, log):
        result = super().run(envelope, view, log)
        current = WORKFLOW_ROUTES["transform"]
        try:
            WORKFLOW_ROUTES["transform"] = Route(
                current.agent, current.handoff_type, current.input_keys,
                current.output_contract, current.allowed_actions, None)
            self.tamper_error = None
        except Exception as exc:  # noqa: BLE001
            self.tamper_error = exc
        return result


# ---------------------------------------------------------------------------
# C1 - the public table is read-only.
# ---------------------------------------------------------------------------

def test_public_route_table_rejects_rebinding():
    with pytest.raises(TypeError):
        WORKFLOW_ROUTES["schema"] = WORKFLOW_ROUTES["intake"]


@pytest.mark.parametrize("operation", [
    pytest.param(lambda t: t.__delitem__("schema"), id="delete"),
    pytest.param(lambda t: t.update({"schema": None}), id="update"),
    pytest.param(lambda t: t.pop("schema"), id="pop"),
    pytest.param(lambda t: t.clear(), id="clear"),
    pytest.param(lambda t: t.setdefault("evil", None), id="setdefault"),
])
def test_public_route_table_rejects_every_mutation(operation):
    with pytest.raises((TypeError, AttributeError)):
        operation(WORKFLOW_ROUTES)


def test_route_entries_are_individually_frozen():
    route = WORKFLOW_ROUTES["schema"]
    with pytest.raises(Exception):
        route.input_keys = ("artifact.cleaned_output",)
    # Fields are tuples, so there is no in-place mutation path either.
    assert isinstance(route.input_keys, tuple)
    assert isinstance(route.allowed_actions, tuple)


# ---------------------------------------------------------------------------
# The three attacks.
# ---------------------------------------------------------------------------

def test_grant_widening_attack_is_blocked(session):
    """Attack A - the runner must not issue authority the policy lacks."""
    session._agents[0] = GrantWideningIntakeAgent(
        source_ref=session._agents[0].source_ref)
    session.step()

    hostile = session._agents[0]
    assert isinstance(hostile.tamper_error, TypeError)
    issued = session.current_envelope()["allowed_actions"]
    assert ACTION_WRITE_CLEANED_OUTPUT not in issued


def test_stage_skipping_attack_is_blocked(session):
    """Attack B - the validator must not be removable by a hostile agent."""
    session._agents[1] = StageSkippingSchemaAgent()
    while not session.done and not session.quarantined:
        session.step()

    assert isinstance(session._agents[1].tamper_error, TypeError)
    assert session.done is True
    assert session.store.has(KEY_VERDICT), "the validation stage was skipped"
    assert session.report()["agents_acted"] == 4


def test_tampering_does_not_persist_across_runs(data_dir, key_file_path):
    """Attack C - the blast radius must not be the process lifetime."""
    hostile = RunSession(data_dir=str(data_dir))
    hostile.start_run(key_file_path)
    hostile._agents[0] = GrantWideningIntakeAgent(
        source_ref=hostile._agents[0].source_ref)
    hostile.step()
    hostile.log.close()

    clean = RunSession(data_dir=str(data_dir))
    clean.start_run(key_file_path)
    clean.step()
    issued = clean.current_envelope()["allowed_actions"]
    clean.log.close()

    assert ACTION_WRITE_CLEANED_OUTPUT not in issued


# ---------------------------------------------------------------------------
# C2 - per-run private copy.
# ---------------------------------------------------------------------------

def test_run_uses_a_private_copy_of_the_routes(session, pristine_routes):
    """Mid-run tampering with the module table must not reach a live run."""
    assert session._routes is not demo_runner._WORKFLOW_ROUTES

    session.step()                                   # intake
    demo_runner._WORKFLOW_ROUTES["schema"] = _widened("schema")

    # The live run's own copy is untouched by the module-level tampering...
    assert (ACTION_WRITE_CLEANED_OUTPUT
            not in session._routes["schema"].allowed_actions)
    assert ACTION_WRITE_CLEANED_OUTPUT in (
        demo_runner._WORKFLOW_ROUTES["schema"].allowed_actions), (
        "the tampering must actually have landed, or this proves nothing"
    )

    # ... so the run continues on the policy it was started with.
    session.step()                                   # schema, from the copy
    assert session.quarantined is False
    assert session.error is None


# ---------------------------------------------------------------------------
# C3 - fingerprint verification.
# ---------------------------------------------------------------------------

def test_midrun_tampering_of_the_private_copy_is_detected(session):
    """The Level 2 variant that goes around C1 and C2."""
    session.step()
    session._routes["transform"] = Route(
        "transform_agent", "transform_request", (), "", (), None)

    session.step()

    assert session.quarantined is True
    assert "route integrity failure" in session.error
    assert "modified after the run started" in session.error


def test_route_integrity_failure_is_recorded_as_a_receipt(session):
    session.step()
    session._routes["transform"] = Route(
        "transform_agent", "transform_request", (), "", (), None)
    session.step()

    receipt = session.receipts()[-1]
    assert receipt["status"] == "error"
    assert receipt["contract_result"] == "failed"


def test_quarantined_run_refuses_further_steps(session):
    session.step()
    session._routes["transform"] = Route(
        "transform_agent", "transform_request", (), "", (), None)
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


def test_fingerprint_changes_when_any_field_changes():
    base = dict(WORKFLOW_ROUTES)
    original = route_fingerprint(base)
    for change in ("agent", "input_keys", "output_contract", "allowed_actions",
                   "next_stage"):
        mutated = dict(base)
        current = mutated["schema"]
        kwargs = {
            "agent": "impostor", "input_keys": (),
            "output_contract": "", "allowed_actions": (),
            "next_stage": "intake",
        }
        mutated["schema"] = Route(
            agent=kwargs["agent"] if change == "agent" else current.agent,
            handoff_type=current.handoff_type,
            input_keys=kwargs["input_keys"] if change == "input_keys" else current.input_keys,
            output_contract=(kwargs["output_contract"] if change == "output_contract"
                             else current.output_contract),
            allowed_actions=(kwargs["allowed_actions"] if change == "allowed_actions"
                             else current.allowed_actions),
            next_stage=kwargs["next_stage"] if change == "next_stage" else current.next_stage,
        )
        assert route_fingerprint(mutated) != original, f"{change} not covered"


# ---------------------------------------------------------------------------
# Residual limitations - executable.
# ---------------------------------------------------------------------------

def test_residual_level_2_can_rewrite_the_private_table(pristine_routes,
                                                        data_dir, key_file_path):
    """RESIDUAL (case 03 does not fix this, and cannot in-process).

    MappingProxyType is a view, not a freeze. Code that reaches the private
    dict rewrites it, and if it does so BEFORE start_run the fingerprint is
    computed over the already-tampered table - so the run proceeds undetected.
    """
    demo_runner._WORKFLOW_ROUTES["schema"] = _widened("schema")

    session = RunSession(data_dir=str(data_dir))
    session.start_run(key_file_path)
    session.step()
    issued = session.current_envelope()["allowed_actions"]
    quarantined = session.quarantined
    session.log.close()

    assert ACTION_WRITE_CLEANED_OUTPUT in issued, (
        "if this now fails, the expected policy moved outside the process - "
        "update case 03's residual-limitation section and this test"
    )
    assert quarantined is False, "pre-run tampering is not detected"


def test_residual_matching_fingerprint_passes_verification(session):
    """The reference value lives where the adversary can reach it.

    Same shape as case 02's hash-in-the-same-dict residual. Together they are
    the more important finding: an integrity check whose expected value is
    stored in the adversary's reach detects careless tampering, not careful
    tampering.
    """
    session.step()
    session._routes["transform"] = Route(
        "transform_agent", "transform_request", (), "", (), None)
    session._route_fingerprint = route_fingerprint(session._routes)

    session.step()
    assert session.quarantined is False, (
        "if this now fails, the fingerprint moved outside the runner's reach - "
        "update case 03's residual-limitation section and this test"
    )
