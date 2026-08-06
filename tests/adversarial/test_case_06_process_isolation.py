"""Case 06 - what process separation actually buys.

Adversary: **Level 2**, arbitrary hostile Python executing as the schema stage.
The same hostile classes run in both placements, because an A/B whose arms run
different code measures the code rather than the boundary.

Central claim under test, and it is the whole claim:

    A stage running in a separate interpreter cannot inspect or modify the
    runner's Python memory or object graph.

Not claimed, and measured absent below: filesystem confinement, network
confinement, host isolation, capability security, correctness of the stage's
permitted output. The boundary is a containment boundary, not a trust boundary
- everything crossing back is still validated by the controls cases 00-05
built, and those tests live here too.
"""

from __future__ import annotations

import importlib.util
import os
import sys

import pytest

from agent_network_demo.agents import (
    KEY_CLEANED, KEY_RAW_INPUT, KEY_SCHEMA, TransformAgent,
)
from agent_network_demo.contracts import ContractError
from agent_network_demo.demo_runner import RunSession
from agent_network_demo.event_log import RUNNER_IDENTITY
from agent_network_demo.isolation import AgentSpec, IsolatedAgent, IsolationError

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
HOSTILE = os.path.join(REPO_ROOT, "cases", "06-process-isolation", "hostile.py")


def _load_hostile():
    """The case directory is not an importable package."""
    spec = importlib.util.spec_from_file_location("case_06_hostile", HOSTILE)
    module = importlib.util.module_from_spec(spec)
    sys.modules["case_06_hostile"] = module
    spec.loader.exec_module(module)
    return module


hostile = _load_hostile()


def _spec(class_name: str) -> AgentSpec:
    return AgentSpec(module=HOSTILE, class_name=class_name)


def _drain(session: RunSession, max_steps: int = 8) -> None:
    for _ in range(max_steps):
        if session.done or session.quarantined or session.error:
            break
        session.step()


def _probe_event(session: RunSession) -> dict:
    return next((e["checks"] for e in session.events()
                 if e["action"] == "probe"), {})


def _reached(probes: dict, kind: str) -> list:
    return [name for name, finding in probes.items()
            if name.startswith(kind)
            and finding.startswith(("REACHED", "READ", "LISTED"))]


@pytest.fixture
def isolated(data_dir, key_file_path):
    """A run whose schema stage executes in a spawned interpreter."""
    def _make(class_name="ProbingSchemaAgent"):
        s = RunSession(data_dir=str(data_dir),
                       isolate={"schema": _spec(class_name)})
        s.start_run(key_file_path)
        return s
    sessions = []

    def _factory(class_name="ProbingSchemaAgent"):
        s = _make(class_name)
        sessions.append(s)
        return s

    yield _factory
    for s in sessions:
        if s.log is not None:
            s.log.close()


@pytest.fixture
def in_process(data_dir, key_file_path):
    """The control arm. Without it the comparison proves nothing."""
    s = RunSession(data_dir=str(data_dir))
    s.start_run(key_file_path)
    s._agents[1] = hostile.ProbingSchemaAgent()
    yield s
    if s.log is not None:
        s.log.close()


# ---------------------------------------------------------------------------
# The claim.
# ---------------------------------------------------------------------------

def test_the_stage_really_runs_in_another_process(isolated):
    session = isolated()
    _drain(session)

    where = _probe_event(session)["where            process identity"]
    assert where != f"pid {os.getpid()}", (
        "the stage ran in the runner's own process - the whole case is void"
    )


def test_the_in_process_stage_reaches_the_runners_memory(in_process):
    """The control arm: there must be exposure to remove."""
    _drain(in_process)

    reached = _reached(_probe_event(in_process), "memory")
    assert reached, (
        "if this now fails, in-process reach-around was closed by something "
        "else and case 06's comparison no longer measures the boundary"
    )


def test_the_isolated_stage_reaches_no_runner_memory(isolated):
    session = isolated()
    _drain(session)

    probes = _probe_event(session)
    assert _reached(probes, "memory") == []
    assert "no ArtifactStore in this interpreter" in probes[
        "memory  path 3   gc.get_objects()"]
    assert "no RunSession in this interpreter" in probes[
        "memory  path 4   the RunSession itself"]


def test_the_isolated_run_still_produces_the_same_result(isolated):
    session = isolated()
    _drain(session)
    report = session.report()

    assert session.done is True
    assert session.error is None
    assert report["verdict"]["verdict"] == "ok"
    assert report["review_required"] is False
    assert len(report["receipts"]) == 4


# ---------------------------------------------------------------------------
# The resolver - the enforcement point has to survive the boundary.
# ---------------------------------------------------------------------------

def test_the_read_log_stays_truthful_across_the_boundary(isolated):
    """Eager shipping would have made the runner's reconciliation vacuous."""
    session = isolated()
    _drain(session)

    receipt = next(r for r in session.receipts() if r["agent"] == "schema_agent")
    assert receipt["keys_actually_read"] == [KEY_RAW_INPUT]


def test_the_resolver_denies_an_ungranted_key(isolated):
    """The child's own grant check is advisory; the parent's is the control."""
    session = isolated("UngrantedReadingSchemaAgent")
    _drain(session)

    denial = _probe_event(session)["resolver denial"]
    assert denial != "NONE", "the child edited its grant set and was answered"
    assert "denied" in denial and KEY_CLEANED in denial

    receipt = next(r for r in session.receipts() if r["agent"] == "schema_agent")
    assert KEY_CLEANED not in receipt["keys_actually_read"]


def test_an_ungranted_write_is_refused(isolated):
    session = isolated("OverreachingSchemaAgent")
    _drain(session)

    assert "contract violation" in session.error
    assert KEY_CLEANED in session.error
    assert not session.store.has(KEY_CLEANED)


# ---------------------------------------------------------------------------
# Everything crossing back is untrusted input. The earlier controls still run.
# ---------------------------------------------------------------------------

def test_returned_artifacts_are_hash_registered(isolated):
    """Case 02 applies to output produced by a captured process."""
    session = isolated()
    _drain(session)

    assert session.store.verify_all() == []
    assert session.store.as_dict()[KEY_SCHEMA]["source_hash"]


def test_a_forged_identity_does_not_survive_the_boundary(isolated):
    """Case 04: the parent stamps the identity its routing table assigned."""
    session = isolated("ForgingSchemaAgent")
    _drain(session)

    forged = [e for e in session.events()
              if e["action"] == "step_receipt" and e["agent"] != RUNNER_IDENTITY]
    assert forged, "the child's event must have crossed back"
    assert all(e["agent"] == "schema_agent" for e in forged)

    labelled = [e for e in session.events() if e["agent"] == RUNNER_IDENTITY]
    assert len(labelled) == session._runner_event_count
    assert session.quarantined is False


def test_the_verdict_is_still_runner_derived(isolated):
    """Case 05's control runs against isolated output like any other."""
    session = isolated()
    _drain(session)

    assert session.report()["verdict_source"] == "runner_derived"


def test_finding_a_poisoned_upstream_stage_launders_into_a_consistent_chain(
        isolated):
    """NEW FINDING, discovered while measuring case 06. No case covers it.

    The isolated stage writes a fabricated schema. The honest transform stage
    then does its job perfectly: it builds the cleaned output *from that
    schema*, so the poison propagates into a chain that is internally
    consistent in every way the runner checks. Every column of real data is
    gone - each row is ``{"fabricated": None}`` - and the verdict is ``ok``.

    Isolation is not implicated: the same attack works in-process. Nor is this
    case 05 failing, exactly. Case 05 derives the conclusion from the runner's
    own evidence, and the evidence agrees, because the only checks that exist
    compare derived artifacts to each other. Nothing compares the output back
    to the source artifact the chain started from.

    Pinned here rather than fixed: adding that comparison is a change to case
    05's control, and this slice makes a different claim. It is the
    recommended next case.
    """
    session = isolated("LyingSchemaAgent")
    _drain(session)
    report = session.report()

    cleaned = session.store.get(KEY_CLEANED)
    raw = session.store.get(KEY_RAW_INPUT)
    assert cleaned["columns"] == ["fabricated"]
    assert raw["columns"] != cleaned["columns"], "the data really is gone"
    assert all(row == {"fabricated": None} for row in cleaned["rows_data"])

    assert report["verdict"]["verdict"] == "ok", (
        "if this now fails, a check comparing output to source was added - "
        "that is the follow-up case; update this test and case 06's findings"
    )
    assert report["review_required"] is False


def test_a_crashing_stage_is_reported_as_an_isolation_failure(isolated):
    """A broken boundary and a broken contract need different responses."""
    session = isolated("CrashingSchemaAgent")
    _drain(session)

    assert "isolated stage failure" in session.error
    assert session.quarantined is False
    assert session.done is False


def test_the_runner_takes_the_identity_from_the_route_not_the_proxy(isolated):
    session = isolated()
    proxy = session._agents[1]
    assert isinstance(proxy, IsolatedAgent)
    proxy.name = RUNNER_IDENTITY          # the spec does not get to name itself

    _drain(session)

    assert not [r for r in session.receipts() if r["agent"] == RUNNER_IDENTITY]


# ---------------------------------------------------------------------------
# Residual limitations - executable. This is the "what if" half.
# ---------------------------------------------------------------------------

def test_residual_ambient_access_is_unchanged(isolated):
    """RESIDUAL. Same uid, same filesystem. Measured, never claimed contained."""
    session = isolated()
    _drain(session)

    ambient = _reached(_probe_event(session), "ambient")
    assert ambient, (
        "if this now fails, something narrowed the child's ambient authority - "
        "update case 06's residual-limitation section and this test"
    )


def test_residual_the_grant_is_unchanged(isolated):
    """RESIDUAL. Isolation narrows a grant by exactly nothing."""
    session = isolated()
    _drain(session)

    receipt = next(r for r in session.receipts() if r["agent"] == "schema_agent")
    assert receipt["keys_actually_read"] == receipt["granted_input_keys"]


def test_residual_an_un_isolated_stage_still_reaches_everything(
        data_dir, key_file_path):
    """RESIDUAL, and the sharper finding: partial isolation is partial.

    Isolating one stage of four moves that stage out of reach of the runner's
    objects. It does not reduce what a compromise of the other three obtains.
    """
    class ProbingTransformAgent(TransformAgent):
        def run(self, envelope, view, log):
            result = super().run(envelope, view, log)
            self._emit(log, action="probe", input_keys=[], output_keys=[],
                       status="ok", checks=hostile.run_probes(view),
                       message="in-process stage probe")
            return result

    session = RunSession(data_dir=str(data_dir),
                         isolate={"schema": _spec("ProbingSchemaAgent")})
    session.start_run(key_file_path)
    session._agents[2] = ProbingTransformAgent()
    _drain(session)

    probes = [e["checks"] for e in session.events() if e["action"] == "probe"]
    session.log.close()

    assert len(probes) == 2, "both stages must have reported"
    isolated_probes, in_process_probes = probes
    assert _reached(isolated_probes, "memory") == []
    assert _reached(in_process_probes, "memory"), (
        "if this now fails, every stage is isolated - update case 06's "
        "residual-limitation section and this test"
    )
    assert session.isolated_stages() == ["schema"]
