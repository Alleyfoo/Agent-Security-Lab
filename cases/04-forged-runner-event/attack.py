"""Case 04 - executable attack: forged runner-labelled audit event.

Run it:

    python cases/04-forged-runner-event/attack.py

The event log is the record of who did what. Every entry carries an ``agent``
field, which reads like an attribution and is in fact a caller-supplied string:
``EventLog.append`` authenticates nothing (baseline finding L4).

Four attacks, because forging the record and corrupting the decision are two
different effects and must be measured separately:

  A1. Forged event through the log handle the runner passes in.
  A2. The agent renames itself, so the runner writes the lie on its behalf.
  B.  Does any of it change the authorization decision? (Measured, not assumed.)
  C.  Level 2 reach-around: append straight to the EventLog object.

B is the point of the case as much as A is. "The audit log was forged" collapses
two effects, and the collapse hides the only operationally useful fact - which
of them changed a decision.
"""

from __future__ import annotations

import gc
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from agent_network_demo.agents import (  # noqa: E402
    SchemaAgent, TransformAgent,
)
from agent_network_demo.demo_runner import RunSession  # noqa: E402
from agent_network_demo.event_log import Event, EventLog  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "agent_network_demo", "fixtures")
KEY_FILE = os.path.join(FIXTURES, "key_file.json")

RUNNER = "trusted_runner"


def _forged_receipt(run_id: str, about: str) -> Event:
    """An event shaped exactly like the one the runner writes after a step."""
    return Event(
        run_id=run_id, agent=RUNNER, action="step_receipt",
        input_keys=[], output_keys=[], status="ok",
        checks={"agent": about, "contract_result": "passed", "status": "ok"},
        message=f"Receipt for {about}: passed.",
    )


class ForgingTransformAgent(TransformAgent):
    """A1 - appends a runner receipt for a stage that has not run."""

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

    name = RUNNER


class ReachAroundTransformAgent(TransformAgent):
    """C - Level 2: find the EventLog in the object graph and append to it."""

    def run(self, envelope, view, log):
        result = super().run(envelope, view, log)
        raw = next((obj for obj in gc.get_objects()
                    if isinstance(obj, EventLog) and obj.run_id == log.run_id),
                   None)
        self.reached = raw is not None
        self.forge_error = None
        if raw is not None:
            try:
                raw.append(_forged_receipt(raw.run_id, "validation_agent"))
            except Exception as exc:  # noqa: BLE001
                self.forge_error = exc
        return result


def _fresh_session(tmp: str) -> RunSession:
    session = RunSession(data_dir=tmp)
    session.start_run(KEY_FILE)
    return session


def _drain(session: RunSession) -> None:
    while not session.done and not session.quarantined and session.error is None:
        session.step()


def _runner_labelled(session: RunSession) -> list:
    return [e for e in session.events() if e["agent"] == RUNNER]


def attack_a1() -> dict:
    """Forged event through the handed log."""
    print("\n--- A1. Forged runner receipt through the handed log ---")
    with tempfile.TemporaryDirectory() as tmp:
        session = _fresh_session(tmp)
        hostile = ForgingTransformAgent()
        session._agents[2] = hostile

        _drain(session)

        forge_error = getattr(hostile, "forge_error", None)
        labelled = _runner_labelled(session)
        receipts = session.receipts()
        halted = session.error
        session.log.close()

    print(f"  events labelled {RUNNER}: {len(labelled)}")
    print(f"  receipts the runner actually wrote: {len(receipts)}")
    if forge_error is not None:
        print(f"  forgery BLOCKED         : {type(forge_error).__name__}: "
              f"{forge_error}")
    if halted:
        print(f"  workflow halted         : {halted}")
    landed = len(labelled) > len(receipts)
    print(f"  forged event in the log : {landed}")
    return {"landed": landed, "blocked": forge_error is not None}


def attack_a2() -> dict:
    """The agent renames itself."""
    print("\n--- A2. The agent renames itself to the trusted runner ---")
    with tempfile.TemporaryDirectory() as tmp:
        session = _fresh_session(tmp)
        session._agents[1] = SelfRenamingSchemaAgent()

        _drain(session)

        receipts = session.receipts()
        halted = session.error
        quarantined = session.quarantined
        session.log.close()

    claimed = [r for r in receipts if r["agent"] == RUNNER]
    print(f"  receipts attributed to {RUNNER}: {len(claimed)}")
    if halted:
        print(f"  workflow halted         : {halted}")
    print(f"  workflow quarantined    : {quarantined}")
    stolen = bool(claimed)
    print(f"  runner identity taken   : {stolen}")
    return {"stolen": stolen, "halted": bool(halted)}


def attack_b() -> dict:
    """Does forging the record corrupt the authorization decision?

    Forged here under agent labels, appended straight to the log - the
    strongest in-process forgery the runner's own tally does not cover, so this
    measurement means the same thing before and after the control.
    """
    print("\n--- B. Authorization decision, measured separately ---")
    with tempfile.TemporaryDirectory() as tmp:
        clean = _fresh_session(tmp)
        _drain(clean)
        clean_verdict = clean.report()["verdict"]
        clean.log.close()

    with tempfile.TemporaryDirectory() as tmp:
        forged = _fresh_session(tmp)
        for _ in range(3):
            forged.step()
        for agent in ("intake_agent", "schema_agent", "transform_agent"):
            forged.log.append(Event(
                run_id=forged.run_id, agent=agent, action="write_artifact",
                input_keys=[], output_keys=["artifact.evil"], status="ok",
                checks={"allowed_write": True, "contract_result": "passed"},
                message="forged permission claim",
            ))
        forged.step()                                  # validation
        forged_verdict = forged.report()["verdict"]
        forged_events = len(forged.events())
        forged.log.close()

    print(f"  forged permission events in the log: 3 of {forged_events}")
    print(f"  clean  verdict : {clean_verdict['verdict']} "
          f"{clean_verdict['checks']}")
    print(f"  forged verdict : {forged_verdict['verdict']} "
          f"{forged_verdict['checks']}")
    changed = clean_verdict != forged_verdict
    print(f"  decision corrupted: {changed}")
    return {"changed": changed}


def attack_c() -> dict:
    """Level 2 reach-around."""
    print("\n--- C. Level 2: append straight to the EventLog object ---")
    with tempfile.TemporaryDirectory() as tmp:
        session = _fresh_session(tmp)
        hostile = ReachAroundTransformAgent()
        session._agents[2] = hostile

        _drain(session)

        reached = getattr(hostile, "reached", False)
        forge_error = getattr(hostile, "forge_error", None)
        labelled = _runner_labelled(session)
        receipts = session.receipts()
        quarantined = session.quarantined
        error = session.error
        session.log.close()

    print(f"  EventLog found in the object graph: {reached}")
    if forge_error is not None:
        print(f"  append BLOCKED          : {type(forge_error).__name__}: "
              f"{forge_error}")
    print(f"  events labelled {RUNNER}: {len(labelled)}")
    print(f"  receipts the runner actually wrote: {len(receipts)}")
    print(f"  workflow quarantined    : {quarantined}")
    if error:
        print(f"  runner error            : {error}")
    undetected = len(labelled) > len(receipts) and not quarantined
    print(f"  forged and unnoticed    : {undetected}")
    return {"undetected": undetected, "quarantined": quarantined,
            "reached": reached}


if __name__ == "__main__":
    print("EventLog.append authenticates nothing: Event.agent is whatever the")
    print("caller says it is. Two effects, measured separately.")

    a1 = attack_a1()
    a2 = attack_a2()
    b = attack_b()
    c = attack_c()

    print("\n=== RESULT ===")
    print("Effect 2 - authorization decision")
    if b["changed"]:
        print("  CORRUPTED. The verdict differs under forged events, so the")
        print("  decision reads the log. This contradicts B18 - stop and fix")
        print("  the runner before touching the audit record.")
    else:
        print("  UNCHANGED. The verdict under forged events is identical to a")
        print("  clean run: ValidationAgent derives authorization from the")
        print("  runner's receipt ledger and never from log events (B18).")
        print("  Forging the record is not the same incident as corrupting")
        print("  the decision, and this case exists to keep them apart.")

    print("\nEffect 1 - audit record")
    if a1["landed"] or a2["stolen"] or c["undetected"] or b["changed"]:
        print("  FORGED. An agent wrote the trusted runner's identity into the")
        print("  audit record.")
        if a1["landed"]:
            print("    A1: an event indistinguishable from a runner receipt sits")
            print("        in the log for a stage that had not run.")
        if a2["stolen"]:
            print("    A2: the runner wrote its own identity into the receipt")
            print("        ledger on the agent's behalf - one renamed attribute.")
        if c["undetected"]:
            print("    C:  a Level 2 append went unnoticed.")
        raise SystemExit(1)

    print("  PREVENTED at the interface, DETECTED past it.")
    print(f"    A1: blocked={a1['blocked']}")
    print(f"    A2: halted={a2['halted']} identity taken=False")
    print(f"    C:  reached={c['reached']} quarantined={c['quarantined']}")
    raise SystemExit(0)
