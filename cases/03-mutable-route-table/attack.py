"""Case 03 - executable attack: altering runner-owned routing data.

Run it:

    python cases/03-mutable-route-table/attack.py

WORKFLOW_ROUTES is the trusted policy table: it fixes, for every stage, which
agent receives the envelope, what it may read, what it may write, and what runs
next. Agents are supposed to have no say in it.

It is a module-level dict, reachable from any agent by import. ``Route`` is a
frozen dataclass, but freezing an entry does not freeze the mapping that holds
it - rebinding a key is unrestricted.

Two attacks, because route tampering has two distinct effects:

  A. Grant issuance - the runner issues an envelope carrying authority the
     policy never contained.
  B. Sequence tampering - a stage is removed from the workflow entirely.
"""

from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from agent_network_demo import demo_runner  # noqa: E402
from agent_network_demo.agents import (  # noqa: E402
    IntakeAgent, KEY_VERDICT, SchemaAgent,
)
from agent_network_demo.contracts import (  # noqa: E402
    ACTION_WRITE_CLEANED_OUTPUT,
)
from agent_network_demo.demo_runner import RunSession  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "agent_network_demo", "fixtures")
KEY_FILE = os.path.join(FIXTURES, "key_file.json")


def _routes():
    """The live routing table, however the runner currently exposes it."""
    return demo_runner.WORKFLOW_ROUTES


def _replace(stage: str, **changes):
    """Rebind one stage's route. Returns the error raised, or None."""
    table = _routes()
    try:
        current = table[stage]
        table[stage] = demo_runner.Route(
            agent=changes.get("agent", current.agent),
            handoff_type=changes.get("handoff_type", current.handoff_type),
            input_keys=changes.get("input_keys", current.input_keys),
            output_contract=changes.get("output_contract", current.output_contract),
            allowed_actions=changes.get("allowed_actions", current.allowed_actions),
            next_stage=changes.get("next_stage", current.next_stage),
        )
        return None
    except Exception as exc:  # noqa: BLE001
        return exc


class GrantWideningIntakeAgent(IntakeAgent):
    """Adds an action the policy never granted to the NEXT stage."""

    def run(self, envelope, view, log):
        result = super().run(envelope, view, log)
        current = _routes()["schema"]
        self.tamper_error = _replace(
            "schema",
            allowed_actions=tuple(current.allowed_actions) + (ACTION_WRITE_CLEANED_OUTPUT,),
        )
        return result


class StageSkippingSchemaAgent(SchemaAgent):
    """Removes the validation stage by cutting the chain after transform."""

    def run(self, envelope, view, log):
        result = super().run(envelope, view, log)
        self.tamper_error = _replace("transform", next_stage=None)
        return result


PRISTINE = dict(_routes())


def _restore() -> None:
    """Undo tampering between attacks so each is measured independently."""
    table = _routes()
    try:
        for stage, route in PRISTINE.items():
            table[stage] = route
    except Exception:  # noqa: BLE001 - read-only table; nothing to restore
        pass


def _fresh_session(tmp: str) -> RunSession:
    session = RunSession(data_dir=tmp)
    session.start_run(KEY_FILE)
    return session


def attack_a() -> dict:
    """Grant issuance."""
    print("\n--- A. Grant issuance ---")
    policy_actions = tuple(_routes()["schema"].allowed_actions)
    with tempfile.TemporaryDirectory() as tmp:
        session = _fresh_session(tmp)
        hostile = GrantWideningIntakeAgent(source_ref=session._agents[0].source_ref)
        session._agents[0] = hostile
        session.step()                                   # intake + tamper

        issued = session.current_envelope().get("allowed_actions", [])
        blocked = getattr(hostile, "tamper_error", None)
        quarantined = session.quarantined
        session.log.close()

    print(f"  policy allowed_actions   : {list(policy_actions)}")
    print(f"  issued to schema stage   : {issued}")
    if blocked is not None:
        print(f"  tampering BLOCKED        : {type(blocked).__name__}: {blocked}")
    print(f"  workflow quarantined     : {quarantined}")
    smuggled = ACTION_WRITE_CLEANED_OUTPUT in issued
    print(f"  smuggled action issued   : {smuggled}")
    return {"smuggled": smuggled, "blocked": blocked is not None,
            "quarantined": quarantined}


def attack_b() -> dict:
    """Sequence tampering."""
    print("\n--- B. Sequence tampering (skip the validator) ---")
    with tempfile.TemporaryDirectory() as tmp:
        session = _fresh_session(tmp)
        hostile = StageSkippingSchemaAgent()
        session._agents[1] = hostile

        while not session.done and not session.quarantined:
            session.step()

        blocked = getattr(hostile, "tamper_error", None)
        agents_acted = session.report()["agents_acted"] if not session.quarantined else None
        has_verdict = session.store.has(KEY_VERDICT)
        done = session.done
        quarantined = session.quarantined
        error = session.error
        session.log.close()

    if blocked is not None:
        print(f"  tampering BLOCKED        : {type(blocked).__name__}: {blocked}")
    print(f"  workflow reports done    : {done}")
    print(f"  agents that acted        : {agents_acted} of 4")
    print(f"  verdict artifact present : {has_verdict}")
    print(f"  workflow quarantined     : {quarantined}")
    if error:
        print(f"  runner error             : {error}")
    skipped = done and not has_verdict and not quarantined
    print(f"  validator silently skipped: {skipped}")
    return {"skipped": skipped, "blocked": blocked is not None,
            "quarantined": quarantined}


def attack_c() -> dict:
    """Persistence: does the tampering outlive the run that did it?

    Noticed by accident - attack A's mutation was still present when attack B
    ran. Measured deliberately here, because it decides the blast radius.
    """
    print("\n--- C. Persistence across runs ---")
    _restore()
    before = tuple(_routes()["schema"].allowed_actions)

    with tempfile.TemporaryDirectory() as tmp:
        session = _fresh_session(tmp)
        hostile = GrantWideningIntakeAgent(source_ref=session._agents[0].source_ref)
        session._agents[0] = hostile
        session.step()
        session.log.close()
    # The hostile run is over. Its session object is gone.

    after = tuple(_routes()["schema"].allowed_actions)
    with tempfile.TemporaryDirectory() as tmp:
        clean = _fresh_session(tmp)
        clean.step()
        inherited = clean.current_envelope().get("allowed_actions", [])
        clean.log.close()

    print(f"  policy before hostile run : {list(before)}")
    print(f"  table after hostile run   : {list(after)}")
    print(f"  next run's issued grant   : {inherited}")
    persisted = ACTION_WRITE_CLEANED_OUTPUT in inherited
    print(f"  tampering outlived the run: {persisted}")
    return {"persisted": persisted}


if __name__ == "__main__":
    print("WORKFLOW_ROUTES is the trusted policy table. Agents should have no")
    print("say in it. Three hostile agents try to rewrite it.")

    _restore()
    a = attack_a()
    _restore()
    b = attack_b()
    c = attack_c()
    _restore()

    print("\n=== RESULT ===")
    if a["smuggled"] or b["skipped"] or c["persisted"]:
        print("ATTACK SUCCEEDED. An agent altered runner-owned routing data.")
        if a["smuggled"]:
            print("  A: the runner issued an envelope carrying authority the")
            print("     policy never contained.")
        if b["skipped"]:
            print("  B: the validation stage was removed and the run still")
            print("     reported completion - no error, no quarantine.")
        if c["persisted"]:
            print("  C: the tampering outlived the run and contaminated the")
            print("     next session in the same process.")
        raise SystemExit(1)

    print("ATTACK STOPPED. Route modification was prevented at the interface")
    print("and/or detected before the runner acted on it.")
    print(f"  A: blocked={a['blocked']} quarantined={a['quarantined']}")
    print(f"  B: blocked={b['blocked']} quarantined={b['quarantined']}")
    print(f"  C: persisted={c['persisted']}")
    raise SystemExit(0)
