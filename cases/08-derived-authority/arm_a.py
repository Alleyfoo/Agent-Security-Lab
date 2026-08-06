"""Arm A - the stored per-stage grant. The production model.

Not a strawman: the record type is `demo_runner.Route` and the write key comes
from `contracts.write_key_for`, exactly as `RunSession._envelope_for` resolves
a grant. What is stripped away is the workflow machinery, so the comparison is
about how a grant is decided and nothing else.

The stored record *is* the authorization answer for the task. Reading it is the
whole resolution step.
"""

from __future__ import annotations

import os
import sys
from typing import Dict, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from agent_network_demo.agents import (  # noqa: E402
    KEY_CLEANED, KEY_RAW_INPUT, KEY_SCHEMA,
)
from agent_network_demo.contracts import (  # noqa: E402
    ACTION_READ_ARTIFACT, ACTION_WRITE_SCHEMA_PROFILE, CONTRACT_SCHEMA_PROFILE,
    write_key_for,
)
from agent_network_demo.demo_runner import Route  # noqa: E402

from common import Grant  # noqa: E402

NAME = "A: stored per-stage grant"

# The one authority-bearing store in this arm. Same shape as
# demo_runner._WORKFLOW_ROUTES, holding the answer for each stage.
GRANT_TABLE: Dict[str, Route] = {}


def reset() -> None:
    GRANT_TABLE.clear()
    GRANT_TABLE["schema"] = Route(
        agent="schema_agent", handoff_type="schema_request",
        input_keys=(KEY_RAW_INPUT,), output_contract=CONTRACT_SCHEMA_PROFILE,
        allowed_actions=(ACTION_READ_ARTIFACT, ACTION_WRITE_SCHEMA_PROFILE),
        next_stage="transform",
    )


def surfaces() -> List[str]:
    """The stored, authority-bearing records this arm has."""
    return ["route or grant definition"]


def resolve(stage: str, present_keys: List[str]) -> Grant:
    """Look the answer up. ``present_keys`` is accepted so both arms take the
    same inputs; this arm does not consult it, which is the point."""
    route = GRANT_TABLE[stage]
    return Grant(
        read_keys=list(route.input_keys),
        write_key=write_key_for(route.output_contract),
        actions=list(route.allowed_actions),
        source=NAME,
    )


# ---------------------------------------------------------------------------
# Mutations. One function per surface, each the smallest single edit that could
# obtain the named capability. They return a description for the report.
# ---------------------------------------------------------------------------

def mutate_grant_definition(target_key: str) -> str:
    route = GRANT_TABLE["schema"]
    GRANT_TABLE["schema"] = Route(
        agent=route.agent, handoff_type=route.handoff_type,
        input_keys=tuple(route.input_keys) + (target_key,),
        output_contract=route.output_contract,
        allowed_actions=route.allowed_actions, next_stage=route.next_stage,
    )
    return f"appended {target_key!r} to the schema stage's input_keys"


MUTATIONS = {
    "route or grant definition": mutate_grant_definition,
}

# Where a successful mutation reaches, on the case's scope scale. The table is
# module state, so it outlives the run that was attacked - case 03 attack C
# measured exactly this end to end.
SCOPES = {
    "route or grant definition": "process lifetime; future independent runs",
}

# What, if anything, inside this arm would notice.
DETECTION = {
    "route or grant definition":
        "nothing before the run starts. RunSession fingerprints the table at "
        "start_run and re-checks it per step (case 03 C3), so tampering "
        "*during* a run is caught - but a pre-run edit is fingerprinted as if "
        "it were the policy, which is case 03's unclosed residual.",
}
