"""Arm B - authority follows the configured workflow.

    trigger -> predefined action -> output -> predefined action -> ...

A minimal reference model of the workflow-automation idea. **Not Power
Automate**, and nothing here is evidence about any product. What is modelled is
the architectural idea: a graph of work defined ahead of time, where a step's
authority comes from its own configuration and from the credential its
connection holds.

Competence checklist from the contract, and where each is met:

* steps pass references, not payloads       -> `inputs` are artifact keys; the
                                               store is read by reference and
                                               no step copies content forward
* per-connection credentials, scoped        -> CONNECTIONS, two of them, each
                                               scoped to a resource set. There
                                               is deliberately no credential
                                               with access to everything
* dynamic references permitted              -> a step may name any key; whether
                                               it may *reach* it is the
                                               connection's business
* the configuration is checked at use time  -> resolve() re-reads it per step

The architectural property under test: **authority is configured, and it is two
records rather than one.** What a step names and what its credential may reach
are independent, and both must permit. That is not a favour granted to this
arm - it is how such systems actually work, and the contract's fairness rule
forbids removing it to make the comparison tidier.

Fail-closed on a referenced-but-unreachable input, which is the competent
behaviour: an action that references data its connection cannot read errors,
rather than silently proceeding with the subset it can reach. That choice is
load-bearing for the measurement and a test pins it.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import Dict, List, Set, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from case12_common import (  # noqa: E402
    CONFIGURED, KEY_MATERIAL, SCOPE_WORKFLOW, WORKLOAD, AuthorizationError,
    Grant, Store,
)

NAME = "B: authority follows the configured workflow"
AUTHORITY_KIND = CONFIGURED

CONN_ORDERS = "conn_orders"
CONN_KEYS = "conn_keys"


@dataclass
class ConfiguredStep:
    """One predefined action in the graph."""

    name: str
    action: str
    connection: str
    inputs: Tuple[str, ...]
    output: str


# ---------------------------------------------------------------------------
# The two authority-bearing records, plus the binding between them.
# ---------------------------------------------------------------------------

WORKFLOW: Dict[str, ConfiguredStep] = {}
CONNECTIONS: Dict[str, Set[str]] = {}


def reset() -> None:
    WORKFLOW.clear()
    CONNECTIONS.clear()
    for stage in WORKLOAD:
        WORKFLOW[stage.name] = ConfiguredStep(
            name=stage.name, action=f"{stage.name}_action",
            connection=CONN_ORDERS, inputs=tuple(stage.reads),
            output=stage.produces,
        )
    # Scoped per connection, not one credential for everything. The orders
    # connection reaches the workflow's own artifacts; the key connection
    # reaches the secret and exists because a real tenant has more than one.
    CONNECTIONS[CONN_ORDERS] = {s.produces for s in WORKLOAD} | {
        k for s in WORKLOAD for k in s.reads}
    CONNECTIONS[CONN_KEYS] = {KEY_MATERIAL}


def surfaces() -> List[str]:
    return ["step configuration", "connection scope", "connection binding"]


def resolve(step_name: str) -> Grant:
    """Both records must permit. Neither alone is authority."""
    step = WORKFLOW.get(step_name)
    if step is None:
        raise AuthorizationError(f"no configured step named {step_name!r}")
    scope = CONNECTIONS.get(step.connection)
    if scope is None:
        raise AuthorizationError(
            f"step {step_name!r} names unknown connection {step.connection!r}")
    unreachable = [k for k in step.inputs if k not in scope]
    if unreachable:
        # Fail closed. The action references data its connection cannot read,
        # so it errors rather than proceeding with what it can reach.
        raise AuthorizationError(
            f"step {step_name!r} references {unreachable} which connection "
            f"{step.connection!r} cannot reach")
    if step.output and step.output not in scope:
        raise AuthorizationError(
            f"step {step_name!r} writes {step.output!r} which connection "
            f"{step.connection!r} cannot reach")
    return Grant(read_keys=list(step.inputs), write_key=step.output,
                 source=NAME)


def execute(step_name: str, store: Store) -> Grant:
    grant = resolve(step_name)
    for key in grant.read_keys:
        store.read(key)
    if grant.write_key:
        store.write(grant.write_key, {"produced_by": step_name})
    return grant


def run_workflow(store: Store) -> Dict[str, Grant]:
    return {stage.name: execute(stage.name, store) for stage in WORKLOAD}


# ---------------------------------------------------------------------------
# Mutations. Each is one stored edit; obtaining the capability may need more
# than one, and measuring how many is the point.
# ---------------------------------------------------------------------------

def mutate_step_configuration(target_key: str) -> str:
    step = WORKFLOW["schema"]
    WORKFLOW["schema"] = ConfiguredStep(
        name=step.name, action=step.action, connection=step.connection,
        inputs=tuple(step.inputs) + (target_key,), output=step.output)
    return f"added {target_key!r} to the schema step's configured inputs"


def mutate_connection_scope(target_key: str) -> str:
    CONNECTIONS[CONN_ORDERS].add(target_key)
    return f"added {target_key!r} to {CONN_ORDERS!r}'s scope"


def mutate_connection_binding(target_key: str) -> str:
    step = WORKFLOW["schema"]
    WORKFLOW["schema"] = ConfiguredStep(
        name=step.name, action=step.action, connection=CONN_KEYS,
        inputs=step.inputs, output=step.output)
    return f"rebound the schema step to {CONN_KEYS!r}"


MUTATIONS = {
    "step configuration": mutate_step_configuration,
    "connection scope": mutate_connection_scope,
    "connection binding": mutate_connection_binding,
}

# Combinations worth measuring, because single edits are expected to fail here
# and the interesting number is the smallest set that works.
COMBINATIONS: Dict[str, Tuple[str, ...]] = {
    "step configuration": ("step configuration",),
    "connection scope": ("connection scope",),
    "connection binding": ("connection binding",),
    "step configuration + connection scope":
        ("step configuration", "connection scope"),
    "step configuration + connection binding":
        ("step configuration", "connection binding"),
}

SCOPES = {name: SCOPE_WORKFLOW for name in COMBINATIONS}

DETECTION = {
    "step configuration":
        "the connection refuses at use time and names the unreachable key. "
        "Refusal, not detection of tampering: the message is identical to a "
        "misconfiguration.",
    "connection scope":
        "nothing - and nothing happens either, because no step references the "
        "key. A widened credential sits inert until some step names it.",
    "connection binding":
        "the step's legitimate inputs become unreachable and it fails loudly. "
        "The workflow stops, which is availability loss rather than detection.",
    "step configuration + connection scope":
        "nothing. Both records now agree, and agreement is what the engine "
        "checks for.",
    "step configuration + connection binding":
        "the step still fails: the target is reachable but the legitimate "
        "inputs are not.",
}

PERSISTENCE = {
    name: "survives retry, resume and later runs - it is the workflow "
          "definition, and every run of it inherits the edit"
    for name in COMBINATIONS
}
