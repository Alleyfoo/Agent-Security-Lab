"""Arm B - the grant derived at use time from versioned premises.

No stored per-task authorization answer. The grant is computed when the step
runs, from the object's state and artifact map, the transition table, and the
skill's declared contract.

This does **not** eliminate stored authority. It stores different things:
skill contracts, object types, state transitions, artifact relationships. What
it removes is the persisted answer to "may this stage read this key".

Faithful to the concept note where the note is specific:

* §11 a skill declares one approved transformation, by artifact *type*;
* §12 the queue item is ready work; the manager validates the transition
  rather than executing what the item names;
* §13 workers are temporary and hold no standing authority;
* §24 this lives in the case directory, not in the product package.

Whether the manager's validation actually holds is measured, not assumed.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from agent_network_demo.contracts import (  # noqa: E402
    ACTION_READ_ARTIFACT, ACTION_WRITE_SCHEMA_PROFILE,
)

from common import AuthorizationError, Grant  # noqa: E402

NAME = "B: grant derived at use time"

# Artifact *types*. Skills declare these; only the object's map knows which
# concrete key currently holds one.
T_TABLE_PREVIEW = "table_preview"
T_SCHEMA_PROFILE = "schema_profile"
T_CLEANED_OUTPUT = "cleaned_output"
T_VALIDATION_VERDICT = "validation_verdict"
T_KEY_MATERIAL = "key_material"


@dataclass(frozen=True)
class Skill:
    """One approved transformation, declared over artifact types."""

    name: str
    reads: Tuple[str, ...]
    produces: str
    effects: str = "derive"


# ---------------------------------------------------------------------------
# The stored, authority-bearing records.
# ---------------------------------------------------------------------------

# Surface: skill contract. Shared by every object that uses the skill.
SKILL_REGISTRY: Dict[str, Skill] = {}

# Surface: route or grant definition. Arm B still has one - what it does not
# have is a stored *grant*. This says which skill is required next; it says
# nothing about which keys become readable.
TRANSITIONS: Dict[Tuple[str, str], str] = {}

# Surface: object type. Which skills an object of this type may ever run.
OBJECT_TYPES: Dict[str, Tuple[str, ...]] = {}


@dataclass
class WorkObject:
    """Surfaces: object type/state, and artifact relationship/map."""

    object_id: str
    object_type: str
    state: str
    artifacts: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class QueueItem:
    """Surface: ready-work record. A proposal, not an instruction."""

    object_id: str
    skill: str


def reset() -> None:
    """The approved deployment. Nothing here is per-task."""
    SKILL_REGISTRY.clear()
    SKILL_REGISTRY.update({
        "infer_schema": Skill("infer_schema", (T_TABLE_PREVIEW,),
                              T_SCHEMA_PROFILE),
        "clean_table": Skill("clean_table",
                             (T_TABLE_PREVIEW, T_SCHEMA_PROFILE),
                             T_CLEANED_OUTPUT),
        # A skill that legitimately reads cleaned_output. Its existence is the
        # realistic case and it matters: a dangerous-if-misapplied skill being
        # already present is one of the ways a single edit can be enough.
        "validate_chain": Skill("validate_chain",
                                (T_TABLE_PREVIEW, T_SCHEMA_PROFILE,
                                 T_CLEANED_OUTPUT),
                                T_VALIDATION_VERDICT, effects="read_only"),
    })

    TRANSITIONS.clear()
    TRANSITIONS.update({
        ("orders_table", "ingested"): "infer_schema",
        ("orders_table", "profiled"): "clean_table",
        ("orders_table", "transformed"): "validate_chain",
    })

    OBJECT_TYPES.clear()
    OBJECT_TYPES["orders_table"] = ("infer_schema", "clean_table",
                                    "validate_chain")


def surfaces() -> List[str]:
    return ["route or grant definition", "object type / state",
            "skill contract", "ready-work or queue record",
            "artifact relationship / map"]


# ---------------------------------------------------------------------------
# Object persistence. The architecture intends workflow objects to be saved,
# so they are - otherwise "survives resume" would be an assumption rather than
# a measurement.
# ---------------------------------------------------------------------------

def save_object(obj: WorkObject, store_dir: str) -> str:
    os.makedirs(store_dir, exist_ok=True)
    path = os.path.join(store_dir, f"{obj.object_id}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj.to_dict(), fh, indent=2)
    return path


def load_object(object_id: str, store_dir: str) -> WorkObject:
    path = os.path.join(store_dir, f"{object_id}.json")
    with open(path, "r", encoding="utf-8") as fh:
        return WorkObject(**json.load(fh))


# ---------------------------------------------------------------------------
# The evaluator. Off-limits to the attacker by this case's threat model.
# ---------------------------------------------------------------------------

def required_skill(obj: WorkObject) -> str:
    """What this object needs next, from its own type and state."""
    key = (obj.object_type, obj.state)
    if key not in TRANSITIONS:
        raise AuthorizationError(
            f"no transition for {obj.object_type!r} in state {obj.state!r}")
    return TRANSITIONS[key]


def validate(item: QueueItem, obj: WorkObject) -> str:
    """§12: the manager validates ready work rather than executing it.

    The queue item names a skill. The manager re-derives what the object
    actually requires and refuses anything else, so the item is a proposal.
    """
    if item.skill not in SKILL_REGISTRY:
        raise AuthorizationError(f"no approved skill named {item.skill!r}")
    if item.skill not in OBJECT_TYPES.get(obj.object_type, ()):
        raise AuthorizationError(
            f"object type {obj.object_type!r} does not permit {item.skill!r}")
    needed = required_skill(obj)
    if item.skill != needed:
        raise AuthorizationError(
            f"queue item names {item.skill!r} but {obj.object_type!r} in state "
            f"{obj.state!r} requires {needed!r}")
    return item.skill


def derive_grant(obj: WorkObject, skill_name: str) -> Grant:
    """Compute the answer. Nothing persisted holds it.

    Reads resolve through the object's own artifact map, so a declared type
    with no artifact behind it yields no key. Writes are named by convention
    from the produced type - a function, not a record.
    """
    skill = SKILL_REGISTRY[skill_name]
    read_keys = [obj.artifacts[t] for t in skill.reads if t in obj.artifacts]
    write_key = "" if skill.effects == "read_only" else f"artifact.{skill.produces}"
    actions = [ACTION_READ_ARTIFACT] if read_keys else []
    if write_key:
        actions.append(ACTION_WRITE_SCHEMA_PROFILE)
    return Grant(read_keys=read_keys, write_key=write_key, actions=actions,
                 source=NAME)


def resolve(item: QueueItem, obj: WorkObject) -> Grant:
    """The whole authorization step, at use time."""
    return derive_grant(obj, validate(item, obj))


# ---------------------------------------------------------------------------
# Mutations. One per surface, each the smallest single edit that could plausibly
# obtain the named capability. The harness applies them independently.
# ---------------------------------------------------------------------------

def mutate_transition(obj: WorkObject, target_key: str) -> str:
    """Point this object's current state at a skill with a wider contract."""
    TRANSITIONS[(obj.object_type, obj.state)] = "validate_chain"
    return "repointed the (orders_table, ingested) transition at validate_chain"


def mutate_object_state(obj: WorkObject, target_key: str) -> str:
    """Advance the object so a wider skill becomes the one it requires."""
    obj.state = "transformed"
    return "set the object's state to 'transformed' (requires validate_chain)"


def mutate_skill_contract(obj: WorkObject, target_key: str) -> str:
    """Widen the approved skill's declared reads by one artifact type."""
    skill = SKILL_REGISTRY["infer_schema"]
    added = _type_of(target_key)
    SKILL_REGISTRY["infer_schema"] = Skill(
        skill.name, tuple(skill.reads) + (added,), skill.produces, skill.effects)
    return f"added type {added!r} to infer_schema's declared reads"


def mutate_queue_record(obj: WorkObject, target_key: str) -> str:
    """Name a wider skill directly in the ready-work item."""
    return "queue item rewritten to name validate_chain"


def mutate_artifact_map(obj: WorkObject, target_key: str) -> str:
    """Redirect a type the skill already reads at a different key.

    No policy changes at all. The map is the indirection from declared type to
    concrete key, which makes it authority-bearing.
    """
    obj.artifacts[T_TABLE_PREVIEW] = target_key
    return f"repointed the object's {T_TABLE_PREVIEW!r} entry at {target_key!r}"


def _type_of(key: str) -> str:
    return {"artifact.raw_input": T_TABLE_PREVIEW,
            "artifact.schema_profile": T_SCHEMA_PROFILE,
            "artifact.cleaned_output": T_CLEANED_OUTPUT,
            "artifact.key_material": T_KEY_MATERIAL}[key]


MUTATIONS = {
    "route or grant definition": mutate_transition,
    "object type / state": mutate_object_state,
    "skill contract": mutate_skill_contract,
    "ready-work or queue record": mutate_queue_record,
    "artifact relationship / map": mutate_artifact_map,
}

SCOPES = {
    "route or grant definition":
        "process lifetime; future independent runs of every orders_table object",
    "object type / state":
        "current object lifetime, including retries and resume - the record is "
        "persisted",
    "skill contract":
        "deployment lifetime; every object that runs this skill, until the "
        "registry is redeployed",
    "ready-work or queue record": "current step",
    "artifact relationship / map":
        "current object lifetime, including retries and resume",
}

DETECTION = {
    "route or grant definition":
        "the manager re-derives the required skill, so a transition edit that "
        "disagrees with the queue item is refused by name; an edit made before "
        "the item is enqueued is consistent and is not noticed",
    "object type / state":
        "nothing. A state value is a fact about the object, and the evaluator "
        "has no independent account of what state it should be in",
    "skill contract":
        "nothing in this arm. Case 09 asks whether an independent authority "
        "can say which skill version is legitimate",
    "ready-work or queue record":
        "the manager's re-derivation, by construction",
    "artifact relationship / map":
        "nothing. The map is the object's own record of what it holds",
}
