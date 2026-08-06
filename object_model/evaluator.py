"""The manager: validate ready work, then derive a grant at use time.

Nothing here persists an authorization answer. The grant is computed from the
object's state and artifact map, the transition table, and the pinned skill
contract, at the moment the step runs.

Evaluator code is outside the attacker model cases 08-10 define. An adversary
who rewrites these functions defeats every arm identically and the comparison
would measure nothing.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Dict, Mapping, Optional, Tuple

from object_model.errors import AuthorizationError
from object_model.objects import Grant, QueueItem, WorkObject
from object_model.skills import REGISTRY, verify_pins

ACTION_READ = "read_artifact"
ACTION_WRITE = "write_artifact"

# Which skill an object of this type, in this state, requires next. A stored
# policy record - arm B still has one. What it does not have is a stored
# *grant*: this says nothing about which keys become readable.
_TRANSITIONS: Dict[Tuple[str, str], str] = {}
TRANSITIONS: Mapping[Tuple[str, str], str] = MappingProxyType(_TRANSITIONS)

# Which skills an object type may ever run.
_OBJECT_TYPES: Dict[str, Tuple[str, ...]] = {}
OBJECT_TYPES: Mapping[str, Tuple[str, ...]] = MappingProxyType(_OBJECT_TYPES)


def reset_workflow() -> None:
    _TRANSITIONS.clear()
    _TRANSITIONS.update({
        ("orders_table", "ingested"): "infer_schema",
        ("orders_table", "profiled"): "clean_table",
        ("orders_table", "transformed"): "validate_chain",
    })
    _OBJECT_TYPES.clear()
    _OBJECT_TYPES["orders_table"] = ("infer_schema", "clean_table",
                                     "validate_chain")


def required_skill(obj: WorkObject) -> str:
    """What this object needs next, from its own type and state."""
    key = (obj.object_type, obj.state)
    if key not in TRANSITIONS:
        raise AuthorizationError(
            f"no transition for {obj.object_type!r} in state {obj.state!r}")
    return TRANSITIONS[key]


def validate(item: QueueItem, obj: WorkObject) -> str:
    """§12: the manager validates ready work rather than executing it."""
    if item.skill not in REGISTRY:
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


def derive_grant(obj: WorkObject, skill_name: str,
                 pinned: Optional[Mapping[str, str]] = None) -> Grant:
    """Compute the answer. Nothing persisted holds it.

    When ``pinned`` is supplied the definition is verified against the version
    the run started with before it is used (case 09, C2). Callers that omit it
    get the baseline behaviour, which is what the unsafe measurements need.
    """
    skill = verify_pins(pinned, skill_name) if pinned is not None \
        else REGISTRY[skill_name]

    read_keys = [obj.artifacts[t] for t in skill.reads if t in obj.artifacts]
    write_key = "" if skill.effects == "read_only" \
        else f"artifact.{skill.produces}"
    actions = ([ACTION_READ] if read_keys else []) + \
              ([ACTION_WRITE] if write_key else [])
    return Grant(read_keys=read_keys, write_key=write_key, actions=actions,
                 skill=skill_name)


def resolve(item: QueueItem, obj: WorkObject,
            pinned: Optional[Mapping[str, str]] = None) -> Grant:
    """The whole authorization step, at use time."""
    return derive_grant(obj, validate(item, obj), pinned)
