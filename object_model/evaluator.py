"""The manager: validate ready work, then derive a grant at use time.

Nothing here persists an authorization answer. The grant is computed from the
object's state and artifact map, the transition table, and the pinned skill
contract, at the moment the step runs.

Evaluator code is outside the attacker model cases 08-10 define. An adversary
who rewrites these functions defeats every arm identically and the comparison
would measure nothing.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Dict, List, Mapping, Optional, Tuple

from object_model.errors import AuthorizationError, ObjectContainedError
from object_model.ledger import ProductionLedger
from object_model.objects import Grant, QueueItem, WorkObject, save_object
from object_model.skills import REGISTRY, verify_pins


@dataclass(frozen=True)
class StepRecord:
    """What one completed step did. Returned for measurement, not authority."""

    skill: str
    grant: Grant
    produced_type: str
    produced_key: str
    new_state: str

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

# Where an object goes once the required skill has completed.
_NEXT_STATE: Dict[Tuple[str, str], str] = {}
NEXT_STATE: Mapping[Tuple[str, str], str] = MappingProxyType(_NEXT_STATE)

TERMINAL_STATE = "validated"


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
    _NEXT_STATE.clear()
    _NEXT_STATE.update({
        ("orders_table", "ingested"): "profiled",
        ("orders_table", "profiled"): "transformed",
        ("orders_table", "transformed"): TERMINAL_STATE,
    })


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


def artifact_map(obj: WorkObject,
                 ledger: Optional[ProductionLedger] = None) -> Dict[str, str]:
    """The type-to-key binding in force for this object.

    Two sources, and which one is used is exactly case 10's comparison: the
    object's own stored map, or a derivation over the runner-owned record of
    what completed steps produced.
    """
    if ledger is None:
        return dict(obj.artifacts)
    return ledger.map_for(obj.object_id)


def derive_grant(obj: WorkObject, skill_name: str,
                 pinned: Optional[Mapping[str, str]] = None,
                 ledger: Optional[ProductionLedger] = None) -> Grant:
    """Compute the answer. Nothing persisted holds it.

    When ``pinned`` is supplied the definition is verified against the version
    the run started with before it is used (case 09, C2). Callers that omit it
    get the baseline behaviour, which is what the unsafe measurements need.
    """
    skill = verify_pins(pinned, skill_name) if pinned is not None \
        else REGISTRY[skill_name]

    available = artifact_map(obj, ledger)
    read_keys = [available[t] for t in skill.reads if t in available]
    write_key = "" if skill.effects == "read_only" \
        else f"artifact.{skill.produces}"
    actions = ([ACTION_READ] if read_keys else []) + \
              ([ACTION_WRITE] if write_key else [])
    return Grant(read_keys=read_keys, write_key=write_key, actions=actions,
                 skill=skill_name)


def resolve(item: QueueItem, obj: WorkObject,
            pinned: Optional[Mapping[str, str]] = None,
            ledger: Optional[ProductionLedger] = None) -> Grant:
    """The whole authorization step, at use time."""
    return derive_grant(obj, validate(item, obj), pinned, ledger)


# ---------------------------------------------------------------------------
# The step lifecycle. Without this the artifact map never changes and
# "the workflow writes the map as it progresses" stays design intent rather
# than something an attack can be measured against (case 10).
# ---------------------------------------------------------------------------

def check_containment(obj: WorkObject,
                      ledger: Optional[ProductionLedger]) -> None:
    """Case 11: a contradicted production record stops the object.

    No new record and no new state. The check reads the record the lifecycle
    already has, and because the contradiction is persisted, the refusal
    outlives a retry, a reload and a resume without anything having to
    remember it.

    Deliberately object-scoped rather than grant-scoped: a conflict on a type
    this step never reads still stops the object. A record that cannot say
    which key holds one type is not trustworthy evidence about the others,
    and the cost of that choice is measured rather than argued.
    """
    if ledger is None:
        return
    conflicts = ledger.conflicts_for(obj.object_id)
    if conflicts:
        raise ObjectContainedError(
            f"object {obj.object_id!r} is contained: its production record "
            f"contradicts itself ({'; '.join(conflicts)}). no step runs "
            "against a record that cannot say which key holds a type"
        )


def run_step(obj: WorkObject, item: QueueItem, store_dir: str,
             pinned: Optional[Mapping[str, str]] = None,
             ledger: Optional[ProductionLedger] = None,
             contain: bool = True) -> StepRecord:
    """Resolve, execute, record what was produced, advance, persist.

    Execution is a stand-in: a skill that declares it produces type ``T`` is
    taken to have produced the canonical key for ``T``. Case 10 is about where
    the *binding* is recorded, not about what a transformation computes.

    Containment runs first, before validation and before any grant is derived,
    so a contained object never resolves authority at all. ``contain=False``
    exists so case 11's unsafe result stays reproducible - the same reason
    case 09's ``pinned`` is optional. It is not a deployment switch, and an
    adversary who can set it is already editing call sites, which is outside
    the attacker model cases 08-11 define.
    """
    if contain:
        check_containment(obj, ledger)
    skill_name = validate(item, obj)
    grant = derive_grant(obj, skill_name, pinned, ledger)
    skill = REGISTRY[skill_name]

    produced_type, produced_key = "", ""
    if grant.write_key:
        produced_type, produced_key = skill.produces, grant.write_key
        if ledger is not None:
            # Derived-map arm: the binding goes to the runner-owned record and
            # the object is not asked to remember it.
            ledger.record(obj.object_id, obj.state, skill_name,
                          produced_type, produced_key)
        else:
            # Stored-map arm: the object carries the binding, and carrying it
            # is what makes the object record authority-bearing.
            obj.artifacts[produced_type] = produced_key

    obj.state = _NEXT_STATE.get((obj.object_type, obj.state), TERMINAL_STATE)
    save_object(obj, store_dir)
    return StepRecord(skill=skill_name, grant=grant,
                      produced_type=produced_type, produced_key=produced_key,
                      new_state=obj.state)


def run_to_completion(obj: WorkObject, store_dir: str,
                      pinned: Optional[Mapping[str, str]] = None,
                      ledger: Optional[ProductionLedger] = None,
                      max_steps: int = 8,
                      contain: bool = True) -> List[StepRecord]:
    steps: List[StepRecord] = []
    for _ in range(max_steps):
        if obj.state == TERMINAL_STATE:
            break
        item = QueueItem(obj.object_id, required_skill(obj))
        steps.append(run_step(obj, item, store_dir, pinned, ledger, contain))
    return steps
