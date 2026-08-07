"""Arm C - authority is derived for a transformation of one object.

    canonical artifacts -> object state -> required transformation
        -> approved skill -> task-scoped worker -> new artifact/state

A thin adapter over `object_model/`, the candidate this laboratory has been
measuring since case 08. **No object_model code is changed by this case.**
Cases 10 and 11 published tables taken against it, and retrofitting anything
here would change a published measurement - the rule case 08's frozen `arm_b`
already established.

Two adaptations are needed to run the shared workload, and both are stated
rather than hidden:

* **Intake is a seed, not a transition.** `object_model`'s workflow table has
  three transitions and is frozen at what cases 10 and 11 measured. Its intake
  is the object arriving with artifacts, which is literally what
  `ProductionLedger.seed(at_state="intake", skill="intake")` records. Arms A
  and B run intake as a step. So the arms are compared on the artifacts they
  end with and on the grant the schema step resolves - not on step count.
* **The derived form is used, not the stored map.** The contract adjudicated
  deriving the binding as *the architectural feature under test*, so this arm
  runs with a ProductionLedger. That also means case 11's containment is
  active, which is correct: it is a control this arm's record can express and
  the others' cannot.
"""

from __future__ import annotations

import os
import sys
from typing import Dict, List

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from case12_common import (  # noqa: E402
    DERIVED, KEY_MATERIAL, KEY_RAW, SCOPE_DEPLOYMENT, SCOPE_OBJECT,
    AuthorizationError, Grant, Store,
)

from object_model import (  # noqa: E402
    QueueItem, WorkObject, pin_versions, reset_registry, save_object,
)
from object_model import evaluator, skills  # noqa: E402
from object_model.ledger import ProductionLedger, ProductionRecord  # noqa: E402

NAME = "C: authority derived for one transformation"
AUTHORITY_KIND = DERIVED

OBJ = "obj_812"

# stage name in the shared workload -> the skill that performs it
SKILL_OF_STAGE = {
    "schema": "infer_schema",
    "transform": "clean_table",
    "validate": "validate_chain",
}

_state: Dict[str, object] = {}


def reset(store_dir: str) -> None:
    reset_registry()
    evaluator.reset_workflow()
    obj = WorkObject(OBJ, "orders_table", "ingested", {})
    ledger = ProductionLedger(path=os.path.join(store_dir, "ledger.jsonl"))
    # Intake: the object arrives carrying its source artifact, and the secret
    # exists in the world exactly as it does for the other two arms.
    ledger.seed(OBJ, {skills.T_TABLE_PREVIEW: KEY_RAW,
                      skills.T_KEY_MATERIAL: KEY_MATERIAL})
    save_object(obj, store_dir)
    _state.clear()
    _state.update({
        "obj": obj, "ledger": ledger, "store_dir": store_dir,
        "pins": pin_versions(evaluator.OBJECT_TYPES["orders_table"]),
    })


def surfaces() -> List[str]:
    return ["artifact binding record", "skill contract", "object state",
            "transition table", "queue item"]


def resolve(stage: str) -> Grant:
    """Derive the answer. Nothing persisted holds it."""
    skill = SKILL_OF_STAGE.get(stage)
    if skill is None:
        raise AuthorizationError(f"no skill performs stage {stage!r}")
    obj, ledger, pins = _state["obj"], _state["ledger"], _state["pins"]
    grant = evaluator.derive_grant(obj, skill, pins, ledger)
    return Grant(read_keys=list(grant.read_keys), write_key=grant.write_key,
                 source=NAME)


def execute(stage: str, store: Store) -> Grant:
    obj, ledger, pins = _state["obj"], _state["ledger"], _state["pins"]
    item = QueueItem(OBJ, evaluator.required_skill(obj))
    record = evaluator.run_step(obj, item, _state["store_dir"], pins, ledger)
    for key in record.grant.read_keys:
        store.read(key)
    if record.grant.write_key:
        store.write(record.grant.write_key, {"produced_by": stage})
    return Grant(read_keys=list(record.grant.read_keys),
                 write_key=record.grant.write_key, source=NAME)


def run_workflow(store: Store) -> Dict[str, Grant]:
    """Intake already happened - the object arrived with its artifact - so the
    store is given raw_input here and the three transformations follow."""
    store.write(KEY_RAW, {"produced_by": "intake"})
    return {stage: execute(stage, store)
            for stage in ("schema", "transform", "validate")}


# ---------------------------------------------------------------------------
# Mutations, one per stored surface. The same five case 08 enumerated, so the
# numbers stay comparable with that case.
# ---------------------------------------------------------------------------

def mutate_artifact_binding(target_key: str) -> str:
    """Rebind the type the schema step reads. Case 10's subject.

    An append is inert and now contains the object (case 11), so the edit that
    obtains the capability is the overwrite - the one case 10 measured as the
    only surviving route and case 11 as structurally invisible.
    """
    ledger: ProductionLedger = _state["ledger"]
    for index, entry in enumerate(ledger._records):
        if entry.artifact_type == skills.T_TABLE_PREVIEW:
            ledger._records[index] = ProductionRecord(
                OBJ, entry.at_state, entry.skill, entry.artifact_type,
                target_key)
            return (f"overwrote the production record binding "
                    f"{skills.T_TABLE_PREVIEW!r} to {target_key!r}")
    return "no record to overwrite"


def mutate_skill_contract(target_key: str) -> str:
    """Widen what the approved transformation may read. Case 09's subject.

    **One edit, placed before the run pins.** Case 09 measured three
    placements and this is the undetected one: the pin records what was there
    at run start, not what should have been, so an edit made earlier is
    pinned as if it were the approved contract. Re-pinning below is not a
    second tamper - it is the run starting afterwards, which is what a pre-run
    edit means.
    """
    current = skills._REGISTRY["infer_schema"]
    skills._REGISTRY["infer_schema"] = skills.Skill(
        name=current.name, version=current.version,
        reads=tuple(current.reads) + (skills.T_KEY_MATERIAL,),
        produces=current.produces, effects=current.effects)
    _state["pins"] = pin_versions(evaluator.OBJECT_TYPES["orders_table"])
    return ("widened infer_schema's declared reads before the run pinned "
            "them")


def mutate_object_state(target_key: str) -> str:
    obj: WorkObject = _state["obj"]
    obj.state = "transformed"
    save_object(obj, _state["store_dir"])
    return "set the object's state to 'transformed'"


def mutate_transition_table(target_key: str) -> str:
    evaluator._TRANSITIONS[("orders_table", "ingested")] = "validate_chain"
    return "pointed the ingested state at validate_chain"


def mutate_queue_item(target_key: str) -> str:
    _state["forced_item"] = QueueItem(OBJ, "validate_chain")
    return "named a different skill in the queue item"


MUTATIONS = {
    "artifact binding record": mutate_artifact_binding,
    "skill contract": mutate_skill_contract,
    "object state": mutate_object_state,
    "transition table": mutate_transition_table,
    "queue item": mutate_queue_item,
}

EDITS = {name: 1 for name in MUTATIONS}

SCOPES = {
    "artifact binding record": SCOPE_OBJECT,
    "skill contract": SCOPE_DEPLOYMENT,
    "object state": SCOPE_OBJECT,
    "transition table": SCOPE_DEPLOYMENT,
    "queue item": SCOPE_OBJECT,
}

DETECTION = {
    "artifact binding record":
        "nothing. An append would be inert and would contain the object "
        "(case 11); the overwrite that works leaves no contradiction to find, "
        "which is case 11's measured blind spot.",
    "skill contract":
        "nothing. The edit precedes the run, and case 09 measured exactly "
        "this: a version pin records what was there at run start, not what "
        "should have been. The same pin detects the identical edit made "
        "mid-run, which is what a pin is actually worth - continuity across "
        "one window, not legitimacy.",
    "object state":
        "no detection is needed: the edit obtains no key authority, because "
        "the grant still resolves through the artifact binding and this does "
        "not touch it.",
    "transition table":
        "as above - it changes which skill runs, not which key a type is "
        "bound to.",
    "queue item":
        "the manager re-validates ready work against the object's own state "
        "and refuses a skill that state does not require (concept note 12).",
}

PERSISTENCE = {
    "artifact binding record":
        "survives retry and resume for this object; does not reach another "
        "object or a later independent run",
    "skill contract":
        "survives until redeployment and reaches every object running that "
        "skill - the widest persistence measured in this case",
    "object state": "survives retry and resume for this object",
    "transition table": "process lifetime",
    "queue item": "one step; the item is re-validated every time",
}
