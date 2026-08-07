"""Shared vocabulary and shared data plane for the three arms.

The arms must differ in **where authority is attached** and in nothing else.
So the workload, the artifact store, the grant type and the scope scale all
live here, and each arm supplies only its own answer to "may this step do this
now?".

Anything an arm needs that is not authority - a store, a step list, a target -
belongs in this module. If it appears in an arm, the comparison has stopped
being like for like.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


class AuthorizationError(RuntimeError):
    """No authority could be established. All three arms raise this."""


# ---------------------------------------------------------------------------
# The shared data plane.
# ---------------------------------------------------------------------------

KEY_RAW = "artifact.raw_input"
KEY_SCHEMA = "artifact.schema_profile"
KEY_CLEANED = "artifact.cleaned_output"
KEY_VERDICT = "artifact.validation_verdict"

# Present in the store from the start, produced by no stage and granted to no
# stage in any arm. The named capability is a read of this key at the schema
# step - the same target cases 08 and 10 used, so the numbers stay comparable
# across the series.
KEY_MATERIAL = "artifact.key_material"

TARGET = KEY_MATERIAL


@dataclass
class Store:
    """A minimal artifact store. Deliberately not the product's.

    No hashing, no views, no integrity verification: those are controls, and a
    control present in the shared layer would be present in all three arms and
    measure nothing about where authority lives.
    """

    contents: Dict[str, object] = field(default_factory=dict)

    def read(self, key: str) -> object:
        return self.contents[key]

    def write(self, key: str, value: object) -> None:
        self.contents[key] = value

    def keys(self) -> List[str]:
        return sorted(self.contents)


def fresh_store() -> Store:
    """The world before the workflow runs: the source payload and one secret
    that belongs to nobody in this workflow."""
    return Store({
        "artifact.source_payload": {"rows": 20},
        KEY_MATERIAL: {"secret": "signing-key-material"},
    })


# ---------------------------------------------------------------------------
# The shared workload. The same business operation in every arm.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Stage:
    name: str
    reads: Tuple[str, ...]
    produces: str


# The validate stage reads everything and produces **nothing**, in all three
# arms. That is not a concession to arm C, whose `validate_chain` skill is
# declared `read_only`; it is what case 05 established - a conclusion the
# validating component authors is not evidence, and the run's conclusion has to
# be derived by trusted code from this same evidence rather than written by the
# validator as an artifact. A workload in which the validator writes its own
# verdict would be measuring the design case 05 refuted.
WORKLOAD: Tuple[Stage, ...] = (
    Stage("intake", (), KEY_RAW),
    Stage("schema", (KEY_RAW,), KEY_SCHEMA),
    Stage("transform", (KEY_RAW, KEY_SCHEMA), KEY_CLEANED),
    Stage("validate", (KEY_RAW, KEY_SCHEMA, KEY_CLEANED), ""),
)

STAGE_NAMES = tuple(s.name for s in WORKLOAD)
STAGES_BY_NAME = {s.name: s for s in WORKLOAD}

# The workflow position every attack is measured at, as in cases 08 and 10.
ATTACK_STAGE = "schema"


@dataclass(frozen=True)
class Grant:
    """What a step may do. The unit of comparison.

    Arm A reads it off a subject's standing permissions, arm B off the step's
    configuration intersected with its connection's scope, arm C derives it
    from the object's state and the approved skill. Same type, three origins.
    """

    read_keys: List[str] = field(default_factory=list)
    write_key: str = ""
    source: str = ""

    def permits_read(self, key: str) -> bool:
        return key in self.read_keys

    def describe(self) -> str:
        return f"reads {sorted(self.read_keys)} writes {self.write_key!r}"


# ---------------------------------------------------------------------------
# The scope scale. Ordered narrowest to widest, so "wider" is a comparison and
# not an adjective.
# ---------------------------------------------------------------------------

SCOPE_STEP = "one step"
SCOPE_OBJECT = "one object, including its retries and resume"
SCOPE_RUN = "one run"
SCOPE_WORKFLOW = "every run of this workflow definition"
SCOPE_SUBJECT = "every future run by that subject, and every resource it may touch"
SCOPE_DEPLOYMENT = "every object in the deployment until redeployment"

SCOPE_ORDER = (SCOPE_STEP, SCOPE_OBJECT, SCOPE_RUN, SCOPE_WORKFLOW,
               SCOPE_SUBJECT, SCOPE_DEPLOYMENT)


def wider(a: str, b: str) -> bool:
    return SCOPE_ORDER.index(a) > SCOPE_ORDER.index(b)


# Where authority lives, as a property of the architecture rather than of an
# implementation choice.
STANDING = "standing - exists between runs, attached to a subject"
CONFIGURED = "configured - fixed ahead of time, attached to a workflow step"
DERIVED = "task-specific - computed at use time for one transformation"


# ---------------------------------------------------------------------------
# Version pinning, shared.
#
# The contract adjudicated this as *not* architecture-specific: pinning a
# definition at run start and re-verifying it before use is available to a
# permission table and a workflow definition exactly as it is to a skill
# registry (case 09's C2). So it is implemented once, here, and all three arms
# use the same machinery - the fairest possible version of "both get it".
#
# It changes no measured cell in this case. It changes detection, and the
# result is that all three arms detect a mid-run edit and none detects a
# pre-run one, which is a finding about pinning rather than about architecture.
# ---------------------------------------------------------------------------

def digest_of(records: object) -> str:
    """A content digest over an arm's authority records.

    Like every integrity value in this repository it is computed and held in
    the same address space as the thing it describes, so it detects careless
    replacement and not careful replacement. That is the cross-cutting finding
    and it applies identically to all three arms.
    """
    return hashlib.sha256(
        json.dumps(records, sort_keys=True, default=_stable).encode("utf-8")
    ).hexdigest()


def _stable(value: object) -> object:
    if isinstance(value, (set, frozenset)):
        return sorted(value)
    if hasattr(value, "__dict__"):
        return {k: v for k, v in sorted(vars(value).items())}
    return str(value)


class PinMismatch(RuntimeError):
    """An authority record is not what the run started with."""


def verify(pinned: str, records: object, what: str) -> None:
    current = digest_of(records)
    if current != pinned:
        raise PinMismatch(
            f"{what} failed version verification: run pinned {pinned[:8]}... "
            f"and it now holds {current[:8]}... - it was replaced after the "
            "run started")


@dataclass
class Measurement:
    """One (arm, surface) cell. Every field is measured, not asserted."""

    arm: str
    surface: str
    obtained: bool
    edits: int
    scope: str
    detection: str
    persists: str
    note: str = ""


@dataclass
class ArmResult:
    """What running one arm's whole measurement produced."""

    name: str
    authority_kind: str
    surfaces: List[str]
    grants: Dict[str, Grant]
    produced: List[str]
    cells: List[Measurement] = field(default_factory=list)

    @property
    def minimum_tamper_set(self) -> Optional[int]:
        """The smallest number of stored edits that obtained the capability,
        or None if no surface obtained it."""
        winning = [c.edits for c in self.cells if c.obtained]
        return min(winning) if winning else None
