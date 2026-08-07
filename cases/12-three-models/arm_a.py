"""Arm A - authority follows the subject.

A minimal reference model of the identity + permission idea:

    subject/process  ->  has permissions  ->  acts on resources

**This is not Unix.** Real uid, mode, ACL and namespace semantics are not
available on this repository's platform, and claiming to have measured Linux
would be false. What is modelled is the architectural idea: named subjects,
standing permissions over named resources, and a mandatory check on every
access. Nothing here is evidence about any operating system.

Competence checklist from the contract, and where each is met:

* each stage runs as its own subject          -> SUBJECT_OF_STAGE, four of them
* least privilege per subject                 -> PERMISSIONS grants exactly the
                                                 stage's declared reads
* the check is mandatory, not advisory        -> resolve() is the only way to a
                                                 Grant, and execute() reads
                                                 through it
* permissions are revocable                   -> revoke()
* no superuser, no exempt stage               -> no subject holds "*", asserted
                                                 by a test

The architectural property under test: **the permission is standing.** It
exists between runs, it is attached to the subject rather than to the work, and
`svc_schema` may read whatever it may read whenever it runs - for this object,
the next one, and every future run.
"""

from __future__ import annotations

import os
import sys
from typing import Dict, List, Set

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from case12_common import (  # noqa: E402
    KEY_MATERIAL, SCOPE_SUBJECT, STANDING, WORKLOAD, AuthorizationError,
    Grant, Store,
)

NAME = "A: authority follows the subject"
AUTHORITY_KIND = STANDING

READ, WRITE = "read", "write"

# ---------------------------------------------------------------------------
# The two authority-bearing records. Both are stored, both are persistent, and
# both are exactly what an administrator of such a system edits.
# ---------------------------------------------------------------------------

# Which subject a stage runs as.
SUBJECT_OF_STAGE: Dict[str, str] = {}

# What each subject may do to each resource: subject -> key -> {read, write}.
PERMISSIONS: Dict[str, Dict[str, Set[str]]] = {}

# The out-of-workflow identity that owns the secret. Its presence is the point:
# in an identity model an attacker does not need to invent authority, only to
# reach an identity that already holds it. Cases 08 and 09 recorded the same
# structural fact - a dangerous-if-misapplied capability already existing is
# one of the ways a single edit is enough.
KEY_OWNER = "svc_keys"


def reset() -> None:
    SUBJECT_OF_STAGE.clear()
    PERMISSIONS.clear()
    for stage in WORKLOAD:
        subject = f"svc_{stage.name}"
        SUBJECT_OF_STAGE[stage.name] = subject
        grants: Dict[str, Set[str]] = {stage.produces: {WRITE}}
        for key in stage.reads:
            grants.setdefault(key, set()).add(READ)
        PERMISSIONS[subject] = grants
    # The secret belongs to an identity outside this workflow, which may read
    # it and nothing else.
    PERMISSIONS[KEY_OWNER] = {KEY_MATERIAL: {READ}}


def surfaces() -> List[str]:
    return ["permission table", "subject assignment"]


def revoke(subject: str, key: str, op: str = READ) -> None:
    """Permissions are revocable. Present because the competence checklist
    requires it, and because an arm that cannot revoke is a strawman."""
    PERMISSIONS.get(subject, {}).get(key, set()).discard(op)


def may(subject: str, key: str, op: str) -> bool:
    return op in PERMISSIONS.get(subject, {}).get(key, set())


def resolve(stage: str) -> Grant:
    """The whole authorization step: what does this stage's subject hold?

    Note what is *not* consulted - the object, its state, the artifacts
    present, or what work is being done. The question this model asks is "what
    is this subject allowed to read, write, or execute?" and the answer is the
    same whenever it is asked.
    """
    subject = SUBJECT_OF_STAGE.get(stage)
    if subject is None:
        raise AuthorizationError(f"no subject assigned to stage {stage!r}")
    if subject not in PERMISSIONS:
        raise AuthorizationError(f"unknown subject {subject!r}")
    reads = sorted(k for k, ops in PERMISSIONS[subject].items() if READ in ops)
    writes = sorted(k for k, ops in PERMISSIONS[subject].items() if WRITE in ops)
    return Grant(read_keys=reads, write_key=writes[0] if writes else "",
                 source=NAME)


def execute(stage: str, store: Store) -> Grant:
    """Run one stage. Every access goes through the check."""
    grant = resolve(stage)
    subject = SUBJECT_OF_STAGE[stage]
    for key in grant.read_keys:
        if not may(subject, key, READ):           # mandatory, not advisory
            raise AuthorizationError(
                f"{subject!r} may not read {key!r}")
        store.read(key)
    if grant.write_key:
        if not may(subject, grant.write_key, WRITE):
            raise AuthorizationError(
                f"{subject!r} may not write {grant.write_key!r}")
        store.write(grant.write_key, {"produced_by": stage})
    return grant


def run_workflow(store: Store) -> Dict[str, Grant]:
    return {stage.name: execute(stage.name, store) for stage in WORKLOAD}


# ---------------------------------------------------------------------------
# Mutations. One per surface, each the smallest single edit that could obtain a
# read of the target at the schema step.
# ---------------------------------------------------------------------------

def mutate_permission_table(target_key: str) -> str:
    """Widen the subject's standing permissions. The ordinary administrative
    act, and the ordinary attack."""
    PERMISSIONS[SUBJECT_OF_STAGE["schema"]].setdefault(target_key, set()).add(READ)
    return f"granted {target_key!r} read to svc_schema in the permission table"


def mutate_subject_assignment(target_key: str) -> str:
    """Do not widen a permission - *become* an identity that already holds it.

    No new authority is created anywhere. This is why an identity model's blast
    radius is not bounded by the workflow: the authority already existed, held
    by someone else, and one edit redirected the work to it.
    """
    SUBJECT_OF_STAGE["schema"] = KEY_OWNER
    return f"reassigned the schema stage to run as {KEY_OWNER!r}"


MUTATIONS = {
    "permission table": mutate_permission_table,
    "subject assignment": mutate_subject_assignment,
}

EDITS = {
    "permission table": 1,
    "subject assignment": 1,
}

SCOPES = {
    "permission table": SCOPE_SUBJECT,
    "subject assignment": SCOPE_SUBJECT,
}

DETECTION = {
    "permission table":
        "nothing. The table is the authority; there is no independent account "
        "of what it should contain, so a widened permission is "
        "indistinguishable from an administrative decision.",
    "subject assignment":
        "nothing in this arm. The work runs, succeeds, and is attributed to "
        "the identity it was reassigned to - which is a correct record of what "
        "happened and a useless one for noticing that it should not have.",
}

PERSISTENCE = {
    "permission table":
        "survives retry, resume, later runs and redeployment - it is "
        "configuration, not run state",
    "subject assignment":
        "survives retry, resume, later runs and redeployment",
}
