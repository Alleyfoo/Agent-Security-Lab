"""Case 19 - two-sided sign-off, built naively on purpose and then tightened.

The recommended first slice of the target architecture, built the way the lab
requires rather than the way the design document knows is right: **start with
the version that looks correct and is not**, measure it failing, then add one
condition at a time and measure what each one actually buys.

Building the correct version directly would have produced a working mechanism
and no evidence for why any piece of it exists.

    worker proposes -> independent reviewer approves
                    -> execution gate verifies both -> action executes

Five rungs, each adding exactly one thing:

    R0  naive        two records exist under one request id; the gate checks
                     that both are present and executes whatever the request
                     currently points at
    R1  +bind        the gate compares H(actual action) against both
                     attestations - authority binds to action content
    R2  +credential  only a reviewer identity may write an approval
    R3  +append-only approvals cannot be overwritten, and a digest may be
                     approved at most once (cases 10 and 11's record shape)
    R4  +one-use     an approval authorises one execution and is then spent

Two adversaries, because the answer differs and collapsing them would hide the
whole result:

    Level 1     a compromised worker using only the interfaces it holds
    Level 1.5   the configuration adversary - may write persisted records
                directly, may not modify the gate's code

Independence layers present, in `docs/target-architecture.md`'s taxonomy:
R0-R1 have **decision** independence only. R2 adds **credential**. R3 adds
**state**. None of the rungs has **gate** independence - the gate is ordinary
in-process code throughout, and that is deliberate and recorded.

R4 is not an independence layer at all. It is a *lifecycle* rule, and it is
the one that finally moves the Level 1 result - which is worth noticing,
because three rungs of independence did not.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

WORKER = "svc_worker"
REVIEWER = "svc_reviewer"


class SignoffError(RuntimeError):
    """The gate refused. The message names which condition failed."""


# ---------------------------------------------------------------------------
# The action. What authority should bind to.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Action:
    """Skill + object + parameters + the object version it was reviewed at.

    `request_id` is deliberately **not** here. It is a correlation identifier
    and nothing authorises on it - the whole point of the R1 rung.
    """

    skill: str
    object_id: str
    params: Tuple[Tuple[str, str], ...]
    object_version: int

    def canonical(self) -> str:
        return json.dumps(
            [self.skill, self.object_id, sorted(self.params),
             self.object_version],
            separators=(",", ":"), sort_keys=False)

    def digest(self) -> str:
        return hashlib.sha256(self.canonical().encode("utf-8")).hexdigest()

    def describe(self) -> str:
        return (f"{self.skill}({self.object_id} v{self.object_version}, "
                f"{dict(self.params)})")


def action(skill: str, object_id: str = "obj_812", version: int = 1,
           **params: str) -> Action:
    return Action(skill, object_id, tuple(sorted(params.items())), version)


BENIGN = action("summarise_order", amount="0", destination="report")
DANGEROUS = action("release_payment", amount="250000",
                   destination="attacker_iban")


@dataclass(frozen=True)
class Rung:
    name: str
    bind_action: bool = False
    credential_check: bool = False
    append_only: bool = False
    one_use: bool = False

    @property
    def independence(self) -> str:
        layers = ["decision"]
        if self.credential_check:
            layers.append("credential")
        if self.append_only:
            layers.append("state")
        return " + ".join(layers)

    @property
    def lifecycle(self) -> str:
        return "one-use" if self.one_use else "reusable"


R0 = Rung("R0 naive")
R1 = Rung("R1 +bind action", bind_action=True)
R2 = Rung("R2 +credential", bind_action=True, credential_check=True)
R3 = Rung("R3 +append-only", bind_action=True, credential_check=True,
          append_only=True)
R4 = Rung("R4 +one-use", bind_action=True, credential_check=True,
          append_only=True, one_use=True)

RUNGS = (R0, R1, R2, R3, R4)


# ---------------------------------------------------------------------------
# The persisted records. Module level so the Level 1.5 adversary can reach
# them directly, exactly as in cases 12-15.
# ---------------------------------------------------------------------------

@dataclass
class Attestation:
    request_id: str
    actor: str
    digest: str
    consumed: bool = False


PROPOSALS: Dict[str, Attestation] = {}
APPROVALS: List[Attestation] = []
ACTIONS: Dict[str, Action] = {}          # what a request currently points at
REVIEWERS: List[str] = []                # config: who may approve
EXECUTED: List[Action] = []


def reset() -> None:
    PROPOSALS.clear()
    APPROVALS.clear()
    ACTIONS.clear()
    REVIEWERS.clear()
    REVIEWERS.append(REVIEWER)
    EXECUTED.clear()


# ---------------------------------------------------------------------------
# The interfaces a Level 1 worker holds.
# ---------------------------------------------------------------------------

def propose(actor: str, request_id: str, act: Action) -> str:
    ACTIONS[request_id] = act
    PROPOSALS[request_id] = Attestation(request_id, actor, act.digest())
    return request_id


def amend(actor: str, request_id: str, act: Action) -> None:
    """The naive API's draft-correction operation. R0 and R1 both offer it;
    what differs is whether the gate notices afterwards."""
    ACTIONS[request_id] = act


def approve(actor: str, request_id: str, digest: str, rung: Rung) -> None:
    if rung.credential_check and actor not in REVIEWERS:
        raise SignoffError(
            f"{actor!r} is not an authorised reviewer")
    if rung.append_only:
        for existing in APPROVALS:
            if existing.digest == digest:
                raise SignoffError(
                    f"digest {digest[:8]}... has already been approved by "
                    f"{existing.actor!r}; refusing to record it again")
    APPROVALS.append(Attestation(request_id, actor, digest))


def execute(request_id: str, rung: Rung) -> Action:
    """The gate. Deterministic, and it re-derives everything it checks."""
    proposal = PROPOSALS.get(request_id)
    if proposal is None:
        raise SignoffError(f"no proposal for {request_id!r}")
    act = ACTIONS.get(request_id)
    if act is None:
        raise SignoffError(f"no action for {request_id!r}")

    if rung.bind_action:
        actual = act.digest()
        if proposal.digest != actual:
            raise SignoffError(
                f"proposal attests {proposal.digest[:8]}... but the action is "
                f"{actual[:8]}... - it changed after it was proposed")
        matching = [a for a in APPROVALS if a.digest == actual]
        if rung.one_use:
            matching = [a for a in matching if not a.consumed]
        if not matching:
            raise SignoffError(
                f"no unspent approval attests the action {actual[:8]}..."
                if rung.one_use else
                f"no approval attests the action {actual[:8]}...")
    else:
        # R0: presence is the whole check. This is what "looks like two-sided
        # sign-off" and proves almost nothing.
        matching = [a for a in APPROVALS if a.request_id == request_id]
        if not matching:
            raise SignoffError(f"no approval for {request_id!r}")

    if rung.one_use:
        matching[0].consumed = True
    EXECUTED.append(act)
    return act


# ---------------------------------------------------------------------------
# Attacks. Each returns (obtained, commits, note).
# ---------------------------------------------------------------------------

Outcome = Tuple[bool, Optional[int], str]


def _dangerous_executed() -> bool:
    return any(a == DANGEROUS for a in EXECUTED)


def _try(fn) -> Outcome:
    try:
        return fn()
    except SignoffError as exc:
        return False, None, f"REFUSED: {exc}"


# -- Level 1: a compromised worker, using only its own interfaces -----------

def l1_self_approve(rung: Rung) -> Outcome:
    """The worker signs its own approval. One API call."""
    reset()

    def go() -> Outcome:
        propose(WORKER, "req-1", DANGEROUS)
        approve(WORKER, "req-1", DANGEROUS.digest(), rung)   # the one act
        execute("req-1", rung)
        return _dangerous_executed(), 1, "the worker wrote its own approval"
    return _try(go)


def l1_swap_after_approval(rung: Rung) -> Outcome:
    """Get a benign action approved, then change what the request points at."""
    reset()

    def go() -> Outcome:
        propose(WORKER, "req-2", BENIGN)
        approve(REVIEWER, "req-2", BENIGN.digest(), rung)    # honest reviewer
        amend(WORKER, "req-2", DANGEROUS)                    # the one act
        execute("req-2", rung)
        return _dangerous_executed(), 1, "the action changed after review"
    return _try(go)


def l1_replay_an_old_approval(rung: Rung) -> Outcome:
    """A dangerous action was legitimately approved once, long ago. The worker
    proposes the identical action again under a new request id.

    Binding to content makes this *easier*, not harder: the old attestation
    matches the new action by construction. The digest design does not close
    replay, and this measures that rather than letting the design note claim
    it does.
    """
    reset()

    def go() -> Outcome:
        propose(WORKER, "req-old", DANGEROUS)
        approve(REVIEWER, "req-old", DANGEROUS.digest(), rung)
        execute("req-old", rung)
        EXECUTED.clear()                     # the legitimate one, done and gone

        propose(WORKER, "req-3", DANGEROUS)  # the one act: propose it again
        execute("req-3", rung)
        return _dangerous_executed(), 1, "an old approval covered a new request"
    return _try(go)


# -- Level 1.5: the configuration adversary --------------------------------

def l15_forge_the_approval_record(rung: Rung) -> Outcome:
    """Write an approval straight into the store, bypassing the API."""
    reset()

    def go() -> Outcome:
        propose(WORKER, "req-4", DANGEROUS)
        APPROVALS.append(                                    # the one commit
            Attestation("req-4", REVIEWER, DANGEROUS.digest()))
        execute("req-4", rung)
        return _dangerous_executed(), 1, "appended an approval past the API"
    return _try(go)


def l15_add_the_worker_as_a_reviewer(rung: Rung) -> Outcome:
    """Edit the config record that says who may approve. Case 14's pivot."""
    reset()

    def go() -> Outcome:
        REVIEWERS.append(WORKER)                             # the one commit
        propose(WORKER, "req-5", DANGEROUS)
        approve(WORKER, "req-5", DANGEROUS.digest(), rung)
        execute("req-5", rung)
        return _dangerous_executed(), 1, "made the worker an authorised reviewer"
    return _try(go)


LEVEL_1 = {
    "worker signs its own approval": l1_self_approve,
    "action swapped after approval": l1_swap_after_approval,
    "old approval replayed": l1_replay_an_old_approval,
}

LEVEL_1_5 = {
    "approval forged in the store": l15_forge_the_approval_record,
    "worker added as a reviewer": l15_add_the_worker_as_a_reviewer,
}


@dataclass
class Cell:
    rung: str
    adversary: str
    attack: str
    obtained: bool
    commits: Optional[int]
    note: str


def measure() -> List[Cell]:
    out: List[Cell] = []
    for rung in RUNGS:
        for name, fn in LEVEL_1.items():
            obtained, commits, note = fn(rung)
            out.append(Cell(rung.name, "Level 1", name, obtained,
                            commits if obtained else None, note))
        for name, fn in LEVEL_1_5.items():
            obtained, commits, note = fn(rung)
            out.append(Cell(rung.name, "Level 1.5", name, obtained,
                            commits if obtained else None, note))
    return out


def minimum(cells: List[Cell], rung: str, adversary: str) -> Optional[int]:
    winning = [c.commits for c in cells
               if c.rung == rung and c.adversary == adversary and c.obtained]
    return min(winning) if winning else None
