"""Step D: displacing a confirmed reservation needs a second authority.

The rule is attached to the **kind of transformation**, not to a risk score:

    creating a new reservation          the worker may do it locally
    modifying someone's confirmed one   protected - proposal + approval + gate

Design inherited from cases 19-22 rather than re-derived, including its limits:

  CONTENT BINDING        the digest covers the exact action - which
                         reservation, from where, to where, and the version
                         of the reservation at proposal time (case 19)
  AUTHORITY INDEPENDENCE only a reviewer identity may approve; the worker
                         cannot (case 19's R2)
  CONSUMPTION            an approval authorises one execution and is spent
                         (case 19's R4, case 20's atomic claim)

**The caveats travel with it.** This is a Level 1 control: it stops a
compromised worker using the interfaces it holds, and a configuration adversary
who can write the approval store defeats it in one commit (cases 19-22). The
store and gate boundaries here are *modelled*, not enforced - case 23 is
blocked on this machine, and nothing in this demo upgrades that claim.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

WORKER = "svc_worker"
REVIEWER = "svc_reviewer"


class SignoffRefused(RuntimeError):
    """The gate refused, and the message names which condition failed."""


@dataclass(frozen=True)
class Displacement:
    """The exact action. `request_id` is deliberately not part of it - authority
    binds to what will happen, not to which ticket asked for it (case 19)."""

    reservation_id: str
    from_slot: Tuple[str, int, int]
    to_slot: Tuple[str, int, int]
    version: int

    def canonical(self) -> str:
        return json.dumps([self.reservation_id, list(self.from_slot),
                           list(self.to_slot), self.version],
                          separators=(",", ":"))

    def digest(self) -> str:
        return hashlib.sha256(self.canonical().encode("utf-8")).hexdigest()

    def describe(self) -> str:
        return (f"{self.reservation_id}: {self.from_slot} -> {self.to_slot} "
                f"(v{self.version})")


@dataclass
class Attestation:
    actor: str
    digest: str
    consumed: bool = False


@dataclass
class SignoffStore:
    reviewers: List[str] = field(default_factory=lambda: [REVIEWER])
    proposals: List[Attestation] = field(default_factory=list)
    approvals: List[Attestation] = field(default_factory=list)
    executed: List[str] = field(default_factory=list)

    # -- the worker's half --------------------------------------------------
    def propose(self, actor: str, action: Displacement) -> Attestation:
        attestation = Attestation(actor, action.digest())
        self.proposals.append(attestation)
        return attestation

    # -- the reviewer's half ------------------------------------------------
    def approve(self, actor: str, digest: str) -> Attestation:
        if actor not in self.reviewers:
            raise SignoffRefused(f"{actor!r} is not an authorised reviewer")
        for existing in self.approvals:
            if existing.digest == digest:
                raise SignoffRefused(
                    f"{digest[:8]}... is already approved by "
                    f"{existing.actor!r}")
        attestation = Attestation(actor, digest)
        self.approvals.append(attestation)
        return attestation

    # -- the gate -----------------------------------------------------------
    def verify_and_spend(self, action: Displacement) -> Attestation:
        """Deterministic, and it re-derives the digest from the action it is
        actually about to perform - not from whatever the request claims."""
        digest = action.digest()
        if not any(p.digest == digest for p in self.proposals):
            raise SignoffRefused(
                f"no proposal attests {action.describe()}")
        unspent = [a for a in self.approvals
                   if a.digest == digest and not a.consumed]
        if not unspent:
            spent = any(a.digest == digest for a in self.approvals)
            raise SignoffRefused(
                f"approval for {digest[:8]}... is already spent" if spent
                else f"no approval attests {action.describe()}")
        unspent[0].consumed = True
        self.executed.append(digest)
        return unspent[0]


def displacement_for(reservation, candidate: Tuple[str, int, int],
                     version: int) -> Displacement:
    return Displacement(
        reservation_id=reservation.reservation_id,
        from_slot=(reservation.facility_id, reservation.day,
                   reservation.start),
        to_slot=candidate, version=version)
