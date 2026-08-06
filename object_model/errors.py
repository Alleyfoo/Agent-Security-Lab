"""Refusals, kept distinct so a caller can tell them apart.

Three different incidents. Collapsing them would hide which boundary failed,
which is the mistake case 04 exists to prevent on the audit plane.
"""

from __future__ import annotations


class AuthorizationError(RuntimeError):
    """No grant could be resolved for this work.

    The ordinary refusal: the object is not in a state that requires this
    skill, the type does not permit it, or no such skill is approved.
    """


class SkillRegistryError(RuntimeError):
    """An approved skill definition is not what the run started with.

    Distinct from AuthorizationError: the request may be entirely legitimate
    and the *vocabulary* has changed underneath it. See
    cases/09-skill-registry/README.md.
    """
