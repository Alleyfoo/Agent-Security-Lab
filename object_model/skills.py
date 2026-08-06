"""The skill registry: approved transformations, their versions, their digests.

A skill declares one approved transformation over artifact *types* (concept
note §11). The registry is the executable vocabulary: no approved skill, no
executable transition.

Two properties this module is responsible for, and they are different claims:

* **C1** the execution plane cannot create, modify or replace an entry. Not a
  denied operation — an absent one. `REGISTRY` is a read-only view over a
  private dict of frozen records.
* **C2** a run is bound to the definitions it started with. Each skill has a
  content digest; a run pins them and re-verifies before acting.

Scope, stated plainly: both are in-process. Code that reaches `_REGISTRY`
rewrites it, and code that reaches a run's pins rewrites those too. This
module raises the level of adversary required; it does not establish an
independent authority over what a legitimate skill version is. See
cases/09-skill-registry/README.md, which measures exactly where that line
falls.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from types import MappingProxyType
from typing import Dict, Iterable, Mapping, Tuple

from object_model.errors import SkillRegistryError

# Artifact types. Skills declare these; only an object's artifact map knows
# which concrete key currently holds one.
T_TABLE_PREVIEW = "table_preview"
T_SCHEMA_PROFILE = "schema_profile"
T_CLEANED_OUTPUT = "cleaned_output"
T_VALIDATION_VERDICT = "validation_verdict"
T_KEY_MATERIAL = "key_material"


@dataclass(frozen=True)
class Skill:
    """One approved transformation.

    Frozen, so an entry cannot be edited in place. That is not isolation —
    a caller holding the private dict rebinds the name — but it does mean the
    read-only view cannot be walked around by mutating what it yields, which
    is the mistake case 04's event view had to fix with copies.
    """

    name: str
    version: str
    reads: Tuple[str, ...]
    produces: str
    effects: str = "derive"

    def canonical(self) -> str:
        return json.dumps(
            [self.name, self.version, list(self.reads), self.produces,
             self.effects],
            sort_keys=False, separators=(",", ":"),
        )


def digest_of(skill: Skill) -> str:
    """SHA-256 over the declared behaviour, not over the object identity.

    Like every integrity value in this repository, it is computed and stored
    in the same address space as the thing it describes. It detects careless
    replacement, not careful replacement.
    """
    return hashlib.sha256(skill.canonical().encode("utf-8")).hexdigest()


# The private registry. Rebinding a name here is the Level 2 attack case 09
# measures; there is no supported path to it from the execution plane.
_REGISTRY: Dict[str, Skill] = {}

# C1: what the execution plane sees.
REGISTRY: Mapping[str, Skill] = MappingProxyType(_REGISTRY)


def reset_registry() -> None:
    """The approved deployment. Stands in for §16's administrative lifecycle,
    which this case does not implement and must not claim."""
    _REGISTRY.clear()
    _REGISTRY.update({
        "infer_schema": Skill("infer_schema", "1.0", (T_TABLE_PREVIEW,),
                              T_SCHEMA_PROFILE),
        "clean_table": Skill("clean_table", "1.0",
                             (T_TABLE_PREVIEW, T_SCHEMA_PROFILE),
                             T_CLEANED_OUTPUT),
        # Legitimately reads cleaned_output. Its presence matters: a
        # dangerous-if-misapplied skill already existing is one of the ways a
        # single edit elsewhere can be enough (case 08).
        "validate_chain": Skill("validate_chain", "1.0",
                                (T_TABLE_PREVIEW, T_SCHEMA_PROFILE,
                                 T_CLEANED_OUTPUT),
                                T_VALIDATION_VERDICT, effects="read_only"),
    })


def manifest() -> Dict[str, str]:
    """Name -> digest for every approved skill, right now."""
    return {name: digest_of(skill) for name, skill in _REGISTRY.items()}


def pin_versions(names: Iterable[str]) -> Dict[str, str]:
    """C2: fix the definitions a run is entitled to use.

    Taken at run start. Anything not pinned is not usable by that run, so a
    skill added later cannot be selected even if something manages to add one.
    """
    pinned: Dict[str, str] = {}
    for name in names:
        if name not in _REGISTRY:
            raise SkillRegistryError(
                f"cannot pin {name!r}: no such approved skill")
        pinned[name] = digest_of(_REGISTRY[name])
    return pinned


def verify_pins(pinned: Mapping[str, str], name: str) -> Skill:
    """C2: the definition in use must be the one the run started with."""
    if name not in pinned:
        raise SkillRegistryError(
            f"{name!r} was not pinned at run start and cannot be used by this "
            "run, whatever the registry says now"
        )
    if name not in _REGISTRY:
        raise SkillRegistryError(
            f"{name!r} was pinned at run start and is no longer registered")
    skill = _REGISTRY[name]
    current = digest_of(skill)
    if current != pinned[name]:
        raise SkillRegistryError(
            f"skill {name!r} failed version verification: run pinned "
            f"{pinned[name][:8]}... and the registry now holds "
            f"{current[:8]}... - the definition was replaced after the run "
            "started"
        )
    return skill
