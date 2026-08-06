"""A candidate object-and-skill model, under measurement.

**This is not the product.** `agent_network_demo/` is. Per the concept note's
§24 the fixed workflow is not being replaced, and nothing here is imported by
the product package. This exists because cases 08, 09 and 10 all measure the
same candidate architecture, and three cases importing each other by file path
was worse than one package they share.

Promoting it out of `cases/08-derived-authority/` is a packaging decision, not
a claim. Whether the model is better than what it is compared against is
exactly what those cases measure, and case 08's answer so far is "it
redistributes stored authority rather than removing it".

    objects.py     the work object: type, state, artifact map, persistence
    skills.py      the registry: approved transformations, versions, digests
    evaluator.py   the manager: validate ready work, derive a grant at use time
    errors.py      refusals, kept distinct so a caller can tell them apart
"""

from __future__ import annotations

from object_model.errors import AuthorizationError, SkillRegistryError
from object_model.evaluator import derive_grant, required_skill, resolve, validate
from object_model.objects import Grant, QueueItem, WorkObject, load_object, save_object
from object_model.skills import (
    REGISTRY, Skill, digest_of, manifest, pin_versions, reset_registry,
    verify_pins,
)

__all__ = [
    "AuthorizationError", "SkillRegistryError",
    "derive_grant", "required_skill", "resolve", "validate",
    "Grant", "QueueItem", "WorkObject", "load_object", "save_object",
    "REGISTRY", "Skill", "digest_of", "manifest", "pin_versions",
    "reset_registry", "verify_pins",
]
