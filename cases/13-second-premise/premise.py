"""Case 13 - a second independent premise, layered onto case 12's arms.

Case 12's arms are **frozen**, for the reason case 08's `arm_b` is: they
produced a published table. Nothing here edits them. Each wrapper below calls
the frozen arm's own `resolve()` and then applies one additional premise, so
the delta being measured is exactly the premise and nothing else.

The premise added to each arm has to be one a competent designer of *that*
architecture would plausibly build, or the experiment is rigged. An invented
extra check would raise the tamper set in any arm and would prove nothing.
Each is justified where it is defined:

  arm A   a MAC-style label policy over a DAC permission table. This is not
          invented for the comparison - it is the structure of SELinux and
          AppArmor, where a subject's domain and a resource's type must be
          allowed to meet, on top of ordinary mode bits.

  arm C   artifacts that declare what they are, and an object type that
          declares which artifact types its skills may read. Both are on the
          concept note's own list of what canonical artifacts are *for*, and
          on the manager's list of where the object model's advantage might
          still come from.

The premises must be genuinely consulted at use time. A premise no runtime path
reads is the "metadata that is never enforced" anti-pattern the project bans,
and it would make the measurement a lie rather than an error.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from typing import Dict, List, Optional, Set, Tuple

CASE_13 = os.path.dirname(os.path.abspath(__file__))
CASES = os.path.dirname(CASE_13)
REPO = os.path.dirname(CASES)
CASE_12 = os.path.join(CASES, "12-three-models")

for path in (CASE_12, REPO):
    if path not in sys.path:
        sys.path.insert(0, path)

import case12_common as c12  # noqa: E402


def _load12(name: str):
    spec = importlib.util.spec_from_file_location(
        f"case12_{name}", os.path.join(CASE_12, f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[f"case12_{name}"] = module
    spec.loader.exec_module(module)
    return module


arm_a = _load12("arm_a")
arm_c = _load12("arm_c")

TARGET = c12.TARGET
STAGE = c12.ATTACK_STAGE


# ---------------------------------------------------------------------------
# Arm A's second premise: a label policy, over the permission table.
#
# Two keying variants, and the difference between them is the whole point.
# SELinux derives a process's domain from a transition on the *executable's*
# label, not from the uid. A simpler design keys the domain off the identity.
# Both are defensible; they are not equally good, and case 12 could not have
# discovered that because it had only one premise.
# ---------------------------------------------------------------------------

BY_SUBJECT, BY_STAGE = "domain follows the subject", "domain follows the stage"

LABEL_OF: Dict[str, str] = {}
DOMAIN_OF_SUBJECT: Dict[str, str] = {}
DOMAIN_OF_STAGE: Dict[str, str] = {}
ALLOW: Set[Tuple[str, str, str]] = set()


def reset_arm_a() -> None:
    arm_a.reset()
    LABEL_OF.clear()
    LABEL_OF.update({
        c12.KEY_RAW: "orders_t", c12.KEY_SCHEMA: "orders_t",
        c12.KEY_CLEANED: "orders_t", c12.KEY_MATERIAL: "secret_t",
    })
    DOMAIN_OF_SUBJECT.clear()
    DOMAIN_OF_SUBJECT.update(
        {f"svc_{s.name}": f"{s.name}_d" for s in c12.WORKLOAD})
    DOMAIN_OF_SUBJECT[arm_a.KEY_OWNER] = "keys_d"
    DOMAIN_OF_STAGE.clear()
    DOMAIN_OF_STAGE.update({s.name: f"{s.name}_d" for s in c12.WORKLOAD})
    ALLOW.clear()
    for stage in c12.WORKLOAD:
        ALLOW.add((f"{stage.name}_d", "orders_t", "read"))
        ALLOW.add((f"{stage.name}_d", "orders_t", "write"))
    # The vault identity is the only domain allowed to meet the secret type.
    ALLOW.add(("keys_d", "secret_t", "read"))


def _domain(stage: str, variant: str) -> str:
    if variant == BY_STAGE:
        return DOMAIN_OF_STAGE.get(stage, "")
    return DOMAIN_OF_SUBJECT.get(arm_a.SUBJECT_OF_STAGE.get(stage, ""), "")


def resolve_arm_a(stage: str, variant: str) -> c12.Grant:
    """Both premises must permit. The DAC answer is arm A's, unmodified."""
    dac = arm_a.resolve(stage)
    domain = _domain(stage, variant)
    permitted = [k for k in dac.read_keys
                 if (domain, LABEL_OF.get(k, "unlabelled_t"), "read") in ALLOW]
    return c12.Grant(read_keys=permitted, write_key=dac.write_key,
                     source=f"{arm_a.NAME} + label policy ({variant})")


def mutate_a_label_policy(target_key: str) -> str:
    ALLOW.add(("schema_d", LABEL_OF[target_key], "read"))
    return "allowed schema_d to read secret_t in the label policy"


# ---------------------------------------------------------------------------
# Arm C's second premises. Two of them, because arm C has two surfaces that
# yield and one premise closes one surface. That asymmetry is a finding, not
# an accident of this implementation.
# ---------------------------------------------------------------------------

# What each artifact declares itself to be: key -> (object_id, artifact_type).
DECLARES: Dict[str, Tuple[str, str]] = {}

# Which artifact types an object of this type may ever have read on its behalf.
TYPE_READABLE: Dict[str, Set[str]] = {}


def reset_arm_c(store_dir: str) -> None:
    from object_model import skills

    arm_c.reset(store_dir)
    DECLARES.clear()
    DECLARES.update({
        c12.KEY_RAW: (arm_c.OBJ, skills.T_TABLE_PREVIEW),
        c12.KEY_SCHEMA: (arm_c.OBJ, skills.T_SCHEMA_PROFILE),
        c12.KEY_CLEANED: (arm_c.OBJ, skills.T_CLEANED_OUTPUT),
        # The secret is the object's in the ledger's telling - that is exactly
        # what made case 12's skill-contract route work - but it declares
        # itself to be key material, which is what it is.
        c12.KEY_MATERIAL: (arm_c.OBJ, skills.T_KEY_MATERIAL),
    })
    TYPE_READABLE.clear()
    TYPE_READABLE["orders_table"] = {
        skills.T_TABLE_PREVIEW, skills.T_SCHEMA_PROFILE,
        skills.T_CLEANED_OUTPUT, skills.T_VALIDATION_VERDICT,
    }


def resolve_arm_c(stage: str, use_declares: bool = True,
                  use_type_policy: bool = True) -> c12.Grant:
    """Derive as arm C does, then require the extra premises to agree.

    Each read key was resolved *for a declared type*. The premises ask whether
    the artifact agrees that it is that type, and whether the object's type
    permits that type to be read at all.
    """
    from object_model import evaluator, skills

    skill_name = arm_c.SKILL_OF_STAGE[stage]
    obj, ledger, pins = (arm_c._state["obj"], arm_c._state["ledger"],
                         arm_c._state["pins"])
    skill = evaluator.verify_pins(pins, skill_name)
    binding = evaluator.artifact_map(obj, ledger)
    readable = TYPE_READABLE.get(obj.object_type, set())

    permitted: List[str] = []
    for artifact_type in skill.reads:
        key = binding.get(artifact_type)
        if key is None:
            continue
        if use_type_policy and artifact_type not in readable:
            continue                    # premise 2: the object type refuses
        if use_declares and DECLARES.get(key) != (obj.object_id, artifact_type):
            continue                    # premise 1: the artifact disagrees
        permitted.append(key)

    write_key = "" if skill.effects == "read_only" \
        else f"artifact.{skill.produces}"
    return c12.Grant(read_keys=permitted, write_key=write_key,
                     source=f"{arm_c.NAME} + declared artifacts")


def mutate_c_declaration(target_key: str) -> str:
    from object_model import skills
    DECLARES[target_key] = (arm_c.OBJ, skills.T_TABLE_PREVIEW)
    return f"rewrote {target_key}'s own declaration to 'table_preview'"


def mutate_c_type_policy(target_key: str) -> str:
    from object_model import skills
    TYPE_READABLE["orders_table"].add(skills.T_KEY_MATERIAL)
    return "added 'key_material' to what an orders_table may have read"


# ---------------------------------------------------------------------------
# The measurement.
# ---------------------------------------------------------------------------

def minimum_tamper_set(cells) -> Optional[int]:
    winning = [edits for edits, obtained in cells if obtained]
    return min(winning) if winning else None
