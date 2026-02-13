import json
import os
from typing import Any, Dict

from core.config import settings


POLICY_DIR = os.path.join(os.path.dirname(__file__), "..", "policies")
DEFAULT_POLICY_NAME = "default"

_POLICY_CACHE: Dict[str, Any] = {}


def _load_policy() -> Dict[str, Any]:
    """
    Loads the active policy JSON from policies/<name>.json.
    Falls back to a built-in default if the file is missing.
    """
    if _POLICY_CACHE:
        return _POLICY_CACHE

    policy_name = os.getenv("BLIP_POLICY", DEFAULT_POLICY_NAME)
    policy_path = os.path.join(POLICY_DIR, f"{policy_name}.json")

    try:
        with open(policy_path, "r", encoding="utf-8") as f:
            _POLICY_CACHE.update(json.load(f))
            return _POLICY_CACHE
    except Exception:
        # Minimal default policy: keep existing behavior (BLOCK with current risk)
        _POLICY_CACHE.update(
            {
                "name": "Blip Default Policy",
                "description": "Built-in policy that keeps existing hard-coded behavior.",
                "rules": [],
            }
        )
        return _POLICY_CACHE


def _rule_matches(rule: Dict[str, Any], threat: Dict[str, Any]) -> bool:
    """
    Returns True if all fields in rule['match'] match the corresponding threat fields.
    Supports '*' wildcard.
    """
    match = rule.get("match", {})
    for key, expected in match.items():
        actual = str(threat.get(key, ""))
        if expected == "*":
            continue
        if str(expected) != actual:
            return False
    return True


def apply_policy(threat: Dict[str, Any]) -> Dict[str, Any]:
    """
    Applies the active policy to a detected threat and returns an augmented threat dict.

    Policy format (policies/*.json):
    {
      "name": "India Govt Policy",
      "rules": [
        {
          "match": { "threat_type": "Aadhaar Number" },
          "risk_level": "CRITICAL",
          "enforcement": "BLOCK"
        },
        {
          "match": { "source": "image" },
          "risk_level": "HIGH",
          "enforcement": "BLOCK"
        },
        {
          "match": { "threat_type": "*" },
          "enforcement": "WARN"
        }
      ]
    }

    The first matching rule wins. If no rule matches, enforcement defaults to "BLOCK".
    """
    policy = _load_policy()
    rules = policy.get("rules", []) or []

    effective = dict(threat)  # shallow copy
    enforcement = "BLOCK"

    for rule in rules:
        if _rule_matches(rule, threat):
            if "risk_level" in rule and rule["risk_level"]:
                effective["risk_level"] = str(rule["risk_level"]).upper()
            if "enforcement" in rule and rule["enforcement"]:
                enforcement = str(rule["enforcement"]).upper()
            break

    effective["policy_enforcement"] = enforcement
    effective.setdefault("risk_level", "MEDIUM")
    return effective


__all__ = ["apply_policy"]

