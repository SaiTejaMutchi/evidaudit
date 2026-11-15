"""Fail-closed deterministic authorization checker for structured propositions."""
from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any

PERMITTED_RANK_DOMAIN = {1, 2, 3}
POLICY_ONLY_IDS = {"P1"}

PREREQ_STATE_MAP = {
    "TRUE": "TRUE",
    "ESTABLISHED_TRUE": "TRUE",
    "FALSE": "FALSE",
    "EXPLICITLY_FAILED": "FALSE",
    "UNKNOWN": "UNKNOWN",
    "MISSING_OR_UNVERIFIED": "UNKNOWN",
}

PROHIB_STATE_STRICT = {
    "TRUE": "TRUE",
    "ESTABLISHED_TRUE": "TRUE",
    "FALSE": "FALSE",
    "EXPLICITLY_FAILED": "UNKNOWN",
    "UNKNOWN": "UNKNOWN",
    "MISSING_OR_UNVERIFIED": "UNKNOWN",
}

PROHIB_STATE_APPLIES = {
    "TRUE": "TRUE",
    "ESTABLISHED_TRUE": "TRUE",
    "EXPLICITLY_FAILED": "TRUE",
    "FALSE": "FALSE",
    "UNKNOWN": "UNKNOWN",
    "MISSING_OR_UNVERIFIED": "UNKNOWN",
}


@dataclass(frozen=True)
class CheckerResult:
    decision: str  # ALLOW | BLOCK | ABSTAIN
    reasons: list[str]
    parsed_ok: bool
    parse_error: str | None = None


def extract_json_object(raw_output: str | dict[str, Any]) -> dict[str, Any] | None:
    """Parse a JSON object from a raw string or pass through a dict."""
    if isinstance(raw_output, dict):
        return raw_output
    if not isinstance(raw_output, str):
        return None
    text = raw_output.strip()
    if not text:
        return None
    try:
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        return None
    try:
        obj = json.loads(match.group(0))
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        return None


def _norm_mapped(val: Any, mapping: dict[str, str]) -> str:
    if isinstance(val, bool):
        return "TRUE" if val else "FALSE"
    if not isinstance(val, str):
        return "UNKNOWN"
    return mapping.get(val.strip().upper(), "UNKNOWN")


def _valid_factual_ids(item: dict[str, Any], valid_packet_ids: set[str] | None) -> list[str]:
    eids = item.get("evidence_ids", [])
    if not isinstance(eids, list):
        return []
    out = [str(e).strip() for e in eids if isinstance(e, str) and str(e).strip()]
    out = [e for e in out if e not in POLICY_ONLY_IDS and not e.upper().startswith("P")]
    if valid_packet_ids is not None:
        factual_allowed = {
            pid for pid in valid_packet_ids if pid not in POLICY_ONLY_IDS and not pid.upper().startswith("P")
        }
        out = [e for e in out if e in factual_allowed]
    return out


def _parse_rank(raw_rank: Any, literal_mode: bool) -> tuple[int, bool]:
    """Return (rank, is_valid_domain). Never coerces 0 -> 2."""
    if isinstance(raw_rank, bool):
        return (0, False)
    if raw_rank is None:
        return (0, not literal_mode)
    if isinstance(raw_rank, int):
        if raw_rank == 0 or raw_rank in PERMITTED_RANK_DOMAIN:
            return (raw_rank, True)
        return (0, False)
    if isinstance(raw_rank, str) and raw_rank.strip().isdigit():
        val = int(raw_rank.strip())
        if val == 0 or val in PERMITTED_RANK_DOMAIN:
            return (val, True)
        return (0, False)
    return (0, False)


def evaluate_extraction(
    extraction: str | dict[str, Any],
    valid_packet_ids: set[str] | None = None,
    variant: str = "v2-strict",
) -> CheckerResult:
    """Evaluate extracted authorization propositions under a fail-closed checker."""
    if variant not in {"v2-strict", "v2-prohibition-applies", "v2-literal"}:
        raise ValueError(f"Unknown variant: {variant}")

    literal_mode = variant == "v2-literal"
    prohib_map = PROHIB_STATE_APPLIES if variant == "v2-prohibition-applies" else PROHIB_STATE_STRICT

    obj = extract_json_object(extraction)
    if obj is None:
        return CheckerResult("ABSTAIN", ["malformed_json_fail_closed"], False, "malformed_json")

    prereqs = obj.get("prerequisites")
    prohibs = obj.get("prohibitions")
    overrides = obj.get("overrides", [])

    if not isinstance(prereqs, list) or not isinstance(prohibs, list) or not isinstance(overrides, list):
        return CheckerResult("ABSTAIN", ["missing_required_lists_fail_closed"], False, "missing_required_lists")

    valid_overrides: dict[str, int] = {}
    ungrounded: list[str] = []

    for ov in overrides:
        if not isinstance(ov, dict):
            ungrounded.append("malformed_override_item")
            continue
        raw_ov = ov.get("override_valid") if "override_valid" in ov else ov.get("override_applies", ov.get("applies"))
        if _norm_mapped(raw_ov, PREREQ_STATE_MAP) == "TRUE":
            eids = _valid_factual_ids(ov, valid_packet_ids)
            if not eids:
                ungrounded.append("ungrounded_override")
                continue
            rank, rank_ok = _parse_rank(ov.get("authority_rank"), literal_mode=literal_mode)
            if not rank_ok:
                ungrounded.append("invalid_authority_rank")
                continue
            target = str(ov.get("targets_prohibition", "")).strip().lower()
            if target and rank >= 2:
                valid_overrides[target] = max(valid_overrides.get(target, 0), rank)

    active_blocks: list[str] = []
    unknown_prohibs: list[str] = []

    for pr in prohibs:
        if not isinstance(pr, dict):
            ungrounded.append("malformed_prohibition_item")
            continue
        name = str(pr.get("name", "unnamed_prohibition")).strip() or "unnamed_prohibition"
        rule_id = str(pr.get("rule_id", "")).strip().lower()
        raw_pr = (
            pr.get("prohibition_applies")
            if "prohibition_applies" in pr
            else (pr.get("evidence_state") if "evidence_state" in pr else pr.get("applies"))
        )
        st = _norm_mapped(raw_pr, prohib_map)
        eids = _valid_factual_ids(pr, valid_packet_ids)

        if st == "TRUE":
            if not eids:
                ungrounded.append(f"ungrounded_prohibition:{name}")
                continue
            ov_rank = valid_overrides.get(rule_id, 0) if rule_id else 0
            if ov_rank == 0:
                ov_rank = valid_overrides.get(name.lower(), 0)
            if ov_rank >= 2:
                continue
            active_blocks.append(name)
        elif st == "FALSE":
            if not eids:
                ungrounded.append(f"ungrounded_prohibition_clear:{name}")
        else:
            unknown_prohibs.append(name)

    if active_blocks:
        return CheckerResult("BLOCK", active_blocks, True, None)

    if len(prereqs) == 0:
        return CheckerResult("ABSTAIN", ["no_prerequisites_extracted"], True, "empty_prerequisites")

    false_prereqs: list[str] = []
    unknown_prereqs: list[str] = []
    true_prereqs: list[str] = []

    for pq in prereqs:
        if not isinstance(pq, dict):
            ungrounded.append("malformed_prereq_item")
            continue
        name = str(pq.get("name", "unnamed_prereq")).strip() or "unnamed_prereq"
        raw_pq = (
            pq.get("prerequisite_satisfied")
            if "prerequisite_satisfied" in pq
            else (pq.get("evidence_state") if "evidence_state" in pq else pq.get("status"))
        )
        st = _norm_mapped(raw_pq, PREREQ_STATE_MAP)
        eids = _valid_factual_ids(pq, valid_packet_ids)

        if st == "FALSE":
            if not eids:
                ungrounded.append(f"ungrounded_prereq_false:{name}")
            else:
                false_prereqs.append(name)
        elif st == "TRUE":
            if not eids:
                ungrounded.append(f"ungrounded_prereq_true:{name}")
            else:
                true_prereqs.append(name)
        else:
            unknown_prereqs.append(name)

    if false_prereqs:
        return CheckerResult("BLOCK", false_prereqs, True, None)
    if unknown_prereqs or unknown_prohibs or ungrounded:
        return CheckerResult("ABSTAIN", unknown_prereqs + unknown_prohibs + ungrounded, True, None)
    if not true_prereqs:
        return CheckerResult("ABSTAIN", ["no_true_prerequisites"], True, "empty_true_prerequisites")

    return CheckerResult("ALLOW", true_prereqs, True, None)

