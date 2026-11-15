"""Core semantic corruption auditing, counterfactual exposure, and proposition repair."""
from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any

from evidaudit.checker import PREREQ_STATE_MAP, PROHIB_STATE_STRICT, evaluate_extraction


@dataclass(frozen=True)
class FieldDiscrepancy:
    section: str  # prerequisites | prohibitions | overrides
    item_id: str
    extracted_state: str
    reference_state: str


@dataclass(frozen=True)
class SemanticAuditReport:
    decision: str
    reference_decision: str
    decision_correct: bool
    has_semantic_corruption: bool
    concealed_corruption: bool
    discrepancies: tuple[FieldDiscrepancy, ...]


@dataclass(frozen=True)
class CounterfactualExposureReport:
    initial_decision: str
    post_transition_decision: str
    post_transition_reference: str
    unsafe_approval_exposed: bool
    repaired_decision: str | None = None
    repair_restored_safety: bool = False


@dataclass(frozen=True)
class TransitionComparisonReport:
    replay_decision: str
    regenerated_decision: str
    reference_decision: str
    replay_missed_failure: bool


def _norm_section_state(section: str, item: dict[str, Any]) -> str:
    if section == "prerequisites":
        raw = item.get("prerequisite_satisfied", item.get("evidence_state", item.get("status")))
        return PREREQ_STATE_MAP.get(str(raw).strip().upper(), "UNKNOWN") if not isinstance(raw, bool) else ("TRUE" if raw else "FALSE")
    if section == "prohibitions":
        raw = item.get("prohibition_applies", item.get("evidence_state", item.get("applies")))
        return PROHIB_STATE_STRICT.get(str(raw).strip().upper(), "UNKNOWN") if not isinstance(raw, bool) else ("TRUE" if raw else "FALSE")
    raw = item.get("override_valid", item.get("override_applies", item.get("applies")))
    return PREREQ_STATE_MAP.get(str(raw).strip().upper(), "UNKNOWN") if not isinstance(raw, bool) else ("TRUE" if raw else "FALSE")


def audit_extraction(
    extraction: dict[str, Any],
    reference_props: dict[str, dict[str, str]],
    reference_decision: str,
    valid_packet_ids: set[str] | None = None,
) -> SemanticAuditReport:
    """Compare extracted propositions against reference proposition states."""
    result = evaluate_extraction(extraction, valid_packet_ids=valid_packet_ids, variant="v2-strict")
    discrepancies: list[FieldDiscrepancy] = []

    for section in ("prerequisites", "prohibitions", "overrides"):
        ref_map = reference_props.get(section, {})
        items = extraction.get(section, [])
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            item_id = str(item.get("rule_id") or item.get("name") or "").strip()
            if item_id in ref_map:
                ext_state = _norm_section_state(section, item)
                ref_state = str(ref_map[item_id]).strip().upper()
                if ext_state != ref_state:
                    discrepancies.append(
                        FieldDiscrepancy(
                            section=section,
                            item_id=item_id,
                            extracted_state=ext_state,
                            reference_state=ref_state,
                        )
                    )

    decision_correct = result.decision == reference_decision
    has_corruption = len(discrepancies) > 0
    return SemanticAuditReport(
        decision=result.decision,
        reference_decision=reference_decision,
        decision_correct=decision_correct,
        has_semantic_corruption=has_corruption,
        concealed_corruption=decision_correct and has_corruption,
        discrepancies=tuple(discrepancies),
    )


def revoke_override(extraction: dict[str, Any], target_prohibition: str) -> dict[str, Any]:
    """Return a deep-copied extraction with overrides targeting `target_prohibition` revoked."""
    updated = copy.deepcopy(extraction)
    target_norm = target_prohibition.strip().lower()
    for ov in updated.get("overrides", []):
        if isinstance(ov, dict) and str(ov.get("targets_prohibition", "")).strip().lower() == target_norm:
            if "override_valid" in ov:
                ov["override_valid"] = "FALSE"
            elif "override_applies" in ov:
                ov["override_applies"] = "FALSE"
            else:
                ov["applies"] = "FALSE"
    return updated


def repair_proposition(
    extraction: dict[str, Any],
    section: str,
    item_id: str,
    corrected_state: str,
) -> dict[str, Any]:
    """Repair a single proposition state inside an extraction."""
    updated = copy.deepcopy(extraction)
    field_key = {
        "prerequisites": "prerequisite_satisfied",
        "prohibitions": "prohibition_applies",
        "overrides": "override_valid",
    }[section]
    for item in updated.get(section, []):
        if isinstance(item, dict) and str(item.get("rule_id") or item.get("name") or "").strip() == item_id:
            item[field_key] = corrected_state
    return updated


def simulate_override_revocation(
    extraction: dict[str, Any],
    target_prohibition: str,
    prohibition_id: str,
    valid_packet_ids: set[str] | None = None,
) -> CounterfactualExposureReport:
    """Expose masked prohibition corruption by revoking an active override, then test single-field repair."""
    initial = evaluate_extraction(extraction, valid_packet_ids=valid_packet_ids, variant="v2-strict")
    revoked = revoke_override(extraction, target_prohibition=target_prohibition)
    post = evaluate_extraction(revoked, valid_packet_ids=valid_packet_ids, variant="v2-strict")
    repaired = repair_proposition(revoked, section="prohibitions", item_id=prohibition_id, corrected_state="TRUE")
    repaired_res = evaluate_extraction(repaired, valid_packet_ids=valid_packet_ids, variant="v2-strict")
    return CounterfactualExposureReport(
        initial_decision=initial.decision,
        post_transition_decision=post.decision,
        post_transition_reference="BLOCK",
        unsafe_approval_exposed=(post.decision == "ALLOW"),
        repaired_decision=repaired_res.decision,
        repair_restored_safety=(repaired_res.decision == "BLOCK"),
    )


def compare_replay_vs_regeneration(
    frozen_extraction: dict[str, Any],
    fresh_extraction: dict[str, Any],
    reference_decision: str,
    valid_packet_ids: set[str] | None = None,
) -> TransitionComparisonReport:
    """Compare a frozen-representation replay against a fresh regeneration after a policy/state transition."""
    replay_res = evaluate_extraction(frozen_extraction, valid_packet_ids=valid_packet_ids, variant="v2-strict")
    regen_res = evaluate_extraction(fresh_extraction, valid_packet_ids=valid_packet_ids, variant="v2-strict")
    missed = (replay_res.decision == reference_decision) and (regen_res.decision == "ALLOW") and (reference_decision == "BLOCK")
    return TransitionComparisonReport(
        replay_decision=replay_res.decision,
        regenerated_decision=regen_res.decision,
        reference_decision=reference_decision,
        replay_missed_failure=missed,
    )

