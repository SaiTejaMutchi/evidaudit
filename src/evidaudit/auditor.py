"""High-level developer API for semantic integrity auditing and counterfactual evaluation."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from evidaudit.audit import (
    CounterfactualExposureReport,
    FieldDiscrepancy,
    TransitionComparisonReport,
    audit_extraction,
    compare_replay_vs_regeneration,
    repair_proposition,
    simulate_override_revocation,
)
from evidaudit.checker import evaluate_extraction, extract_json_object
from evidaudit.oracle import evaluate_declarative_policy


@dataclass(frozen=True)
class EvaluationResult:
    decision: str
    reference_decision: str | None
    decision_correct: bool | None
    semantic_errors: tuple[FieldDiscrepancy, ...]
    grounding_errors: tuple[str, ...]
    concealed_corruption: bool
    explanation: str


class Auditor:
    """Semantic integrity and counterfactual evaluator for AI decision systems."""

    def __init__(self, variant: str = "v2-strict") -> None:
        self.variant = variant

    def evaluate(
        self,
        propositions: dict[str, Any] | str,
        evidence: set[str] | dict[str, Any] | None = None,
        policy: dict[str, Any] | None = None,
    ) -> EvaluationResult:
        """Evaluate extracted propositions against deterministic grounding rules,
        optional declarative policy, and optional reference propositions.
        """
        parsed = extract_json_object(propositions)
        packet_ids: set[str] | None = None
        ref_props: dict[str, dict[str, str]] = {}
        ref_decision: str | None = None

        if isinstance(evidence, set):
            packet_ids = evidence
        elif isinstance(evidence, dict):
            raw_pids = evidence.get("packet_ids")
            if raw_pids is not None:
                packet_ids = set(raw_pids)
            ref_props = evidence.get("reference_propositions", {})
            ref_decision = evidence.get("reference_decision")

        if policy is not None and ref_decision is None:
            ref_decision = evaluate_declarative_policy(policy).decision

        checker_res = evaluate_extraction(
            propositions if parsed is None else parsed,
            valid_packet_ids=packet_ids,
            variant=self.variant,
        )
        grounding_errors = tuple(
            r for r in checker_res.reasons if "ungrounded" in r or "invalid_authority_rank" in r or "malformed" in r
        )

        semantic_errors: tuple[FieldDiscrepancy, ...] = ()
        concealed = False
        decision_correct: bool | None = (checker_res.decision == ref_decision) if ref_decision else None

        if parsed is not None and ref_props:
            audit_res = audit_extraction(
                parsed,
                reference_props=ref_props,
                reference_decision=ref_decision or checker_res.decision,
                valid_packet_ids=packet_ids,
            )
            semantic_errors = audit_res.discrepancies
            concealed = bool(decision_correct and (len(semantic_errors) > 0 or len(grounding_errors) > 0))
        elif decision_correct and len(grounding_errors) > 0:
            concealed = True

        if concealed:
            explanation = (
                f"Decision {checker_res.decision} matches reference ({ref_decision}), "
                f"but conceals {len(semantic_errors)} semantic error(s) and {len(grounding_errors)} grounding error(s)."
            )
        elif semantic_errors or grounding_errors:
            explanation = (
                f"Decision {checker_res.decision} with {len(semantic_errors)} semantic error(s) "
                f"and {len(grounding_errors)} grounding error(s)."
            )
        else:
            explanation = f"Decision {checker_res.decision}; no semantic or grounding errors detected."

        return EvaluationResult(
            decision=checker_res.decision,
            reference_decision=ref_decision,
            decision_correct=decision_correct,
            semantic_errors=semantic_errors,
            grounding_errors=grounding_errors,
            concealed_corruption=concealed,
            explanation=explanation,
        )

    def test_override_revocation(
        self,
        propositions: dict[str, Any],
        target_prohibition: str,
        prohibition_id: str,
        packet_ids: set[str] | None = None,
    ) -> CounterfactualExposureReport:
        """Expose masked prohibition errors by revoking an active override and testing single-field repair."""
        return simulate_override_revocation(
            propositions,
            target_prohibition=target_prohibition,
            prohibition_id=prohibition_id,
            valid_packet_ids=packet_ids,
        )

    def compare_replay_vs_regeneration(
        self,
        frozen_propositions: dict[str, Any],
        fresh_propositions: dict[str, Any],
        reference_decision: str,
        packet_ids: set[str] | None = None,
    ) -> TransitionComparisonReport:
        """Compare frozen-representation replay against fresh regeneration."""
        return compare_replay_vs_regeneration(
            frozen_extraction=frozen_propositions,
            fresh_extraction=fresh_propositions,
            reference_decision=reference_decision,
            valid_packet_ids=packet_ids,
        )

    def repair(
        self,
        propositions: dict[str, Any],
        section: str,
        item_id: str,
        corrected_state: str,
    ) -> dict[str, Any]:
        """Return a copy of `propositions` with one proposition repaired."""
        return repair_proposition(propositions, section=section, item_id=item_id, corrected_state=corrected_state)

