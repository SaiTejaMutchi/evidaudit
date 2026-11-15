"""Minimal runnable example: concealed prohibition corruption exposed by override revocation."""
from __future__ import annotations

from evidaudit import audit_extraction, simulate_override_revocation

packet_ids = {"E1", "E2", "E3"}

# Upstream LLM extractor correctly checks clearance (E1) and active waiver (E3),
# but falsely records the export prohibition (E2) as FALSE.
extraction = {
    "prerequisites": [
        {"rule_id": "req_clearance", "prerequisite_satisfied": "TRUE", "evidence_ids": ["E1"]}
    ],
    "prohibitions": [
        {"rule_id": "prohib_export", "prohibition_applies": "FALSE", "evidence_ids": ["E2"]}
    ],
    "overrides": [
        {
            "rule_id": "ov_waiver",
            "targets_prohibition": "prohib_export",
            "override_valid": "TRUE",
            "authority_rank": 3,
            "evidence_ids": ["E3"],
        }
    ],
}

reference_props = {
    "prerequisites": {"req_clearance": "TRUE"},
    "prohibitions": {"prohib_export": "TRUE"},
    "overrides": {"ov_waiver": "TRUE"},
}

report = audit_extraction(
    extraction,
    reference_props=reference_props,
    reference_decision="ALLOW",
    valid_packet_ids=packet_ids,
)
print(f"Initial decision: {report.decision} (correct={report.decision_correct})")
print(f"Concealed corruption: {report.concealed_corruption} -> {report.discrepancies}")

exposure = simulate_override_revocation(
    extraction,
    target_prohibition="prohib_export",
    prohibition_id="prohib_export",
    valid_packet_ids=packet_ids,
)
print(f"After override revocation: {exposure.post_transition_decision} (unsafe={exposure.unsafe_approval_exposed})")
print(f"After single-field repair: {exposure.repaired_decision} (restored={exposure.repair_restored_safety})")

