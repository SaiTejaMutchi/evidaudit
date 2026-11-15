from __future__ import annotations

from evidaudit import (
    audit_extraction,
    compare_replay_vs_regeneration,
    simulate_override_revocation,
)


def _sample_corrupted_extraction() -> dict:
    return {
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


def test_concealed_corruption_and_counterfactual_repair() -> None:
    ext = _sample_corrupted_extraction()
    ref = {
        "prerequisites": {"req_clearance": "TRUE"},
        "prohibitions": {"prohib_export": "TRUE"},
        "overrides": {"ov_waiver": "TRUE"},
    }
    audit = audit_extraction(ext, reference_props=ref, reference_decision="ALLOW", valid_packet_ids={"E1", "E2", "E3"})
    assert audit.decision == "ALLOW"
    assert audit.decision_correct
    assert audit.concealed_corruption
    assert len(audit.discrepancies) == 1
    assert audit.discrepancies[0].item_id == "prohib_export"

    exposure = simulate_override_revocation(
        ext,
        target_prohibition="prohib_export",
        prohibition_id="prohib_export",
        valid_packet_ids={"E1", "E2", "E3"},
    )
    assert exposure.initial_decision == "ALLOW"
    assert exposure.post_transition_decision == "ALLOW"
    assert exposure.unsafe_approval_exposed
    assert exposure.repaired_decision == "BLOCK"
    assert exposure.repair_restored_safety


def test_replay_vs_regeneration_divergence() -> None:
    frozen = {
        "prerequisites": [{"rule_id": "req_window", "prerequisite_satisfied": "FALSE", "evidence_ids": ["E1"]}],
        "prohibitions": [],
        "overrides": [],
    }
    fresh = {
        "prerequisites": [{"rule_id": "req_window", "prerequisite_satisfied": "TRUE", "evidence_ids": ["E1"]}],
        "prohibitions": [],
        "overrides": [],
    }
    cmp = compare_replay_vs_regeneration(frozen, fresh, reference_decision="BLOCK", valid_packet_ids={"E1"})
    assert cmp.replay_decision == "BLOCK"
    assert cmp.regenerated_decision == "ALLOW"
    assert cmp.replay_missed_failure

