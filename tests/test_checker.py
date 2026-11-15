from __future__ import annotations

from evidaudit.checker import evaluate_extraction


def test_fail_closed_on_malformed_json() -> None:
    res = evaluate_extraction("not json", valid_packet_ids={"E1"})
    assert res.decision == "ABSTAIN"
    assert not res.parsed_ok


def test_ungrounded_policy_only_id_rejected() -> None:
    extraction = {
        "prerequisites": [{"rule_id": "req1", "prerequisite_satisfied": "TRUE", "evidence_ids": ["P1"]}],
        "prohibitions": [],
        "overrides": [],
    }
    res = evaluate_extraction(extraction, valid_packet_ids={"P1", "E1"})
    assert res.decision == "ABSTAIN"
    assert any("ungrounded_prereq_true" in r for r in res.reasons)


def test_unknown_prohibition_abstains() -> None:
    extraction = {
        "prerequisites": [{"rule_id": "req1", "prerequisite_satisfied": "TRUE", "evidence_ids": ["E1"]}],
        "prohibitions": [{"rule_id": "prohib1", "prohibition_applies": "UNKNOWN", "evidence_ids": ["E2"]}],
        "overrides": [],
    }
    res = evaluate_extraction(extraction, valid_packet_ids={"E1", "E2"}, variant="v2-strict")
    assert res.decision == "ABSTAIN"

