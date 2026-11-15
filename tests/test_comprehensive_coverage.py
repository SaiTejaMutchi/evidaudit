from __future__ import annotations

import json
from pathlib import Path

from evidaudit import Auditor, evaluate_declarative_policy, evaluate_extraction
from evidaudit.cli import main
from evidaudit.yaml_runner import run_yaml_test_case


def test_missing_and_invalid_evidence_references_fail_closed() -> None:
    # Empty evidence_ids on prerequisite -> ABSTAIN
    missing_eids = {
        "prerequisites": [{"rule_id": "req_1", "prerequisite_satisfied": "TRUE", "evidence_ids": []}],
        "prohibitions": [],
        "overrides": [],
    }
    res_missing = evaluate_extraction(missing_eids, valid_packet_ids={"E1"}, variant="v2-strict")
    assert res_missing.decision == "ABSTAIN"

    # Unknown packet ID not in packet_ids -> ABSTAIN
    invalid_eid = {
        "prerequisites": [{"rule_id": "req_1", "prerequisite_satisfied": "TRUE", "evidence_ids": ["E99"]}],
        "prohibitions": [],
        "overrides": [],
    }
    res_invalid = evaluate_extraction(invalid_eid, valid_packet_ids={"E1"}, variant="v2-strict")
    assert res_invalid.decision == "ABSTAIN"


def test_malformed_structured_inputs_fail_closed() -> None:
    for bad in ("", "not json", "[]", "[1, 2, 3]"):
        res = evaluate_extraction(bad, valid_packet_ids={"E1"}, variant="v2-strict")
        assert res.parsed_ok is False
        assert res.decision == "ABSTAIN"

    # Missing required list sections -> ABSTAIN
    empty_obj = {}
    res_empty = evaluate_extraction(empty_obj, valid_packet_ids={"E1"}, variant="v2-strict")
    assert res_empty.decision == "ABSTAIN"


def test_meaning_preserving_policy_change_exposes_unsafe_approval() -> None:
    # Reworded meaning-preserving policy where an expired prerequisite window must BLOCK.
    spec = {
        "evaluation_date": "2026-06-15",
        "prerequisites": [
            {
                "id": "req_payment_window",
                "mode": "AND",
                "state": "TRUE",
                "valid_from": "2026-05-01",
                "valid_to": "2026-06-01",
            }
        ],
        "prohibitions": [],
        "overrides": [],
    }
    oracle_res = evaluate_declarative_policy(spec)
    assert oracle_res.decision == "BLOCK"

    # Agent mis-parses the expired window as TRUE under meaning-preserving update.
    propositions = {
        "prerequisites": [{"rule_id": "req_payment_window", "prerequisite_satisfied": "TRUE", "evidence_ids": ["E1"]}],
        "prohibitions": [],
        "overrides": [],
    }
    evidence = {
        "packet_ids": {"E1"},
        "reference_decision": oracle_res.decision,
        "reference_propositions": {
            "prerequisites": {"req_payment_window": "FALSE"},
        },
    }
    audit_res = Auditor().evaluate(propositions=propositions, evidence=evidence)
    assert audit_res.decision == "ALLOW"
    assert audit_res.decision != oracle_res.decision
    assert len(audit_res.semantic_errors) == 1
    assert audit_res.semantic_errors[0].item_id == "req_payment_window"


def test_yaml_runner_failure_conditions_and_cli_exit_codes(tmp_path: Path, capsys) -> None:
    failing_yaml = tmp_path / "failing.yaml"
    failing_yaml.write_text(
        """name: Failing decision expectation
variant: v2-strict
expected_decision: BLOCK
expected_concealed_corruption: false
evidence:
  packet_ids: [E1]
  reference_decision: ALLOW
  reference_propositions:
    prerequisites:
      req_1: TRUE
propositions:
  prerequisites:
    - rule_id: req_1
      prerequisite_satisfied: TRUE
      evidence_ids: [E1]
""",
        encoding="utf-8",
    )
    res = run_yaml_test_case(failing_yaml)
    assert res.passed is False
    assert len(res.failures) >= 1

    rc = main(["test", str(failing_yaml), "--json"])
    assert rc == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["passed"] is False

    # Missing file returns non-zero exit code
    assert main(["test", str(tmp_path / "nonexistent.yaml")]) == 1
