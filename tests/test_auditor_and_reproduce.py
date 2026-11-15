from __future__ import annotations

import json
from pathlib import Path

from evidaudit import Auditor
from evidaudit.cli import main
from evidaudit.reproduce import recompute_all_findings


def test_auditor_evaluate_detects_concealed_corruption() -> None:
    auditor = Auditor()
    propositions = {
        "prerequisites": [{"rule_id": "req_clearance", "prerequisite_satisfied": "TRUE", "evidence_ids": ["E1"]}],
        "prohibitions": [{"rule_id": "prohib_export", "prohibition_applies": "FALSE", "evidence_ids": ["E2"]}],
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
    evidence = {
        "packet_ids": {"E1", "E2", "E3"},
        "reference_propositions": {
            "prerequisites": {"req_clearance": "TRUE"},
            "prohibitions": {"prohib_export": "TRUE"},
            "overrides": {"ov_waiver": "TRUE"},
        },
        "reference_decision": "ALLOW",
    }
    res = auditor.evaluate(propositions=propositions, evidence=evidence)
    assert res.decision == "ALLOW"
    assert res.decision_correct is True
    assert res.concealed_corruption is True
    assert len(res.semantic_errors) == 1
    assert "conceals 1 semantic error" in res.explanation


def test_reproduce_recomputes_exact_headline_numbers() -> None:
    summary = recompute_all_findings()
    assert summary["authorization_semantic_corruption"]["concealed_errors"] == 490
    assert summary["authorization_semantic_corruption"]["strict_correct_total"] == 1870
    assert summary["override_revocation_exposure"]["corrupted_unsafe"] == 10
    assert summary["override_revocation_exposure"]["clean_unsafe"] == 0
    assert summary["override_revocation_exposure"]["clean_total"] == 278
    assert summary["replay_vs_regeneration"]["frozen_replay_unsafe"] == 0
    assert summary["replay_vs_regeneration"]["fresh_regeneration_transition_unsafe"] == 7
    assert summary["replay_vs_regeneration"]["meaning_preserving_v7_unsafe"] == 6
    assert summary["external_folio_replication"]["unambiguous_masking_events"] == 12
    assert summary["external_folio_replication"]["distinct_source_stories"] == 5
    assert summary["external_folio_replication"]["single_formula_repairs"] == 9


def test_cli_reproduce_json_and_verify(capsys) -> None:
    assert main(["reproduce", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["reproduction_mode"] == "benchmark_dataset_recomputation"
    assert main(["verify"]) == 0
    assert "[PASS]" in capsys.readouterr().out


def test_playground_files_exist() -> None:
    root = Path(__file__).resolve().parents[1] / "playground"
    assert (root / "index.html").exists()
    assert (root / "app.js").exists()
    assert (root / "styles.css").exists()

