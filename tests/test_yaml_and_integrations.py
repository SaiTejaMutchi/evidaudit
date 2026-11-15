from __future__ import annotations

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evidaudit.cli import main
from examples.integrations.deepeval_metric import SemanticIntegrityMetric
from examples.integrations.promptfoo_provider import call_api, get_assert


def test_yaml_runner_cli(capsys) -> None:
    yaml_path = Path(__file__).resolve().parents[1] / "examples" / "payment_expiry.yaml"
    assert main(["test", str(yaml_path), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["passed"] is True
    assert payload["decision"] == "ALLOW"
    assert payload["concealed_corruption"] is True
    assert payload["transitions"][0]["post_transition_decision"] == "ALLOW"
    assert payload["transitions"][0]["repaired_decision"] == "BLOCK"


def test_promptfoo_adapter() -> None:
    propositions = {
        "prerequisites": [{"rule_id": "req_1", "prerequisite_satisfied": "TRUE", "evidence_ids": ["E1"]}],
        "prohibitions": [{"rule_id": "prohib_1", "prohibition_applies": "FALSE", "evidence_ids": ["E2"]}],
        "overrides": [{"rule_id": "ov_1", "targets_prohibition": "prohib_1", "override_valid": "TRUE", "authority_rank": 3, "evidence_ids": ["E3"]}],
    }
    evidence = {
        "packet_ids": ["E1", "E2", "E3"],
        "reference_decision": "ALLOW",
        "reference_propositions": {"prerequisites": {"req_1": "TRUE"}, "prohibitions": {"prohib_1": "TRUE"}, "overrides": {"ov_1": "TRUE"}},
    }
    resp = call_api(json.dumps(propositions), context={"vars": {"evidence": evidence}})
    assertion = get_assert(resp["output"])
    assert assertion["pass"] is False
    assert assertion["score"] == 0.0


def test_deepeval_metric() -> None:
    metric = SemanticIntegrityMetric()
    score = metric.measure(
        {
            "actual_output": json.dumps(
                {
                    "prerequisites": [{"rule_id": "req_1", "prerequisite_satisfied": "TRUE", "evidence_ids": ["E1"]}],
                    "prohibitions": [],
                    "overrides": [],
                }
            ),
            "context": {
                "packet_ids": ["E1"],
                "reference_decision": "ALLOW",
                "reference_propositions": {"prerequisites": {"req_1": "TRUE"}},
            },
        }
    )
    assert score == 1.0
    assert metric.is_successful() is True

