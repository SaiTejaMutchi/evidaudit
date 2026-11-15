"""DeepEval-compatible custom metric for semantic integrity evaluation."""
from __future__ import annotations

import json
from typing import Any

from evidaudit import Auditor


class SemanticIntegrityMetric:
    """Drop-in metric compatible with DeepEval's custom metric interface (measure / is_successful)."""

    def __init__(self, threshold: float = 1.0) -> None:
        self.threshold = threshold
        self.score: float = 0.0
        self.reason: str = ""
        self.success: bool = False
        self._auditor = Auditor()

    @property
    def __name__(self) -> str:
        return "Semantic Integrity"

    def measure(self, test_case: Any) -> float:
        """Evaluate an object or dict with `actual_output` (JSON propositions) and `context` (evidence dict)."""
        raw_out = test_case["actual_output"] if isinstance(test_case, dict) else test_case.actual_output
        ctx = test_case.get("context", {}) if isinstance(test_case, dict) else getattr(test_case, "context", {})
        propositions = json.loads(raw_out) if isinstance(raw_out, str) else raw_out

        res = self._auditor.evaluate(propositions=propositions, evidence=ctx)
        self.score = 0.0 if (res.concealed_corruption or res.semantic_errors or res.grounding_errors) else 1.0
        self.reason = res.explanation
        self.success = self.score >= self.threshold
        return self.score

    def is_successful(self) -> bool:
        return self.success


if __name__ == "__main__":
    metric = SemanticIntegrityMetric()
    sample = {
        "actual_output": json.dumps(
            {
                "prerequisites": [{"rule_id": "req_1", "prerequisite_satisfied": "TRUE", "evidence_ids": ["E1"]}],
                "prohibitions": [{"rule_id": "prohib_1", "prohibition_applies": "FALSE", "evidence_ids": ["E2"]}],
                "overrides": [{"rule_id": "ov_1", "targets_prohibition": "prohib_1", "override_valid": "TRUE", "authority_rank": 3, "evidence_ids": ["E3"]}],
            }
        ),
        "context": {
            "packet_ids": ["E1", "E2", "E3"],
            "reference_decision": "ALLOW",
            "reference_propositions": {"prerequisites": {"req_1": "TRUE"}, "prohibitions": {"prohib_1": "TRUE"}, "overrides": {"ov_1": "TRUE"}},
        },
    }
    score = metric.measure(sample)
    print(f"DeepEval-compatible score={score}, success={metric.is_successful()}, reason={metric.reason}")
