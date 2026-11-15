"""Promptfoo custom Python provider & assertion adapter for EvidAudit.

Usage in promptfooconfig.yaml:
  providers:
    - id: file://examples/integrations/promptfoo_provider.py
"""
from __future__ import annotations

import json
from typing import Any

from evidaudit import Auditor


def call_api(prompt: str, options: dict[str, Any] | None = None, context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Promptfoo Python provider entry point returning decision + semantic integrity metadata."""
    vars_dict = (context or {}).get("vars", {})
    propositions = vars_dict.get("propositions") or json.loads(prompt)
    evidence = vars_dict.get("evidence", {})

    auditor = Auditor()
    result = auditor.evaluate(propositions=propositions, evidence=evidence)
    return {
        "output": json.dumps(
            {
                "decision": result.decision,
                "concealed_corruption": result.concealed_corruption,
                "semantic_errors": [e.item_id for e in result.semantic_errors],
                "explanation": result.explanation,
            }
        ),
        "metadata": {
            "concealed_corruption": result.concealed_corruption,
            "decision": result.decision,
        },
    }


def get_assert(output: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Promptfoo custom Python assertion: fail if semantic corruption is detected."""
    data = json.loads(output)
    passed = not bool(data.get("concealed_corruption", False))
    return {
        "pass": passed,
        "score": 1.0 if passed else 0.0,
        "reason": data.get("explanation", ""),
    }
