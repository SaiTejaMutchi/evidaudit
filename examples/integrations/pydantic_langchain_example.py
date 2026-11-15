"""Example: auditing Pydantic-style / LangChain structured LLM outputs with EvidAudit."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from evidaudit import Auditor


@dataclass
class ExtractedGateOutput:
    """Mirrors a Pydantic BaseModel or LangChain with_structured_output() schema."""
    prerequisites: list[dict]
    prohibitions: list[dict]
    overrides: list[dict]


def main() -> None:
    # Valid JSON/schema output from an LLM, but semantically corrupted on payment expiry.
    llm_output = ExtractedGateOutput(
        prerequisites=[{"rule_id": "req_payment_window", "prerequisite_satisfied": "TRUE", "evidence_ids": ["E1"]}],
        prohibitions=[],
        overrides=[],
    )
    evidence = {
        "packet_ids": {"E1"},
        "reference_decision": "BLOCK",
        "reference_propositions": {"prerequisites": {"req_payment_window": "FALSE"}},
    }
    result = Auditor().evaluate(propositions=asdict(llm_output), evidence=evidence)
    print(f"Decision={result.decision}, SemanticErrors={len(result.semantic_errors)}, Explanation={result.explanation}")


if __name__ == "__main__":
    main()
