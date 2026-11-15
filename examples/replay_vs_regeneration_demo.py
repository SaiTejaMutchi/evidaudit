"""Demonstrates how frozen-representation replay misses failures introduced by fresh regeneration."""
from __future__ import annotations

from evidaudit import compare_replay_vs_regeneration, evaluate_declarative_policy

# Policy transition: evaluation date moves past the authorization window (2026-11-25 > 2026-11-20).
policy_spec = {
    "evaluation_date": "2026-11-25",
    "prerequisites": [
        {
            "id": "req_window",
            "mode": "AND",
            "state": "TRUE",
            "valid_from": "2026-11-01",
            "valid_to": "2026-11-20",
        }
    ],
    "prohibitions": [],
    "overrides": [],
}
oracle_result = evaluate_declarative_policy(policy_spec)

# Frozen replay correctly reflects expired date -> BLOCK
frozen_replay_extraction = {
    "prerequisites": [{"rule_id": "req_window", "prerequisite_satisfied": "FALSE", "evidence_ids": ["E1"]}],
    "prohibitions": [],
    "overrides": [],
}

# Fresh LLM regeneration hallucinates prerequisite_satisfied="TRUE" despite expired date -> ALLOW
fresh_regeneration_extraction = {
    "prerequisites": [{"rule_id": "req_window", "prerequisite_satisfied": "TRUE", "evidence_ids": ["E1"]}],
    "prohibitions": [],
    "overrides": [],
}

cmp = compare_replay_vs_regeneration(
    frozen_extraction=frozen_replay_extraction,
    fresh_extraction=fresh_regeneration_extraction,
    reference_decision=oracle_result.decision,
    valid_packet_ids={"E1"},
)
print(f"Declarative oracle reference: {oracle_result.decision} ({oracle_result.decisive_reasons})")
print(f"Frozen replay decision:       {cmp.replay_decision}")
print(f"Fresh regeneration decision:  {cmp.regenerated_decision}")
print(f"Replay missed failure:        {cmp.replay_missed_failure}")

