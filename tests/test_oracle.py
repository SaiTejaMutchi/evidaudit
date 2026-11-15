from __future__ import annotations

from evidaudit.oracle import evaluate_declarative_policy


def test_declarative_oracle_temporal_expiry_blocks() -> None:
    spec = {
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
    res = evaluate_declarative_policy(spec)
    assert res.decision == "BLOCK"
    assert "req_window" in res.decisive_reasons


def test_declarative_oracle_override_allows_when_active() -> None:
    spec = {
        "prerequisites": [{"id": "req1", "mode": "AND", "state": "TRUE"}],
        "prohibitions": [{"id": "prohib1", "state": "TRUE", "authority_rank": 2}],
        "overrides": [{"id": "ov1", "targets_prohibition_id": "prohib1", "state": "TRUE", "authority_rank": 3}],
    }
    res = evaluate_declarative_policy(spec)
    assert res.decision == "ALLOW"
