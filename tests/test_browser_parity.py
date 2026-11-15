from __future__ import annotations

import json
from pathlib import Path
import subprocess

from evidaudit.checker import evaluate_extraction


def _run_js_checker(cases: list[dict]) -> list[str]:
    app_js = Path(__file__).resolve().parents[1] / "playground" / "app.js"
    src = app_js.read_text(encoding="utf-8")
    # Extract VALID_PACKET_IDS and evaluateV2Strict from playground/app.js without DOM dependencies
    start = src.index("const VALID_PACKET_IDS")
    end = src.index("function setPill")
    checker_js = src[start:end]
    script = (
        checker_js
        + "\nconst cases = JSON.parse(process.argv[1]);\n"
        + "console.log(JSON.stringify(cases.map(c => evaluateV2Strict(c))));\n"
    )
    out = subprocess.check_output(["node", "-e", script, json.dumps(cases)], text=True)
    return json.loads(out)


def test_browser_checker_parity_with_python() -> None:
    packet_ids = {"E1", "E2", "E3"}
    cases = [
        # 1. Valid ALLOW
        {
            "prerequisites": [{"rule_id": "req_1", "prerequisite_satisfied": "TRUE", "evidence_ids": ["E1"]}],
            "prohibitions": [{"rule_id": "prohib_1", "prohibition_applies": "FALSE", "evidence_ids": ["E2"]}],
            "overrides": [],
        },
        # 2. Active prohibition blocks
        {
            "prerequisites": [{"rule_id": "req_1", "prerequisite_satisfied": "TRUE", "evidence_ids": ["E1"]}],
            "prohibitions": [{"rule_id": "prohib_1", "prohibition_applies": "TRUE", "evidence_ids": ["E2"]}],
            "overrides": [],
        },
        # 3. Valid override allows despite active prohibition
        {
            "prerequisites": [{"rule_id": "req_1", "prerequisite_satisfied": "TRUE", "evidence_ids": ["E1"]}],
            "prohibitions": [{"rule_id": "prohib_1", "prohibition_applies": "TRUE", "evidence_ids": ["E2"]}],
            "overrides": [
                {
                    "rule_id": "ov_1",
                    "targets_prohibition": "prohib_1",
                    "override_valid": "TRUE",
                    "authority_rank": 3,
                    "evidence_ids": ["E3"],
                }
            ],
        },
        # 4. Missing evidence_ids -> ABSTAIN
        {
            "prerequisites": [{"rule_id": "req_1", "prerequisite_satisfied": "TRUE", "evidence_ids": []}],
            "prohibitions": [],
            "overrides": [],
        },
        # 5. Policy-only P1 citation -> ABSTAIN
        {
            "prerequisites": [{"rule_id": "req_1", "prerequisite_satisfied": "TRUE", "evidence_ids": ["P1"]}],
            "prohibitions": [],
            "overrides": [],
        },
        # 6. Unknown prohibition -> ABSTAIN
        {
            "prerequisites": [{"rule_id": "req_1", "prerequisite_satisfied": "TRUE", "evidence_ids": ["E1"]}],
            "prohibitions": [{"rule_id": "prohib_1", "prohibition_applies": "UNKNOWN", "evidence_ids": ["E2"]}],
            "overrides": [],
        },
        # 7. False prerequisite -> BLOCK
        {
            "prerequisites": [{"rule_id": "req_1", "prerequisite_satisfied": "FALSE", "evidence_ids": ["E1"]}],
            "prohibitions": [],
            "overrides": [],
        },
        # 8. Unknown prerequisite -> ABSTAIN
        {
            "prerequisites": [{"rule_id": "req_1", "prerequisite_satisfied": "UNKNOWN", "evidence_ids": ["E1"]}],
            "prohibitions": [],
            "overrides": [],
        },
        # 9. Empty prerequisites -> ABSTAIN
        {
            "prerequisites": [],
            "prohibitions": [],
            "overrides": [],
        },
    ]

    js_decisions = _run_js_checker(cases)
    py_decisions = [
        evaluate_extraction(case, valid_packet_ids=packet_ids, variant="v2-strict").decision
        for case in cases
    ]
    assert js_decisions == py_decisions
