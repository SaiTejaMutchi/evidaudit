"""Command-line interface for EvidAudit."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

from evidaudit.auditor import Auditor
from evidaudit.oracle import evaluate_declarative_policy
from evidaudit.reproduce import recompute_all_findings
from evidaudit.yaml_runner import run_yaml_test_case


def run_demo() -> int:
    """Execute the core semantic-masking and replay-vs-regeneration demonstrations."""
    auditor = Auditor()
    packet_ids = {"E1", "E2", "E3"}
    corrupted_extraction: dict[str, Any] = {
        "prerequisites": [
            {
                "rule_id": "req_clearance",
                "name": "Security clearance verified",
                "prerequisite_satisfied": "TRUE",
                "evidence_ids": ["E1"],
            }
        ],
        "prohibitions": [
            {
                "rule_id": "prohib_export",
                "name": "Dual-use export restriction",
                "prohibition_applies": "FALSE",  # Corrupted! Should be TRUE
                "evidence_ids": ["E2"],
            }
        ],
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
        "packet_ids": packet_ids,
        "reference_propositions": {
            "prerequisites": {"req_clearance": "TRUE"},
            "prohibitions": {"prohib_export": "TRUE"},
            "overrides": {"ov_waiver": "TRUE"},
        },
        "reference_decision": "ALLOW",
    }

    print("=== EvidAudit Demo 1: Concealed Semantic Corruption & Counterfactual Repair ===")
    res = auditor.evaluate(propositions=corrupted_extraction, evidence=evidence)
    print(f"[1] {res.explanation}")
    for err in res.semantic_errors:
        print(f"    -> {err.section}.{err.item_id}: extracted={err.extracted_state}, reference={err.reference_state}")

    exposure = auditor.test_override_revocation(
        corrupted_extraction,
        target_prohibition="prohib_export",
        prohibition_id="prohib_export",
        packet_ids=packet_ids,
    )
    print(f"[2] Override revoked -> Post-Transition Decision: {exposure.post_transition_decision} (UNSAFE={exposure.unsafe_approval_exposed})")
    print(f"[3] Single-proposition repair -> Repaired Decision: {exposure.repaired_decision} (RESTORED={exposure.repair_restored_safety})")

    print("\n=== EvidAudit Demo 2: Frozen Replay vs. Fresh Regeneration (Temporal Expiry) ===")
    cmp = auditor.compare_replay_vs_regeneration(
        frozen_propositions={"prerequisites": [{"rule_id": "req_window", "prerequisite_satisfied": "FALSE", "evidence_ids": ["E1"]}], "prohibitions": [], "overrides": []},
        fresh_propositions={"prerequisites": [{"rule_id": "req_window", "prerequisite_satisfied": "TRUE", "evidence_ids": ["E1"]}], "prohibitions": [], "overrides": []},
        reference_decision="BLOCK",
        packet_ids={"E1"},
    )
    print(f"    Frozen Replay: {cmp.replay_decision} | Fresh Regeneration: {cmp.regenerated_decision} (replay_missed_failure={cmp.replay_missed_failure})")
    return 0


def run_reproduce(as_json: bool = False, repo_root: Path | None = None) -> int:
    """Programmatically recompute all headline findings from shipped artifacts."""
    summary = recompute_all_findings(repo_root=repo_root)
    if as_json:
        print(json.dumps(summary, indent=2))
        return 0

    auth = summary["authorization_semantic_corruption"]
    ov = summary["override_revocation_exposure"]
    rep = summary["replay_vs_regeneration"]
    ext = summary["external_folio_replication"]

    print("=== EvidAudit Independent Ledger-Based Reproduction (0 LLM Calls) ===")
    print(
        f"1. Concealed semantic/grounding errors: {auth['concealed_errors']}/{auth['strict_correct_total']} "
        f"({auth['rate_pct']}%)"
    )
    for k in ("ALLOW", "BLOCK", "ABSTAIN"):
        d = auth["disaggregated"][k]
        print(f"   - {k:<7}: {d['corrupted']}/{d['total']} ({d['rate_pct']}%)")
    print(
        f"2. Override-revocation exposure: {ov['corrupted_unsafe']}/{ov['corrupted_total']} corrupted unsafe ALLOW "
        f"vs. {ov['clean_unsafe']}/{ov['clean_total']} clean; single-field repair: {ov['single_field_repaired']}/{ov['corrupted_total']}"
    )
    print(
        f"3. Frozen replay vs. fresh regeneration: {rep['frozen_replay_unsafe']}/{rep['frozen_replay_matched_total']} frozen replay "
        f"vs. {rep['fresh_regeneration_transition_unsafe']}/{rep['fresh_regeneration_transition_total']} fresh regeneration; "
        f"separate meaning-preserving (V7): {rep['meaning_preserving_v7_unsafe']}/{rep['meaning_preserving_v7_total']}"
    )
    print(
        f"4. External FOLIO replication ({ext['total_released_generations']} released generations; "
        f"{ext['audited_primary_8shot_generations']} primary 8-shot audited):"
    )
    for m, st in ext["models"].items():
        print(f"   - {m}: {st['erroneous']}/{st['majority_correct']} ({st['rate_pct']}%, 95% CI {st['story_clustered_ci95_pct']})")
    print(
        f"5. External counterfactual masking & repair: {ext['unambiguous_masking_events']} masking events across "
        f"{ext['distinct_source_stories']} source stories; {ext['single_formula_repairs']}/{ext['unambiguous_masking_events']} "
        f"single-formula repairs ({ext['faithful_controls_agree']}/{ext['faithful_controls_tested']} faithful controls)."
    )
    return 0


def run_verify(repo_root: Path | None = None) -> int:
    """Verify deterministic checker, declarative oracle, and immutable ledger integrity."""
    auditor = Auditor()
    res = auditor.evaluate(
        propositions={
            "prerequisites": [{"rule_id": "req_1", "prerequisite_satisfied": "TRUE", "evidence_ids": ["P1"]}],
            "prohibitions": [],
            "overrides": [],
        },
        evidence={"E1"},
    )
    assert res.decision == "ABSTAIN", f"Expected fail-closed ABSTAIN, got {res.decision}"

    oracle_res = evaluate_declarative_policy(
        {
            "evaluation_date": "2026-11-25",
            "prerequisites": [{"id": "req_win", "mode": "AND", "state": "TRUE", "valid_from": "2026-11-01", "valid_to": "2026-11-20"}],
            "prohibitions": [],
            "overrides": [],
        }
    )
    assert oracle_res.decision == "BLOCK", f"Expected BLOCK on expired window, got {oracle_res.decision}"

    try:
        summary = recompute_all_findings(repo_root=repo_root)
        assert summary["authorization_semantic_corruption"]["concealed_errors"] == 490
        assert summary["override_revocation_exposure"]["corrupted_unsafe"] == 10
        assert summary["replay_vs_regeneration"]["fresh_regeneration_transition_unsafe"] == 7
        assert summary["external_folio_replication"]["unambiguous_masking_events"] == 12
        assert summary["external_folio_replication"]["single_formula_repairs"] == 9
        print("[PASS] Deterministic checker, declarative oracle, and all benchmark dataset invariants verified.")
    except FileNotFoundError:
        print("[PASS] Deterministic checker and declarative oracle verified (run inside cloned repo to also verify benchmarks/data/).")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="evidaudit",
        description="Semantic integrity and counterfactual evaluation toolkit for AI decision systems.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("demo", help="Run semantic-masking, counterfactual-repair, and replay-vs-regeneration demos.")
    rep_p = sub.add_parser("reproduce", help="Programmatically recompute all benchmark findings from curated datasets.")
    rep_p.add_argument("--json", action="store_true", help="Emit machine-readable JSON output.")
    sub.add_parser("verify", help="Verify deterministic checker, declarative oracle, and benchmark dataset invariants.")
    sub.add_parser("verify-ledgers", help="Alias for verify.")
    test_p = sub.add_parser("test", help="Run a declarative YAML policy & evidence regression test case.")
    test_p.add_argument("path", help="Path to YAML test case file.")
    test_p.add_argument("--json", action="store_true", help="Emit machine-readable JSON output.")

    args = parser.parse_args(argv)
    if args.command == "demo":
        return run_demo()
    if args.command == "reproduce":
        return run_reproduce(as_json=args.json)
    if args.command in ("verify", "verify-ledgers"):
        return run_verify()
    if args.command == "test":
        res = run_yaml_test_case(args.path)
        payload = {
            "name": res.name,
            "passed": res.passed,
            "decision": res.decision,
            "concealed_corruption": res.concealed_corruption,
            "semantic_errors": res.semantic_errors,
            "transitions": res.transitions,
            "failures": res.failures,
        }
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            status = "PASS" if res.passed else "FAIL"
            print(f"[{status}] {res.name}: decision={res.decision}, concealed_corruption={res.concealed_corruption}")
            for err in res.semantic_errors:
                print(f"  -> semantic_error: {err['section']}.{err['item_id']} ({err['extracted']} != {err['reference']})")
            for tr in res.transitions:
                print(f"  -> transition ({tr['type']}): post={tr['post_transition_decision']}, repaired={tr['repaired_decision']}")
            for fl in res.failures:
                print(f"  [FAILURE] {fl}")
        return 0 if res.passed else 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
