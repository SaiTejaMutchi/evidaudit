#!/usr/bin/env python3
"""Independently coded declarative policy evaluator (Reference Oracle).

Supports 8 structural policy categories:
  1. Permission with revocable override
  2. Time-bounded authorization (evaluation_date vs effective_from / effective_to)
  3. Nested exceptions (exception-to-prohibition, and counter-exception / suspension)
  4. Scope- or entity-specific authorization (requested_scope in allowed_scopes)
  5. Multiple independent blockers (conjunctive prereqs + multiple prohibitions)
  6. Precedence or authority hierarchy (override authority_rank > rule authority_rank)
  7. Conditional fallback authorization (primary prereq OR fallback prereq)
  8. Missing-information / three-valued decisions (UNKNOWN -> ABSTAIN when decisive)

Kept completely separate from scripts/apart/check_rules_v2_corrected.py.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any


@dataclass(frozen=True)
class DeclarativeOracleResult:
    decision: str  # ALLOW | BLOCK | ABSTAIN
    decisive_reasons: tuple[str, ...]
    expected_props: dict[str, Any]  # Normalized proposition-level ground truth for B5-G comparison


def _parse_date(val: str | None) -> date | None:
    if not val:
        return None
    return date.fromisoformat(val)


def _in_window(eval_d: date | None, start_s: str | None, end_s: str | None) -> str:
    """Return 'ACTIVE', 'EXPIRED_OR_INACTIVE', or 'UNKNOWN'."""
    if eval_d is None:
        return "ACTIVE" if (start_s is None and end_s is None) else "UNKNOWN"
    s = _parse_date(start_s)
    e = _parse_date(end_s)
    if s and eval_d < s:
        return "EXPIRED_OR_INACTIVE"
    if e and eval_d > e:
        return "EXPIRED_OR_INACTIVE"
    return "ACTIVE"


def evaluate_declarative_policy(spec: dict[str, Any]) -> DeclarativeOracleResult:
    """Evaluate a structured policy-and-facts specification declaratively.

    Spec fields:
      - evaluation_date: ISO date string or None
      - requested_scope: str or None
      - prerequisites: list[dict] with {id, mode ('AND'|'FALLBACK_GROUP'), state ('TRUE'|'FALSE'|'UNKNOWN'),
                                        valid_from?, valid_to?, allowed_scopes?}
      - prohibitions: list[dict] with {id, state ('TRUE'|'FALSE'|'UNKNOWN'), authority_rank (int),
                                       effective_from?, effective_to?, scopes?,
                                       counter_exception_active? ('TRUE'|'FALSE'|'UNKNOWN')}
      - overrides: list[dict] with {id, targets_prohibition_id, state ('TRUE'|'FALSE'|'UNKNOWN'),
                                    authority_rank (int), effective_from?, effective_to?,
                                    revoked? (bool), suspended_by_nested_exception? ('TRUE'|'FALSE'|'UNKNOWN')}
    """
    eval_d = _parse_date(spec.get("evaluation_date"))
    req_scope = spec.get("requested_scope")

    prereqs: list[dict[str, Any]] = spec.get("prerequisites", [])
    prohibs: list[dict[str, Any]] = spec.get("prohibitions", [])
    overrides: list[dict[str, Any]] = spec.get("overrides", [])

    # 1. Evaluate overrides (accounting for expiry, revocation, nested suspension, rank)
    active_overrides: dict[str, int] = {}
    unknown_overrides: set[str] = set()
    ov_expected: list[dict[str, Any]] = []

    for ov in overrides:
        oid = ov["id"]
        tgt = ov["targets_prohibition_id"]
        st = ov.get("state", "UNKNOWN")
        revoked = bool(ov.get("revoked", False))
        nested_susp = ov.get("suspended_by_nested_exception", "FALSE")
        win = _in_window(eval_d, ov.get("effective_from"), ov.get("effective_to"))
        rank = int(ov.get("authority_rank", 0))

        if revoked or win == "EXPIRED_OR_INACTIVE" or nested_susp == "TRUE" or st == "FALSE":
            eff_ov = "FALSE"
        elif st == "UNKNOWN" or win == "UNKNOWN" or nested_susp == "UNKNOWN":
            eff_ov = "UNKNOWN"
            unknown_overrides.add(tgt)
        else:
            eff_ov = "TRUE"
            active_overrides[tgt] = max(active_overrides.get(tgt, 0), rank)

        ov_expected.append({
            "id": oid,
            "targets_prohibition_id": tgt,
            "effective_state": eff_ov,
            "authority_rank": rank,
        })

    # 2. Evaluate prohibitions (with temporal window, scope, counter-exception, and override rank)
    active_blocks: list[str] = []
    unknown_prohibs: list[str] = []
    pr_expected: list[dict[str, Any]] = []

    for pr in prohibs:
        pid = pr["id"]
        st = pr.get("state", "UNKNOWN")
        pr_rank = int(pr.get("authority_rank", 2))
        win = _in_window(eval_d, pr.get("effective_from"), pr.get("effective_to"))
        pr_scopes = pr.get("scopes")
        scope_applies = True if (not pr_scopes or not req_scope) else (req_scope in pr_scopes)
        counter_exc = pr.get("counter_exception_active", "FALSE")

        if not scope_applies or win == "EXPIRED_OR_INACTIVE" or st == "FALSE":
            eff_pr = "FALSE"
        elif st == "UNKNOWN" or win == "UNKNOWN":
            eff_pr = "UNKNOWN"
            unknown_prohibs.append(pid)
        else:
            # Prohibition is TRUE and in scope/window.
            # Check counter-exception (nested exception that disables the prohibition unless overridden)
            if counter_exc == "TRUE":
                eff_pr = "FALSE"
            elif counter_exc == "UNKNOWN":
                eff_pr = "UNKNOWN"
                unknown_prohibs.append(pid)
            else:
                eff_pr = "TRUE"
                ov_rank = active_overrides.get(pid, 0)
                if ov_rank > pr_rank:
                    pass  # Valid higher-rank override clears this prohibition
                elif pid in unknown_overrides:
                    unknown_prohibs.append(pid)
                else:
                    active_blocks.append(pid)

        pr_expected.append({
            "id": pid,
            "effective_state": eff_pr,
            "overridden": (eff_pr == "TRUE" and active_overrides.get(pid, 0) > pr_rank),
        })

    # 3. Evaluate prerequisites (AND prerequisites + optional FALLBACK_GROUP disjunctive pairs)
    and_false: list[str] = []
    and_unknown: list[str] = []
    fallback_items: list[tuple[str, str]] = []
    pq_expected: list[dict[str, Any]] = []

    for pq in prereqs:
        qid = pq["id"]
        st = pq.get("state", "UNKNOWN")
        win = _in_window(eval_d, pq.get("valid_from"), pq.get("valid_to"))
        allowed_scopes = pq.get("allowed_scopes")
        scope_ok = True if (not allowed_scopes or not req_scope) else (req_scope in allowed_scopes)

        if not scope_ok or win == "EXPIRED_OR_INACTIVE" or st == "FALSE":
            eff_pq = "FALSE"
        elif st == "UNKNOWN" or win == "UNKNOWN":
            eff_pq = "UNKNOWN"
        else:
            eff_pq = "TRUE"

        pq_expected.append({"id": qid, "effective_state": eff_pq, "mode": pq.get("mode", "AND")})

        if pq.get("mode", "AND") == "FALLBACK_GROUP":
            fallback_items.append((qid, eff_pq))
        else:
            if eff_pq == "FALSE":
                and_false.append(qid)
            elif eff_pq == "UNKNOWN":
                and_unknown.append(qid)

    # Evaluate FALLBACK_GROUP (disjunctive: TRUE if any is TRUE; FALSE if all are FALSE; else UNKNOWN)
    fb_false: list[str] = []
    fb_unknown: list[str] = []
    if fallback_items:
        if any(st == "TRUE" for _, st in fallback_items):
            pass
        elif all(st == "FALSE" for _, st in fallback_items):
            fb_false.append("+".join(qid for qid, _ in fallback_items))
        else:
            fb_unknown.append("+".join(qid for qid, st in fallback_items if st != "FALSE"))

    # 4. Precedence:
    #    - Any un-overridden active prohibition OR any failed mandatory/fallback prereq -> BLOCK
    #    - Else any decisive UNKNOWN -> ABSTAIN
    #    - Else -> ALLOW
    all_blocks = active_blocks + and_false + fb_false
    if all_blocks:
        return DeclarativeOracleResult(
            decision="BLOCK",
            decisive_reasons=tuple(all_blocks),
            expected_props={"prereqs": pq_expected, "prohibs": pr_expected, "overrides": ov_expected},
        )

    all_unknowns = unknown_prohibs + and_unknown + fb_unknown
    if all_unknowns:
        return DeclarativeOracleResult(
            decision="ABSTAIN",
            decisive_reasons=tuple(all_unknowns),
            expected_props={"prereqs": pq_expected, "prohibs": pr_expected, "overrides": ov_expected},
        )

    return DeclarativeOracleResult(
        decision="ALLOW",
        decisive_reasons=tuple(pq["id"] for pq in pq_expected if pq["effective_state"] == "TRUE"),
        expected_props={"prereqs": pq_expected, "prohibs": pr_expected, "overrides": ov_expected},
    )
