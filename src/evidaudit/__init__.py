"""EvidAudit: An open-source semantic integrity and counterfactual evaluation toolkit for AI decision systems."""
from __future__ import annotations

from evidaudit.audit import (
    CounterfactualExposureReport,
    FieldDiscrepancy,
    SemanticAuditReport,
    TransitionComparisonReport,
    audit_extraction,
    compare_replay_vs_regeneration,
    repair_proposition,
    revoke_override,
    simulate_override_revocation,
)
from evidaudit.auditor import Auditor, EvaluationResult
from evidaudit.checker import CheckerResult, evaluate_extraction
from evidaudit.oracle import DeclarativeOracleResult, evaluate_declarative_policy

__version__ = "0.1.0"

__all__ = [
    "Auditor",
    "CheckerResult",
    "CounterfactualExposureReport",
    "DeclarativeOracleResult",
    "EvaluationResult",
    "FieldDiscrepancy",
    "SemanticAuditReport",
    "TransitionComparisonReport",
    "audit_extraction",
    "compare_replay_vs_regeneration",
    "evaluate_declarative_policy",
    "evaluate_extraction",
    "repair_proposition",
    "revoke_override",
    "simulate_override_revocation",
]
