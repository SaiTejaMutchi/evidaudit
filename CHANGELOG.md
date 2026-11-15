# Changelog

## [0.1.0] - 2026-11-15
### Added
- Initial public release of **EvidAudit** (`evidaudit`), an open-source semantic integrity and counterfactual evaluation toolkit for AI decision systems.
- Cohesive `Auditor` API (`Auditor().evaluate(...)`, `test_override_revocation(...)`, `compare_replay_vs_regeneration(...)`, `repair(...)`).
- Fail-closed deterministic authorization checker (`v2-strict`, `v2-prohibition-applies`, `v2-literal`) and independent 8-category declarative transition oracle.
- CLI commands: `evidaudit demo`, `evidaudit reproduce [--json]`, and `evidaudit verify`.
- Programmatic ledger-based reproduction (`recompute_all_findings`) covering all headline findings from immutable artifacts with zero paid LLM calls.
- Interactive client-side browser playground (`playground/`) for Demo A (concealed corruption and repair) and Demo B (frozen replay vs. fresh regeneration).
- Curated benchmark datasets, data schema, verification scripts, and provenance documentation (`benchmarks/data/`, `benchmarks/DATA_SCHEMA.md`, `benchmarks/LIMITATIONS_AND_PROVENANCE.md`).

