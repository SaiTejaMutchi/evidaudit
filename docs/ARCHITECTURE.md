# Architecture

**EvidAudit** separates upstream semantic extraction from deterministic policy evaluation and tests whether correct decisions survive policy updates, override revocations, and fresh regeneration.

```text
  Source Packet (P, E, a)
           |
           v
  Upstream Extractor (LLM / Neuro-Symbolic Parser)
           |  -> Structured Propositions Z = (prereq, prohib, override) + citations
           v
  +----------------------------------------------------------+
  | EvidAudit Core                                           |
  |  1. checker.py: Fail-closed deterministic gate (v2-strict)|
  |  2. audit.py:   Proposition-level semantic corruption    |
  |  3. audit.py:   Counterfactual override revocation       |
  |  4. audit.py:   Single-proposition repair                |
  |  5. oracle.py:  Independent declarative transition oracle|
  +----------------------------------------------------------+
           |
           +--> Static Decision Check (D == Y)
           +--> Semantic Integrity Check (Z == Z*)
           +--> Transition Safety Check (Replay vs. Fresh Regeneration)
```

## Components
- `src/evidaudit/checker.py`: Fail-closed deterministic checker (`v2-strict`, `v2-prohibition-applies`, `v2-literal`) enforcing factual grounding, exact rule-ID override matching, and three-valued (`TRUE`/`FALSE`/`UNKNOWN`) abstention semantics.
- `src/evidaudit/audit.py`: Compares extracted propositions against reference annotations (`audit_extraction`), revokes active overrides (`simulate_override_revocation`), applies targeted single-field repairs (`repair_proposition`), and measures replay-vs-regeneration divergence (`compare_replay_vs_regeneration`).
- `src/evidaudit/oracle.py`: Independently coded declarative evaluator supporting 8 structural policy categories (revocable overrides, time-bounded windows, nested exceptions, scope restrictions, multiple blockers, authority hierarchies, conditional fallbacks, and three-valued missing information).
- `src/evidaudit/cli.py`: Zero-dependency CLI (`evidaudit demo`, `evidaudit verify-ledgers`).

