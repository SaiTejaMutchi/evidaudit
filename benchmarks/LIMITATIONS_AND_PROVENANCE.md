# Limitations, Negative Results, and Provenance

To preserve scientific transparency, this document records the exact denominators, methodological boundaries, negative results, and retractions from the accompanying study (*Correct Decisions, Wrong Evidence: What AI Authorization Accuracy Conceals*).

## Key Denominators & Scope
- **Local Authorization Evaluations:** 4,972 total evaluations across 99 instantiated policy families (16 structural policy forms) using local 3.8B–8B Ollama models (`llama3.1:latest`, `qwen3:8b`, `gemma3:4b`, `phi4-mini:3.8b`).
  - **Semantic Corruption Audit:** 2,903 formal parsed structured rows across 69 families; 490/1,870 (26.2%) strict-checker-correct decisions conceal consumed semantic or grounding corruption (`ALLOW`: 12/518 = 2.3%; `BLOCK`: 256/921 = 27.8%; `ABSTAIN`: 222/431 = 51.5%).
  - **Policy Transition Evaluation:** 24 families across 8 structural categories x 7 variants (168 cases, 672 calls). On matched `ALLOW->BLOCK` and `BLOCK->BLOCK` transitions (`N=96`), frozen replay predicts 0/96 unsafe approvals vs. 7/96 (7.3%, all on `ALLOW->BLOCK`) under fresh regeneration. Separately, meaning-preserving updates (`N=48`) yield 6/48 (12.5%) unsafe approvals under fresh regeneration. 12/13 fresh-regeneration failures stem from upstream temporal semantic binding past expiry across 3 temporal families.
- **External Benchmark Replication (FOLIO / LINC):**
  - 16,380 total released generations across 9 LINC `folio-neurosymbolic` runs (182 examples, 67 source stories, 10 generations/example).
  - Audited subset: 3 primary 8-shot models (`gpt-4-0613`, `gpt-3.5-turbo-16k-0613`, `starcoderplus` = 5,460 generations; 348 majority-correct formalizations audited).
  - Counterfactual validation: 286 eligible pairs across the 3 primary models (62 ineligible solver/timeout pairs retained), yielding 12 unambiguous counterfactual masking events across 5 distinct source stories (9/12 repaired by single-formula correction), plus 12/13 faithful control agreement.

## Limitations & Preserved Negative Results
1. **Methodological Scope & Shared Closed-World Specification:** Authorization results are evaluated against specified reference policies and deterministic decision rules, where the authorization oracle, deterministic checkers, and declarative transition evaluator share a closed-world formal specification. External logical reasoning results use FOLIO reference annotations and prover-based verification.
2. **Inconclusive Primary Cohorts:** The prospective `C=1` corruption cohort (`0/144`) and the historical multi-blocker `BLOCK->BLOCK` cohort (`0/921`) were empty, leaving those two specific hypotheses inconclusive.
3. **Retracted & Negative Prior Claims:** 14/18 earlier checker-collision claims were extraction-induced (`321/332` `CHECKER`-labeled errors were masked upstream extraction faults); strict schemas lower `ALLOW` recall by `-15.9` pp vs. direct judging and trail direct judging on authentic FAR prose (`58.3%` vs. `91.7%`).
4. **External Qualitative Transfer:** Logical QA (`TableauProver` over FOLIO) is not an authorization gate; prevalence rates do not transfer directly to production access-control systems. Some gold FOLIO formulas contain typos or inclusive/exclusive-OR ambiguity (examples `18`, `31`, `40`), explicitly retained in `benchmarks/data/folio_counterfactual_results.csv`.

