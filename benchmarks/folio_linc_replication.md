# External Neuro-Symbolic Benchmark Replication (FOLIO / LINC)

This benchmark guide documents the upstream datasets and publicly released neuro-symbolic model traces audited in the accompanying paper (*Correct Decisions, Wrong Evidence*).

## Upstream Attribution & Pinned Versions
We do **not** redistribute raw third-party model outputs or benchmark datasets inside this repository where upstream licensing or redistribution terms apply. Instead, we ship curated verification datasets (`benchmarks/data/folio_multimodel_summary.json`, `benchmarks/data/folio_counterfactual_summary.json`, `benchmarks/data/folio_counterfactual_results.csv`) and exact pinned upstream references:

1. **LINC Neuro-Symbolic Traces (`benlipkin/linc`)**
   - Repository: https://github.com/benlipkin/linc
   - Pinned Commit SHA: `718dfe8fae342028a837a96096e5e1e412ad4f2e`
   - Audited Runs: All 9 `folio-neurosymbolic` runs (182 examples across 67 distinct source stories, 10 generations per example = 16,380 total generations).
   - Semantic Audit Subset: 3 primary 8-shot models (`gpt-4-0613`, `gpt-3.5-turbo-16k-0613`, `starcoderplus` = 5,460 generations; 348 majority-correct formalizations audited).

2. **LINC FOLIO Dataset (`benlipkin/folio`)**
   - Dataset: https://huggingface.co/datasets/benlipkin/folio
   - Exact Validation Alignment: 204/204 match against `Yale-LILY/FOLIO v0.0`.

3. **Yale-LILY FOLIO Reference (`Yale-LILY/FOLIO`)**
   - Repository: https://github.com/Yale-LILY/FOLIO (`v0.0`)

## Offline Statistical Reproduction vs. Full Upstream Prover Replay
- **Offline statistical reproduction (`evidaudit reproduce`):** Recomputes all headline findings directly from the curated benchmark datasets (`benchmarks/data/`) with zero external downloads and zero LLM calls.
- **Full upstream prover replay:** Re-executing `TableauProver` over the raw third-party model generations requires cloning the pinned LINC repository and installing optional research dependencies:

```bash
git clone https://github.com/benlipkin/linc.git external_research/linc
git -C external_research/linc checkout 718dfe8fae342028a837a96096e5e1e412ad4f2e
pip install -e ".[research]"
```

