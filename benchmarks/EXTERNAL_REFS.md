# Pinned External Datasets and Repositories

All external evaluations use publicly released model traces and datasets with **0 new LLM calls** and **$0.00 paid spend**.

1. **LINC Neuro-Symbolic Repository (`benlipkin/linc`)**
   - URL: https://github.com/benlipkin/linc
   - Pinned Commit SHA: `718dfe8fae342028a837a96096e5e1e412ad4f2e`
   - Local checkout path: `external_research/linc/`
   - Audited traces: all 9 `folio-neurosymbolic` runs (182 examples across 67 source stories, 10 generations/example = 16,380 total generations; primary 8-shot models: `gpt-4-0613`, `gpt-3.5-turbo-16k-0613`, `starcoderplus`).

2. **LINC FOLIO Dataset (`benlipkin/folio`)**
   - URL: https://huggingface.co/datasets/benlipkin/folio
   - Exact alignment: 204/204 validation examples aligned to `Yale-LILY/FOLIO v0.0`.

3. **Yale-LILY FOLIO Reference (`Yale-LILY/FOLIO`)**
   - URL: https://github.com/Yale-LILY/FOLIO
   - Tag / Version: `v0.0` (validation split; 182 examples aligned to LINC runs).

