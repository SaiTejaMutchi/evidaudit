# Benchmark Datasets and Schema

All benchmark datasets consumed by `evidaudit reproduce` and `evidaudit verify` live under `benchmarks/data/`. They contain evaluation inputs, model outputs, reference annotations, and counterfactual outcomes with zero paid API calls required.

## Dataset Inventory

### 1. `authorization_audit_inventory.csv`
- **Scope:** `3,104` historical inventory records (a subset of `4,972` total local authorization evaluation calls across the broader study), comprising `2,903` formally parsed (`FORMAL_PARSED`) authorization traces across `364` synthetic cases, `69` instantiated policy families (`2` underlying structural forms), `6` extraction schemas (`B5_A`–`B5_G`), and `4` open-weight Ollama models, plus `192` `UNVERIFIED_EX14` FAR rows and `9` `PARSE_FAILED` rows. Among `1,870` strict-checker-correct (`v2-strict`) formal decisions, `490` (`26.2%`) contain concealed semantic or grounding corruption.
- **Model Sample Sizes (Parsed / `v2-strict` Correct / Concealed Corruption):** `llama3.1:latest` (`1,375` / `784` / `231` = `29.46%`), `qwen3:8b` (`1,384` / `977` / `243` = `24.87%`), `phi4-mini:3.8b` (`72` / `53` / `12` = `22.64%`), and `gemma3:4b` (`72` / `56` / `4` = `7.14%`).
- **Key Columns:** `status`, `v2s_ok`, `is_masked_v2s`, `gold` (`ALLOW`, `BLOCK`, `ABSTAIN`), `family`, `model`, `arm`.

### 2. `override_revocation_cohort.csv`
- **Scope:** Counterfactual override-revocation exposure and single-field repair cohort (`N = 288` overridden-prohibition `ALLOW` decisions: `10` corrupted-prohibition approvals from earlier schemas `B5_A`/`B5_B`/`B5_F` vs. `278` clean approvals; `0/36` corrupted in `B5_G`).
- **Key Columns:** `prohib_corrupted`, `is_corrupted`, `unsafe_u_v2s`, `repaired_v2s`, `family`, `model`, `arm`.

### 3. `policy_transition_traces.jsonl`
- **Scope:** Protocol-defined prospective evaluation (`protocol_ex27b.json`) over `24` template-generated policy families (`8` structural categories × `3` families × `7` variants = `168` cases, `672` calls across `llama3.1:latest` and `qwen3:8b`), including `96` matched `V2_TRANSITION_U` + `V5_2BLOCKER_U` fresh-regeneration evaluations and `48` separately evaluated `V7_MEANING_M` meaning-preserving updates.
- **Key Fields:** `arm`, `variant`, `family_id`, `category`, `unsafe_allow`.

### 4. `phase1_extraction_labels.csv`
- **Scope:** Phase-1 extraction corruption labels (`144` records across `B5_G`) used to compute deterministic frozen-replay predictions (`0/96` unsafe approvals under clean Phase-1 extractions).
- **Key Columns:** `arm`, `corrupted`, `consumed`.

### 5. `folio_multimodel_summary.json`
- **Scope:** Cross-model external logical reasoning audit summary over released LINC/FOLIO outputs (`16,380` released generations; `348` majority-correct 8-shot model-example pairs audited across `gpt-4-0613`, `gpt-3.5-turbo-16k-0613`, and `starcoderplus` over `182` examples and `67` source stories).
- **Key Fields:** `runs`, `primary_8shot_audits` (`correct_erroneous`, `majority_correct`, `err_prevalence_pct`, `story_clustered_ci95_pct`).

### 6. `folio_counterfactual_summary.json` & `folio_counterfactual_results.csv`
- **Scope:** Counterfactual exposure and single-formula repair results over FOLIO/LINC formalizations (`286` eligible pairs and `62` ineligible solver/timeout pairs retained from `348` majority-correct pairs; `12` retrospectively curated unambiguous masking events across `5` distinct source stories; `9/12` repaired by single-formula replacement; `12/13` faithful controls agree; `2` additional `AMBIGUOUS_XOR_VS_OR` witnesses on `EX 31`).
- **Key Fields/Columns:** `total_eligible`, `faithful_controls_agree`, `faithful_controls_tested`, `story_id`, `outcome`, `ambig_ref`.

## Reproduction Commands

```bash
evidaudit reproduce
evidaudit reproduce --json
evidaudit verify
```
