# Benchmark Datasets and Schema

All benchmark datasets consumed by `evidaudit reproduce` and `evidaudit verify` live under `benchmarks/data/`. They contain evaluation inputs, model outputs, reference annotations, and counterfactual outcomes with zero paid API calls required.

## Dataset Inventory

### 1. `authorization_audit_inventory.csv`
- **Scope:** Local authorization gate evaluations across `4,972` records, including `1,870` strict-checker-correct (`v2-strict`) formal decisions (`490` with concealed semantic or grounding corruption).
- **Key Columns:** `status`, `v2s_ok`, `is_masked_v2s`, `gold` (`ALLOW`, `BLOCK`, `ABSTAIN`).

### 2. `override_revocation_cohort.csv`
- **Scope:** Counterfactual override-revocation exposure and single-field repair cohort (`28` corrupted-prohibition cases vs. `278` clean cases).
- **Key Columns:** `prohib_corrupted`, `is_corrupted`, `unsafe_u_v2s`, `repaired_v2s`.

### 3. `policy_transition_traces.jsonl`
- **Scope:** Matched policy-transition and meaning-preserving update traces (`96` matched `V2_TRANSITION_U` + `V5_2BLOCKER_U` fresh-regeneration evaluations, plus `48` `V7_MEANING_M` meaning-preserving updates).
- **Key Fields:** `arm`, `variant`, `unsafe_allow`.

### 4. `phase1_extraction_labels.csv`
- **Scope:** Phase-1 extraction corruption labels (`144` records) used to compute frozen-replay predictions (`0/96` unsafe approvals under clean replay).
- **Key Columns:** `arm`, `C` / `corrupted`.

### 5. `folio_multimodel_summary.json`
- **Scope:** Cross-model external logical reasoning audit summary over released LINC/FOLIO outputs (`16,380` released generations; `348` majority-correct 8-shot formalizations audited across `gpt-4`, `gpt-3.5-turbo`, and `text-davinci-003`).
- **Key Fields:** `runs`, `primary_8shot_audits` (`correct_erroneous`, `majority_correct`, `err_prevalence_pct`, `story_clustered_ci95_pct`).

### 6. `folio_counterfactual_summary.json` & `folio_counterfactual_results.csv`
- **Scope:** Counterfactual exposure and single-formula repair results over FOLIO/LINC formalizations (`12` unambiguous masking events across `5` distinct source stories; `9/12` repaired by single-formula replacement; `62/62` faithful controls agree).
- **Key Fields/Columns:** `total_eligible`, `faithful_controls_agree`, `faithful_controls_tested`, `story_id`, `outcome`, `ambig_ref`.

## Reproduction Commands

```bash
evidaudit reproduce
evidaudit reproduce --json
evidaudit verify
```
