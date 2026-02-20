# pySigma Hawk Backend - LLM Handoff

## Scope

This project is the new converter backend that emits Hawk score JSON from Sigma rules.
Primary backend code:

- `sigma/backends/hawk/hawk.py`
- `sigma/backends/hawk/field_mapper.py`
- `sigma/backends/hawk/config/hawk_field_config.yml`
- `sigma/pipelines/hawk/hawk.py`

## Current Progress

1. Added robust field mapping support:
   - case-insensitive mapping
   - snake-case fallback mapping
   - compact-key fallback mapping
2. Added high-impact field translations (including `parent_command`, hash aliases/splits, web fields).
3. Fixed pipeline source injection:
   - now uses `hawk_source` (not `source`) in `sigma/pipelines/hawk/hawk.py`.
4. Boolean output correctness:
   - `regex`/`case` handling is emitted as JSON booleans in backend output.
5. MITRE normalization:
   - `attack.t####` tags are also surfaced as `T####` tags.

## Golden Contract (Do Not Violate)

Authoritative available fields/functions are:

- `..\HAWKScores-Export.csv`
- `..\..\hawk-data\app\tpls\scores_fields.json`

If a translated field is not in these sources:

1. escalate
2. decide map/define/add-new-column
3. use `payload` fallback only as temporary bridge

## Reports / Results Location

Validation scripts and reports are outside this repo in:

- `..\converter_validation\`
- `..\converter_validation\reports\`

Key recent artifacts:

- `..\converter_validation\reports\migration_state_report_v3_partial_live.json`
- `..\converter_validation\reports\migration_state_details_v3_partial_live.csv`
- `..\converter_validation\reports\unknown_columns_v3_partial_live.json`
- `..\converter_validation\reports\subset_50_boolean_compare_v2.json`
- `..\converter_validation\reports\subset_50_mismatch_diagnostics.json`
- `..\converter_validation\TAXONOMY_PARITY_FINDINGS.md`

## Current Known State (Important)

1. Full conversion runtime is high with current per-rule subprocess approach.
2. Current parity is not production-ready in strict mode.
3. 50-ID matched subset results after comparator improvements:
   - semantic AST parity: 80%
   - core AST parity: 94%
4. Remaining core mismatches are mostly rule-shaping differences and taxonomy/equivalence gaps, not just simple field aliases.

## Required Validation Modes

Always evaluate in 3 views:

1. strict parity (all fields, including enrichment/context)
2. core parity (detector logic only)
3. enrichment-aware parity (presence + taxonomy values for enrichment fields)

Do not treat core parity alone as release readiness.

## Immediate TODO (Priority Order)

1. Build/automate enrichment-aware parity gate (required fields + taxonomy checks).
2. Adjudicate the current 50-ID mismatches into:
   - regression
   - approved growth
   - taxonomy translation gap
3. Apply equivalence fixes for validated gaps (example: integrity level taxonomy normalization).
4. Expand calibration from 50 to 200 matched IDs and re-measure.
5. Replace slow per-rule conversion with faster in-process/chunked batch conversion path.
6. Re-run full corpus and regenerate migration + unknown-column reports.

## How To Reproduce Quick Checks

From `..\` (repo root `sigma`):

```powershell
python -m pytest pySigma-backend-hawk\tests converter_validation\tests -q
python converter_validation\compare_boolean_trees.py --old converter_validation\reports\subset_50_production.jsonl --new converter_validation\reports\subset_50_new.jsonl --report-json converter_validation\reports\subset_50_boolean_compare_v2.json --gap-csv converter_validation\reports\subset_50_boolean_gap_v2.csv --max-examples 50
```

