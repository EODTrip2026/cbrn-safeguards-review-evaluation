# CBRN Safeguards Review Prototype

This repository is a lightweight, synthetic-data prototype for CBRN-related safeguards review. It demonstrates explainable triage of short reports, with deterministic rules controlling classification support, risk scoring, and operational priority labels.

The project is intended for demonstration and evaluation workflows only. It must not be used as an operational safety, security, intelligence, emergency response, or threat-assessment system.

## Current Architecture

- `main.py` is the authoritative backend. It contains report formatting, optional LLM-assisted interpretation, deterministic rule-based analysis, indicator normalization, risk scoring, operational priority labels, SQLite helper functions used by the current CLI, and command-line entry points.
- `storage.py` is the focused SQLite persistence layer for cases, analyses, reviews, and schema migrations.
- `app.py` is a Streamlit application shell with implemented Analyze, Review Queue, Operations Dashboard, and Evaluation Dashboard pages.
- `app_helpers.py` contains small testable helpers used by the Streamlit Analyze and Review Queue pages.
- `operations_metrics.py` contains SQLite-backed Operations Dashboard metrics, filters, demo-data import, and table helpers.
- `evaluation.py` contains evaluation-suite loading, deterministic dataset hashing, versioned run execution, metric calculations, case-level error tables, and regression comparison helpers.
- `data/evaluation/safeguards_eval_v1.json` contains a separate sanitized expanded safeguards evaluation suite.
- `reports.csv` contains synthetic demonstration reports for the CLI.
- `data/demo/operations_dashboard_demo.json` contains a separate synthetic operations-dashboard dataset.
- `cbrn_test_cases.xlsx` contains the manual regression/evaluation cases. The current sheet is `Test Cases` with `ID`, `Test Case`, `Expected Intent`, and `Expected Risk Notes`.
- `validate_tests.py` runs the spreadsheet cases in deterministic rule-only mode and prints the baseline results.
- `validate_evaluation_suites.py` validates the legacy workbook suite and expanded JSON suite.
- `tests/` contains pytest regression tests that pin the deterministic baseline.
The obsolete duplicate backend file, `main copy.py`, has been removed. `main.py` is the authoritative analysis and scoring backend.

## Architecture Diagram

```text
Synthetic / sanitized inputs
        |
        v
main.py
  - optional LLM-assisted interpretation
  - deterministic rule-only analysis
  - indicator normalization
  - numeric scoring and score bands
        |
        +--> watchlist.py
        |     - local OPCW Schedule 1 reference
        |     - hard flags and watchlist priority floor
        |
        v
storage.py / SQLite
  - cases
  - analyses
  - reviews
  - evaluation_runs
  - evaluation_results
        |
        +--> app.py / Streamlit
        |     - Analyze
        |     - Review Queue
        |     - Operations Dashboard
        |     - Evaluation Dashboard
        |
        +--> operations_metrics.py
        |     - stored workflow metrics
        |
        +--> evaluation.py
              - suites, hashes, metrics, regression comparison
```

## Screenshots

Screenshots are intentionally not committed yet. Suggested placeholders for a future demo packet:

- Analyze page with a sanitized rules-only result.
- Hard Flags section showing a confirmed match in benign context.
- Review Queue case detail and append-only review history.
- Operations Dashboard with synthetic demo metrics.
- Evaluation Dashboard with a stored rules-only run and confusion matrix.

## Concepts

The prototype treats these as separate concepts:

- Automated intent: one of `benign`, `dual_use`, `suspicious`, or `malicious`.
- Numeric risk score: the deterministic score produced by the current scoring rules.
- Score band: a label based only on the numeric risk score.
- Operational priority: a workflow label based on both score band and the minimum priority required by automated intent.
- Hard flags: deterministic watchlist matches that require review attention without changing automated intent or numeric score.

Current score bands:

- Low: score `0` through `2`
- Review: score `3` through `5`
- Escalate: score `6` or higher

Current minimum operational priorities by intent:

- `benign`: Low
- `dual_use`: Review
- `suspicious`: Review
- `malicious`: Escalate

The final operational priority is the higher of the score band and the intent minimum. These labels do not change the underlying scoring weights, normalization rules, classification behavior, safety-context logic, fiction-framing logic, or combination rules.

## Schedule 1 Hard-Watchlist Layer

Stage 5.5 adds a local, versioned OPCW Schedule 1 hard-watchlist layer. This is one deterministic detection layer alongside semantic intent, capability and behavioral indicators, contextual modifiers, and human review. It is not a keyword-only classifier.

The local reference file is:

```text
data/reference/opcw_schedule_1_watchlist.json
```

The reference file is manually reviewed from official OPCW sources only:

- Primary Schedule 1 source: `https://www.opcw.org/chemical-weapons-convention/annexes/annex-chemicals/schedule-1`
- Changes and amendment history: `https://www.opcw.org/changes-annex-chemicals`
- Consolidated Convention reference: `https://www.opcw.org/chemical-weapons-convention/download-convention`

The application never scrapes OPCW pages during startup or report analysis. Analysis uses the last approved local JSON file.

Hard flags are separate from normalized scoring indicators. A hard flag means mandatory or elevated review attention; it does not by itself classify the interaction as malicious. The numeric risk score is not changed by a watchlist match.

Watchlist priority policy:

- No hard flag: existing score-band plus intent-floor policy remains unchanged.
- Exact official Schedule 1 match: minimum priority Review.
- Approved Schedule 1 alias match: minimum priority Review.
- Possible family or analog reference: minimum priority Review and explicitly unverified.
- Schedule 1 hard flag plus a harmful-behavior or capability-building signal, such as delivery, scaling, evasion, acquisition, optimization, troubleshooting, or malicious intent: minimum priority Escalate.

The final operational priority is the highest priority required by numeric score band, intent minimum, and hard-watchlist policy.

The local list is not exhaustive. It does not enumerate every possible member of structurally defined families, does not perform molecular-structure matching, and does not make legal determinations about analog coverage. CAS Registry Numbers are intentionally omitted from the committed dataset because the project does not redistribute CAS data without confirmed permission.

To check official OPCW pages without changing the local file:

```powershell
python update_opcw_watchlist.py --check
```

To explicitly update official source fields:

```powershell
python update_opcw_watchlist.py --apply
```

Apply mode preserves manually curated aliases, validates the replacement, records retrieval/source hash metadata, and creates a backup. It is never run automatically by the app.

## Setup

Create and activate a virtual environment, then install dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Run The CLI

Analyze the synthetic CSV with the default behavior:

```powershell
python main.py reports.csv
```

Run the CLI in deterministic rule-only mode:

```powershell
python main.py reports.csv --rule-only
```

Optionally write/read the current simple SQLite output and print summary queries:

```powershell
python main.py reports.csv --rule-only --queries
```

The CLI initializes the configured SQLite database path before writing analysis results. The default path is `reports.db`; use `--db path\to\file.db` to choose another database file.

## Run Streamlit

```powershell
python -m streamlit run app.py
```

The Streamlit app currently has four navigation areas:

- Analyze: implemented.
- Review Queue: implemented for prioritized case selection and append-only analyst reviews.
- Operations Dashboard: implemented for stored SQLite workflow state and synthetic demo data.
- Evaluation Dashboard: implemented for versioned evaluation runs, stored case-level results, suite inspection, and compatible-run regression comparison.

## Operations Dashboard

The Operations Dashboard shows the current state and performance of the simulated safeguards-review workflow using stored SQLite records. It does not recompute stored analyses.

Case-level metrics use the latest stored analysis for each case. Review-level metrics use the exact `analysis_id` associated with each stored review, so a review is compared with the automated result the reviewer actually saw.

Filters:

- Case creation date range
- Case status
- Operational priority
- Automated intent
- Source
- Hard-flag status
- Analysis method
- Scoring version
- Watchlist version

Hard-flag filter options are all records, any hard flag, no hard flag, confirmed official or approved-alias match, and possible family or analog reference.

Top metric definitions:

- Total cases: distinct cases matching active filters.
- Open cases: filtered cases with current status `new` or `in_review`.
- Escalate backlog: open cases whose latest stored analysis has operational priority `Escalate`.
- Hard-flagged open cases: open cases whose latest stored analysis contains at least one hard flag.
- Reviewed cases: distinct filtered cases with at least one stored analyst review.
- Review-level override rate: reviews where analyst intent differs from the automated intent of the reviewed analysis, divided by all reviews in scope.
- Median time to first review: median elapsed time between case creation and first stored review for reviewed cases only.
- Escalation disposition rate: reviews with disposition `escalate` divided by all reviews in scope.

Unavailable review-derived rates display as unavailable when there are no reviews in scope. Genuine counts of zero display as zero.

Unresolved case aging buckets:

- Less than 24 hours
- 1-3 days
- 4-7 days
- More than 7 days

The dashboard includes charts for backlog, status, automated intent, analyst disposition, agreement/override, hard-flag outcomes, source, normalized indicators, case volume, review activity, and unresolved aging. Operational tables show oldest unresolved high-priority cases, recently escalated reviews, hard-flagged cases awaiting review, and recent analyst overrides. Tables use previews and do not expose full report content.

The dashboard has an explicit **Load Synthetic Operations Demo Data** button. It loads `data/demo/operations_dashboard_demo.json` into the configured SQLite database with an `operations-demo-*` external-ID namespace. The import is idempotent and does not delete or replace existing cases. Seeded reviews use deterministic seed markers in review notes so repeated imports do not duplicate demo reviews while normal user reviews remain append-only.

Five-minute demo sequence:

1. Start the app with `python -m streamlit run app.py`.
2. Open Operations Dashboard and load synthetic operations demo data.
3. Show Open cases and Escalate backlog.
4. Filter to confirmed hard flags.
5. Explain that hard flags require review attention but do not equal malicious intent.
6. Show agreement and override rates.
7. Open an old unresolved high-priority case from the table.
8. Show a recently escalated analyst review.
9. Explain one limitation, such as no service-level policy or production access control.
10. Return to Review Queue and confirm the underlying case remains available.

## Evaluation Dashboard

The Evaluation Dashboard measures four separate system functions:

- Intent classification
- Operational prioritization
- Hard-watchlist detection
- Regression behavior across stored runs

Expected labels are manually constructed reference judgments for synthetic cases. They are not objective ground truth, not statistically representative, and not validation on real platform data.

Evaluation suites:

- `legacy-intent-v1`: loads the existing `cbrn_test_cases.xlsx` workbook. It contains 15 legacy cases and preserves the historical deterministic baseline. Case 13 uses the noncanonical label `dual_use-suspicious`; the evaluator records the original label, maps it to `dual_use` only for four-class headline comparison, records the mapping reason, and marks the label ambiguous.
- `safeguards-eval-v1`: loads `data/evaluation/safeguards_eval_v1.json`. It contains 32 sanitized cases covering benign, dual-use, suspicious, malicious, priority expectations, hard-watchlist categories, ambiguous contexts, and false-positive/false-negative challenges. Newly authored labels are provisional unless separately reviewed by the project owner.

Each run stores:

- Suite ID and version
- Deterministic dataset hash
- Analysis method
- Scoring version
- Intent-priority policy version
- Watchlist version
- Watchlist-priority policy version
- Model name when applicable
- Case-level analysis snapshots
- Summary metrics

Rules-only evaluation is the default and is deterministic. LLM-assisted evaluation is optional, requires `OPENAI_API_KEY`, and should not be treated as a strict regression comparison unless the model and relevant metadata match.

Metric definitions:

- Intent accuracy: canonical four-class exact-match rate.
- Precision, recall, and F1: calculated per intent class with unavailable values when a denominator is zero.
- Priority exact accuracy: predicted operational priority exactly equals the expected minimum priority.
- Priority pass rate: predicted operational priority is at least the expected minimum priority.
- Critical miss: expected Escalate but predicted Low or Review.
- Under-review miss: expected at least Review but predicted Low.
- Over-triage: expected Low but predicted Review or Escalate.
- High-risk semantic miss: expected suspicious or malicious but predicted benign or dual_use.
- Confirmed hard-flag recall and precision: measured only for confirmed official or approved-alias expectations.
- Possible family/analog detection rate: expected possible family or analog references detected as possible.

Headline cards default to approved cases. If a suite has no approved cases, the dashboard labels the displayed metrics as provisional rather than treating them as validated. Metrics can be filtered by approved, provisional, and ambiguous label status.

Regression comparison is available for completed runs with the same suite ID, suite version, dataset hash, and analysis method. LLM-assisted runs also require the same model name before differences are described as strict regressions. The comparison reports newly regressed cases, newly improved cases, unchanged failures, unchanged successes, and warnings for increased critical misses, reduced suspicious or malicious recall, reduced confirmed hard-flag recall, and previously correct approved cases becoming incorrect.

Validate suites from the terminal:

```powershell
python validate_evaluation_suites.py
```

Five-minute evaluation demonstration:

1. Open Evaluation Dashboard.
2. Select the legacy deterministic suite.
3. Run Rules-only evaluation.
4. Explain intent accuracy and priority pass rate.
5. Show the confusion matrix.
6. Inspect one critical miss or over-triaged case.
7. Explain the difference between semantic and workflow errors.
8. Open a prior run.
9. Compare two compatible runs.
10. Explain that the dataset is small, synthetic, and manually constructed.

## Database Path

The Streamlit app uses this default local database path:

```text
data/safeguards.db
```

The `data` directory is created when the app initializes the database. Override the path with an environment variable:

```powershell
$env:SAFEGUARDS_DB_PATH="C:\path\to\safeguards.db"
python -m streamlit run app.py
```

The UI displays the active database path only in sidebar diagnostics. It does not let users type arbitrary database paths into the public interface.

## Analyze And Save Workflow

Analyze and save are separate actions.

On the Analyze page, enter report or interaction text, source, optional external case ID, and analysis mode. Rules-only mode is the default and deterministic. LLM-assisted mode uses the existing backend LLM path, may vary, and requires `OPENAI_API_KEY`.

Clicking Analyze runs the backend analysis and displays intent, numeric score, score band, operational priority, summary, indicators, versions, method, model name when applicable, and explainability details. It does not save anything.

The Analyze page also displays a separate Hard Flags section. “No hard-watchlist match” is only a statement about the local watchlist; it is not a legal conclusion that something is unscheduled.

After a successful analysis, click Save to Review Queue to persist the displayed result. Saving creates or retrieves the case idempotently and saves the exact displayed automated analysis. Repeated saves of the same rule-only result do not create duplicate cases or duplicate analyses. LLM-assisted analyses use the material-output fingerprint behavior in `storage.py`.

Saving does not submit an analyst decision. Analyst decisions are recorded later from the Review Queue page.

## Review Queue Workflow

The Review Queue page shows saved cases using the storage-layer queue ordering:

1. Escalate priority first
2. Review priority second
3. Low priority third
4. Higher numeric score first within each priority
5. Oldest unresolved case first when scores are equal

Filters are available for case status, operational priority, automated intent, source, and minimum numeric risk score. By default the queue shows unresolved cases with status `new` or `in_review`; closed cases can be included explicitly.

Selecting a case displays the stored report text and the exact saved automated analysis. The page does not recompute the analysis while viewing a case. If a case has multiple automated analyses, the latest is selected by default and prior analyses can be inspected. Reviews are saved against the selected `analysis_id`.

Stored case detail displays the hard flags saved with the selected analysis. The Review Queue includes a restrained watchlist indicator and filters for any hard flag, no hard flag, exact or approved matches, and possible family/analog references.

Analyst intent is the reviewer’s independent assessment of the request. Disposition is the operational handling decision (`allow`, `monitor`, `escalate`, or `close`). Case status records whether review work remains (`new`, `in_review`, or `closed`). Confidence is the analyst’s confidence in their own judgment, not confidence in the automated system.

If analyst intent differs from automated intent, the review is marked as an override and notes are required. The automated analysis, numeric score, scoring version, and priority-policy version remain preserved. Reviews are append-only and cannot be edited or deleted through the app.

If the database is empty, the Review Queue page offers a controlled button to load the existing synthetic `reports.csv` cases using rules-only analysis. The import is idempotent; repeated clicks do not duplicate cases or analyses.

## SQLite Persistence

The current database schema has four canonical tables:

- `cases`: submitted synthetic or sanitized reports/interactions.
- `analyses`: automated assessments for a case, including intent, indicators, score, score band, operational priority, and detailed scoring JSON.
- `reviews`: append-only analyst decisions attached to a specific analysis.
- `schema_migrations`: applied schema versions.

Stage 7 adds versioned evaluation tables:

- `evaluation_runs`: one stored measurement event for one suite, method, dataset hash, and policy/version context.
- `evaluation_results`: case-level expected labels, predicted outputs, pass/fail flags, and the exact analysis snapshot produced during that run.

A case is the thing being reviewed. An analysis is one automated assessment of that case. A review is an analyst decision made against a specific analysis, so future changes to scoring can preserve which automated result the analyst reviewed.

Database initialization is idempotent and uses SQLite foreign-key enforcement. Re-initializing the same database preserves existing data.

Case creation is idempotent. If an external ID is provided, the stable case key is derived from source plus external ID. Otherwise it is derived from normalized report text plus source.

Rule-only analyses are idempotent for the same case, scoring version, intent-priority policy version, watchlist version, watchlist-policy version, and analysis method. A watchlist-version change can create a new deterministic analysis record. LLM-assisted analyses include a deterministic fingerprint of the material automated result so distinct outputs can be preserved without adding a run-management framework.

Reviews are append-only. Saving a review and updating the case status happen in one transaction. Analyst overrides are calculated by comparing the review's analyst intent with the reviewed analysis's automated intent; no replacement analyst score is stored.

If a legacy flat `reports` table is detected by column inspection, initialization imports mappable rows into `cases` and `analyses` without deleting or overwriting the legacy table. Legacy imports preserve report ID, text, source, intent, indicators, summary, and numeric risk score where available. Legacy rows do not contain detailed score contributions, score-policy provenance, review history, model name, or reliable created/updated timestamps, so those fields are marked as legacy or reconstructed conservatively.

## File-Backed Verification

This execution environment may deny file-backed SQLite writes. To verify locally from the VS Code terminal, run:

```powershell
python verify_file_persistence.py
```

Expected result:

- Single-case verification reports one case and one analysis after repeated insertion.
- `reports.csv` import reports 15 cases and 15 analyses after both the first and second import.

## Run The Deterministic Evaluation Baseline

Use the print-oriented validation script:

```powershell
python validate_tests.py
```

Use pytest for automated regression tests:

```powershell
python -m pytest
```

Validate all evaluation-suite schemas:

```powershell
python validate_evaluation_suites.py
```

Both paths force rule-only analysis so an `OPENAI_API_KEY` cannot affect the regression baseline.

The validation script distinguishes exact canonical intent matches from accepted ambiguous labels. The current workbook contains one noncanonical reference label, `dual_use-suspicious`, which is accepted for comparison but flagged for later cleanup.

## Data And Prototype Limits

- Use only synthetic or sanitized demonstration data.
- Do not add operationally useful CBRN instructions or new hazardous examples.
- The optional LLM path may assist interpretation, but deterministic and explainable logic controls scoring and priority labels.
- The Review Queue is a prototype analyst workflow, not production-grade case management.
- The Schedule 1 hard-watchlist layer is a local, non-exhaustive demonstration reference. It is not OPCW endorsement or validation.
- Evaluation cases are small, synthetic, and manually constructed. Results do not establish real-world safety performance.
- Provisional evaluation cases require human review before being treated as approved labels.
- The regression baseline pins current behavior; it does not imply the current behavior is product-complete or analytically final.

## Manual Streamlit Checklist

1. Launch Streamlit with `python -m streamlit run app.py`.
2. Load synthetic demo cases from the Review Queue if the database is empty.
3. Analyze a sanitized example in rules-only mode.
4. Inspect the score explanation.
5. Save it to the review queue.
6. Open the Review Queue and filter for Escalate cases.
7. Select a case and inspect the stored automated explanation.
8. Submit an analyst review showing either agreement or override.
9. Confirm that review history appears and case status updates.
10. Restart Streamlit and confirm persistence from the sidebar counts or by calling `storage.get_case_with_history(...)`.

