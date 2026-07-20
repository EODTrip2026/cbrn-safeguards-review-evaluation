# CBRN Simulation Project Guide

## Purpose

This project is a lightweight CBRN safeguards review prototype. It ingests synthetic reports, extracts intent and indicators through optional LLM assistance plus deterministic rules, applies explainable risk scoring, supports human-in-the-loop review, and stores repeatable versioned evaluation runs.

## Current Architecture

- `main.py`: authoritative backend analysis pipeline, deterministic rules, risk scoring, operational priority labels, simple CLI, and compatibility wrappers for persistence.
- `storage.py`: focused SQLite persistence module for cases, analyses, reviews, schema initialization, queue retrieval, and legacy flat-table migration.
- `app.py`: Streamlit application shell with Analyze, Review Queue, Operations Dashboard, and Evaluation Dashboard implemented.
- `app_helpers.py`: testable helper functions for Analyze-page input conversion, explanation formatting, database path resolution, review queue view models, review validation, and save behavior.
- `operations_metrics.py`: testable SQLite reporting layer for Operations Dashboard metrics, filters, charts, tables, and synthetic demo-data import.
- `evaluation.py`: testable evaluation layer for suite loading, dataset hashing, run persistence, metric calculations, case-level errors, and regression comparison.
- `watchlist.py`: deterministic local OPCW Schedule 1 hard-watchlist loading, validation, matching, priority-floor helpers, and update-check/apply utilities.
- `update_opcw_watchlist.py`: command-line wrapper for the explicit OPCW watchlist check/apply workflow.
- `data/reference/opcw_schedule_1_watchlist.json`: reviewed local Schedule 1 reference and curated aliases. CAS Registry Numbers are omitted.
- `data/demo/operations_dashboard_demo.json`: separate synthetic demonstration data for dashboard workflows.
- `data/evaluation/safeguards_eval_v1.json`: separate sanitized expanded evaluation suite.
- `reports.csv`: synthetic input data for demonstration.
- `cbrn_test_cases.xlsx`: manual regression/evaluation test cases.
- `validate_tests.py`: deterministic rule-only baseline runner for the spreadsheet cases.
- `validate_evaluation_suites.py`: validation command for the legacy and expanded evaluation suites.
- `tests/`: pytest regression tests for deterministic baseline behavior.
The obsolete duplicate backend file, `main copy.py`, has been removed.

## Core Design Principle

The LLM may assist with interpretation, but final classification support, risk scoring, and priority labels must remain deterministic, explainable, and traceable.

## Current Concepts

- Automated intent: `benign`, `dual_use`, `suspicious`, or `malicious`.
- Numeric risk score: output from the existing deterministic scoring logic.
- Score band: label based only on numeric score.
- Operational priority: workflow label based on score band plus the minimum priority required by automated intent.
- Hard flags: deterministic watchlist matches that require review attention without changing automated intent or numeric score.

Score bands:

- Low: score 0 through 2
- Review: score 3 through 5
- Escalate: score 6 or higher

Minimum operational priorities by intent:

- benign: Low
- dual_use: Review
- suspicious: Review
- malicious: Escalate

The final operational priority is the higher of the score band and the intent minimum. This policy must not change scoring weights, normalization rules, classification behavior, safety-context logic, fiction-framing logic, or combination rules.

## OPCW Schedule 1 Hard-Watchlist Layer

The hard-watchlist layer is deterministic and local. It is one layer alongside semantic intent, capability and behavioral indicators, contextual modifiers, and human analyst review. It must not become the only classifier.

Approved automated source provenance is limited to official OPCW pages:

- `https://www.opcw.org/chemical-weapons-convention/annexes/annex-chemicals/schedule-1`
- `https://www.opcw.org/changes-annex-chemicals`
- `https://www.opcw.org/chemical-weapons-convention/download-convention`

Normal app startup and analysis must not fetch live OPCW pages. Use `python update_opcw_watchlist.py --check` to compare official pages with the local file, and `python update_opcw_watchlist.py --apply` only when deliberately updating official source fields. Apply mode must preserve curated aliases and avoid silently changing screening behavior.

Hard flags stay separate from normalized indicators and score contributions. A hard flag means review attention, not malicious intent. Do not change numeric risk scores because of watchlist matches.

Watchlist priority policy:

- Exact official Schedule 1 match: minimum Review.
- Approved Schedule 1 alias match: minimum Review.
- Possible family or analog reference: minimum Review, labeled unverified.
- Hard flag plus harmful-behavior or capability-building signal: minimum Escalate.

The final priority is the highest priority from score band, intent minimum, and watchlist policy.

The local reference is not exhaustive. Do not claim complete Schedule 1 enumeration, molecular-structure detection, legal analog confirmation, CAS matching, production deployment, real-user monitoring, or OPCW endorsement. CAS Registry Numbers must remain omitted unless redistribution permission is confirmed in a later task.

## Coding Rules

- Keep code simple, readable, and modular.
- Do not introduce unnecessary complexity, frameworks, or abstractions.
- Preserve separation between backend (`main.py`) and UI (`app.py`).
- Avoid duplicating business logic across files.
- All scoring logic must remain explainable and traceable.
- Prefer rule-based adjustments over expanding LLM dependency.
- Avoid adding operationally useful CBRN instructions or new hazardous examples.

## Risk Model Expectations

- Clearly malicious intent should produce high risk scores.
- Benign technical or safety context should produce low risk scores.
- Dual-use or ambiguous context should generally require review or escalation depending on indicators.
- Evasion, hazardous-material indicators, and delivery indicators should significantly increase risk.

## Testing Expectations

- Use `cbrn_test_cases.xlsx` for validation.
- Regression tests must force deterministic rule-only analysis, regardless of whether `OPENAI_API_KEY` is present.
- Preserve the current scoring behavior unless a later task explicitly changes it.
- Similar inputs should produce consistent outputs.
- Noncanonical expected-intent labels must be reported separately from exact canonical matches.

## Persistence Model

The SQLite schema has four canonical workflow tables:

- `cases`: submitted synthetic or sanitized reports/interactions.
- `analyses`: automated assessments for a case.
- `reviews`: append-only analyst decisions attached to a specific analysis.
- `schema_migrations`: applied schema versions.

Relationship:

`cases -> analyses -> reviews`

Stage 7 adds evaluation storage:

- `evaluation_runs`: one stored measurement event for a selected suite, dataset hash, method, and policy/version context.
- `evaluation_results`: case-level expected labels, predictions, pass/fail flags, normalized indicators, hard flags, and the exact analysis snapshot from that run.

Reviews reference `analysis_id`, not just `case_id`, so the reviewed automated result remains clear after future scoring or policy changes.

Database initialization is idempotent and enables SQLite foreign-key enforcement. The CLI defaults to `reports.db`, and callers can pass another database path through the existing `--db` option.

The Streamlit app defaults to `data/safeguards.db`. Override it with `SAFEGUARDS_DB_PATH`; do not add public UI controls that accept arbitrary database paths.

Rule-only analyses are idempotent for the same case, scoring version, intent-priority policy version, watchlist version, watchlist-policy version, and method. A watchlist-version change can create a new deterministic analysis record. LLM-assisted analyses include a deterministic result fingerprint so materially different outputs can create distinct analysis records.

Reviews are append-only. A review insert and the corresponding case status update occur in one transaction.

If an existing flat legacy `reports` table is detected by inspecting its columns, mappable rows are imported without deleting or overwriting the legacy table. Legacy imports preserve report ID, text, source, intent, indicators, summary, and numeric risk score where available. Legacy detailed score contributions, exact scoring provenance, review history, model name, and reliable created/updated timestamps are not available.

## Streamlit Analyze Workflow

Analyze and save are separate actions. Clicking Analyze runs backend analysis only. Clicking Save to Review Queue persists the exact displayed analysis.

Analyze page inputs:

- Report or interaction text
- Source
- Optional external case ID
- Analysis mode: Rules only or LLM assisted

Rules-only mode is deterministic and should remain the default. LLM-assisted mode may vary and requires `OPENAI_API_KEY`.

The Analyze page displays automated intent, numeric risk score, score band, operational priority, summary, normalized indicators, versions, method, model name when applicable, score-changing factors, zero-point activated rules, and a plain-language priority explanation.

The Analyze page also displays hard flags separately. The UI may say “No hard-watchlist match,” but must not state or imply a broad legal conclusion such as “not scheduled.”

## Streamlit Review Queue Workflow

The Review Queue page is the current human-in-the-loop workflow. It must display stored automated analyses exactly as saved and must not recompute a case while an analyst is viewing it.

Queue filters:

- Case status
- Operational priority
- Automated intent
- Source
- Minimum numeric risk score

Default queue status filters are `new` and `in_review`. Closed cases are included only when the user asks to include them. Queue ordering comes from `storage.get_cases_for_review_queue(...)`: Escalate, then Review, then Low; higher numeric scores within each priority; oldest unresolved cases first when scores tie.

Analyst intent is the reviewer’s independent assessment. Disposition is the handling decision. Case status indicates whether review work remains. Agreement or override is calculated by comparing analyst intent to the reviewed automated intent.

Overrides require notes. Reviews do not replace automated intent or numeric score. Each review is append-only and references the selected `analysis_id`, so cases with multiple analyses can preserve which automated result was reviewed.

The Review Queue can load the existing synthetic `reports.csv` cases when the database is empty. This is a user-triggered, rules-only, idempotent demo-data import.

Case Detail must display the hard flags stored with the selected analysis and must not recompute them. Queue filters may include hard-flag status, but watchlist status must not overwrite automated intent.

## Streamlit Operations Dashboard

The Operations Dashboard is implemented for stored SQLite data. It must not recompute analyses. Case-level metrics use the latest stored analysis per case unless a metric explicitly concerns analysis history. Review-level metrics use the exact `analysis_id` attached to each review.

Dashboard filters:

- Case creation date range
- Case status
- Operational priority
- Automated intent
- Source
- Hard-flag status
- Analysis method
- Scoring version
- Watchlist version

Metric definitions:

- Total cases: distinct filtered cases.
- Open cases: filtered cases with status `new` or `in_review`.
- Escalate backlog: open cases whose latest stored analysis priority is `Escalate`.
- Hard-flagged open cases: open cases with at least one stored hard flag on the latest analysis.
- Reviewed cases: distinct filtered cases with at least one stored review.
- Review-level override rate: stored reviews where analyst intent differs from the automated intent of the reviewed analysis, divided by reviews in scope.
- Median time to first review: reviewed cases only; unresolved cases are not treated as zero-time reviews.
- Escalation disposition rate: reviews with disposition `escalate` divided by reviews in scope.

Unavailable review-derived metrics should display as unavailable when there is no review population. Genuine counts may display zero.

Unresolved aging buckets are Less than 24 hours, 1-3 days, 4-7 days, and More than 7 days. Do not present these as service-level compliance or breach.

Operations demo data lives in `data/demo/operations_dashboard_demo.json`, separate from `reports.csv`, the workbook, and the OPCW reference dataset. It uses the `operations-demo-*` external-ID namespace and is loaded only when the user clicks the dashboard button. The import is idempotent. Seeded reviews use `[seed:...]` markers in notes to avoid duplicate seeded reviews on repeat import; this does not change normal append-only review behavior.

Hard-flag metrics remain separate from intent metrics. A hard flag means elevated screening attention, not malicious intent.

## Streamlit Evaluation Dashboard

The Evaluation Dashboard is implemented for versioned, repeatable measurement. It evaluates intent classification, operational priority, hard-watchlist behavior, and regression behavior separately.

Evaluation suites:

- `legacy-intent-v1`: the existing `cbrn_test_cases.xlsx` workbook. It preserves the 15-case historical deterministic baseline. Case 13 has the noncanonical label `dual_use-suspicious`; the evaluator records the original label, maps it to `dual_use` only for four-class headline comparison, records the mapping reason, and marks the case ambiguous.
- `safeguards-eval-v1`: `data/evaluation/safeguards_eval_v1.json`, a 32-case sanitized provisional suite covering intent classes, priority expectations, confirmed hard flags, possible family/analog flags, benign treaty and historical contexts, harmful semantic intent without watchlist terms, and false-positive/false-negative challenges.

Expected labels are manually constructed reference judgments, not objective ground truth. The expanded suite is small and not statistically representative. Provisional cases require human review before being treated as approved.

Stored run metadata includes suite ID, suite version, deterministic dataset hash, analysis method, scoring version, intent-priority policy version, watchlist version, watchlist-priority policy version, model name when applicable, timestamp, status, and summary metrics. Stored result rows preserve the exact analysis snapshot and must not be recomputed when viewing old runs.

Metric definitions:

- Intent accuracy: canonical four-class exact match.
- Precision, recall, and F1: per intent class, with unavailable values when a denominator is zero.
- Priority exact accuracy: predicted priority exactly equals expected minimum priority.
- Priority pass rate: predicted priority is at least expected minimum priority.
- Critical miss: expected Escalate assigned Low or Review.
- Under-review miss: expected at least Review assigned Low.
- Over-triage: expected Low assigned Review or Escalate.
- High-risk semantic miss: expected suspicious or malicious predicted benign or dual_use.
- Confirmed hard-flag recall and precision: official or approved-alias hard-flag expectations.
- Possible family/analog detection rate: possible family or analog expectations detected as possible.

Headline metrics should default to approved cases. If a suite contains no approved labels, present metrics as provisional rather than validated. Always keep approved, provisional, and ambiguous label populations visible.

Regression comparison is strict only for completed runs with the same suite ID, suite version, dataset hash, and analysis method. LLM-assisted runs must also match model name before being described as strict regressions. Compare case-level changes, not only aggregate accuracy, and warn when critical misses increase, suspicious or malicious recall decreases, confirmed hard-flag recall decreases, or previously correct approved cases become incorrect.

Validate suites with:

```powershell
python validate_evaluation_suites.py
```

Five-minute evaluation demo:

1. Open Evaluation Dashboard.
2. Select the legacy deterministic suite.
3. Run Rules-only evaluation.
4. Explain intent accuracy and priority pass rate.
5. Show the intent and priority confusion matrices.
6. Inspect one critical miss or over-triaged case.
7. Explain semantic errors versus workflow-priority errors.
8. Open a prior run without rerunning it.
9. Compare two compatible runs.
10. Explain one limitation and one next improvement.

## Development Guidelines For Codex

- Make the smallest effective change.
- Do not rewrite entire functions unless necessary.
- Do not break existing functionality.
- When updating scoring logic, do not modify unrelated components.
- Ensure new logic generalizes to future reports and is not hardcoded to one case.

## Current Limitations

- The Streamlit app currently implements Analyze, Save to Review Queue, Review Queue analyst decisions, Operations Dashboard, and Evaluation Dashboard.
- The Review Queue is a local prototype workflow and does not provide production-grade access control, multi-user concurrency, or tamper-proof auditing.
- The Schedule 1 hard-watchlist layer is non-exhaustive and does not provide molecular or legal confirmation.
- Evaluation results are small synthetic measurements and do not establish real-world safety performance.
