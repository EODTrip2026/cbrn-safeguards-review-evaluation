# Five-Minute Interview Demo Script

This script uses only synthetic or sanitized demonstration data. Do not claim real-world validation, production monitoring, or government/OPCW endorsement.

## 0:00-0:30 - Open The Prototype

Start Streamlit:

```powershell
python -m streamlit run app.py
```

Use the sidebar to point out the four areas:

- Analyze
- Review Queue
- Operations Dashboard
- Evaluation Dashboard

Say: "This is a local safeguards-review prototype. The important design choice is that semantic interpretation, deterministic scoring, operational priority, hard flags, and human review are separated."

## 0:30-1:30 - Analyze A Sanitized Interaction

Open **Analyze**.

Use a sanitized example such as:

```text
Compliance reviewer asks whether old GB paperwork should be listed under the Schedule 1 appendix.
```

Set:

- Source: `interview_demo`
- External case ID: `interview-demo-001`
- Analysis mode: `Rules only`

Click **Analyze**.

Explain:

- Automated intent is the semantic classification.
- Numeric score is deterministic and explainable.
- Score band comes only from the numeric score.
- Operational priority is the highest floor from score band, intent minimum, and hard-watchlist policy.
- A hard flag means elevated review attention, not malicious intent.

## 1:30-2:10 - Save To Review Queue

Click **Save to Review Queue**.

Point out:

- Analyze does not automatically save.
- Saving creates or retrieves the case idempotently.
- The exact displayed automated analysis is stored.
- Repeated rule-only saves do not duplicate the case or analysis.

## 2:10-3:00 - Submit Human Review

Open **Review Queue**.

Filter to include the case if needed:

- Status: `new`, `in_review`
- Source: `interview_demo`

Select the case and inspect the stored analysis.

Submit either:

- Agreement: analyst intent matches automated intent, disposition `monitor`, confidence `3`, resulting status `in_review`.
- Override: choose a different analyst intent and add notes explaining the analyst rationale.

Explain:

- Reviews are append-only.
- A review is saved against a specific `analysis_id`.
- Analyst intent does not overwrite automated intent.
- Analysts do not replace the numeric score.
- Case status update and review insert happen in one transaction.

## 3:00-3:45 - Show Operations Dashboard

Open **Operations Dashboard**.

If needed, click **Load Synthetic Operations Demo Data**.

Show:

- Open cases
- Escalate backlog
- Hard-flagged open cases
- Review-level override rate
- Oldest unresolved high-priority cases

Say: "All metrics come from stored SQLite records. Case-level metrics use the latest stored analysis per case; review-level metrics use the exact analysis the reviewer saw."

## 3:45-4:30 - Run Or Open Evaluation Dashboard Result

Open **Evaluation Dashboard**.

Select `legacy-intent-v1`.

Either run a Rules-only evaluation or open a stored run.

Show:

- Intent accuracy
- Priority pass rate
- Intent confusion matrix
- Priority confusion matrix
- Case-level error table

Discuss one current critical miss:

- `legacy-08` is expected Escalate from the legacy "High" note but receives Review priority under current deterministic behavior.

## 4:30-5:00 - Discuss Analog Detection Limitation

Switch to `safeguards-eval-v1` or mention the stored review packet.

Discuss:

- The expanded suite is provisional.
- Cases `safeguards-007`, `safeguards-015`, `safeguards-022`, and `safeguards-026` expect possible family/analog flags.
- The current matcher only creates possible-family flags near a concrete official term or approved alias.
- It avoids claiming molecular or legal confirmation from generic "Schedule 1 family" language.

Close with:

"This is a demonstration of architecture, traceability, reproducibility, and human-in-the-loop workflow. The synthetic results do not establish real-world safety performance."
