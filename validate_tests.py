import sys

try:
    import pandas as pd
except Exception as e:
    print("pandas not installed:", e, file=sys.stderr)
    raise

from main import (
    CANONICAL_INTENTS,
    analyze_report,
    compute_detailed_risk_score,
    compute_risk_score,
    determine_operational_priority,
    get_score_band,
)


def find_column(columns, *candidates):
    lowered = {str(col).strip().lower(): col for col in columns}
    for candidate in candidates:
        match = lowered.get(candidate.lower())
        if match is not None:
            return match
    return None


def classify_intent_result(actual_intent, expected_intent) -> str:
    actual = str(actual_intent).strip().lower()
    expected = str(expected_intent).strip().lower()
    if not expected:
        return "invalid_reference_label"

    canonical = set(CANONICAL_INTENTS)
    if expected in canonical:
        return "exact_canonical_match" if actual == expected else "mismatch"

    expected_options = [part.strip() for part in expected.split("-") if part.strip()]
    if expected_options and all(option in canonical for option in expected_options):
        return "accepted_ambiguous_match" if actual in expected_options else "mismatch"

    return "invalid_reference_label"


fn = "cbrn_test_cases.xlsx"
try:
    df = pd.read_excel(fn)
except Exception as e:
    print(f"Failed to read {fn}: {e}", file=sys.stderr)
    raise

print("Columns:", list(df.columns))
print("Rows:", len(df))

text_col = find_column(df.columns, "text", "report", "description", "test case")
expected_intent_col = find_column(
    df.columns,
    "expected_intent",
    "intent_expected",
    "expected intent",
)
id_col = find_column(df.columns, "id")

if text_col is None:
    raise ValueError("Could not find a report text column in the spreadsheet.")

result_counts = {
    "exact_canonical_match": 0,
    "accepted_ambiguous_match": 0,
    "mismatch": 0,
    "invalid_reference_label": 0,
}
invalid_reference_labels = []

for i, row in df.iterrows():
    case_id = row.get(id_col) if id_col else i + 1
    text = row.get(text_col)
    expected_intent = row.get(expected_intent_col) if expected_intent_col else None

    print(f"\n--- Row {i + 1} (ID={case_id}) ---")
    print("Text:", text)

    analysis = analyze_report({"text": text}, rule_only=True)
    score = compute_risk_score(analysis.get("intent"), analysis.get("indicators"))
    details = compute_detailed_risk_score(analysis.get("intent"), analysis.get("indicators"))

    actual_intent = analysis.get("intent")
    print("Analysis:", analysis)
    print("Computed risk score:", score)
    print("Score band:", get_score_band(score))
    print("Operational priority:", determine_operational_priority(actual_intent, score))
    print("Scoring version:", details["scoring_version"])
    print("Priority policy version:", details["priority_policy_version"])

    if expected_intent is not None:
        result = classify_intent_result(actual_intent, expected_intent)
        result_counts[result] += 1
        expected_clean = str(expected_intent).strip().lower()
        if expected_clean not in set(CANONICAL_INTENTS):
            invalid_reference_labels.append((case_id, expected_intent))
        print("Expected intent:", expected_intent)
        print("Intent result:", result)

print("\nIntent validation summary:")
if expected_intent_col is None:
    print(" - No expected intent column found.")
else:
    print(f" - Exact canonical matches: {result_counts['exact_canonical_match']}")
    print(f" - Accepted ambiguous/alias matches: {result_counts['accepted_ambiguous_match']}")
    print(f" - Mismatches: {result_counts['mismatch']}")
    print(f" - Invalid unaccepted reference labels: {result_counts['invalid_reference_label']}")
    print(f" - Noncanonical reference labels: {len(invalid_reference_labels)}")
    if invalid_reference_labels:
        print(" - Noncanonical reference labels requiring cleanup:")
        for case_id, label in invalid_reference_labels:
            print(f"   * ID={case_id}: {label}")

print("\nValidation run complete.")
