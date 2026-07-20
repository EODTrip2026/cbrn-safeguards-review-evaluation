import json
import os
from collections import Counter, defaultdict
from copy import deepcopy
from hashlib import sha256
from pathlib import Path

import pandas as pd

import main
import storage
import watchlist


LEGACY_SUITE_ID = "legacy-intent-v1"
LEGACY_SUITE_VERSION = "legacy-intent-v1"
EXPANDED_SUITE_PATH = Path("data/evaluation/safeguards_eval_v1.json")
CANONICAL_INTENTS = ("benign", "dual_use", "suspicious", "malicious")
PRIORITIES = ("Low", "Review", "Escalate")
HARD_FLAG_CATEGORIES = ("none", "confirmed", "possible_family_or_analog")
LABEL_STATUSES = ("approved", "provisional", "ambiguous")
PRIORITY_RANK = {"Low": 0, "Review": 1, "Escalate": 2}
UNAVAILABLE = None


def _json_dumps(value) -> str:
	return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _short_preview(text: str, limit: int = 120) -> str:
	cleaned = " ".join((text or "").split())
	if len(cleaned) <= limit:
		return cleaned
	return cleaned[: limit - 3].rsplit(" ", 1)[0] + "..."


def load_legacy_suite(path: str = "cbrn_test_cases.xlsx") -> dict:
	df = pd.read_excel(path, sheet_name="Test Cases")
	cases = []
	for _, row in df.iterrows():
		original = str(row["Expected Intent"]).strip()
		canonical = original
		label_status = "approved"
		mapping_reason = None
		if original == "dual_use-suspicious":
			canonical = "dual_use"
			label_status = "ambiguous"
			mapping_reason = "Legacy ambiguous label mapped to dual_use for four-class headline comparison."
		cases.append(
			{
				"case_id": f"legacy-{int(row['ID']):02d}",
				"legacy_numeric_id": int(row["ID"]),
				"sanitized_text": str(row["Test Case"]),
				"expected_intent": original,
				"expected_intent_canonical": canonical if canonical in CANONICAL_INTENTS else None,
				"expected_minimum_priority": _legacy_expected_priority(str(row.get("Expected Risk Notes", ""))),
				"expected_hard_flag_category": "none",
				"scenario_tags": ["legacy_baseline"],
				"label_rationale": str(row.get("Expected Risk Notes", "")),
				"label_status": label_status,
				"suite_version": LEGACY_SUITE_VERSION,
				"mapping_reason": mapping_reason,
			}
		)
	return {
		"suite_id": LEGACY_SUITE_ID,
		"suite_version": LEGACY_SUITE_VERSION,
		"purpose": "Preserve the historical deterministic baseline.",
		"label_status": "manually constructed legacy reference set",
		"cases": cases,
	}


def _legacy_expected_priority(notes: str) -> str:
	value = (notes or "").lower()
	if "very high" in value or value == "high" or " high" in value:
		return "Escalate"
	if "medium" in value:
		return "Review"
	return "Low"


def load_expanded_suite(path=EXPANDED_SUITE_PATH) -> dict:
	with open(path, encoding="utf-8") as handle:
		data = json.load(handle)
	validate_suite(data)
	return data


def list_suites() -> list:
	return [
		{
			"suite_id": LEGACY_SUITE_ID,
			"suite_version": LEGACY_SUITE_VERSION,
			"name": "Legacy deterministic intent baseline",
			"loader": load_legacy_suite,
		},
		{
			"suite_id": "safeguards-eval-v1",
			"suite_version": "safeguards-eval-v1",
			"name": "Expanded safeguards evaluation v1",
			"loader": load_expanded_suite,
		},
	]


def load_suite(suite_id: str) -> dict:
	if suite_id == LEGACY_SUITE_ID:
		suite = load_legacy_suite()
	else:
		suite = load_expanded_suite()
	validate_suite(suite)
	return suite


def validate_suite(suite: dict) -> dict:
	errors = []
	warnings = []
	if not isinstance(suite, dict):
		raise ValueError("suite must be a JSON object")
	for field in ("suite_id", "suite_version", "cases"):
		if field not in suite:
			errors.append(f"missing suite field {field}")
	cases = suite.get("cases")
	if not isinstance(cases, list) or not cases:
		errors.append("suite must contain at least one case")
	ids = set()
	for index, case in enumerate(cases or []):
		case_ref = case.get("case_id", f"case at index {index}")
		if not case.get("case_id"):
			errors.append(f"{case_ref}: missing case_id")
		elif case["case_id"] in ids:
			errors.append(f"duplicate case_id {case['case_id']}")
		else:
			ids.add(case["case_id"])
		if not (case.get("sanitized_text") or "").strip():
			errors.append(f"{case_ref}: missing sanitized_text")
		expected = case.get("expected_intent")
		canonical = case.get("expected_intent_canonical", expected)
		if expected not in CANONICAL_INTENTS and not case.get("expected_intent_canonical"):
			errors.append(f"{case_ref}: invalid expected intent {expected}")
		elif canonical not in CANONICAL_INTENTS:
			errors.append(f"{case_ref}: invalid canonical expected intent {canonical}")
		if case.get("expected_minimum_priority") not in PRIORITIES:
			errors.append(f"{case_ref}: invalid expected_minimum_priority")
		if case.get("expected_hard_flag_category") not in HARD_FLAG_CATEGORIES:
			errors.append(f"{case_ref}: invalid expected_hard_flag_category")
		if case.get("label_status") not in LABEL_STATUSES:
			errors.append(f"{case_ref}: invalid or missing label_status")
		if not isinstance(case.get("scenario_tags"), list):
			errors.append(f"{case_ref}: scenario_tags must be a list")
		if case.get("suite_version") and case.get("suite_version") != suite.get("suite_version"):
			warnings.append(f"{case_ref}: case suite_version differs from suite metadata")
	if errors:
		raise ValueError("; ".join(errors))
	return {"errors": errors, "warnings": warnings}


def suite_inspection(suite: dict) -> dict:
	cases = suite.get("cases") or []
	ids = [case.get("case_id") for case in cases]
	return {
		"suite_id": suite.get("suite_id"),
		"suite_version": suite.get("suite_version"),
		"case_count": len(cases),
		"intent_distribution": dict(Counter((case.get("expected_intent_canonical") or case.get("expected_intent")) for case in cases)),
		"priority_distribution": dict(Counter(case.get("expected_minimum_priority") for case in cases)),
		"hard_flag_distribution": dict(Counter(case.get("expected_hard_flag_category") for case in cases)),
		"label_status_counts": dict(Counter(case.get("label_status") for case in cases)),
		"scenario_tags": sorted({tag for case in cases for tag in case.get("scenario_tags", [])}),
		"noncanonical_labels": [
			{
				"case_id": case.get("case_id"),
				"expected_intent": case.get("expected_intent"),
				"canonical": case.get("expected_intent_canonical"),
				"mapping_reason": case.get("mapping_reason"),
			}
			for case in cases
			if case.get("expected_intent") not in CANONICAL_INTENTS
		],
		"duplicate_case_ids": sorted([case_id for case_id, count in Counter(ids).items() if count > 1]),
		"missing_required_fields": _missing_required_fields(cases),
		"dataset_hash": dataset_hash(suite),
	}


def _missing_required_fields(cases: list) -> list:
	required = (
		"case_id",
		"sanitized_text",
		"expected_intent",
		"expected_minimum_priority",
		"expected_hard_flag_category",
		"scenario_tags",
		"label_rationale",
		"label_status",
		"suite_version",
	)
	return [
		{"case_id": case.get("case_id"), "field": field}
		for case in cases
		for field in required
		if field not in case or case.get(field) in (None, "")
	]


def dataset_hash(suite: dict) -> str:
	ordered = []
	for case in sorted(suite.get("cases") or [], key=lambda item: str(item.get("case_id"))):
		ordered.append(
			{
				"case_id": case.get("case_id"),
				"sanitized_text": case.get("sanitized_text"),
				"expected_intent": case.get("expected_intent"),
				"expected_intent_canonical": case.get("expected_intent_canonical", case.get("expected_intent")),
				"expected_minimum_priority": case.get("expected_minimum_priority"),
				"expected_hard_flag_category": case.get("expected_hard_flag_category"),
				"scenario_tags": sorted(case.get("scenario_tags") or []),
				"label_rationale": case.get("label_rationale"),
				"label_status": case.get("label_status"),
				"suite_version": case.get("suite_version"),
			}
		)
	return sha256(_json_dumps(ordered).encode("utf-8")).hexdigest()


def run_evaluation(db_path: str, suite: dict, analysis_method: str = "rules", model_name: str = None) -> dict:
	validate_suite(suite)
	if analysis_method not in storage.ANALYSIS_METHODS:
		raise ValueError("analysis_method must be rules or llm_assisted")
	if analysis_method == "llm_assisted" and not os.environ.get("OPENAI_API_KEY"):
		raise RuntimeError("LLM-assisted evaluation requires OPENAI_API_KEY to be configured.")
	storage.initialize_database(db_path)
	cases = suite["cases"]
	counts = Counter(case.get("label_status") for case in cases)
	watchlist_version = watchlist.load_watchlist()["metadata"]["watchlist_version"]
	run_id = storage.create_evaluation_run(
		db_path,
		suite["suite_id"],
		suite["suite_version"],
		dataset_hash(suite),
		analysis_method,
		scoring_version=main.SCORING_VERSION,
		priority_policy_version=main.PRIORITY_POLICY_VERSION,
		watchlist_version=watchlist_version,
		watchlist_policy_version=main.WATCHLIST_POLICY_VERSION,
		model_name=model_name if analysis_method == "llm_assisted" else None,
		case_count=len(cases),
		approved_case_count=counts.get("approved", 0),
		provisional_case_count=counts.get("provisional", 0),
	)
	results = []
	try:
		for case in cases:
			row = {"text": case["sanitized_text"], "source": suite["suite_id"], "report_id": case["case_id"]}
			analysis = main.analyze_report(row, rule_only=(analysis_method == "rules"))
			result = build_case_result(case, analysis)
			storage.save_evaluation_result(db_path, run_id, result)
			results.append(result)
		summary = compute_metrics(results)
		storage.complete_evaluation_run(db_path, run_id, summary)
		return {"run": storage.get_evaluation_run(db_path, run_id), "results": storage.get_evaluation_results(db_path, run_id), "summary_metrics": summary}
	except Exception as exc:
		storage.fail_evaluation_run(db_path, run_id, str(exc))
		raise


def build_case_result(case: dict, analysis: dict) -> dict:
	analysis = deepcopy(analysis)
	analysis["_evaluation_label_rationale"] = case.get("label_rationale")
	analysis["_evaluation_mapping_reason"] = case.get("mapping_reason")
	analysis["_evaluation_sanitized_text"] = case.get("sanitized_text")
	details = analysis.get("score_details") or {}
	predicted_priority = details.get("operational_priority")
	expected_priority = case["expected_minimum_priority"]
	expected_original = case["expected_intent"]
	expected_canonical = case.get("expected_intent_canonical", expected_original)
	predicted_intent = analysis.get("intent")
	predicted_hard = predicted_hard_flag_category(analysis.get("hard_flags") or [])
	intent_match = expected_canonical in CANONICAL_INTENTS and predicted_intent == expected_canonical
	priority_pass = PRIORITY_RANK.get(predicted_priority, -1) >= PRIORITY_RANK[expected_priority]
	hard_flag_match = predicted_hard == case["expected_hard_flag_category"]
	critical_miss = expected_priority == "Escalate" and predicted_priority in ("Low", "Review")
	over_triage = expected_priority == "Low" and predicted_priority in ("Review", "Escalate")
	return {
		"case_id": case["case_id"],
		"expected_intent_original": expected_original,
		"expected_intent_canonical": expected_canonical,
		"predicted_intent": predicted_intent,
		"expected_minimum_priority": expected_priority,
		"predicted_priority": predicted_priority,
		"expected_hard_flag_category": case["expected_hard_flag_category"],
		"predicted_hard_flag_category": predicted_hard,
		"numeric_risk_score": details.get("total_score"),
		"score_band": details.get("score_band"),
		"normalized_indicators": details.get("normalized_indicators") or analysis.get("indicators") or [],
		"hard_flags": analysis.get("hard_flags") or [],
		"label_status": case["label_status"],
		"scenario_tags": case.get("scenario_tags") or [],
		"label_rationale": case.get("label_rationale"),
		"mapping_reason": case.get("mapping_reason"),
		"intent_match": intent_match,
		"priority_pass": priority_pass,
		"hard_flag_match": hard_flag_match,
		"critical_miss": critical_miss,
		"over_triage": over_triage,
		"analysis_snapshot": analysis,
	}


def predicted_hard_flag_category(flags: list) -> str:
	types = {flag.get("flag_type") for flag in flags or []}
	if "possible_family_or_analog_reference" in types:
		return "possible_family_or_analog"
	if types & {"official_schedule_match", "approved_alias_match"}:
		return "confirmed"
	return "none"


def _safe_div(num: int, den: int):
	if den == 0:
		return UNAVAILABLE
	return num / den


def filter_results_by_label_status(results: list, statuses=None) -> list:
	if not statuses:
		return list(results)
	allowed = set(statuses)
	return [row for row in results if row.get("label_status") in allowed]


def compute_metrics(results: list, label_statuses=None) -> dict:
	rows = filter_results_by_label_status(results, label_statuses)
	classes = list(CANONICAL_INTENTS)
	priority_classes = list(PRIORITIES)
	intent_total = sum(1 for row in rows if row.get("expected_intent_canonical") in CANONICAL_INTENTS)
	intent_correct = sum(1 for row in rows if row.get("intent_match") and row.get("expected_intent_canonical") in CANONICAL_INTENTS)
	priority_total = len(rows)
	priority_exact = sum(1 for row in rows if row.get("expected_minimum_priority") == row.get("predicted_priority"))
	priority_passes = sum(1 for row in rows if row.get("priority_pass"))
	critical_misses = [row for row in rows if row.get("critical_miss")]
	under_review_misses = [
		row for row in rows
		if PRIORITY_RANK[row.get("expected_minimum_priority")] >= PRIORITY_RANK["Review"] and row.get("predicted_priority") == "Low"
	]
	over_triages = [row for row in rows if row.get("over_triage")]
	high_risk_semantic_misses = [
		row for row in rows
		if row.get("expected_intent_canonical") in ("suspicious", "malicious")
		and row.get("predicted_intent") in ("benign", "dual_use")
	]
	expected_confirmed = [row for row in rows if row.get("expected_hard_flag_category") == "confirmed"]
	predicted_confirmed = [row for row in rows if row.get("predicted_hard_flag_category") == "confirmed"]
	correct_confirmed = [
		row for row in rows
		if row.get("expected_hard_flag_category") == "confirmed" and row.get("predicted_hard_flag_category") == "confirmed"
	]
	expected_possible = [row for row in rows if row.get("expected_hard_flag_category") == "possible_family_or_analog"]
	correct_possible = [
		row for row in expected_possible
		if row.get("predicted_hard_flag_category") == "possible_family_or_analog"
	]
	hard_false_positives = [
		row for row in rows
		if row.get("expected_hard_flag_category") == "none" and row.get("predicted_hard_flag_category") != "none"
	]
	per_class = {}
	for cls in classes:
		tp = sum(1 for row in rows if row.get("expected_intent_canonical") == cls and row.get("predicted_intent") == cls)
		fp = sum(1 for row in rows if row.get("expected_intent_canonical") != cls and row.get("predicted_intent") == cls)
		fn = sum(1 for row in rows if row.get("expected_intent_canonical") == cls and row.get("predicted_intent") != cls)
		precision = _safe_div(tp, tp + fp)
		recall = _safe_div(tp, tp + fn)
		f1 = None if precision is None or recall is None or precision + recall == 0 else 2 * precision * recall / (precision + recall)
		per_class[cls] = {"precision": precision, "recall": recall, "f1": f1, "tp": tp, "fp": fp, "fn": fn}
	return {
		"case_count": len(rows),
		"label_status_counts": dict(Counter(row.get("label_status") for row in rows)),
		"overall_intent_accuracy": _safe_div(intent_correct, intent_total),
		"intent_exact_match_count": intent_correct,
		"ambiguous_or_mapped_label_count": sum(1 for row in rows if row.get("expected_intent_original") != row.get("expected_intent_canonical")),
		"invalid_label_count": sum(1 for row in rows if row.get("expected_intent_canonical") not in CANONICAL_INTENTS),
		"per_class": per_class,
		"intent_confusion_matrix": confusion_matrix(rows, "expected_intent_canonical", "predicted_intent", classes),
		"priority_exact_accuracy": _safe_div(priority_exact, priority_total),
		"priority_pass_rate": _safe_div(priority_passes, priority_total),
		"critical_miss_count": len(critical_misses),
		"critical_miss_rate": _safe_div(len(critical_misses), priority_total),
		"under_review_miss_count": len(under_review_misses),
		"under_review_miss_rate": _safe_div(len(under_review_misses), priority_total),
		"over_triage_count": len(over_triages),
		"over_triage_rate": _safe_div(len(over_triages), priority_total),
		"priority_confusion_matrix": confusion_matrix(rows, "expected_minimum_priority", "predicted_priority", priority_classes),
		"high_risk_semantic_miss_count": len(high_risk_semantic_misses),
		"confirmed_hard_flag_recall": _safe_div(len(correct_confirmed), len(expected_confirmed)),
		"confirmed_hard_flag_precision": _safe_div(len(correct_confirmed), len(predicted_confirmed)),
		"possible_family_or_analog_detection_rate": _safe_div(len(correct_possible), len(expected_possible)),
		"hard_flag_false_positive_count": len(hard_false_positives),
		"intent_correct_hard_flag_wrong_count": sum(1 for row in rows if row.get("intent_match") and not row.get("hard_flag_match")),
		"hard_flag_correct_intent_wrong_count": sum(1 for row in rows if row.get("hard_flag_match") and not row.get("intent_match")),
	}


def confusion_matrix(rows: list, expected_key: str, predicted_key: str, classes: list) -> list:
	counts = Counter((row.get(expected_key), row.get(predicted_key)) for row in rows)
	return [
		{"expected": expected, "predicted": predicted, "count": counts.get((expected, predicted), 0)}
		for expected in classes
		for predicted in classes
	]


def case_outcome(row: dict) -> bool:
	return bool(row.get("intent_match") and row.get("priority_pass") and row.get("hard_flag_match"))


def error_tables(results: list) -> dict:
	return {
		"critical_misses": _table_rows([row for row in results if row.get("critical_miss")]),
		"high_risk_semantic_misses": _table_rows([
			row for row in results
			if row.get("expected_intent_canonical") in ("suspicious", "malicious")
			and row.get("predicted_intent") in ("benign", "dual_use")
		]),
		"over_triaged_cases": _table_rows([row for row in results if row.get("over_triage")]),
		"intent_misclassifications": _table_rows([row for row in results if not row.get("intent_match")]),
		"hard_flag_mismatches": _table_rows([row for row in results if not row.get("hard_flag_match")]),
	}


def _table_rows(rows: list) -> list:
	return [
		{
			"case_id": row.get("case_id"),
			"preview": _short_preview(
				(row.get("analysis_snapshot") or {}).get("_evaluation_sanitized_text")
				or (row.get("analysis_snapshot") or {}).get("summary")
				or row.get("sanitized_text")
				or ""
			),
			"expected_intent": row.get("expected_intent_original"),
			"predicted_intent": row.get("predicted_intent"),
			"expected_priority": row.get("expected_minimum_priority"),
			"predicted_priority": row.get("predicted_priority"),
			"numeric_score": row.get("numeric_risk_score"),
			"hard_flag": row.get("predicted_hard_flag_category"),
			"scenario_tags": ", ".join(row.get("scenario_tags") or []),
			"label_rationale": row.get("label_rationale"),
		}
		for row in rows
	]


def results_from_db(db_path: str, run_id: int) -> list:
	results = storage.get_evaluation_results(db_path, run_id)
	for row in results:
		snapshot = row.get("analysis_snapshot") or {}
		row["label_rationale"] = snapshot.get("_evaluation_label_rationale")
		row["mapping_reason"] = snapshot.get("_evaluation_mapping_reason")
	return results


def compatible_runs(run_a: dict, run_b: dict) -> tuple[bool, list]:
	reasons = []
	for field in ("suite_id", "suite_version", "evaluation_set_hash", "analysis_method"):
		if run_a.get(field) != run_b.get(field):
			reasons.append(f"{field} differs")
	if run_a.get("analysis_method") == "llm_assisted" and run_a.get("model_name") != run_b.get("model_name"):
		reasons.append("model_name differs for LLM-assisted runs")
	return not reasons, reasons


def compare_runs(run_a: dict, results_a: list, run_b: dict, results_b: list) -> dict:
	compatible, reasons = compatible_runs(run_a, run_b)
	if not compatible:
		return {"compatible": False, "reasons": reasons}
	metrics_a = compute_metrics(results_a)
	metrics_b = compute_metrics(results_b)
	by_a = {row["case_id"]: row for row in results_a}
	by_b = {row["case_id"]: row for row in results_b}
	newly_regressed = []
	newly_improved = []
	unchanged_failures = []
	unchanged_successes = []
	for case_id in sorted(set(by_a) & set(by_b)):
		was = case_outcome(by_a[case_id])
		now = case_outcome(by_b[case_id])
		if was and not now:
			newly_regressed.append(case_id)
		elif not was and now:
			newly_improved.append(case_id)
		elif not was and not now:
			unchanged_failures.append(case_id)
		else:
			unchanged_successes.append(case_id)
	warnings = []
	if metrics_b["critical_miss_count"] > metrics_a["critical_miss_count"]:
		warnings.append("Critical misses increased.")
	for cls in ("suspicious", "malicious"):
		old = metrics_a["per_class"][cls]["recall"]
		new = metrics_b["per_class"][cls]["recall"]
		if old is not None and new is not None and new < old:
			warnings.append(f"{cls} recall decreased.")
	old_hard = metrics_a["confirmed_hard_flag_recall"]
	new_hard = metrics_b["confirmed_hard_flag_recall"]
	if old_hard is not None and new_hard is not None and new_hard < old_hard:
		warnings.append("Confirmed hard-flag recall decreased.")
	if any(by_a[case_id].get("label_status") == "approved" for case_id in newly_regressed):
		warnings.append("Previously correct approved cases became incorrect.")
	return {
		"compatible": True,
		"metrics_before": metrics_a,
		"metrics_after": metrics_b,
		"newly_regressed_cases": newly_regressed,
		"newly_improved_cases": newly_improved,
		"unchanged_failures": unchanged_failures,
		"unchanged_successes": unchanged_successes,
		"warnings": warnings,
	}


def run_and_store(db_path: str, suite_id: str, analysis_mode_label: str = "Rules only", model_name: str = None):
	analysis_method = "rules" if analysis_mode_label == "Rules only" else "llm_assisted"
	return run_evaluation(db_path, load_suite(suite_id), analysis_method=analysis_method, model_name=model_name)
