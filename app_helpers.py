import contextlib
import hashlib
import io
import os
from pathlib import Path

import main
import storage
import watchlist


DEFAULT_DB_PATH = "data/safeguards.db"
DB_PATH_ENV_VAR = "SAFEGUARDS_DB_PATH"
ANALYSIS_MODE_RULES = "Rules only"
ANALYSIS_MODE_LLM = "LLM assisted"
REVIEW_STATUS_DEFAULTS = ("new", "in_review")
ANALYST_INTENTS = ("benign", "dual_use", "suspicious", "malicious")
DISPOSITIONS = ("allow", "monitor", "escalate", "close")
CASE_STATUSES = ("new", "in_review", "closed")


def get_database_path() -> str:
	return os.environ.get(DB_PATH_ENV_VAR, DEFAULT_DB_PATH)


def ensure_database_ready(db_path: str) -> None:
	path = Path(db_path)
	if not str(db_path).startswith("file:") and path.parent:
		path.parent.mkdir(parents=True, exist_ok=True)
	storage.initialize_database(db_path)


def build_analysis_row(report_text: str, source: str = None, external_case_id: str = None) -> dict:
	return {
		"text": report_text or "",
		"source": source or "",
		"report_id": external_case_id or "",
	}


def run_analysis_from_form(report_text: str, source: str, external_case_id: str, analysis_mode: str) -> dict:
	if not (report_text or "").strip():
		raise ValueError("Enter report or interaction text before analyzing.")
	if analysis_mode not in (ANALYSIS_MODE_RULES, ANALYSIS_MODE_LLM):
		raise ValueError("Unknown analysis mode.")
	if analysis_mode == ANALYSIS_MODE_LLM and not os.environ.get("OPENAI_API_KEY"):
		raise RuntimeError("LLM-assisted mode requires OPENAI_API_KEY to be configured.")

	rule_only = analysis_mode == ANALYSIS_MODE_RULES
	row = build_analysis_row(report_text, source, external_case_id)
	analysis = main.analyze_report(row, rule_only=rule_only)
	method = "rules" if rule_only else "llm_assisted"
	model_name = None if rule_only else os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
	return {
		"input": row,
		"analysis": analysis,
		"analysis_method": method,
		"model_name": model_name,
		"input_fingerprint": make_input_fingerprint(report_text, source, external_case_id, analysis_mode),
	}


def make_input_fingerprint(report_text: str, source: str, external_case_id: str, analysis_mode: str) -> str:
	return storage.make_case_key(
		f"{analysis_mode}\n{report_text or ''}",
		source=source or "",
		external_id=external_case_id or None,
	)


def split_score_explanation(score_details: dict) -> tuple[list, list]:
	score_changing = []
	zero_point_rules = []
	for contribution in score_details.get("contributions", []):
		if contribution.get("points") == 0:
			zero_point_rules.append(contribution)
		else:
			score_changing.append(contribution)
	for rule in score_details.get("triggered_rules", []):
		if rule.get("points") == 0 and rule.get("rule_id") not in {item.get("rule_id") for item in zero_point_rules}:
			zero_point_rules.append(
				{
					"factor": rule.get("rule_id"),
					"points": 0,
					"reason": rule.get("description"),
					"rule_id": rule.get("rule_id"),
				}
			)
	return score_changing, zero_point_rules


def priority_explanation(intent: str, score_details: dict) -> dict:
	score_band = score_details.get("score_band")
	priority = score_details.get("operational_priority")
	watchlist_source = score_details.get("watchlist_priority_source")
	watchlist_reason = score_details.get("watchlist_priority_explanation")
	intent_floor = main.MINIMUM_PRIORITY_BY_INTENT.get((intent or "benign").lower(), "Low")
	score_rank = main.PRIORITY_RANKS.get(score_band, 0)
	intent_rank = main.PRIORITY_RANKS.get(intent_floor, 0)
	if score_rank > intent_rank:
		source = "score band"
		text = f"The numeric score places this case in {score_band}, which is higher than the {intent_floor} minimum for {intent} intent."
	elif intent_rank > score_rank:
		source = "intent minimum"
		text = f"The numeric score band is {score_band}, but {intent} intent requires at least {intent_floor} review priority."
	else:
		source = "both"
		text = f"The numeric score band and the {intent} intent minimum both resolve to {priority}."
	if watchlist_source and watchlist_source != "existing priority policy":
		source = watchlist_source
		text = f"{text} {watchlist_reason}"
	return {
		"source": source,
		"text": text,
		"score_band": score_band,
		"intent_floor": intent_floor,
		"operational_priority": priority,
	}


def save_displayed_analysis(db_path: str, result: dict) -> dict:
	ensure_database_ready(db_path)
	input_row = result["input"]
	analysis = result["analysis"]
	case_id = storage.create_or_get_case(
		db_path,
		input_row.get("text") or "",
		source=input_row.get("source") or None,
		external_id=input_row.get("report_id") or None,
		synthetic=True,
	)
	analysis_id = storage.save_automated_analysis(
		db_path,
		case_id,
		analysis,
		analysis_method=result["analysis_method"],
		model_name=result.get("model_name"),
	)
	queue_ids = {
		row["case_id"]
		for row in storage.get_cases_for_review_queue(db_path)
	}
	return {
		"case_id": case_id,
		"analysis_id": analysis_id,
		"in_review_queue": case_id in queue_ids,
	}


def run_reports_import_twice(db_path: str) -> tuple[dict, dict]:
	ensure_database_ready(db_path)
	with contextlib.redirect_stdout(io.StringIO()):
		main.load_and_print("reports.csv", db_path=db_path, rule_only=True)
	first = storage.summarize_records(db_path)
	with contextlib.redirect_stdout(io.StringIO()):
		main.load_and_print("reports.csv", db_path=db_path, rule_only=True)
	second = storage.summarize_records(db_path)
	return first, second


def short_preview(text: str, limit: int = 120) -> str:
	cleaned = " ".join((text or "").split())
	if len(cleaned) <= limit:
		return cleaned
	return cleaned[: limit - 3].rsplit(" ", 1)[0] + "..."


def get_review_queue(
	db_path: str,
	statuses=None,
	operational_priority: str = None,
	automated_intent: str = None,
	source: str = None,
	minimum_risk_score=None,
	hard_flag_filter: str = None,
) -> list:
	status_filter = tuple(statuses) if statuses is not None else REVIEW_STATUS_DEFAULTS
	if not status_filter:
		return []
	rows = storage.get_cases_for_review_queue(
		db_path,
		status=status_filter,
		operational_priority=operational_priority or None,
		automated_intent=automated_intent or None,
		source=source or None,
		minimum_risk_score=minimum_risk_score if minimum_risk_score not in (None, "") else None,
		hard_flag_filter=hard_flag_filter or None,
	)
	return [queue_row_view_model(row) for row in rows]


def queue_row_view_model(row: dict) -> dict:
	hard_flags = row.get("hard_flags") or []
	return {
		"case_id": row["case_id"],
		"analysis_id": row["analysis_id"],
		"created_at": row["created_at"],
		"source": row.get("source") or "",
		"status": row["status"],
		"automated_intent": row["automated_intent"],
		"numeric_risk_score": row["numeric_risk_score"],
		"operational_priority": row["operational_priority"],
		"hard_flag_summary": summarize_hard_flags(hard_flags),
		"hard_flags": hard_flags,
		"watchlist_version": row.get("watchlist_version"),
		"watchlist_policy_version": row.get("watchlist_policy_version"),
		"text_preview": short_preview(row.get("report_text") or ""),
		"review_count": row.get("review_count", 0),
	}


def summarize_hard_flags(hard_flags: list) -> str:
	if not hard_flags:
		return "None"
	types = {flag.get("flag_type") for flag in hard_flags}
	if "official_schedule_match" in types:
		return "Official"
	if "approved_alias_match" in types:
		return "Alias"
	if "possible_family_or_analog_reference" in types:
		return "Possible analog/family"
	return "Flagged"


def hard_flag_view_models(analysis: dict) -> list:
	items = []
	for flag in analysis.get("hard_flags") or []:
		items.append(
			{
				"authority": flag.get("authority", "OPCW"),
				"schedule": flag.get("schedule", "Schedule 1"),
				"status": {
					"official_schedule_match": "Official match",
					"approved_alias_match": "Approved alias match",
					"possible_family_or_analog_reference": "Possible family/analog reference",
				}.get(flag.get("flag_type"), "Hard flag"),
				"matched_term": flag.get("matched_term"),
				"reason": flag.get("explanation"),
				"watchlist_version": flag.get("watchlist_version") or analysis.get("watchlist_version"),
				"priority_effect": flag.get("minimum_priority", "Review"),
				"confidence_category": flag.get("confidence_category"),
				"entry_code": flag.get("entry_code"),
			}
		)
	return items


def load_demo_cases(db_path: str) -> dict:
	ensure_database_ready(db_path)
	with contextlib.redirect_stdout(io.StringIO()):
		main.load_and_print("reports.csv", db_path=db_path, rule_only=True)
	return storage.summarize_records(db_path)


def get_case_detail(db_path: str, case_id: int, analysis_id: int = None) -> dict:
	case = storage.get_case_with_history(db_path, case_id)
	if case is None:
		return None
	analyses = case.get("analyses") or []
	if analysis_id is None and analyses:
		analysis = analyses[0]
	else:
		analysis = next((item for item in analyses if item["analysis_id"] == analysis_id), None)
	return {
		"case": case,
		"analyses": analyses,
		"selected_analysis": analysis,
		"review_history": flatten_review_history(case),
	}


def stored_analysis_display_result(case: dict, analysis: dict) -> dict:
	score_details = analysis.get("score_details") or {}
	return {
		"input": {
			"text": case.get("report_text") or "",
			"source": case.get("source") or "",
			"report_id": case.get("case_key") or "",
		},
		"analysis": {
			"intent": analysis.get("automated_intent"),
			"indicators": analysis.get("normalized_indicators") or [],
			"summary": analysis.get("summary"),
			"score_details": score_details,
			"scoring_version": analysis.get("scoring_version"),
			"priority_policy_version": analysis.get("priority_policy_version"),
			"hard_flags": analysis.get("hard_flags") or [],
			"watchlist_version": analysis.get("watchlist_version") or watchlist.NO_WATCHLIST_VERSION,
			"watchlist_match_count": len(analysis.get("hard_flags") or []),
			"watchlist_policy_version": analysis.get("watchlist_policy_version") or watchlist.LEGACY_WATCHLIST_POLICY_VERSION,
		},
		"analysis_method": analysis.get("analysis_method"),
		"model_name": analysis.get("model_name"),
		"input_fingerprint": f"stored:{case.get('case_id')}:{analysis.get('analysis_id')}",
	}


def flatten_review_history(case: dict) -> list:
	history = []
	for analysis in case.get("analyses") or []:
		for review in analysis.get("reviews") or []:
			agreement = analyst_agreement(review.get("analyst_intent"), analysis.get("automated_intent"))
			history.append(
				{
					"created_at": review.get("created_at"),
					"reviewer": review.get("reviewer"),
					"analyst_intent": review.get("analyst_intent"),
					"automated_intent": analysis.get("automated_intent"),
					"agreement": agreement,
					"disposition": review.get("disposition"),
					"confidence": review.get("confidence"),
					"resulting_case_status": review.get("resulting_case_status"),
					"notes": review.get("notes"),
					"analysis_id": analysis.get("analysis_id"),
					"scoring_version": analysis.get("scoring_version"),
					"priority_policy_version": analysis.get("priority_policy_version"),
				}
			)
	return sorted(history, key=lambda item: (item.get("created_at") or "", item.get("analysis_id") or 0))


def analyst_agreement(analyst_intent: str, automated_intent: str) -> str:
	return "Agreement" if analyst_intent == automated_intent else "Override"


def review_validation(analyst_intent: str, automated_intent: str, disposition: str, confidence: int, notes: str, resulting_status: str) -> dict:
	errors = []
	warnings = []
	if analyst_intent not in ANALYST_INTENTS:
		errors.append("Analyst intent is not valid.")
	if disposition not in DISPOSITIONS:
		errors.append("Disposition is not valid.")
	if resulting_status not in CASE_STATUSES:
		errors.append("Resulting case status is not valid.")
	if not isinstance(confidence, int) or not 1 <= confidence <= 5:
		errors.append("Confidence must be an integer from 1 through 5.")
	if analyst_agreement(analyst_intent, automated_intent) == "Override" and not (notes or "").strip():
		errors.append("Overrides require notes explaining the analyst rationale.")
	if disposition == "escalate" and resulting_status == "closed":
		warnings.append("Disposition is escalate while resulting status is closed. Confirm this exception is intentional.")
	if disposition == "close" and resulting_status != "closed":
		warnings.append("Disposition close normally results in status closed.")
	if resulting_status == "new":
		warnings.append("Resulting status new after review means the case has been reviewed but remains marked new.")
	return {
		"errors": errors,
		"warnings": warnings,
		"agreement": analyst_agreement(analyst_intent, automated_intent),
	}


def review_submission_key(analysis_id: int, reviewer: str, analyst_intent: str, disposition: str, confidence: int, notes: str, resulting_status: str) -> str:
	payload = "\x1f".join(
		" ".join(str(part or "").strip().split())
		for part in (analysis_id, reviewer, analyst_intent, disposition, confidence, notes or "", resulting_status)
	)
	return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def save_review_once(db_path: str, submitted_keys: set, analysis_id: int, reviewer: str, analyst_intent: str, disposition: str, confidence: int, notes: str, resulting_status: str) -> dict:
	key = review_submission_key(analysis_id, reviewer, analyst_intent, disposition, confidence, notes, resulting_status)
	if key in submitted_keys:
		return {"saved": False, "duplicate": True, "review_id": None, "submission_key": key}
	review_id = storage.save_analyst_review(
		db_path,
		analysis_id,
		reviewer=reviewer,
		analyst_intent=analyst_intent,
		disposition=disposition,
		confidence=confidence,
		notes=notes,
		resulting_case_status=resulting_status,
	)
	submitted_keys.add(key)
	return {"saved": True, "duplicate": False, "review_id": review_id, "submission_key": key}


def default_disposition_for_intent(intent: str) -> str:
	if intent == "malicious":
		return "escalate"
	if intent in ("suspicious", "dual_use"):
		return "monitor"
	return "allow"


def default_status_for_disposition(disposition: str) -> str:
	return "closed" if disposition in ("allow", "close") else "in_review"
