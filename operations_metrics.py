import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import main
import storage


DEMO_DATA_PATH = Path("data/demo/operations_dashboard_demo.json")
UNAVAILABLE = None
PRIORITY_ORDER = {"Escalate": 0, "Review": 1, "Low": 2}
AGING_BUCKETS = ("Less than 24 hours", "1-3 days", "4-7 days", "More than 7 days")


def parse_utc(value):
	if value in (None, ""):
		return None
	if isinstance(value, datetime):
		dt = value
	else:
		dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
	if dt.tzinfo is None:
		dt = dt.replace(tzinfo=timezone.utc)
	return dt.astimezone(timezone.utc)


def iso_utc(dt: datetime) -> str:
	return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def now_utc() -> datetime:
	return datetime.now(timezone.utc).replace(microsecond=0)


def _json_loads(value, default):
	if value in (None, ""):
		return default
	try:
		return json.loads(value)
	except (TypeError, json.JSONDecodeError):
		return default


def _matches_hard_flag_filter(flags: list, hard_flag_status: str = None) -> bool:
	if hard_flag_status in (None, "all"):
		return True
	types = {flag.get("flag_type") for flag in flags or []}
	if hard_flag_status == "any":
		return bool(types)
	if hard_flag_status == "none":
		return not types
	if hard_flag_status == "confirmed":
		return bool(types & {"official_schedule_match", "approved_alias_match"})
	if hard_flag_status == "possible":
		return "possible_family_or_analog_reference" in types
	raise ValueError("hard_flag_status must be all, any, none, confirmed, or possible")


def _matches_filter(value, allowed):
	return not allowed or value in set(allowed)


def get_filter_options(db_path: str) -> dict:
	with storage.connect(db_path) as conn:
		return {
			"statuses": [row["status"] for row in conn.execute("SELECT DISTINCT status FROM cases ORDER BY status").fetchall()],
			"priorities": [row["operational_priority"] for row in conn.execute("SELECT DISTINCT operational_priority FROM analyses ORDER BY operational_priority").fetchall()],
			"intents": [row["automated_intent"] for row in conn.execute("SELECT DISTINCT automated_intent FROM analyses ORDER BY automated_intent").fetchall()],
			"sources": [row["source"] for row in conn.execute("SELECT DISTINCT source FROM cases WHERE source IS NOT NULL AND source != '' ORDER BY source").fetchall()],
			"methods": [row["analysis_method"] for row in conn.execute("SELECT DISTINCT analysis_method FROM analyses ORDER BY analysis_method").fetchall()],
			"scoring_versions": [row["scoring_version"] for row in conn.execute("SELECT DISTINCT scoring_version FROM analyses ORDER BY scoring_version").fetchall()],
			"watchlist_versions": [row["watchlist_version"] for row in conn.execute("SELECT DISTINCT watchlist_version FROM analyses ORDER BY watchlist_version").fetchall()],
		}


def _latest_case_rows(db_path: str) -> list:
	query = """
		SELECT
			c.case_id, c.case_key, c.report_text, c.source, c.synthetic, c.status,
			c.created_at, c.updated_at,
			a.analysis_id, a.automated_intent, a.normalized_indicators_json,
			a.numeric_risk_score, a.score_band, a.operational_priority,
			a.analysis_method, a.scoring_version, a.priority_policy_version,
			a.hard_flags_json, a.watchlist_version, a.watchlist_policy_version,
			a.created_at AS analysis_created_at,
			(
				SELECT COUNT(*)
				FROM reviews r
				JOIN analyses ra ON ra.analysis_id = r.analysis_id
				WHERE ra.case_id = c.case_id
			) AS review_count
		FROM cases c
		JOIN (
			SELECT a.*
			FROM analyses a
			JOIN (
				SELECT case_id, MAX(analysis_id) AS analysis_id
				FROM analyses
				GROUP BY case_id
			) latest ON latest.analysis_id = a.analysis_id
		) a ON a.case_id = c.case_id
	"""
	with storage.connect(db_path) as conn:
		rows = []
		for row in conn.execute(query).fetchall():
			data = dict(row)
			data["hard_flags"] = _json_loads(data.pop("hard_flags_json", None), [])
			data["normalized_indicators"] = _json_loads(data.pop("normalized_indicators_json", None), [])
			rows.append(data)
		return rows


def apply_case_filters(rows: list, filters: dict = None) -> list:
	filters = filters or {}
	from_date = parse_utc(filters.get("created_from"))
	to_date = parse_utc(filters.get("created_to"))
	result = []
	for row in rows:
		created = parse_utc(row.get("created_at"))
		if from_date and created and created < from_date:
			continue
		if to_date and created and created > to_date:
			continue
		if not _matches_filter(row.get("status"), filters.get("statuses")):
			continue
		if not _matches_filter(row.get("operational_priority"), filters.get("operational_priorities")):
			continue
		if not _matches_filter(row.get("automated_intent"), filters.get("automated_intents")):
			continue
		if not _matches_filter(row.get("source"), filters.get("sources")):
			continue
		if not _matches_filter(row.get("analysis_method"), filters.get("analysis_methods")):
			continue
		if not _matches_filter(row.get("scoring_version"), filters.get("scoring_versions")):
			continue
		if not _matches_filter(row.get("watchlist_version"), filters.get("watchlist_versions")):
			continue
		if not _matches_hard_flag_filter(row.get("hard_flags"), filters.get("hard_flag_status")):
			continue
		result.append(row)
	return result


def _review_rows_for_cases(db_path: str, case_ids: set) -> list:
	if not case_ids:
		return []
	placeholders = ", ".join("?" for _ in case_ids)
	query = f"""
		SELECT
			r.review_id, r.analysis_id, r.reviewer, r.analyst_intent, r.disposition,
			r.confidence, r.notes, r.resulting_case_status, r.created_at AS review_created_at,
			a.case_id, a.automated_intent, a.hard_flags_json, a.watchlist_version,
			a.scoring_version, a.priority_policy_version, c.created_at AS case_created_at,
			c.source, c.status
		FROM reviews r
		JOIN analyses a ON a.analysis_id = r.analysis_id
		JOIN cases c ON c.case_id = a.case_id
		WHERE a.case_id IN ({placeholders})
		ORDER BY r.created_at DESC, r.review_id DESC
	"""
	with storage.connect(db_path) as conn:
		rows = []
		for row in conn.execute(query, tuple(case_ids)).fetchall():
			data = dict(row)
			data["hard_flags"] = _json_loads(data.pop("hard_flags_json", None), [])
			data["agreement"] = "Agreement" if data["analyst_intent"] == data["automated_intent"] else "Override"
			rows.append(data)
		return rows


def _median(values: list):
	if not values:
		return UNAVAILABLE
	values = sorted(values)
	mid = len(values) // 2
	if len(values) % 2:
		return values[mid]
	return (values[mid - 1] + values[mid]) / 2


def _percent(numerator: int, denominator: int):
	if denominator == 0:
		return UNAVAILABLE
	return numerator / denominator


def hard_flag_group(flags: list) -> str:
	types = {flag.get("flag_type") for flag in flags or []}
	if types & {"official_schedule_match", "approved_alias_match"}:
		return "Confirmed official or alias"
	if "possible_family_or_analog_reference" in types:
		return "Possible family or analog"
	return "No hard flag"


def aging_bucket(created_at: str, now: datetime = None) -> str:
	now = now or now_utc()
	created = parse_utc(created_at)
	if created is None:
		return "Unknown"
	age_seconds = max(0, (now - created).total_seconds())
	if age_seconds < 24 * 3600:
		return "Less than 24 hours"
	if age_seconds <= 3 * 24 * 3600:
		return "1-3 days"
	if age_seconds <= 7 * 24 * 3600:
		return "4-7 days"
	return "More than 7 days"


def _count_by(rows: list, key: str, ordered=None) -> list:
	counts = Counter(row.get(key) or "Unknown" for row in rows)
	keys = ordered or sorted(counts)
	return [{"label": key_value, "count": counts.get(key_value, 0)} for key_value in keys if counts.get(key_value, 0) or ordered]


def _time_bucket(created_at: str, group: str) -> str:
	dt = parse_utc(created_at)
	if dt is None:
		return "Unknown"
	if group == "weekly":
		start = dt.date()
		start = start.fromordinal(start.toordinal() - start.weekday())
		return start.isoformat()
	return dt.date().isoformat()


def _volume_over_time(rows: list, time_key: str) -> list:
	if not rows:
		return []
	dates = [parse_utc(row.get(time_key)) for row in rows if parse_utc(row.get(time_key))]
	if not dates:
		return []
	span_days = (max(dates) - min(dates)).days
	group = "weekly" if span_days > 45 else "daily"
	counts = Counter(_time_bucket(row.get(time_key), group) for row in rows)
	return [{"period": period, "count": counts[period], "grouping": group} for period in sorted(counts)]


def build_dashboard(db_path: str, filters: dict = None, now: datetime = None) -> dict:
	now = now or now_utc()
	all_case_rows = _latest_case_rows(db_path)
	cases = apply_case_filters(all_case_rows, filters)
	case_ids = {row["case_id"] for row in cases}
	reviews = _review_rows_for_cases(db_path, case_ids)
	open_cases = [row for row in cases if row["status"] in ("new", "in_review")]
	reviewed_case_ids = {row["case_id"] for row in reviews}
	override_count = sum(1 for row in reviews if row["agreement"] == "Override")
	escalate_review_count = sum(1 for row in reviews if row["disposition"] == "escalate")
	first_review_seconds = []
	for case_id in reviewed_case_ids:
		case_reviews = [row for row in reviews if row["case_id"] == case_id]
		first_review = min(parse_utc(row["review_created_at"]) for row in case_reviews)
		case_created = parse_utc(case_reviews[0]["case_created_at"])
		if first_review and case_created:
			first_review_seconds.append((first_review - case_created).total_seconds())
	indicator_counts = Counter()
	for row in cases:
		for indicator in set(row.get("normalized_indicators") or []):
			indicator_counts[indicator] += 1
	hard_flag_outcomes = defaultdict(Counter)
	for row in reviews:
		hard_flag_outcomes[hard_flag_group(row.get("hard_flags"))][row["disposition"]] += 1
	return {
		"cases": cases,
		"reviews": reviews,
		"top_metrics": {
			"total_cases": len(cases),
			"open_cases": len(open_cases),
			"escalate_backlog": sum(1 for row in open_cases if row["operational_priority"] == "Escalate"),
			"hard_flagged_open_cases": sum(1 for row in open_cases if row.get("hard_flags")),
			"reviewed_cases": len(reviewed_case_ids),
			"review_level_override_rate": _percent(override_count, len(reviews)),
			"median_time_to_first_review_seconds": _median(first_review_seconds),
			"escalation_disposition_rate": _percent(escalate_review_count, len(reviews)),
		},
		"visualizations": {
			"open_backlog_by_priority": _count_by(open_cases, "operational_priority", ["Escalate", "Review", "Low"]),
			"cases_by_status": _count_by(cases, "status", ["new", "in_review", "closed"]),
			"automated_intent_distribution": _count_by(cases, "automated_intent", ["benign", "dual_use", "suspicious", "malicious"]),
			"analyst_disposition_distribution": _count_by(reviews, "disposition", ["allow", "monitor", "escalate", "close"]),
			"agreement_vs_override": _count_by(reviews, "agreement", ["Agreement", "Override"]),
			"hard_flag_outcomes": [
				{"hard_flag_group": group, "disposition": disposition, "count": count}
				for group, dispositions in hard_flag_outcomes.items()
				for disposition, count in dispositions.items()
			],
			"cases_by_source": _count_by(cases, "source"),
			"top_indicators": [
				{"indicator": indicator, "count": count}
				for indicator, count in indicator_counts.most_common(10)
			],
			"case_volume_over_time": _volume_over_time(cases, "created_at"),
			"review_activity_over_time": _volume_over_time(
				[{**row, "created_at": row["review_created_at"]} for row in reviews],
				"created_at",
			),
			"aging_buckets": [
				{"bucket": bucket, "count": Counter(aging_bucket(row["created_at"], now) for row in open_cases).get(bucket, 0)}
				for bucket in AGING_BUCKETS
			],
		},
		"tables": {
			"oldest_unresolved_high_priority": oldest_unresolved_high_priority(cases, now),
			"recently_escalated_reviews": recently_escalated_reviews(reviews),
			"hard_flagged_awaiting_review": hard_flagged_awaiting_review(cases),
			"recent_analyst_overrides": recent_analyst_overrides(reviews),
		},
		"review_scope_note": f"Review-level metrics include {len(reviews)} stored review(s) attached to the {len(cases)} filtered case(s), compared against each reviewed analysis_id.",
	}


def age_label(created_at: str, now: datetime = None) -> str:
	now = now or now_utc()
	created = parse_utc(created_at)
	if not created:
		return "Unknown"
	days = int((now - created).total_seconds() // 86400)
	if days == 0:
		return "Less than 1 day"
	if days == 1:
		return "1 day"
	return f"{days} days"


def flag_indicator(flags: list) -> str:
	if not flags:
		return "No hard flag"
	return hard_flag_group(flags)


def notes_preview(notes: str, limit: int = 90) -> str:
	text = " ".join((notes or "").split())
	if len(text) <= limit:
		return text
	return text[: limit - 3].rsplit(" ", 1)[0] + "..."


def oldest_unresolved_high_priority(cases: list, now: datetime = None) -> list:
	now = now or now_utc()
	rows = [
		row for row in cases
		if row["status"] in ("new", "in_review") and row["operational_priority"] in ("Escalate", "Review")
	]
	rows.sort(key=lambda row: (PRIORITY_ORDER[row["operational_priority"]], parse_utc(row["created_at"]) or now))
	return [
		{
			"case_id": row["case_id"],
			"source": row.get("source"),
			"status": row["status"],
			"automated_intent": row["automated_intent"],
			"risk_score": row["numeric_risk_score"],
			"operational_priority": row["operational_priority"],
			"hard_flag": flag_indicator(row.get("hard_flags")),
			"age": age_label(row["created_at"], now),
			"review_count": row.get("review_count", 0),
		}
		for row in rows[:10]
	]


def recently_escalated_reviews(reviews: list) -> list:
	rows = [row for row in reviews if row["disposition"] == "escalate"]
	rows.sort(key=lambda row: (parse_utc(row["review_created_at"]) or datetime.min.replace(tzinfo=timezone.utc)), reverse=True)
	return [
		{
			"review_timestamp": row["review_created_at"],
			"case_id": row["case_id"],
			"reviewer": row.get("reviewer"),
			"automated_intent": row["automated_intent"],
			"analyst_intent": row["analyst_intent"],
			"agreement": row["agreement"],
			"confidence": row["confidence"],
			"hard_flag": flag_indicator(row.get("hard_flags")),
			"notes_preview": notes_preview(row.get("notes")),
		}
		for row in rows[:10]
	]


def hard_flagged_awaiting_review(cases: list) -> list:
	rows = [
		row for row in cases
		if row["status"] in ("new", "in_review") and row.get("hard_flags")
	]
	return [
		{
			"case_id": row["case_id"],
			"source": row.get("source"),
			"status": row["status"],
			"operational_priority": row["operational_priority"],
			"hard_flag_type": flag_indicator(row.get("hard_flags")),
			"watchlist_version": row.get("watchlist_version"),
			"review_count": row.get("review_count", 0),
		}
		for row in rows[:10]
	]


def recent_analyst_overrides(reviews: list) -> list:
	rows = [row for row in reviews if row["agreement"] == "Override"]
	rows.sort(key=lambda row: (parse_utc(row["review_created_at"]) or datetime.min.replace(tzinfo=timezone.utc)), reverse=True)
	return [
		{
			"review_timestamp": row["review_created_at"],
			"case_id": row["case_id"],
			"reviewer": row.get("reviewer"),
			"automated_intent": row["automated_intent"],
			"analyst_intent": row["analyst_intent"],
			"confidence": row["confidence"],
			"notes_preview": notes_preview(row.get("notes")),
		}
		for row in rows[:10]
	]


def validate_demo_dataset(data: dict) -> None:
	if not isinstance(data, dict) or data.get("dataset") != "synthetic_operations_dashboard_demo":
		raise ValueError("invalid operations demo dataset")
	cases = data.get("cases")
	if not isinstance(cases, list) or not 20 <= len(cases) <= 30:
		raise ValueError("demo dataset must contain 20 to 30 cases")
	ids = set()
	for case in cases:
		for field in ("external_id", "text", "source", "created_at", "status", "synthetic"):
			if field not in case:
				raise ValueError(f"demo case missing {field}")
		if case["external_id"] in ids:
			raise ValueError(f"duplicate demo external_id {case['external_id']}")
		ids.add(case["external_id"])
		if case["synthetic"] is not True:
			raise ValueError("demo case must be synthetic")
		for review in case.get("reviews", []):
			for field in ("review_id", "reviewer", "analyst_intent", "disposition", "confidence", "notes", "resulting_case_status", "created_at"):
				if field not in review:
					raise ValueError(f"demo review missing {field}")


def load_demo_dataset(path=DEMO_DATA_PATH) -> dict:
	with open(path, encoding="utf-8") as handle:
		data = json.load(handle)
	validate_demo_dataset(data)
	return data


def _set_case_status_and_times(db_path: str, case_id: int, status: str, created_at: str, updated_at: str = None) -> None:
	with storage.connect(db_path) as conn:
		conn.execute(
			"UPDATE cases SET status = ?, created_at = ?, updated_at = ? WHERE case_id = ?",
			(status, created_at, updated_at or created_at, case_id),
		)


def _set_analysis_time(db_path: str, analysis_id: int, created_at: str) -> None:
	with storage.connect(db_path) as conn:
		conn.execute("UPDATE analyses SET created_at = ? WHERE analysis_id = ?", (created_at, analysis_id))


def _seeded_review_exists(db_path: str, analysis_id: int, seed_id: str) -> bool:
	token = f"[seed:{seed_id}]"
	with storage.connect(db_path) as conn:
		row = conn.execute(
			"SELECT review_id FROM reviews WHERE analysis_id = ? AND notes LIKE ? LIMIT 1",
			(analysis_id, token + "%"),
		).fetchone()
		return row is not None


def _set_review_time(db_path: str, review_id: int, created_at: str) -> None:
	with storage.connect(db_path) as conn:
		conn.execute("UPDATE reviews SET created_at = ? WHERE review_id = ?", (created_at, review_id))


def import_operations_demo_data(db_path: str, dataset_path=DEMO_DATA_PATH) -> dict:
	storage.initialize_database(db_path)
	before = storage.summarize_records(db_path)
	data = load_demo_dataset(dataset_path)
	inserted_reviews = 0
	for case in data["cases"]:
		case_id = storage.create_or_get_case(
			db_path,
			case["text"],
			source=case["source"],
			external_id=case["external_id"],
			synthetic=True,
			status=case["status"],
		)
		analysis = main.analyze_report({"text": case["text"], "source": case["source"], "report_id": case["external_id"]}, rule_only=True)
		analysis_id = storage.save_automated_analysis(db_path, case_id, analysis, analysis_method="rules")
		_set_case_status_and_times(db_path, case_id, case["status"], case["created_at"], case.get("updated_at"))
		_set_analysis_time(db_path, analysis_id, case.get("analysis_created_at", case["created_at"]))
		for review in case.get("reviews", []):
			if _seeded_review_exists(db_path, analysis_id, review["review_id"]):
				continue
			review_id = storage.save_analyst_review(
				db_path,
				analysis_id,
				reviewer=review["reviewer"],
				analyst_intent=review["analyst_intent"],
				disposition=review["disposition"],
				confidence=int(review["confidence"]),
				notes=f"[seed:{review['review_id']}] {review['notes']}",
				resulting_case_status=review["resulting_case_status"],
			)
			_set_review_time(db_path, review_id, review["created_at"])
			_set_case_status_and_times(
				db_path,
				case_id,
				review["resulting_case_status"],
				case["created_at"],
				review["created_at"],
			)
			inserted_reviews += 1
		_set_case_status_and_times(db_path, case_id, case["status"], case["created_at"], case.get("updated_at"))
	after = storage.summarize_records(db_path)
	return {
		"before": before,
		"after": after,
		"dataset_cases": len(data["cases"]),
		"inserted_reviews": inserted_reviews,
	}
