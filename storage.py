import hashlib
import json
import sqlite3
from datetime import datetime, timezone

import watchlist

CASE_STATUSES = ("new", "in_review", "closed")
ANALYSIS_METHODS = ("rules", "llm_assisted")
ANALYST_INTENTS = ("benign", "dual_use", "suspicious", "malicious")
DISPOSITIONS = ("allow", "monitor", "escalate", "close")
PRIORITIES = ("Low", "Review", "Escalate")
LEGACY_SCORING_VERSION = "legacy-or-unknown"
LEGACY_PRIORITY_POLICY_VERSION = "legacy-or-unknown"
SCHEMA_VERSION = 4


class ClosingConnection(sqlite3.Connection):
	def __exit__(self, exc_type, exc_value, traceback):
		try:
			return super().__exit__(exc_type, exc_value, traceback)
		finally:
			self.close()


def utc_now() -> str:
	return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def connect(db_path: str) -> sqlite3.Connection:
	conn = sqlite3.connect(db_path, uri=str(db_path).startswith("file:"), factory=ClosingConnection)
	conn.row_factory = sqlite3.Row
	conn.execute("PRAGMA foreign_keys = ON")
	return conn


def _normalize_text(value) -> str:
	return " ".join(str(value or "").strip().split())


def _hash_payload(*parts) -> str:
	payload = "\x1f".join(_normalize_text(part) for part in parts)
	return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def make_case_key(report_text: str, source: str = None, external_id: str = None) -> str:
	if external_id is not None and str(external_id).strip():
		return "external:" + _hash_payload(source or "", external_id)
	return "derived:" + _hash_payload(source or "", report_text)


def _json_dumps(value) -> str:
	return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _json_loads(value, default):
	if value in (None, ""):
		return default
	try:
		return json.loads(value)
	except (TypeError, json.JSONDecodeError):
		return default


def _validate_allowed(name: str, value: str, allowed) -> str:
	if value not in allowed:
		raise ValueError(f"{name} must be one of: {', '.join(allowed)}")
	return value


def _score_band(score: int) -> str:
	if score <= 2:
		return "Low"
	if score <= 5:
		return "Review"
	return "Escalate"


def _priority_rank(priority: str) -> int:
	return {"Low": 0, "Review": 1, "Escalate": 2}[priority]


def _legacy_priority(intent: str, score: int) -> str:
	score_band = _score_band(score)
	intent_floor = {
		"benign": "Low",
		"dual_use": "Review",
		"suspicious": "Review",
		"malicious": "Escalate",
	}.get((intent or "benign").lower(), "Low")
	return intent_floor if _priority_rank(intent_floor) > _priority_rank(score_band) else score_band


def _row_to_dict(row):
	if row is None:
		return None
	return dict(row)


def _analysis_from_row(row):
	data = _row_to_dict(row)
	if data is None:
		return None
	data["normalized_indicators"] = _json_loads(data.get("normalized_indicators_json"), [])
	data["score_details"] = _json_loads(data.get("score_details_json"), {})
	data["hard_flags"] = _json_loads(data.get("hard_flags_json"), [])
	data["watchlist_version"] = data.get("watchlist_version") or watchlist.NO_WATCHLIST_VERSION
	data["watchlist_policy_version"] = data.get("watchlist_policy_version") or watchlist.LEGACY_WATCHLIST_POLICY_VERSION
	data.pop("normalized_indicators_json", None)
	data.pop("score_details_json", None)
	data.pop("hard_flags_json", None)
	return data


def _review_from_row(row):
	return _row_to_dict(row)


def initialize_database(db_path: str) -> None:
	with connect(db_path) as conn:
		_create_schema(conn)
		_record_migration(conn, 1, "Create cases, analyses, reviews, and schema_migrations")
		_migrate_schema(conn)
		_migrate_legacy_reports_if_present(conn)


def _create_schema(conn: sqlite3.Connection) -> None:
	conn.executescript(
		"""
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			description TEXT NOT NULL,
			applied_at TEXT NOT NULL
		);

		CREATE TABLE IF NOT EXISTS cases (
			case_id INTEGER PRIMARY KEY,
			case_key TEXT NOT NULL UNIQUE,
			report_text TEXT NOT NULL,
			source TEXT,
			synthetic INTEGER NOT NULL DEFAULT 1 CHECK (synthetic IN (0, 1)),
			status TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'in_review', 'closed')),
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);

		CREATE TABLE IF NOT EXISTS analyses (
			analysis_id INTEGER PRIMARY KEY,
			case_id INTEGER NOT NULL,
			analysis_key TEXT NOT NULL UNIQUE,
			automated_intent TEXT NOT NULL,
			normalized_indicators_json TEXT NOT NULL,
			summary TEXT,
			numeric_risk_score INTEGER NOT NULL,
			score_band TEXT NOT NULL CHECK (score_band IN ('Low', 'Review', 'Escalate')),
			operational_priority TEXT NOT NULL CHECK (operational_priority IN ('Low', 'Review', 'Escalate')),
			score_details_json TEXT NOT NULL,
			analysis_method TEXT NOT NULL CHECK (analysis_method IN ('rules', 'llm_assisted')),
			scoring_version TEXT NOT NULL,
			priority_policy_version TEXT NOT NULL,
			hard_flags_json TEXT NOT NULL DEFAULT '[]',
			watchlist_version TEXT NOT NULL DEFAULT 'no_watchlist_applied',
			watchlist_policy_version TEXT NOT NULL DEFAULT 'legacy_or_unknown',
			model_name TEXT,
			created_at TEXT NOT NULL,
			FOREIGN KEY (case_id) REFERENCES cases(case_id)
		);

		CREATE TABLE IF NOT EXISTS reviews (
			review_id INTEGER PRIMARY KEY,
			analysis_id INTEGER NOT NULL,
			reviewer TEXT,
			analyst_intent TEXT NOT NULL CHECK (analyst_intent IN ('benign', 'dual_use', 'suspicious', 'malicious')),
			disposition TEXT NOT NULL CHECK (disposition IN ('allow', 'monitor', 'escalate', 'close')),
			confidence INTEGER NOT NULL CHECK (confidence BETWEEN 1 AND 5),
			notes TEXT,
			resulting_case_status TEXT NOT NULL CHECK (resulting_case_status IN ('new', 'in_review', 'closed')),
			created_at TEXT NOT NULL,
			FOREIGN KEY (analysis_id) REFERENCES analyses(analysis_id)
		);

		CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
		CREATE INDEX IF NOT EXISTS idx_cases_created ON cases(created_at);
		CREATE INDEX IF NOT EXISTS idx_analyses_case_created ON analyses(case_id, created_at DESC);
		CREATE INDEX IF NOT EXISTS idx_analyses_priority ON analyses(operational_priority);
		CREATE INDEX IF NOT EXISTS idx_reviews_analysis_created ON reviews(analysis_id, created_at DESC);
		CREATE INDEX IF NOT EXISTS idx_reviews_created ON reviews(created_at);

		CREATE TABLE IF NOT EXISTS evaluation_runs (
			run_id INTEGER PRIMARY KEY,
			suite_id TEXT NOT NULL,
			suite_version TEXT NOT NULL,
			evaluation_set_hash TEXT NOT NULL,
			analysis_method TEXT NOT NULL CHECK (analysis_method IN ('rules', 'llm_assisted')),
			scoring_version TEXT,
			priority_policy_version TEXT,
			watchlist_version TEXT,
			watchlist_policy_version TEXT,
			model_name TEXT,
			case_count INTEGER NOT NULL DEFAULT 0,
			approved_case_count INTEGER NOT NULL DEFAULT 0,
			provisional_case_count INTEGER NOT NULL DEFAULT 0,
			started_at TEXT NOT NULL,
			completed_at TEXT,
			summary_metrics_json TEXT NOT NULL DEFAULT '{}',
			run_status TEXT NOT NULL CHECK (run_status IN ('running', 'completed', 'failed')),
			error_message TEXT
		);

		CREATE TABLE IF NOT EXISTS evaluation_results (
			result_id INTEGER PRIMARY KEY,
			run_id INTEGER NOT NULL,
			case_id TEXT NOT NULL,
			expected_intent_original TEXT NOT NULL,
			expected_intent_canonical TEXT,
			predicted_intent TEXT,
			expected_minimum_priority TEXT NOT NULL,
			predicted_priority TEXT,
			expected_hard_flag_category TEXT NOT NULL,
			predicted_hard_flag_category TEXT,
			numeric_risk_score INTEGER,
			score_band TEXT,
			normalized_indicators_json TEXT NOT NULL DEFAULT '[]',
			hard_flags_json TEXT NOT NULL DEFAULT '[]',
			label_status TEXT NOT NULL,
			scenario_tags_json TEXT NOT NULL DEFAULT '[]',
			intent_match INTEGER NOT NULL DEFAULT 0,
			priority_pass INTEGER NOT NULL DEFAULT 0,
			hard_flag_match INTEGER NOT NULL DEFAULT 0,
			critical_miss INTEGER NOT NULL DEFAULT 0,
			over_triage INTEGER NOT NULL DEFAULT 0,
			analysis_snapshot_json TEXT NOT NULL DEFAULT '{}',
			created_at TEXT NOT NULL,
			FOREIGN KEY (run_id) REFERENCES evaluation_runs(run_id)
		);

		CREATE INDEX IF NOT EXISTS idx_eval_runs_suite ON evaluation_runs(suite_id, suite_version, evaluation_set_hash);
		CREATE INDEX IF NOT EXISTS idx_eval_results_run ON evaluation_results(run_id);
		CREATE INDEX IF NOT EXISTS idx_eval_results_case ON evaluation_results(case_id);
		"""
	)


def _table_columns(conn: sqlite3.Connection, table_name: str) -> set:
	return {row["name"] for row in conn.execute(f"PRAGMA table_info({table_name})").fetchall()}


def _migrate_schema(conn: sqlite3.Connection) -> None:
	columns = _table_columns(conn, "analyses")
	if "hard_flags_json" not in columns:
		conn.execute("ALTER TABLE analyses ADD COLUMN hard_flags_json TEXT NOT NULL DEFAULT '[]'")
	if "watchlist_version" not in columns:
		conn.execute("ALTER TABLE analyses ADD COLUMN watchlist_version TEXT NOT NULL DEFAULT 'no_watchlist_applied'")
	if "watchlist_policy_version" not in columns:
		conn.execute("ALTER TABLE analyses ADD COLUMN watchlist_policy_version TEXT NOT NULL DEFAULT 'legacy_or_unknown'")
	conn.execute("CREATE INDEX IF NOT EXISTS idx_cases_created ON cases(created_at)")
	conn.execute("CREATE INDEX IF NOT EXISTS idx_analyses_priority ON analyses(operational_priority)")
	conn.execute("CREATE INDEX IF NOT EXISTS idx_analyses_method_version ON analyses(analysis_method, scoring_version, watchlist_version)")
	conn.execute("CREATE INDEX IF NOT EXISTS idx_reviews_created ON reviews(created_at)")
	_record_migration(conn, 2, "Add hard-watchlist snapshot fields to analyses")
	_record_migration(conn, 3, "Add dashboard query indexes")
	_record_migration(conn, 4, "Add evaluation run and result tables")


def _record_migration(conn: sqlite3.Connection, version: int, description: str) -> None:
	conn.execute(
		"""
		INSERT OR IGNORE INTO schema_migrations (version, description, applied_at)
		VALUES (?, ?, ?)
		""",
		(version, description, utc_now()),
	)


def create_or_get_case(
	db_path: str,
	report_text: str,
	source: str = None,
	external_id: str = None,
	synthetic: bool = True,
	status: str = "new",
) -> int:
	_validate_allowed("status", status, CASE_STATUSES)
	case_key = make_case_key(report_text, source=source, external_id=external_id)
	now = utc_now()
	with connect(db_path) as conn:
		conn.execute(
			"""
			INSERT INTO cases (case_key, report_text, source, synthetic, status, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(case_key) DO UPDATE SET
				updated_at = cases.updated_at
			""",
			(case_key, report_text or "", source, 1 if synthetic else 0, status, now, now),
		)
		row = conn.execute("SELECT case_id FROM cases WHERE case_key = ?", (case_key,)).fetchone()
		return int(row["case_id"])


def _analysis_key(
	case_id: int,
	analysis_method: str,
	scoring_version: str,
	priority_policy_version: str,
	watchlist_version: str = watchlist.NO_WATCHLIST_VERSION,
	watchlist_policy_version: str = watchlist.LEGACY_WATCHLIST_POLICY_VERSION,
	result_fingerprint: str = None,
) -> str:
	if analysis_method == "rules":
		return "rules:" + _hash_payload(
			case_id,
			scoring_version,
			priority_policy_version,
			watchlist_version,
			watchlist_policy_version,
			analysis_method,
		)
	return "llm:" + _hash_payload(
		case_id,
		scoring_version,
		priority_policy_version,
		watchlist_version,
		watchlist_policy_version,
		analysis_method,
		result_fingerprint or "",
	)


def _analysis_result_fingerprint(
	automated_intent: str,
	normalized_indicators,
	summary: str,
	numeric_risk_score: int,
	score_details,
	model_name: str = None,
) -> str:
	return _hash_payload(
		automated_intent,
		_json_dumps(normalized_indicators or []),
		summary or "",
		numeric_risk_score,
		_json_dumps(score_details or {}),
		model_name or "",
	)


def save_automated_analysis(
	db_path: str,
	case_id: int,
	analysis: dict,
	analysis_method: str = "rules",
	model_name: str = None,
) -> int:
	_validate_allowed("analysis_method", analysis_method, ANALYSIS_METHODS)
	_validate_allowed("automated_intent", analysis.get("intent"), ANALYST_INTENTS)
	indicators = analysis.get("normalized_indicators") or analysis.get("indicators") or []
	score_details = analysis.get("score_details") or {}
	numeric_risk_score = analysis.get("numeric_risk_score", analysis.get("risk_score", score_details.get("total_score")))
	if numeric_risk_score is None:
		raise ValueError("analysis must include a numeric risk score or score_details.total_score")
	score_band = analysis.get("score_band", score_details.get("score_band"))
	operational_priority = analysis.get("operational_priority", score_details.get("operational_priority"))
	if score_band is None or operational_priority is None:
		raise ValueError("analysis must include score band and operational priority")
	_validate_allowed("score_band", score_band, PRIORITIES)
	_validate_allowed("operational_priority", operational_priority, PRIORITIES)
	scoring_version = analysis.get("scoring_version") or score_details.get("scoring_version")
	priority_policy_version = analysis.get("priority_policy_version") or score_details.get("priority_policy_version")
	if not scoring_version or not priority_policy_version:
		raise ValueError("analysis must include scoring and priority-policy versions")
	hard_flags = analysis.get("hard_flags") or []
	watchlist_version = analysis.get("watchlist_version") or score_details.get("watchlist_version") or watchlist.NO_WATCHLIST_VERSION
	watchlist_policy_version = (
		analysis.get("watchlist_policy_version")
		or score_details.get("watchlist_policy_version")
		or watchlist.LEGACY_WATCHLIST_POLICY_VERSION
	)
	result_fingerprint = None
	if analysis_method == "llm_assisted":
		result_fingerprint = _analysis_result_fingerprint(
			analysis.get("intent"),
			indicators,
			analysis.get("summary"),
			numeric_risk_score,
			{"score_details": score_details, "hard_flags": hard_flags},
			model_name,
		)
	analysis_key = _analysis_key(
		case_id,
		analysis_method,
		scoring_version,
		priority_policy_version,
		watchlist_version,
		watchlist_policy_version,
		result_fingerprint,
	)
	now = utc_now()
	with connect(db_path) as conn:
		conn.execute(
			"""
			INSERT OR IGNORE INTO analyses (
				case_id, analysis_key, automated_intent, normalized_indicators_json,
				summary, numeric_risk_score, score_band, operational_priority,
				score_details_json, analysis_method, scoring_version,
				priority_policy_version, hard_flags_json, watchlist_version,
				watchlist_policy_version, model_name, created_at
			)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			""",
			(
				case_id,
				analysis_key,
				analysis.get("intent"),
				_json_dumps(indicators),
				analysis.get("summary"),
				int(numeric_risk_score),
				score_band,
				operational_priority,
				_json_dumps(score_details),
				analysis_method,
				scoring_version,
				priority_policy_version,
				_json_dumps(hard_flags),
				watchlist_version,
				watchlist_policy_version,
				model_name,
				now,
			),
		)
		row = conn.execute("SELECT analysis_id FROM analyses WHERE analysis_key = ?", (analysis_key,)).fetchone()
		return int(row["analysis_id"])


def get_analysis_by_id(db_path: str, analysis_id: int) -> dict:
	with connect(db_path) as conn:
		row = conn.execute("SELECT * FROM analyses WHERE analysis_id = ?", (analysis_id,)).fetchone()
		return _analysis_from_row(row)


def get_latest_analysis_for_case(db_path: str, case_id: int) -> dict:
	with connect(db_path) as conn:
		row = conn.execute(
			"""
			SELECT * FROM analyses
			WHERE case_id = ?
			ORDER BY created_at DESC, analysis_id DESC
			LIMIT 1
			""",
			(case_id,),
		).fetchone()
		return _analysis_from_row(row)


def get_case_with_history(db_path: str, case_id: int) -> dict:
	with connect(db_path) as conn:
		case = _row_to_dict(conn.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone())
		if case is None:
			return None
		analysis_rows = conn.execute(
			"SELECT * FROM analyses WHERE case_id = ? ORDER BY created_at DESC, analysis_id DESC",
			(case_id,),
		).fetchall()
		analyses = []
		for row in analysis_rows:
			analysis = _analysis_from_row(row)
			review_rows = conn.execute(
				"SELECT * FROM reviews WHERE analysis_id = ? ORDER BY created_at ASC, review_id ASC",
				(analysis["analysis_id"],),
			).fetchall()
			analysis["reviews"] = [_review_from_row(review) for review in review_rows]
			analyses.append(analysis)
		case["analyses"] = analyses
		return case


def save_analyst_review(
	db_path: str,
	analysis_id: int,
	reviewer: str,
	analyst_intent: str,
	disposition: str,
	confidence: int,
	notes: str = None,
	resulting_case_status: str = "in_review",
) -> int:
	_validate_allowed("analyst_intent", analyst_intent, ANALYST_INTENTS)
	_validate_allowed("disposition", disposition, DISPOSITIONS)
	_validate_allowed("resulting_case_status", resulting_case_status, CASE_STATUSES)
	if not isinstance(confidence, int) or not 1 <= confidence <= 5:
		raise ValueError("confidence must be an integer from 1 through 5")
	now = utc_now()
	with connect(db_path) as conn:
		try:
			conn.execute("BEGIN")
			row = conn.execute("SELECT case_id FROM analyses WHERE analysis_id = ?", (analysis_id,)).fetchone()
			if row is None:
				raise ValueError("analysis_id does not exist")
			conn.execute(
				"""
				INSERT INTO reviews (
					analysis_id, reviewer, analyst_intent, disposition,
					confidence, notes, resulting_case_status, created_at
				)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)
				""",
				(analysis_id, reviewer, analyst_intent, disposition, confidence, notes, resulting_case_status, now),
			)
			review_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
			conn.execute(
				"UPDATE cases SET status = ?, updated_at = ? WHERE case_id = ?",
				(resulting_case_status, now, row["case_id"]),
			)
			conn.commit()
			return int(review_id)
		except Exception:
			conn.rollback()
			raise


def get_cases_for_review_queue(
	db_path: str,
	status=None,
	operational_priority: str = None,
	automated_intent: str = None,
	source: str = None,
	minimum_risk_score: int = None,
	hard_flag_filter: str = None,
):
	params = []
	where = ["latest.analysis_id IS NOT NULL"]
	if status is not None:
		statuses = [status] if isinstance(status, str) else list(status)
		for item in statuses:
			_validate_allowed("status", item, CASE_STATUSES)
		placeholders = ", ".join("?" for _ in statuses)
		where.append(f"c.status IN ({placeholders})")
		params.extend(statuses)
	if operational_priority is not None:
		_validate_allowed("operational_priority", operational_priority, PRIORITIES)
		where.append("latest.operational_priority = ?")
		params.append(operational_priority)
	if automated_intent is not None:
		_validate_allowed("automated_intent", automated_intent, ANALYST_INTENTS)
		where.append("latest.automated_intent = ?")
		params.append(automated_intent)
	if source is not None:
		where.append("c.source = ?")
		params.append(source)
	if minimum_risk_score is not None:
		where.append("latest.numeric_risk_score >= ?")
		params.append(int(minimum_risk_score))
	if hard_flag_filter is not None:
		if hard_flag_filter == "any":
			where.append("latest.hard_flags_json != '[]'")
		elif hard_flag_filter == "none":
			where.append("latest.hard_flags_json = '[]'")
		elif hard_flag_filter == "confirmed":
			where.append("(latest.hard_flags_json LIKE ? OR latest.hard_flags_json LIKE ?)")
			params.extend(["%official_schedule_match%", "%approved_alias_match%"])
		elif hard_flag_filter == "possible":
			where.append("latest.hard_flags_json LIKE ?")
			params.append("%possible_family_or_analog_reference%")
		else:
			raise ValueError("hard_flag_filter must be one of: any, none, confirmed, possible")
	query = f"""
		SELECT
			c.case_id, c.case_key, c.report_text, c.source, c.synthetic, c.status,
			c.created_at, c.updated_at, latest.analysis_id, latest.automated_intent,
			latest.numeric_risk_score, latest.score_band, latest.operational_priority,
			latest.hard_flags_json, latest.watchlist_version, latest.watchlist_policy_version,
			latest.created_at AS analysis_created_at,
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
			) newest ON newest.analysis_id = a.analysis_id
		) latest ON latest.case_id = c.case_id
		WHERE {" AND ".join(where)}
		ORDER BY
			CASE latest.operational_priority
				WHEN 'Escalate' THEN 0
				WHEN 'Review' THEN 1
				ELSE 2
			END,
			latest.numeric_risk_score DESC,
			CASE
				WHEN (latest.hard_flags_json LIKE '%official_schedule_match%' OR latest.hard_flags_json LIKE '%approved_alias_match%')
					AND latest.hard_flags_json NOT LIKE '%possible_family_or_analog_reference%' THEN 0
				WHEN latest.hard_flags_json LIKE '%official_schedule_match%' OR latest.hard_flags_json LIKE '%approved_alias_match%' THEN 1
				WHEN latest.hard_flags_json LIKE '%possible_family_or_analog_reference%' THEN 2
				ELSE 3
			END,
			CASE WHEN c.status = 'closed' THEN 1 ELSE 0 END,
			c.created_at ASC,
			c.case_id ASC
	"""
	with connect(db_path) as conn:
		rows = []
		for row in conn.execute(query, params).fetchall():
			data = _row_to_dict(row)
			data["hard_flags"] = _json_loads(data.get("hard_flags_json"), [])
			data.pop("hard_flags_json", None)
			rows.append(data)
		return rows


def get_case_sources(db_path: str) -> list:
	with connect(db_path) as conn:
		rows = conn.execute(
			"SELECT DISTINCT source FROM cases WHERE source IS NOT NULL AND source != '' ORDER BY source"
		).fetchall()
		return [row["source"] for row in rows]


def summarize_records(db_path: str) -> dict:
	with connect(db_path) as conn:
		return {
			"cases": conn.execute("SELECT COUNT(*) AS count FROM cases").fetchone()["count"],
			"analyses": conn.execute("SELECT COUNT(*) AS count FROM analyses").fetchone()["count"],
			"reviews": conn.execute("SELECT COUNT(*) AS count FROM reviews").fetchone()["count"],
		}


def create_evaluation_run(
	db_path: str,
	suite_id: str,
	suite_version: str,
	evaluation_set_hash: str,
	analysis_method: str,
	scoring_version: str = None,
	priority_policy_version: str = None,
	watchlist_version: str = None,
	watchlist_policy_version: str = None,
	model_name: str = None,
	case_count: int = 0,
	approved_case_count: int = 0,
	provisional_case_count: int = 0,
) -> int:
	_validate_allowed("analysis_method", analysis_method, ANALYSIS_METHODS)
	with connect(db_path) as conn:
		conn.execute(
			"""
			INSERT INTO evaluation_runs (
				suite_id, suite_version, evaluation_set_hash, analysis_method,
				scoring_version, priority_policy_version, watchlist_version,
				watchlist_policy_version, model_name, case_count,
				approved_case_count, provisional_case_count, started_at,
				summary_metrics_json, run_status
			)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			""",
			(
				suite_id,
				suite_version,
				evaluation_set_hash,
				analysis_method,
				scoring_version,
				priority_policy_version,
				watchlist_version,
				watchlist_policy_version,
				model_name,
				int(case_count),
				int(approved_case_count),
				int(provisional_case_count),
				utc_now(),
				_json_dumps({}),
				"running",
			),
		)
		return int(conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"])


def save_evaluation_result(db_path: str, run_id: int, result: dict) -> int:
	with connect(db_path) as conn:
		conn.execute(
			"""
			INSERT INTO evaluation_results (
				run_id, case_id, expected_intent_original,
				expected_intent_canonical, predicted_intent,
				expected_minimum_priority, predicted_priority,
				expected_hard_flag_category, predicted_hard_flag_category,
				numeric_risk_score, score_band, normalized_indicators_json,
				hard_flags_json, label_status, scenario_tags_json,
				intent_match, priority_pass, hard_flag_match,
				critical_miss, over_triage, analysis_snapshot_json, created_at
			)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			""",
			(
				run_id,
				result["case_id"],
				result["expected_intent_original"],
				result.get("expected_intent_canonical"),
				result.get("predicted_intent"),
				result["expected_minimum_priority"],
				result.get("predicted_priority"),
				result["expected_hard_flag_category"],
				result.get("predicted_hard_flag_category"),
				result.get("numeric_risk_score"),
				result.get("score_band"),
				_json_dumps(result.get("normalized_indicators") or []),
				_json_dumps(result.get("hard_flags") or []),
				result["label_status"],
				_json_dumps(result.get("scenario_tags") or []),
				1 if result.get("intent_match") else 0,
				1 if result.get("priority_pass") else 0,
				1 if result.get("hard_flag_match") else 0,
				1 if result.get("critical_miss") else 0,
				1 if result.get("over_triage") else 0,
				_json_dumps(result.get("analysis_snapshot") or {}),
				utc_now(),
			),
		)
		return int(conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"])


def complete_evaluation_run(db_path: str, run_id: int, summary_metrics: dict) -> None:
	with connect(db_path) as conn:
		conn.execute(
			"""
			UPDATE evaluation_runs
			SET completed_at = ?, summary_metrics_json = ?, run_status = 'completed', error_message = NULL
			WHERE run_id = ?
			""",
			(utc_now(), _json_dumps(summary_metrics or {}), run_id),
		)


def fail_evaluation_run(db_path: str, run_id: int, error_message: str) -> None:
	with connect(db_path) as conn:
		conn.execute(
			"""
			UPDATE evaluation_runs
			SET completed_at = ?, run_status = 'failed', error_message = ?
			WHERE run_id = ?
			""",
			(utc_now(), str(error_message), run_id),
		)


def list_evaluation_runs(db_path: str, suite_id: str = None, limit: int = 50) -> list:
	params = []
	where = ""
	if suite_id:
		where = "WHERE suite_id = ?"
		params.append(suite_id)
	params.append(int(limit))
	with connect(db_path) as conn:
		rows = conn.execute(
			f"""
			SELECT * FROM evaluation_runs
			{where}
			ORDER BY started_at DESC, run_id DESC
			LIMIT ?
			""",
			params,
		).fetchall()
		result = []
		for row in rows:
			data = dict(row)
			data["summary_metrics"] = _json_loads(data.pop("summary_metrics_json", None), {})
			result.append(data)
		return result


def get_evaluation_run(db_path: str, run_id: int) -> dict:
	with connect(db_path) as conn:
		row = conn.execute("SELECT * FROM evaluation_runs WHERE run_id = ?", (run_id,)).fetchone()
		if row is None:
			return None
		data = dict(row)
		data["summary_metrics"] = _json_loads(data.pop("summary_metrics_json", None), {})
		return data


def get_evaluation_results(db_path: str, run_id: int) -> list:
	with connect(db_path) as conn:
		rows = conn.execute(
			"SELECT * FROM evaluation_results WHERE run_id = ? ORDER BY case_id",
			(run_id,),
		).fetchall()
		results = []
		for row in rows:
			data = dict(row)
			data["normalized_indicators"] = _json_loads(data.pop("normalized_indicators_json", None), [])
			data["hard_flags"] = _json_loads(data.pop("hard_flags_json", None), [])
			data["scenario_tags"] = _json_loads(data.pop("scenario_tags_json", None), [])
			data["analysis_snapshot"] = _json_loads(data.pop("analysis_snapshot_json", None), {})
			for key in ("intent_match", "priority_pass", "hard_flag_match", "critical_miss", "over_triage"):
				data[key] = bool(data[key])
			results.append(data)
		return results


def legacy_reports_table_columns(conn: sqlite3.Connection):
	row = conn.execute(
		"SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'reports'"
	).fetchone()
	if row is None:
		return None
	return [item["name"] for item in conn.execute("PRAGMA table_info(reports)").fetchall()]


def is_legacy_reports_table(conn: sqlite3.Connection) -> bool:
	columns = legacy_reports_table_columns(conn)
	if columns is None:
		return False
	required = {"report_id", "text", "source", "intent", "indicators", "summary", "risk_score"}
	return required.issubset(set(columns))


def _migrate_legacy_reports_if_present(conn: sqlite3.Connection) -> None:
	if not is_legacy_reports_table(conn):
		return
	rows = conn.execute(
		"SELECT rowid, report_id, text, source, intent, indicators, summary, risk_score FROM reports"
	).fetchall()
	for row in rows:
		case_id = _create_or_get_case_conn(
			conn,
			report_text=row["text"] or "",
			source=row["source"],
			external_id=row["report_id"],
			synthetic=True,
			status="new",
		)
		indicators = _json_loads(row["indicators"], [])
		risk_score = int(row["risk_score"] or 0)
		score_band = _score_band(risk_score)
		priority = _legacy_priority(row["intent"], risk_score)
		score_details = {
			"total_score": risk_score,
			"score_band": score_band,
			"operational_priority": priority,
			"scoring_version": LEGACY_SCORING_VERSION,
			"priority_policy_version": LEGACY_PRIORITY_POLICY_VERSION,
			"watchlist_version": watchlist.NO_WATCHLIST_VERSION,
			"watchlist_policy_version": watchlist.LEGACY_WATCHLIST_POLICY_VERSION,
			"normalized_indicators": indicators,
			"contributions": [],
			"triggered_rules": [],
			"explanation": "Imported from legacy reports table; detailed contribution history was not available.",
		}
		analysis_key = "legacy:" + _hash_payload(row["rowid"], row["report_id"], row["text"], row["source"], row["risk_score"])
		conn.execute(
			"""
			INSERT OR IGNORE INTO analyses (
				case_id, analysis_key, automated_intent, normalized_indicators_json,
				summary, numeric_risk_score, score_band, operational_priority,
				score_details_json, analysis_method, scoring_version,
				priority_policy_version, hard_flags_json, watchlist_version,
				watchlist_policy_version, model_name, created_at
			)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			""",
			(
				case_id,
				analysis_key,
				row["intent"] or "benign",
				_json_dumps(indicators),
				row["summary"],
				risk_score,
				score_band,
				priority,
				_json_dumps(score_details),
				"rules",
				LEGACY_SCORING_VERSION,
				LEGACY_PRIORITY_POLICY_VERSION,
				_json_dumps([]),
				watchlist.NO_WATCHLIST_VERSION,
				watchlist.LEGACY_WATCHLIST_POLICY_VERSION,
				None,
				utc_now(),
			),
		)


def _create_or_get_case_conn(
	conn: sqlite3.Connection,
	report_text: str,
	source: str = None,
	external_id: str = None,
	synthetic: bool = True,
	status: str = "new",
) -> int:
	case_key = make_case_key(report_text, source=source, external_id=external_id)
	now = utc_now()
	conn.execute(
		"""
		INSERT INTO cases (case_key, report_text, source, synthetic, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(case_key) DO UPDATE SET
			updated_at = cases.updated_at
		""",
		(case_key, report_text or "", source, 1 if synthetic else 0, status, now, now),
	)
	row = conn.execute("SELECT case_id FROM cases WHERE case_key = ?", (case_key,)).fetchone()
	return int(row["case_id"])
