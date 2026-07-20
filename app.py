import streamlit as st

import app_helpers
import evaluation
import operations_metrics
import storage


st.set_page_config(page_title="CBRN Safeguards Prototype", layout="wide")


def init_state():
	defaults = {
		"analysis_result": None,
		"analysis_error": None,
		"analysis_status": "idle",
		"save_status": None,
		"save_result": None,
		"last_input_fingerprint": None,
		"saved_analysis_ids": set(),
		"selected_case_id": None,
		"selected_analysis_id": None,
		"review_success": None,
		"review_error": None,
		"submitted_review_keys": set(),
		"review_form_nonce": 0,
		"evaluation_selected_run_id": None,
		"evaluation_compare_run_a": None,
		"evaluation_compare_run_b": None,
		"evaluation_error": None,
		"evaluation_last_request_key": None,
	}
	for key, value in defaults.items():
		if key not in st.session_state:
			st.session_state[key] = value


def render_sidebar():
	st.sidebar.title("Safeguards Prototype")
	page = st.sidebar.radio(
		"Navigation",
		["Analyze", "Review Queue", "Operations Dashboard", "Evaluation Dashboard"],
	)
	st.sidebar.divider()
	st.sidebar.caption("Diagnostics")
	st.sidebar.code(app_helpers.get_database_path())
	try:
		db_path = app_helpers.get_database_path()
		app_helpers.ensure_database_ready(db_path)
		counts = storage.summarize_records(db_path)
		st.sidebar.caption(f"Cases: {counts['cases']} | Analyses: {counts['analyses']} | Reviews: {counts['reviews']}")
	except Exception:
		st.sidebar.caption("Database unavailable in this environment.")
	return page


def render_context_notes():
	st.info(
		"This local prototype is for synthetic or sanitized demonstration data. "
		"Rules-only mode is deterministic. LLM-assisted mode may vary and requires a configured API key. "
		"This is not a deployed enforcement system."
	)


def render_analysis_summary(result):
	analysis = result["analysis"]
	details = analysis["score_details"]
	cols = st.columns(4)
	cols[0].metric("Automated intent", analysis.get("intent", "unknown"))
	cols[1].metric("Risk score", details.get("total_score"))
	cols[2].metric("Score band", details.get("score_band"))
	cols[3].metric("Operational priority", details.get("operational_priority"))

	st.subheader("Summary")
	st.write(analysis.get("summary") or "No summary available.")

	st.subheader("Indicators")
	indicators = details.get("normalized_indicators") or []
	if indicators:
		for indicator in indicators:
			st.write(f"- `{indicator}`")
	else:
		st.write("- `<none>`")

	meta_cols = st.columns(4)
	meta_cols[0].write(f"Scoring version: `{details.get('scoring_version')}`")
	meta_cols[1].write(f"Priority policy: `{details.get('priority_policy_version')}`")
	meta_cols[2].write(f"Method: `{result['analysis_method']}`")
	meta_cols[3].write(f"Model: `{result.get('model_name') or 'not used'}`")
	watch_cols = st.columns(3)
	watch_cols[0].write(f"Watchlist version: `{analysis.get('watchlist_version') or details.get('watchlist_version')}`")
	watch_cols[1].write(f"Watchlist policy: `{analysis.get('watchlist_policy_version') or details.get('watchlist_policy_version')}`")
	watch_cols[2].write(f"Hard-flag count: `{analysis.get('watchlist_match_count', len(analysis.get('hard_flags') or []))}`")


def render_explainability(result):
	analysis = result["analysis"]
	details = analysis["score_details"]
	score_changing, zero_rules = app_helpers.split_score_explanation(details)
	priority = app_helpers.priority_explanation(analysis.get("intent"), details)

	st.subheader("Explainability")

	st.markdown("**A. Factors That Changed The Numeric Score**")
	if score_changing:
		for item in score_changing:
			st.write(f"- `{item.get('factor')}`: {item.get('points')} point(s). {item.get('reason')}")
	else:
		st.write("- No score-changing factors were recorded.")

	st.markdown("**B. Safeguard Rules Activated Without Changing The Score**")
	if zero_rules:
		for item in zero_rules:
			st.write(f"- `{item.get('factor')}`: {item.get('reason')}")
	else:
		st.write("- No zero-point safeguard rules activated.")

	st.markdown("**C. Priority Explanation**")
	st.write(priority["text"])
	st.caption(f"Priority source: {priority['source']}")


def render_hard_flags(result):
	analysis = result["analysis"]
	flags = app_helpers.hard_flag_view_models(analysis)
	st.subheader("Hard Flags")
	st.caption(
		"A hard flag means mandatory or elevated review attention. It does not by itself establish malicious intent. "
		"The local reference list is not exhaustive, and analog or family references are not molecularly verified."
	)
	if not flags:
		st.write("No hard-watchlist match.")
		return
	for flag in flags:
		with st.container(border=True):
			cols = st.columns(4)
			cols[0].write(f"Authority: `{flag['authority']}`")
			cols[1].write(f"Schedule: `{flag['schedule']}`")
			cols[2].write(f"Status: `{flag['status']}`")
			cols[3].write(f"Priority effect: at least `{flag['priority_effect']}`")
			st.write(f"Matched term: `{flag['matched_term']}`")
			st.write(f"Entry code: `{flag['entry_code']}`")
			st.write(flag["reason"])
			st.caption(f"Watchlist version: {flag['watchlist_version']} | Confidence: {flag['confidence_category']}")


def render_save_controls(result):
	st.subheader("Save To Review Queue")
	st.write("Analyzing does not save anything. Save only when you want this result available for a future review queue.")
	db_path = app_helpers.get_database_path()
	analysis_key = result["input_fingerprint"] + "|" + result["analysis_method"]
	already_saved = analysis_key in st.session_state.saved_analysis_ids
	if st.session_state.save_result and already_saved:
		saved = st.session_state.save_result
		st.success(
			f"Already saved. Case ID {saved['case_id']}, analysis ID {saved['analysis_id']}. "
			f"Available in queue: {saved['in_review_queue']}."
		)
	if st.button("Save to Review Queue", disabled=already_saved):
		try:
			saved = app_helpers.save_displayed_analysis(db_path, result)
			st.session_state.saved_analysis_ids.add(analysis_key)
			st.session_state.save_result = saved
			st.session_state.save_status = "saved"
			st.success(
				f"Saved. Case ID {saved['case_id']}, analysis ID {saved['analysis_id']}. "
				f"Available in queue: {saved['in_review_queue']}."
			)
		except Exception as exc:
			st.session_state.save_status = "error"
			st.error(f"Save failed: {exc}")


def render_demo_data_loader(db_path):
	st.warning("The database has no saved cases. You can load the existing synthetic demonstration cases from reports.csv.")
	if st.button("Load synthetic demo cases"):
		try:
			counts = app_helpers.load_demo_cases(db_path)
			st.success(
				f"Demo data loaded. Cases: {counts['cases']}, analyses: {counts['analyses']}, reviews: {counts['reviews']}."
			)
			st.rerun()
		except Exception as exc:
			st.error(f"Demo-data import failed: {exc}")


def render_queue_filters(db_path):
	st.subheader("Queue Filters")
	include_closed = st.checkbox("Include closed cases", value=False)
	status_options = list(app_helpers.CASE_STATUSES)
	default_statuses = list(app_helpers.REVIEW_STATUS_DEFAULTS)
	if include_closed:
		default_statuses.append("closed")
	statuses = st.multiselect("Case status", status_options, default=default_statuses)

	cols = st.columns(4)
	priority = cols[0].selectbox("Operational priority", ["Any", "Escalate", "Review", "Low"])
	intent = cols[1].selectbox("Automated intent", ["Any"] + list(app_helpers.ANALYST_INTENTS))
	try:
		source_options = ["Any"] + storage.get_case_sources(db_path)
	except Exception:
		source_options = ["Any"]
	source = cols[2].selectbox("Source", source_options)
	minimum_score = cols[3].number_input("Minimum risk score", min_value=0, step=1, value=0)
	hard_flag_choice = st.selectbox(
		"Hard-watchlist status",
		["Any status", "Any hard flag", "No hard flag", "Exact or approved match", "Possible family/analog reference"],
	)
	hard_flag_filter = {
		"Any status": None,
		"Any hard flag": "any",
		"No hard flag": "none",
		"Exact or approved match": "confirmed",
		"Possible family/analog reference": "possible",
	}[hard_flag_choice]

	return {
		"statuses": statuses,
		"operational_priority": None if priority == "Any" else priority,
		"automated_intent": None if intent == "Any" else intent,
		"source": None if source == "Any" else source,
		"minimum_risk_score": int(minimum_score) if minimum_score else None,
		"hard_flag_filter": hard_flag_filter,
		"include_closed": include_closed,
	}


def render_queue_table(rows):
	table_rows = [
		{
			"Case ID": row["case_id"],
			"Created": row["created_at"],
			"Source": row["source"],
			"Status": row["status"],
			"Automated intent": row["automated_intent"],
			"Risk score": row["numeric_risk_score"],
			"Priority": row["operational_priority"],
			"Watchlist": row["hard_flag_summary"],
			"Preview": row["text_preview"],
			"Prior reviews": row["review_count"],
		}
		for row in rows
	]
	st.dataframe(table_rows, hide_index=True, use_container_width=True)


def render_analysis_selector(analyses):
	if not analyses:
		return None
	options = [analysis["analysis_id"] for analysis in analyses]
	current = st.session_state.selected_analysis_id
	if current not in options:
		current = options[0]
		st.session_state.selected_analysis_id = current
	labels = {
		analysis["analysis_id"]: (
			f"Analysis {analysis['analysis_id']} | {analysis['analysis_method']} | "
			f"{analysis['automated_intent']} | score {analysis['numeric_risk_score']} | {analysis['created_at']}"
		)
		for analysis in analyses
	}
	return st.selectbox(
		"Automated analysis",
		options,
		index=options.index(current),
		format_func=lambda analysis_id: labels[analysis_id],
		key="analysis_selector",
	)


def render_case_detail(db_path, case_id):
	detail = app_helpers.get_case_detail(db_path, case_id, st.session_state.selected_analysis_id)
	if detail is None:
		st.error("The selected case could not be found.")
		return None
	case = detail["case"]
	analyses = detail["analyses"]
	if not analyses:
		st.warning("This case has no saved automated analyses.")
		return None

	st.subheader(f"Case {case['case_id']}")
	meta_cols = st.columns(4)
	meta_cols[0].write(f"Source: `{case.get('source') or 'unspecified'}`")
	meta_cols[1].write(f"Status: `{case['status']}`")
	meta_cols[2].write(f"Created: `{case['created_at']}`")
	meta_cols[3].write(f"Updated: `{case['updated_at']}`")

	st.markdown("**Full Sanitized Report Text**")
	st.text_area("Report text", value=case.get("report_text") or "", height=160, disabled=True, label_visibility="collapsed")

	selected_analysis_id = render_analysis_selector(analyses)
	if selected_analysis_id != st.session_state.selected_analysis_id:
		st.session_state.selected_analysis_id = selected_analysis_id
		st.rerun()

	detail = app_helpers.get_case_detail(db_path, case_id, st.session_state.selected_analysis_id)
	selected = detail["selected_analysis"]
	st.caption(f"Currently selected analysis ID: {selected['analysis_id']}")
	display_result = app_helpers.stored_analysis_display_result(case, selected)
	render_analysis_summary(display_result)
	render_hard_flags(display_result)
	st.write(f"Analysis timestamp: `{selected['created_at']}`")
	render_explainability(display_result)
	return detail


def render_review_history(history):
	st.subheader("Review History")
	if not history:
		st.caption("No analyst reviews have been saved for this case yet.")
		return
	for review in history:
		with st.expander(
			f"{review['created_at']} | {review['agreement']} | {review['disposition']} | status {review['resulting_case_status']}",
			expanded=False,
		):
			cols = st.columns(4)
			cols[0].write(f"Reviewer: `{review.get('reviewer') or 'unspecified'}`")
			cols[1].write(f"Analyst intent: `{review['analyst_intent']}`")
			cols[2].write(f"Automated intent: `{review['automated_intent']}`")
			cols[3].write(f"Confidence: `{review['confidence']}`")
			st.write(f"Analysis ID: `{review['analysis_id']}`")
			st.write(f"Scoring version: `{review['scoring_version']}`")
			st.write(f"Priority policy: `{review['priority_policy_version']}`")
			st.write(review.get("notes") or "No notes recorded.")


def render_review_form(db_path, detail):
	case = detail["case"]
	analysis = detail["selected_analysis"]
	st.subheader("Analyst Decision")
	st.caption("The review is saved against the selected analysis. The automated analysis and numeric score are preserved.")

	form_key = f"review_form_{case['case_id']}_{analysis['analysis_id']}_{st.session_state.review_form_nonce}"
	default_disposition = app_helpers.default_disposition_for_intent(analysis["automated_intent"])
	default_status = app_helpers.default_status_for_disposition(default_disposition)
	with st.form(form_key):
		reviewer = st.text_input("Reviewer name", value="Demo Analyst")
		st.caption("Reviewer records who made this demonstration decision.")
		analyst_intent = st.selectbox(
			"Analyst intent",
			app_helpers.ANALYST_INTENTS,
			index=app_helpers.ANALYST_INTENTS.index(analysis["automated_intent"]),
		)
		st.caption("The analyst's independent assessment of the request.")
		disposition = st.selectbox(
			"Disposition",
			app_helpers.DISPOSITIONS,
			index=app_helpers.DISPOSITIONS.index(default_disposition),
		)
		st.caption("The operational handling decision.")
		confidence = st.slider("Confidence", min_value=1, max_value=5, value=3)
		st.caption("Confidence in the analyst judgment, not confidence in the automated system.")
		notes = st.text_area("Notes", height=120)
		st.caption("A concise rationale supporting the decision.")
		resulting_status = st.selectbox(
			"Resulting case status",
			app_helpers.CASE_STATUSES,
			index=app_helpers.CASE_STATUSES.index(default_status),
		)
		st.caption("Whether additional review work remains.")

		validation = app_helpers.review_validation(
			analyst_intent,
			analysis["automated_intent"],
			disposition,
			int(confidence),
			notes,
			resulting_status,
		)
		if validation["agreement"] == "Agreement":
			st.success("Agreement: analyst intent matches the automated intent.")
		else:
			st.warning("Override: analyst intent differs from the automated intent. The automated result will remain preserved.")
		for warning in validation["warnings"]:
			st.warning(warning)
		confirm_warnings = True
		if validation["warnings"]:
			confirm_warnings = st.checkbox("I confirm these warning conditions are intentional.")
		submitted = st.form_submit_button("Submit Review")

	if not submitted:
		return
	validation = app_helpers.review_validation(
		analyst_intent,
		analysis["automated_intent"],
		disposition,
		int(confidence),
		notes,
		resulting_status,
	)
	if validation["errors"]:
		st.session_state.review_error = " ".join(validation["errors"])
		st.error(st.session_state.review_error)
		return
	if validation["warnings"] and not confirm_warnings:
		st.session_state.review_error = "Confirm the warning conditions before saving this review."
		st.error(st.session_state.review_error)
		return
	try:
		result = app_helpers.save_review_once(
			db_path,
			st.session_state.submitted_review_keys,
			analysis["analysis_id"],
			reviewer,
			analyst_intent,
			disposition,
			int(confidence),
			notes,
			resulting_status,
		)
		if result["duplicate"]:
			st.info("This review submission was already saved during this session.")
		else:
			st.session_state.review_success = {
				"review_id": result["review_id"],
				"agreement": validation["agreement"],
			}
			st.session_state.review_form_nonce += 1
			st.success(f"Review saved as {validation['agreement']}. Review ID {result['review_id']}.")
			st.rerun()
	except Exception as exc:
		st.session_state.review_error = str(exc)
		st.error(f"Review save failed: {exc}")


def render_review_queue_page():
	st.title("Review Queue")
	render_context_notes()
	db_path = app_helpers.get_database_path()
	try:
		app_helpers.ensure_database_ready(db_path)
		counts = storage.summarize_records(db_path)
	except Exception as exc:
		st.error(f"Database cannot be accessed: {exc}")
		return

	if counts["cases"] == 0:
		render_demo_data_loader(db_path)
		return

	filters = render_queue_filters(db_path)
	try:
		rows = app_helpers.get_review_queue(
			db_path,
			statuses=filters["statuses"],
			operational_priority=filters["operational_priority"],
			automated_intent=filters["automated_intent"],
			source=filters["source"],
			minimum_risk_score=filters["minimum_risk_score"],
			hard_flag_filter=filters["hard_flag_filter"],
		)
	except Exception as exc:
		st.error(f"Queue retrieval failed: {exc}")
		return

	if not rows:
		all_rows = app_helpers.get_review_queue(db_path, statuses=app_helpers.CASE_STATUSES)
		unresolved = [row for row in all_rows if row["status"] in app_helpers.REVIEW_STATUS_DEFAULTS]
		if not unresolved and not filters["include_closed"]:
			st.info("All cases have been closed. Select Include closed cases to inspect completed work.")
		else:
			st.info("No cases match the selected filters.")
		return

	st.subheader("Prioritized Cases")
	render_queue_table(rows)
	case_ids = [row["case_id"] for row in rows]
	if st.session_state.selected_case_id is None:
		st.session_state.selected_case_id = case_ids[0]
		st.session_state.selected_analysis_id = rows[0]["analysis_id"]
	labels = {
		row["case_id"]: (
			f"Case {row['case_id']} | {row['operational_priority']} | score {row['numeric_risk_score']} | "
			f"{row['automated_intent']} | {row['text_preview']}"
		)
		for row in rows
	}
	if st.session_state.selected_case_id in case_ids:
		selected_case_id = st.selectbox(
			"Select case",
			case_ids,
			index=case_ids.index(st.session_state.selected_case_id),
			format_func=lambda case_id: labels[case_id],
		)
		if selected_case_id != st.session_state.selected_case_id:
			st.session_state.selected_case_id = selected_case_id
			st.session_state.selected_analysis_id = next(row["analysis_id"] for row in rows if row["case_id"] == selected_case_id)
			st.session_state.review_error = None
			st.session_state.review_success = None
			st.rerun()
	else:
		st.warning("The selected case no longer matches the current filters, but remains open below for continuity.")
		if st.button("Select first matching case"):
			st.session_state.selected_case_id = case_ids[0]
			st.session_state.selected_analysis_id = rows[0]["analysis_id"]
			st.session_state.review_error = None
			st.session_state.review_success = None
			st.rerun()

	if st.session_state.review_success:
		st.success(
			f"Last saved review: {st.session_state.review_success['agreement']} "
			f"(review ID {st.session_state.review_success['review_id']})."
		)

	detail = render_case_detail(db_path, st.session_state.selected_case_id)
	if detail:
		render_review_form(db_path, detail)
		refreshed = app_helpers.get_case_detail(db_path, st.session_state.selected_case_id, st.session_state.selected_analysis_id)
		render_review_history(refreshed["review_history"])


def render_analyze_page():
	st.title("Analyze")
	render_context_notes()

	with st.form("analysis_form"):
		report_text = st.text_area("Report or interaction text", height=220, key="report_text")
		cols = st.columns([2, 2, 1])
		source = cols[0].text_input("Source", value="manual_demo", key="source")
		external_case_id = cols[1].text_input("External case ID (optional)", key="external_case_id")
		analysis_mode = cols[2].selectbox(
			"Analysis mode",
			[app_helpers.ANALYSIS_MODE_RULES, app_helpers.ANALYSIS_MODE_LLM],
			key="analysis_mode",
		)
		submitted = st.form_submit_button("Analyze")

	current_fingerprint = app_helpers.make_input_fingerprint(report_text, source, external_case_id, analysis_mode)
	if st.session_state.analysis_result and current_fingerprint != st.session_state.last_input_fingerprint:
		st.warning("The displayed result belongs to a prior input. Click Analyze to refresh it for the current text.")

	if submitted:
		st.session_state.analysis_status = "running"
		st.session_state.analysis_error = None
		st.session_state.save_status = None
		st.session_state.save_result = None
		try:
			result = app_helpers.run_analysis_from_form(report_text, source, external_case_id, analysis_mode)
			st.session_state.analysis_result = result
			st.session_state.last_input_fingerprint = result["input_fingerprint"]
			st.session_state.analysis_status = "success"
		except RuntimeError as exc:
			st.session_state.analysis_status = "missing_api_key"
			st.session_state.analysis_error = str(exc)
		except ValueError as exc:
			st.session_state.analysis_status = "input_error"
			st.session_state.analysis_error = str(exc)
		except Exception as exc:
			st.session_state.analysis_status = "failure"
			st.session_state.analysis_error = str(exc)

	if st.session_state.analysis_status == "idle":
		st.caption("Enter text and click Analyze.")
	elif st.session_state.analysis_status == "running":
		st.info("Analysis in progress...")
	elif st.session_state.analysis_status == "missing_api_key":
		st.warning(st.session_state.analysis_error)
	elif st.session_state.analysis_status == "input_error":
		st.warning(st.session_state.analysis_error)
	elif st.session_state.analysis_status == "failure":
		st.error(f"Analysis failed: {st.session_state.analysis_error}")

	result = st.session_state.analysis_result
	if result:
		render_analysis_summary(result)
		render_hard_flags(result)
		render_explainability(result)
		render_save_controls(result)


def render_placeholder(title, body):
	st.title(title)
	st.info(body)


def _format_metric_value(value, kind="count"):
	if value is None:
		return "No data"
	if kind == "percent":
		return f"{value * 100:.0f}%"
	if kind == "duration":
		hours = value / 3600
		if hours < 24:
			return f"{hours:.1f} hours"
		return f"{hours / 24:.1f} days"
	return str(value)


def render_operations_filters(db_path):
	options = operations_metrics.get_filter_options(db_path)
	st.subheader("Filters")
	st.caption("Case-level metrics use the latest stored analysis for each case. Review-level metrics use the exact analysis_id associated with each stored review.")
	cols = st.columns(2)
	start_date = cols[0].date_input("Case created from", value=None)
	end_date = cols[1].date_input("Case created through", value=None)
	statuses = st.multiselect("Case status", ["new", "in_review", "closed"], default=options["statuses"])
	cols = st.columns(3)
	priorities = cols[0].multiselect("Operational priority", ["Escalate", "Review", "Low"], default=options["priorities"])
	intents = cols[1].multiselect("Automated intent", ["benign", "dual_use", "suspicious", "malicious"], default=options["intents"])
	sources = cols[2].multiselect("Source", options["sources"], default=options["sources"])
	cols = st.columns(4)
	hard_choice = cols[0].selectbox("Hard-flag status", ["All", "Any hard flag", "No hard flag", "Confirmed official or approved-alias match", "Possible family or analog reference"])
	methods = cols[1].multiselect("Analysis method", options["methods"], default=options["methods"])
	scoring_versions = cols[2].multiselect("Scoring version", options["scoring_versions"], default=options["scoring_versions"])
	watchlist_versions = cols[3].multiselect("Watchlist version", options["watchlist_versions"], default=options["watchlist_versions"])
	hard_flag_status = {
		"All": "all",
		"Any hard flag": "any",
		"No hard flag": "none",
		"Confirmed official or approved-alias match": "confirmed",
		"Possible family or analog reference": "possible",
	}[hard_choice]
	return {
		"created_from": f"{start_date.isoformat()}T00:00:00Z" if start_date else None,
		"created_to": f"{end_date.isoformat()}T23:59:59Z" if end_date else None,
		"statuses": statuses,
		"operational_priorities": priorities,
		"automated_intents": intents,
		"sources": sources,
		"hard_flag_status": hard_flag_status,
		"analysis_methods": methods,
		"scoring_versions": scoring_versions,
		"watchlist_versions": watchlist_versions,
	}


def render_metric_cards(metrics):
	cards = [
		("Total cases", metrics["total_cases"], "Number of distinct cases matching the active filters.", "count"),
		("Open cases", metrics["open_cases"], "Filtered cases whose current status is new or in_review.", "count"),
		("Escalate backlog", metrics["escalate_backlog"], "Open cases whose latest stored analysis has operational priority Escalate.", "count"),
		("Hard-flagged open cases", metrics["hard_flagged_open_cases"], "Open cases whose latest stored analysis contains at least one hard flag.", "count"),
		("Reviewed cases", metrics["reviewed_cases"], "Distinct filtered cases with at least one stored analyst review.", "count"),
		("Review-level override rate", metrics["review_level_override_rate"], "Reviews where analyst intent differs from the automated intent of the reviewed analysis, divided by all reviews in scope.", "percent"),
		("Median time to first review", metrics["median_time_to_first_review_seconds"], "Median elapsed time between case creation and first stored review for reviewed cases only.", "duration"),
		("Escalation disposition rate", metrics["escalation_disposition_rate"], "Reviews with disposition escalate divided by all reviews in scope.", "percent"),
	]
	for chunk_start in range(0, len(cards), 4):
		cols = st.columns(4)
		for col, (label, value, help_text, kind) in zip(cols, cards[chunk_start : chunk_start + 4]):
			col.metric(label, _format_metric_value(value, kind), help=help_text)


def render_chart(title, rows, label_key="label"):
	st.markdown(f"**{title}**")
	if not rows:
		st.caption("No data available for this metric.")
		return
	st.bar_chart({row[label_key]: row["count"] for row in rows})


def render_operations_visuals(visuals):
	left, right = st.columns(2)
	with left:
		render_chart("Open backlog by operational priority", visuals["open_backlog_by_priority"])
		render_chart("Automated intent distribution", visuals["automated_intent_distribution"])
		render_chart("Agreement versus override", visuals["agreement_vs_override"])
		render_chart("Cases by source", visuals["cases_by_source"])
		render_chart("Unresolved backlog by aging bucket", visuals["aging_buckets"], label_key="bucket")
	with right:
		render_chart("Cases by current status", visuals["cases_by_status"])
		render_chart("Analyst disposition distribution", visuals["analyst_disposition_distribution"])
		render_chart("Most frequent normalized indicators", visuals["top_indicators"], label_key="indicator")
		render_chart("Case volume over time", visuals["case_volume_over_time"], label_key="period")
		render_chart("Review activity over time", visuals["review_activity_over_time"], label_key="period")
	st.markdown("**Hard-flag outcomes**")
	if visuals["hard_flag_outcomes"]:
		st.dataframe(visuals["hard_flag_outcomes"], hide_index=True, use_container_width=True)
	else:
		st.caption("No data available for this metric.")


def render_operations_tables(tables):
	st.subheader("Operational Tables")
	for title, key in [
		("Oldest unresolved high-priority cases", "oldest_unresolved_high_priority"),
		("Recently escalated reviews", "recently_escalated_reviews"),
		("Hard-flagged cases awaiting review", "hard_flagged_awaiting_review"),
		("Recent analyst overrides", "recent_analyst_overrides"),
	]:
		st.markdown(f"**{title}**")
		rows = tables[key]
		if rows:
			st.dataframe(rows, hide_index=True, use_container_width=True)
		else:
			st.caption("No data available for this metric.")


def render_operations_demo_loader(db_path):
	st.subheader("Synthetic Operations Demo Data")
	st.warning("Loading this dataset creates synthetic demonstration metrics only. It does not delete or replace existing cases.")
	if st.button("Load Synthetic Operations Demo Data"):
		try:
			result = operations_metrics.import_operations_demo_data(db_path)
			st.success(
				f"Loaded synthetic operations demo data. Before: {result['before']}. "
				f"After: {result['after']}. Dataset cases: {result['dataset_cases']}. "
				f"New seeded reviews inserted: {result['inserted_reviews']}."
			)
			st.rerun()
		except Exception as exc:
			st.error(f"Demo import failed: {exc}")


def render_operations_dashboard_page():
	st.title("Operations Dashboard")
	render_context_notes()
	st.info(
		"Metrics are calculated from stored SQLite records. Case-level metrics use the latest stored analysis per case. "
		"Review-level metrics compare each review with the exact automated analysis the reviewer saw."
	)
	st.caption(
		"Hard flags indicate elevated screening attention. They do not independently establish malicious intent. "
		"The local Schedule 1 reference is not exhaustive, and possible family or analog references are unverified."
	)
	db_path = app_helpers.get_database_path()
	try:
		app_helpers.ensure_database_ready(db_path)
		counts = storage.summarize_records(db_path)
	except Exception as exc:
		st.error(f"Database cannot be accessed: {exc}")
		return
	render_operations_demo_loader(db_path)
	if counts["cases"] == 0:
		st.caption("No stored cases are available yet. Load synthetic operations demo data or save cases from Analyze.")
		return
	filters = render_operations_filters(db_path)
	dashboard = operations_metrics.build_dashboard(db_path, filters)
	if not dashboard["cases"]:
		st.warning("No cases match the active filters.")
	render_metric_cards(dashboard["top_metrics"])
	st.caption(dashboard["review_scope_note"])
	render_operations_visuals(dashboard["visualizations"])
	render_operations_tables(dashboard["tables"])


def _format_eval_metric(value, kind="percent"):
	if value is None:
		return "No data"
	if kind == "percent":
		return f"{value * 100:.0f}%"
	return str(value)


def render_evaluation_suite_inspection(suite):
	inspection = evaluation.suite_inspection(suite)
	st.subheader("Suite Inspection")
	cols = st.columns(4)
	cols[0].metric("Cases", inspection["case_count"])
	cols[1].metric("Approved", inspection["label_status_counts"].get("approved", 0))
	cols[2].metric("Provisional", inspection["label_status_counts"].get("provisional", 0))
	cols[3].metric("Ambiguous", inspection["label_status_counts"].get("ambiguous", 0))
	st.caption(f"Dataset hash: `{inspection['dataset_hash']}`")
	dist_cols = st.columns(3)
	with dist_cols[0]:
		render_chart("Expected intent distribution", [{"label": k, "count": v} for k, v in inspection["intent_distribution"].items()])
	with dist_cols[1]:
		render_chart("Expected priority distribution", [{"label": k, "count": v} for k, v in inspection["priority_distribution"].items()])
	with dist_cols[2]:
		render_chart("Expected hard-flag distribution", [{"label": k, "count": v} for k, v in inspection["hard_flag_distribution"].items()])
	if inspection["noncanonical_labels"]:
		st.warning("This suite contains noncanonical labels that are mapped explicitly for four-class comparison.")
		st.dataframe(inspection["noncanonical_labels"], hide_index=True, use_container_width=True)
	st.caption("Scenario tags: " + (", ".join(inspection["scenario_tags"]) or "none"))
	if inspection["missing_required_fields"]:
		st.error("Missing required fields were found.")
		st.dataframe(inspection["missing_required_fields"], hide_index=True, use_container_width=True)


def render_evaluation_run_controls(db_path, suite):
	st.subheader("Run Evaluation")
	st.caption(
		"Evaluation cases are synthetic, manually constructed reference judgments. "
		"Rules-only evaluation is deterministic. LLM-assisted evaluation may vary and requires an API key."
	)
	mode = st.selectbox("Evaluation mode", ["Rules only", "LLM assisted"])
	if mode == "LLM assisted":
		st.warning("LLM-assisted runs are potentially non-deterministic and require OPENAI_API_KEY.")
	request_key = f"{suite['suite_id']}|{evaluation.dataset_hash(suite)}|{mode}"
	duplicate_request = st.session_state.evaluation_last_request_key == request_key
	allow_rerun = True
	if duplicate_request:
		allow_rerun = st.checkbox("Create another run with the same suite, dataset hash, and mode.")
		st.caption("A deliberate rerun creates a new stored measurement event.")
	if st.button("Run evaluation", disabled=duplicate_request and not allow_rerun):
		try:
			progress = st.progress(0, text="Starting evaluation...")
			with st.spinner("Running evaluation and storing case-level results..."):
				result = evaluation.run_and_store(db_path, suite["suite_id"], mode)
				progress.progress(100, text="Evaluation complete.")
			st.session_state.evaluation_selected_run_id = result["run"]["run_id"]
			st.session_state.evaluation_last_request_key = request_key
			st.success(f"Stored evaluation run {result['run']['run_id']} with {len(result['results'])} case-level result(s).")
			st.rerun()
		except RuntimeError as exc:
			st.session_state.evaluation_error = str(exc)
			st.warning(str(exc))
		except Exception as exc:
			st.session_state.evaluation_error = str(exc)
			st.error(f"Evaluation failed: {exc}")


def render_eval_matrix(title, matrix):
	st.markdown(f"**{title}**")
	if not matrix:
		st.caption("No data available for this metric.")
		return
	st.dataframe(matrix, hide_index=True, use_container_width=True)


def render_eval_metric_cards(metrics):
	st.subheader("Metrics")
	cards = [
		("Intent accuracy", metrics["overall_intent_accuracy"], "Canonical four-class intent accuracy.", "percent"),
		("Priority pass rate", metrics["priority_pass_rate"], "Predicted priority is at least the expected minimum.", "percent"),
		("Critical misses", metrics["critical_miss_count"], "Expected Escalate assigned Low or Review.", "count"),
		("Over-triage", metrics["over_triage_count"], "Expected Low assigned Review or Escalate.", "count"),
		("High-risk semantic misses", metrics["high_risk_semantic_miss_count"], "Expected suspicious or malicious predicted benign or dual_use.", "count"),
		("Confirmed hard-flag recall", metrics["confirmed_hard_flag_recall"], "Confirmed expected hard flags that were detected.", "percent"),
		("Confirmed hard-flag precision", metrics["confirmed_hard_flag_precision"], "Detected confirmed hard flags that were expected.", "percent"),
		("Possible analog detection", metrics["possible_family_or_analog_detection_rate"], "Expected possible family/analog references detected as possible.", "percent"),
	]
	for chunk in range(0, len(cards), 4):
		cols = st.columns(4)
		for col, (label, value, help_text, kind) in zip(cols, cards[chunk : chunk + 4]):
			col.metric(label, _format_eval_metric(value, kind), help=help_text)


def render_eval_visualizations(metrics, results):
	left, right = st.columns(2)
	with left:
		render_eval_matrix("Intent confusion matrix", metrics["intent_confusion_matrix"])
		render_eval_matrix("Priority confusion matrix", metrics["priority_confusion_matrix"])
		per_class_rows = [
			{"intent": intent, **values}
			for intent, values in metrics["per_class"].items()
		]
		st.markdown("**Per-class precision, recall, and F1**")
		st.dataframe(per_class_rows, hide_index=True, use_container_width=True)
	with right:
		tag_outcomes = {}
		for row in results:
			for tag in row.get("scenario_tags") or []:
				tag_outcomes.setdefault(tag, {"tag": tag, "pass": 0, "fail": 0, "critical_miss": 0, "over_triage": 0})
				if evaluation.case_outcome(row):
					tag_outcomes[tag]["pass"] += 1
				else:
					tag_outcomes[tag]["fail"] += 1
				if row.get("critical_miss"):
					tag_outcomes[tag]["critical_miss"] += 1
				if row.get("over_triage"):
					tag_outcomes[tag]["over_triage"] += 1
		st.markdown("**Pass/fail outcomes by scenario tag**")
		st.dataframe(sorted(tag_outcomes.values(), key=lambda item: item["tag"]), hide_index=True, use_container_width=True)
		hard_rows = [
			{"expected_hard_flag_category": k, "count": v}
			for k, v in sorted({row.get("expected_hard_flag_category"): 0 for row in results}.items())
		]
		counts = {}
		for row in results:
			counts[row.get("expected_hard_flag_category")] = counts.get(row.get("expected_hard_flag_category"), 0) + (1 if row.get("hard_flag_match") else 0)
		for row in hard_rows:
			row["matched"] = counts.get(row["expected_hard_flag_category"], 0)
		st.markdown("**Hard-flag performance by expected category**")
		st.dataframe(hard_rows, hide_index=True, use_container_width=True)


def render_eval_error_tables(results):
	st.subheader("Case-Level Error Tables")
	tables = evaluation.error_tables(results)
	labels = [
		("Critical misses", "critical_misses"),
		("High-risk semantic misses", "high_risk_semantic_misses"),
		("Over-triaged cases", "over_triaged_cases"),
		("Intent misclassifications", "intent_misclassifications"),
		("Hard-flag mismatches", "hard_flag_mismatches"),
	]
	for label, key in labels:
		st.markdown(f"**{label}**")
		if tables[key]:
			st.dataframe(tables[key], hide_index=True, use_container_width=True)
		else:
			st.caption("No data available for this metric.")


def render_eval_case_detail(results):
	if not results:
		return
	options = [row["case_id"] for row in results]
	selected = st.selectbox("Inspect case-level result", options)
	row = next(item for item in results if item["case_id"] == selected)
	snapshot = row.get("analysis_snapshot") or {}
	st.markdown("**Sanitized Case Text**")
	st.text_area("Evaluation case text", value=snapshot.get("_evaluation_sanitized_text") or "", height=120, disabled=True, label_visibility="collapsed")
	cols = st.columns(4)
	cols[0].write(f"Expected intent: `{row.get('expected_intent_original')}`")
	cols[1].write(f"Canonical comparison: `{row.get('expected_intent_canonical')}`")
	cols[2].write(f"Predicted intent: `{row.get('predicted_intent')}`")
	cols[3].write(f"Label status: `{row.get('label_status')}`")
	st.write(f"Label rationale: {snapshot.get('_evaluation_label_rationale') or 'No rationale stored.'}")
	display_result = {
		"analysis": snapshot,
		"analysis_method": storage.get_evaluation_run(app_helpers.get_database_path(), row["run_id"]).get("analysis_method"),
		"model_name": storage.get_evaluation_run(app_helpers.get_database_path(), row["run_id"]).get("model_name"),
	}
	render_hard_flags(display_result)
	render_explainability(display_result)


def render_evaluation_run_history(db_path, suite_id):
	st.subheader("Run History")
	runs = storage.list_evaluation_runs(db_path, suite_id=suite_id)
	if not runs:
		st.caption("No stored evaluation runs yet.")
		return None, []
	table = [
		{
			"Run ID": run["run_id"],
			"Started": run["started_at"],
			"Suite": run["suite_id"],
			"Version": run["suite_version"],
			"Method": run["analysis_method"],
			"Model": run.get("model_name") or "",
			"Scoring": run.get("scoring_version"),
			"Priority policy": run.get("priority_policy_version"),
			"Watchlist": run.get("watchlist_version"),
			"Cases": run.get("case_count"),
			"Approved": run.get("approved_case_count"),
			"Provisional": run.get("provisional_case_count"),
			"Status": run.get("run_status"),
			"Intent accuracy": _format_eval_metric((run.get("summary_metrics") or {}).get("overall_intent_accuracy")),
			"Priority pass": _format_eval_metric((run.get("summary_metrics") or {}).get("priority_pass_rate")),
		}
		for run in runs
	]
	st.dataframe(table, hide_index=True, use_container_width=True)
	completed_ids = [run["run_id"] for run in runs if run["run_status"] == "completed"]
	if not completed_ids:
		return None, runs
	selected = st.selectbox("Open stored run", completed_ids, index=0 if st.session_state.evaluation_selected_run_id not in completed_ids else completed_ids.index(st.session_state.evaluation_selected_run_id))
	st.session_state.evaluation_selected_run_id = selected
	return storage.get_evaluation_run(db_path, selected), runs


def render_evaluation_run_results(db_path, run):
	results = storage.get_evaluation_results(db_path, run["run_id"])
	status_options = ["approved", "provisional", "ambiguous"]
	default_statuses = ["approved"]
	if not any(row["label_status"] == "approved" for row in results):
		default_statuses = ["provisional"]
		st.warning("This run has no approved cases in the selected suite. Headline metrics are provisional, not validated.")
	selected_statuses = st.multiselect("Metric label-status scope", status_options, default=default_statuses)
	scoped = evaluation.filter_results_by_label_status(results, selected_statuses)
	metrics = evaluation.compute_metrics(scoped)
	st.caption(
		"Intent, priority, and hard-watchlist metrics are reported separately. Expected labels are manually constructed reference judgments, not objective ground truth."
	)
	st.caption(
		f"Run {run['run_id']} | dataset hash `{run['evaluation_set_hash']}` | scoring `{run.get('scoring_version')}` | "
		f"priority policy `{run.get('priority_policy_version')}` | watchlist `{run.get('watchlist_version')}`"
	)
	render_eval_metric_cards(metrics)
	render_eval_visualizations(metrics, scoped)
	render_eval_error_tables(scoped)
	render_eval_case_detail(scoped)
	return results


def render_evaluation_comparison(db_path, runs):
	st.subheader("Regression Comparison")
	completed = [run for run in runs if run["run_status"] == "completed"]
	if len(completed) < 2:
		st.caption("At least two completed compatible runs are required for comparison.")
		return
	run_ids = [run["run_id"] for run in completed]
	cols = st.columns(2)
	first = cols[0].selectbox("Baseline run", run_ids, index=1 if len(run_ids) > 1 else 0, key="compare_first")
	second = cols[1].selectbox("Candidate run", run_ids, index=0, key="compare_second")
	if first == second:
		st.caption("Choose two different runs to compare.")
		return
	run_a = storage.get_evaluation_run(db_path, first)
	run_b = storage.get_evaluation_run(db_path, second)
	comparison = evaluation.compare_runs(
		run_a,
		storage.get_evaluation_results(db_path, first),
		run_b,
		storage.get_evaluation_results(db_path, second),
	)
	if not comparison["compatible"]:
		st.warning("Runs are not compatible for strict regression comparison: " + "; ".join(comparison["reasons"]))
		return
	for warning in comparison["warnings"]:
		st.warning(warning)
	st.write(
		f"Intent accuracy: {_format_eval_metric(comparison['metrics_before']['overall_intent_accuracy'])} -> "
		f"{_format_eval_metric(comparison['metrics_after']['overall_intent_accuracy'])}"
	)
	st.write(
		f"Priority pass rate: {_format_eval_metric(comparison['metrics_before']['priority_pass_rate'])} -> "
		f"{_format_eval_metric(comparison['metrics_after']['priority_pass_rate'])}"
	)
	st.write(
		f"Critical misses: {comparison['metrics_before']['critical_miss_count']} -> "
		f"{comparison['metrics_after']['critical_miss_count']}"
	)
	for title, key in [
		("Newly regressed cases", "newly_regressed_cases"),
		("Newly improved cases", "newly_improved_cases"),
		("Unchanged failures", "unchanged_failures"),
		("Unchanged successes", "unchanged_successes"),
	]:
		st.markdown(f"**{title}**")
		items = comparison[key]
		st.write(", ".join(items) if items else "None")


def render_evaluation_dashboard_page():
	st.title("Evaluation Dashboard")
	render_context_notes()
	st.info(
		"This dashboard measures intent classification, operational prioritization, hard-watchlist detection, and regression behavior separately. "
		"Stored runs preserve exact case-level analysis snapshots."
	)
	db_path = app_helpers.get_database_path()
	try:
		app_helpers.ensure_database_ready(db_path)
	except Exception as exc:
		st.error(f"Database cannot be accessed: {exc}")
		return
	suites = evaluation.list_suites()
	labels = {suite["suite_id"]: suite["name"] for suite in suites}
	suite_id = st.selectbox("Evaluation suite", [suite["suite_id"] for suite in suites], format_func=lambda item: labels[item])
	try:
		suite = evaluation.load_suite(suite_id)
	except Exception as exc:
		st.error(f"Suite could not be loaded: {exc}")
		return
	render_evaluation_suite_inspection(suite)
	render_evaluation_run_controls(db_path, suite)
	run, runs = render_evaluation_run_history(db_path, suite_id)
	if run:
		st.subheader("Stored Run Results")
		render_evaluation_run_results(db_path, run)
		render_evaluation_comparison(db_path, runs)


def main():
	init_state()
	page = render_sidebar()
	if page == "Analyze":
		render_analyze_page()
	elif page == "Review Queue":
		render_review_queue_page()
	elif page == "Operations Dashboard":
		render_operations_dashboard_page()
	elif page == "Evaluation Dashboard":
		render_evaluation_dashboard_page()


if __name__ == "__main__":
	main()
