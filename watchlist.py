import argparse
import copy
import difflib
import hashlib
import html
import json
import re
import sys
import urllib.request
from html.parser import HTMLParser
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_WATCHLIST_PATH = Path("data/reference/opcw_schedule_1_watchlist.json")
WATCHLIST_POLICY_VERSION = "opcw-schedule-1-hard-flag-policy-v1"
NO_WATCHLIST_VERSION = "no_watchlist_applied"
LEGACY_WATCHLIST_POLICY_VERSION = "legacy_or_unknown"
OPCW_SCHEDULE_1_URL = "https://www.opcw.org/chemical-weapons-convention/annexes/annex-chemicals/schedule-1"
OPCW_CHANGES_URL = "https://www.opcw.org/changes-annex-chemicals"
OPCW_CONVENTION_URL = "https://www.opcw.org/chemical-weapons-convention/download-convention"
CAS_PATTERN = re.compile(r"\b\d{2,7}-\d{2}-\d\b")
ANALOG_LANGUAGE_PATTERN = re.compile(r"\b(analog|analogue|derivative|substitute|related family|family member)\b", re.IGNORECASE)
HARMFUL_SIGNAL_PREFIXES = ("delivery:", "evasion:", "scale:")
HARMFUL_SIGNAL_TERMS = ("acquisition", "optimization", "troubleshooting", "targeting")
PRIORITY_RANKS = {"Low": 0, "Review": 1, "Escalate": 2}
EXPECTED_SCHEDULE_1_NUMBERS = tuple(range(1, 17))


def utc_now() -> str:
	return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_watchlist(path=DEFAULT_WATCHLIST_PATH) -> dict:
	with open(path, encoding="utf-8") as handle:
		data = json.load(handle)
	validate_watchlist(data)
	return data


def validate_watchlist(data: dict) -> None:
	if not isinstance(data, dict):
		raise ValueError("watchlist must be an object")
	metadata = data.get("metadata") or {}
	if not metadata.get("watchlist_version"):
		raise ValueError("watchlist metadata requires watchlist_version")
	entries = data.get("entries")
	aliases = data.get("aliases", [])
	if not isinstance(entries, list) or not entries:
		raise ValueError("watchlist requires at least one entry")
	entry_codes = set()
	for entry in entries:
		for field in (
			"entry_code",
			"schedule",
			"entry_type",
			"official_entry_text",
			"approved_match_terms",
			"source_title",
			"source_reference",
			"source_effective_date",
			"retrieved_at",
			"watchlist_version",
		):
			if field not in entry:
				raise ValueError(f"watchlist entry missing {field}")
		if CAS_PATTERN.search(json.dumps(entry, ensure_ascii=False)):
			raise ValueError(f"CAS Registry Number found in entry {entry.get('entry_code')}")
		entry_codes.add(entry["entry_code"])
	for alias in aliases:
		for field in ("alias", "alias_type", "entry_code", "source_or_reviewer_basis", "reviewed"):
			if field not in alias:
				raise ValueError(f"watchlist alias missing {field}")
		if alias["entry_code"] not in entry_codes:
			raise ValueError(f"alias references unknown entry {alias['entry_code']}")
		if alias["reviewed"] is not True:
			raise ValueError(f"alias is not reviewed: {alias.get('alias')}")
		if CAS_PATTERN.search(json.dumps(alias, ensure_ascii=False)):
			raise ValueError(f"CAS Registry Number found in alias {alias.get('alias')}")


def normalize_for_match(value: str) -> str:
	value = (value or "").casefold()
	value = value.replace("α", "alpha").replace("≤", "<=")
	value = re.sub(r"[^a-z0-9]+", " ", value)
	return " ".join(value.split())


def _term_pattern(term: str) -> re.Pattern:
	parts = normalize_for_match(term).split()
	if not parts:
		return re.compile(r"a^")
	if len(parts) == 1 and len(parts[0]) <= 12 and parts[0].isalpha():
		body = r"[\W_]*".join(re.escape(char) for char in parts[0])
	else:
		body = r"[\W_]*".join(re.escape(part) for part in parts)
	return re.compile(rf"(?<![A-Za-z0-9]){body}(?![A-Za-z0-9])", re.IGNORECASE)


def _entries_by_code(watchlist: dict) -> dict:
	return {entry["entry_code"]: entry for entry in watchlist.get("entries", [])}


def _make_flag(entry: dict, term: str, match, flag_type: str, match_method: str, confidence: str, explanation: str) -> dict:
	return {
		"flag_type": flag_type,
		"authority": "OPCW",
		"schedule": entry["schedule"],
		"entry_code": entry["entry_code"],
		"matched_term": term,
		"match_method": match_method,
		"matched_text": match.group(0),
		"span": [match.start(), match.end()],
		"confidence_category": confidence,
		"minimum_priority": "Review",
		"watchlist_version": entry["watchlist_version"],
		"explanation": explanation,
	}


def _dedupe_flags(flags: list) -> list:
	seen = set()
	deduped = []
	for flag in flags:
		key = (flag["flag_type"], flag["entry_code"], normalize_for_match(flag["matched_term"]), tuple(flag["span"]))
		if key not in seen:
			seen.add(key)
			deduped.append(flag)
	return deduped


def match_text(text: str, watchlist: dict = None) -> list:
	watchlist = watchlist or load_watchlist()
	flags = []
	for entry in watchlist.get("entries", []):
		official_terms = [
			term
			for term in entry.get("approved_match_terms", [])
			if term
		]
		for term in official_terms:
			for match in _term_pattern(term).finditer(text or ""):
				flags.append(
					_make_flag(
						entry,
						term,
						match,
						"official_schedule_match",
						"normalized_exact_official_term",
						"confirmed_term_match",
						"Official Schedule 1 entry or explicitly listed example matched; this requires review attention but does not establish malicious intent.",
					)
				)
	entries = _entries_by_code(watchlist)
	for alias in watchlist.get("aliases", []):
		entry = entries[alias["entry_code"]]
		for match in _term_pattern(alias["alias"]).finditer(text or ""):
			flags.append(
				_make_flag(
					entry,
					alias["alias"],
					match,
					"approved_alias_match",
					f"normalized_{alias['alias_type'].replace(' ', '_')}",
					"reviewed_alias_match",
					"Reviewed alias for an OPCW Schedule 1 entry matched; this requires review attention but does not establish malicious intent.",
				)
			)
	for flag in list(flags):
		window_start = max(0, flag["span"][0] - 80)
		window_end = min(len(text or ""), flag["span"][1] + 80)
		window = (text or "")[window_start:window_end]
		if ANALOG_LANGUAGE_PATTERN.search(window):
			entry = entries[flag["entry_code"]]
			flags.append(
				{
					"flag_type": "possible_family_or_analog_reference",
					"authority": "OPCW",
					"schedule": entry["schedule"],
					"entry_code": entry["entry_code"],
					"matched_term": flag["matched_term"],
					"match_method": "explicit_analog_or_family_language_near_match",
					"matched_text": flag["matched_text"],
					"span": flag["span"],
					"confidence_category": "unverified_reference",
					"minimum_priority": "Review",
					"watchlist_version": entry["watchlist_version"],
					"explanation": "The text uses analog, derivative, substitute, or family language near a Schedule 1 term. This is unverified and is not a legal or molecular confirmation.",
				}
			)
	return _dedupe_flags(flags)


def get_watchlist_version(watchlist: dict = None) -> str:
	watchlist = watchlist or load_watchlist()
	return watchlist.get("metadata", {}).get("watchlist_version", NO_WATCHLIST_VERSION)


def has_harmful_behavior_signal(intent: str, indicators) -> bool:
	if (intent or "").lower() == "malicious":
		return True
	for indicator in indicators or []:
		value = (indicator or "").lower()
		if value.startswith(HARMFUL_SIGNAL_PREFIXES):
			return True
		if any(term in value for term in HARMFUL_SIGNAL_TERMS):
			return True
	return False


def watchlist_priority_floor(hard_flags: list, intent: str, indicators) -> tuple[str, str]:
	if not hard_flags:
		return "Low", "No hard-watchlist match."
	if has_harmful_behavior_signal(intent, indicators):
		return "Escalate", "A Schedule 1 hard flag appears with a harmful-behavior or capability-building signal, so the watchlist policy requires Escalate."
	return "Review", "A Schedule 1 hard flag requires at least Review priority, without changing automated intent or numeric score."


def apply_watchlist_priority(existing_priority: str, hard_flags: list, intent: str, indicators) -> tuple[str, str, str]:
	floor, reason = watchlist_priority_floor(hard_flags, intent, indicators)
	final = existing_priority
	if PRIORITY_RANKS[floor] > PRIORITY_RANKS.get(final, 0):
		final = floor
	source = "watchlist policy" if final == floor and floor != "Low" and final != existing_priority else "existing priority policy"
	if final == existing_priority and floor != "Low" and PRIORITY_RANKS[floor] == PRIORITY_RANKS.get(existing_priority, 0):
		source = "both existing policy and watchlist policy"
	return final, source, reason


def build_analysis_watchlist_fields(text: str, intent: str, indicators, existing_priority: str, watchlist: dict = None) -> dict:
	watchlist = watchlist or load_watchlist()
	flags = match_text(text, watchlist)
	version = get_watchlist_version(watchlist)
	final_priority, source, reason = apply_watchlist_priority(existing_priority, flags, intent, indicators)
	return {
		"hard_flags": flags,
		"watchlist_version": version,
		"watchlist_match_count": len(flags),
		"watchlist_policy_version": WATCHLIST_POLICY_VERSION,
		"watchlist_priority_source": source,
		"watchlist_priority_explanation": reason,
		"operational_priority": final_priority,
	}


def strip_cas_numbers(value: str) -> str:
	cleaned = CAS_PATTERN.sub("", value or "")
	cleaned = re.sub(r"\(\s*\)", "", cleaned)
	return " ".join(cleaned.split())


class _ScopedTextParser(HTMLParser):
	def __init__(self):
		super().__init__(convert_charrefs=True)
		self.stack = []
		self.capturing = False
		self.capture_depth = None
		self.candidates = []
		self.title_parts = []
		self.in_title = False
		self._parts = []
		self._attrs = []

	def handle_starttag(self, tag, attrs):
		self.stack.append(tag)
		attr_map = {name: value or "" for name, value in attrs}
		self._attrs.append(attr_map)
		if tag == "title":
			self.in_title = True
		if not self.capturing and tag in ("main", "article"):
			self.capturing = True
			self.capture_depth = len(self.stack)
		if not self.capturing:
			combined = " ".join(attr_map.get(name, "") for name in ("id", "class", "role"))
			if any(token in combined.lower() for token in ("main-content", "main content", "content", "node", "article")):
				self.capturing = True
				self.capture_depth = len(self.stack)

	def handle_endtag(self, tag):
		if tag == "title":
			self.in_title = False
		if tag in ("p", "div", "h1", "h2", "h3", "h4", "li", "tr", "td", "th", "br"):
			self._flush()
		if self.capturing and self.capture_depth == len(self.stack):
			self.capturing = False
			self.capture_depth = None
		if self.stack:
			self.stack.pop()
		if self._attrs:
			self._attrs.pop()

	def handle_data(self, data):
		if self.in_title:
			self.title_parts.append(data)
		if self.capturing:
			self._parts.append(data)

	def _flush(self):
		text = " ".join(" ".join(self._parts).split())
		if text:
			self.candidates.append(text)
		self._parts = []

	def close(self):
		super().close()
		self._flush()


def _article_text_lines(raw_html: str) -> tuple[list, str]:
	parser = _ScopedTextParser()
	parser.feed(raw_html or "")
	parser.close()
	lines = [html.unescape(line).replace("\xa0", " ").strip() for line in parser.candidates]
	lines = [" ".join(line.split()) for line in lines if line.strip()]
	if not any("A. Toxic Chemicals" in line for line in lines):
		lines = _visible_text_from_html(raw_html)
	title = " ".join(" ".join(parser.title_parts).split())
	return lines, title


def _visible_text_from_html(raw_html: str) -> list:
	raw_html = re.sub(r"(?is)<(script|style).*?</\1>", "", raw_html)
	raw_html = re.sub(r"(?i)<br\s*/?>", "\n", raw_html)
	raw_html = re.sub(r"(?i)</(p|div|h1|h2|h3|li|tr)>", "\n", raw_html)
	text = re.sub(r"(?s)<[^>]+>", " ", raw_html)
	lines = [html.unescape(line).strip() for line in text.splitlines()]
	return [" ".join(line.split()) for line in lines if line.strip()]


def _line_contains(line: str, target: str) -> bool:
	return target.casefold() in (line or "").casefold()


def _slice_schedule_1_lines(lines: list) -> list:
	try:
		start = next(index for index, line in enumerate(lines) if _line_contains(line, "A. Toxic Chemicals"))
		precursors = next(index for index, line in enumerate(lines) if index > start and _line_contains(line, "B. Precursors"))
	except StopIteration as exc:
		raise ValueError("Could not locate Schedule 1 section headings") from exc
	end = len(lines)
	for index in range(precursors + 1, len(lines)):
		line = lines[index]
		if index > precursors + 1 and _line_contains(line, "Annex on Chemicals") and not re.match(r"^\(\d+\)", line):
			end = index
			break
	return lines[start:end]


def _entry_type(section: str, number: int, official_text: str) -> str:
	if section == "B":
		return "named_precursor" if number in (11, 12) else "precursor_family"
	if number in (7, 8, 15):
		return "named_toxic_chemical"
	if number in (4, 5, 6):
		return "toxic_chemical_group"
	return "toxic_chemical_family"


def parse_schedule_1_from_html(raw_html: str, source_reference: str = OPCW_SCHEDULE_1_URL) -> dict:
	lines, _ = _article_text_lines(raw_html)
	lines = _slice_schedule_1_lines(lines)
	entry_pattern = re.compile(r"^\((\d+)\)\s*(.*)$")
	entries = []
	current_section = "A"
	current = None
	pending_number = None
	for line in lines:
		if "CAS registry number" in line or "CAS Registry number" in line:
			continue
		if _line_contains(line, "A. Toxic Chemicals"):
			current_section = "A"
			continue
		if _line_contains(line, "B. Precursors"):
			current_section = "B"
			continue
		match = entry_pattern.match(line)
		if match:
			if current:
				entries.append(current)
			number = int(match.group(1))
			remainder = strip_cas_numbers(match.group(2)).strip(" :")
			if not remainder:
				pending_number = number
				current = None
				continue
			current = {
				"entry_code": f"1.{current_section}.{number}",
				"entry_number": number,
				"schedule": "Schedule 1",
				"entry_type": _entry_type(current_section, number, remainder),
				"official_entry_text": remainder,
				"official_examples": [],
				"source_reference": source_reference,
			}
			pending_number = None
		elif current:
			cleaned = strip_cas_numbers(line).strip()
			if cleaned.startswith("e.g."):
				cleaned = cleaned[4:].strip()
			if cleaned:
				current["official_examples"].append(cleaned)
		elif pending_number is not None:
			cleaned = strip_cas_numbers(line).strip(" :")
			if cleaned:
				current = {
					"entry_code": f"1.{current_section}.{pending_number}",
					"entry_number": pending_number,
					"schedule": "Schedule 1",
					"entry_type": _entry_type(current_section, pending_number, cleaned),
					"official_entry_text": cleaned,
					"official_examples": [],
					"source_reference": source_reference,
				}
				pending_number = None
	if current:
		entries.append(current)
	by_number = {}
	for entry in entries:
		number = entry["entry_number"]
		if number in by_number:
			raise ValueError(f"Duplicate Schedule 1 entry number parsed: {number}")
		by_number[number] = entry
	missing = [number for number in EXPECTED_SCHEDULE_1_NUMBERS if number not in by_number]
	if missing:
		raise ValueError(f"Missing Schedule 1 entry numbers: {missing}; parsed {len(by_number)} unique entries")
	if len(by_number) != 16:
		raise ValueError(f"Parsed {len(by_number)} unique Schedule 1 entries; expected exactly 16")
	sorted_entries = [by_number[number] for number in EXPECTED_SCHEDULE_1_NUMBERS]
	return {"entries": sorted_entries}


def fetch_official_pages(fetcher=None) -> dict:
	fetcher = fetcher or _fetch_url
	return {
		"schedule_1": fetcher(OPCW_SCHEDULE_1_URL),
		"changes": fetcher(OPCW_CHANGES_URL),
		"convention": fetcher(OPCW_CONVENTION_URL),
	}


def _fetch_url(url: str) -> str:
	return fetch_url_with_diagnostics(url)["body"]


def fetch_url_with_diagnostics(url: str) -> dict:
	request = urllib.request.Request(url, headers={"User-Agent": "CBRN-safeguards-prototype/1.0"})
	with urllib.request.urlopen(request, timeout=30) as response:
		body = response.read()
		text = body.decode("utf-8", errors="replace")
		return {
			"url": url,
			"status_code": response.getcode(),
			"final_url": response.geturl(),
			"content_type": response.headers.get("Content-Type", ""),
			"body_length": len(body),
			"body": text,
		}


def diagnose_schedule_1_response(response: dict) -> dict:
	body = response.get("body", "")
	lines, title = _article_text_lines(body)
	candidate_markers = re.findall(r"\(\s*(?:[1-9]|1[0-6])\s*\)", " ".join(lines))
	contains = {
		"A. Toxic Chemicals": "A. Toxic Chemicals" in body,
		"B. Precursors": "B. Precursors" in body,
		"(1)": "(1)" in body,
		"(16)": "(16)" in body,
	}
	lower = body.casefold()
	if contains["A. Toxic Chemicals"] and contains["B. Precursors"] and contains["(1)"]:
		response_kind = "real_opcw_page"
	elif "access denied" in lower or "forbidden" in lower or "captcha" in lower:
		response_kind = "access_denied_or_challenge"
	elif "consent" in lower and "cookie" in lower:
		response_kind = "consent_page"
	else:
		response_kind = "unexpected_response"
	return {
		"http_status_code": response.get("status_code"),
		"final_url": response.get("final_url"),
		"content_type": response.get("content_type"),
		"response_body_length": response.get("body_length"),
		"page_title": title,
		"contains": contains,
		"candidate_numbered_entry_markers": len(candidate_markers),
		"response_kind": response_kind,
	}


def official_dataset_from_pages(pages: dict, base_watchlist: dict) -> dict:
	parsed = parse_schedule_1_from_html(pages["schedule_1"])
	if "7 June 2020" not in pages.get("changes", "") and "7 June 2020" not in pages.get("convention", ""):
		raise ValueError("Could not verify Schedule 1 amendment effective date in official pages")
	updated = copy.deepcopy(base_watchlist)
	metadata = updated["metadata"]
	metadata["retrieved_at"] = utc_now()
	metadata["source_hash"] = hashlib.sha256(pages["schedule_1"].encode("utf-8")).hexdigest()
	parsed_by_code = {entry["entry_code"]: entry for entry in parsed["entries"]}
	for entry in updated["entries"]:
		if entry["entry_code"] in parsed_by_code:
			entry["official_entry_text"] = parsed_by_code[entry["entry_code"]]["official_entry_text"]
			entry["official_examples"] = parsed_by_code[entry["entry_code"]]["official_examples"]
			entry["retrieved_at"] = metadata["retrieved_at"]
	validate_watchlist(updated)
	return updated


def diff_watchlists(local_data: dict, fetched_data: dict) -> str:
	local_entries = {entry["entry_code"]: entry for entry in local_data.get("entries", [])}
	fetched_entries = {entry["entry_code"]: entry for entry in fetched_data.get("entries", [])}
	lines = []
	additions = sorted(set(fetched_entries) - set(local_entries))
	removals = sorted(set(local_entries) - set(fetched_entries))
	if additions:
		lines.append("Additions: " + ", ".join(additions))
	if removals:
		lines.append("Removals: " + ", ".join(removals))
	for code in sorted(set(local_entries) & set(fetched_entries)):
		local_text = local_entries[code].get("official_entry_text", "")
		fetched_text = fetched_entries[code].get("official_entry_text", "")
		if local_text != fetched_text:
			lines.append(f"Changed official entry text for {code}:")
			lines.extend(difflib.unified_diff([local_text], [fetched_text], fromfile="local", tofile="fetched", lineterm=""))
	if not lines:
		return "No official Schedule 1 entry changes detected."
	return "\n".join(lines)


def run_update_check(path=DEFAULT_WATCHLIST_PATH, fetcher=None) -> tuple[str, dict]:
	local_data = load_watchlist(path)
	pages = fetch_official_pages(fetcher=fetcher)
	fetched_data = official_dataset_from_pages(pages, local_data)
	return diff_watchlists(local_data, fetched_data), fetched_data


def apply_update(path=DEFAULT_WATCHLIST_PATH, fetcher=None) -> str:
	local_data = load_watchlist(path)
	diff_text, fetched_data = run_update_check(path, fetcher=fetcher)
	fetched_data["aliases"] = local_data.get("aliases", [])
	validate_watchlist(fetched_data)
	path = Path(path).resolve()
	backup = path.with_suffix(path.suffix + ".bak")
	backup.write_text(json.dumps(local_data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
	temp_path = path.with_suffix(path.suffix + ".tmp")
	temp_path.write_text(json.dumps(fetched_data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
	validate_watchlist(json.loads(temp_path.read_text(encoding="utf-8")))
	try:
		temp_path.replace(path)
	except PermissionError:
		path.unlink()
		temp_path.replace(path)
	return diff_text


def main(argv=None) -> int:
	parser = argparse.ArgumentParser(description="Check or update the local OPCW Schedule 1 watchlist.")
	parser.add_argument("--check", action="store_true", help="Fetch official OPCW pages and report differences without writing.")
	parser.add_argument("--apply", action="store_true", help="Explicitly update official source fields in the local watchlist.")
	parser.add_argument("--diagnose", action="store_true", help="Print concise diagnostics for the official Schedule 1 response.")
	parser.add_argument("--path", default=str(DEFAULT_WATCHLIST_PATH), help="Local watchlist path.")
	args = parser.parse_args(argv)
	if sum(1 for item in (args.apply, args.check, args.diagnose) if item) > 1:
		parser.error("choose only one of --check, --apply, or --diagnose")
	try:
		if args.diagnose:
			response = fetch_url_with_diagnostics(OPCW_SCHEDULE_1_URL)
			print(json.dumps(diagnose_schedule_1_response(response), indent=2, ensure_ascii=False))
			return 0
		if not args.apply:
			diff_text, _ = run_update_check(args.path)
			print(diff_text)
			return 0
		diff_text = apply_update(args.path)
		print(diff_text)
		return 0
	except Exception as exc:
		print(f"OPCW watchlist update failed: {exc}", file=sys.stderr)
		return 2


if __name__ == "__main__":
	raise SystemExit(main())
