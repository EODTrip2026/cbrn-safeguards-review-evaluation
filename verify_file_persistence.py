import contextlib
import io
import time
from pathlib import Path
from uuid import uuid4

import main
import storage


def database_files(path: Path):
	return [
		path,
		Path(str(path) + "-wal"),
		Path(str(path) + "-shm"),
		Path(str(path) + "-journal"),
	]


def remove_database_files(path: Path) -> None:
	for candidate in database_files(path):
		for attempt in range(3):
			try:
				candidate.unlink()
				break
			except FileNotFoundError:
				break
			except PermissionError:
				if attempt == 2:
					raise
				time.sleep(0.1)


def main_verify():
	root = Path(".manual_verification")
	root.mkdir(exist_ok=True)
	run_id = uuid4().hex
	db_path = root / f"stage4_file_persistence_{run_id}.db"
	cli_db_path = root / f"stage4_reports_import_{run_id}.db"

	try:
		storage.initialize_database(str(db_path))
		case_id = storage.create_or_get_case(
			str(db_path),
			"Routine lab safety inspection completed",
			source="manual_verification",
			external_id="stage4-1",
		)
		analysis = main.analyze_report({"text": "Routine lab safety inspection completed"}, rule_only=True)
		analysis_id = storage.save_automated_analysis(str(db_path), case_id, analysis, analysis_method="rules")
		reopened = storage.get_case_with_history(str(db_path), case_id)
		repeated_case_id = storage.create_or_get_case(
			str(db_path),
			"Routine lab safety inspection completed",
			source="manual_verification",
			external_id="stage4-1",
		)
		repeated_analysis_id = storage.save_automated_analysis(str(db_path), repeated_case_id, analysis, analysis_method="rules")
		counts = storage.summarize_records(str(db_path))

		with contextlib.redirect_stdout(io.StringIO()):
			main.load_and_print("reports.csv", db_path=str(cli_db_path), rule_only=True)
		first_import = storage.summarize_records(str(cli_db_path))
		with contextlib.redirect_stdout(io.StringIO()):
			main.load_and_print("reports.csv", db_path=str(cli_db_path), rule_only=True)
		second_import = storage.summarize_records(str(cli_db_path))

		print("single_case:", {
			"case_id": case_id,
			"analysis_id": analysis_id,
			"reopened": reopened is not None,
			"repeated_case_id": repeated_case_id,
			"repeated_analysis_id": repeated_analysis_id,
			"counts": counts,
		})
		print("reports_import_first:", first_import)
		print("reports_import_second:", second_import)
	finally:
		remove_database_files(db_path)
		remove_database_files(cli_db_path)
		try:
			root.rmdir()
		except OSError:
			pass


if __name__ == "__main__":
	main_verify()
