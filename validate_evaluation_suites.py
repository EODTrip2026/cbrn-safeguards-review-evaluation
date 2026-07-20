import argparse
import sys

import evaluation


def main() -> int:
	parser = argparse.ArgumentParser(description="Validate versioned synthetic evaluation suites.")
	parser.add_argument("--suite", choices=[evaluation.LEGACY_SUITE_ID, "safeguards-eval-v1", "all"], default="all")
	args = parser.parse_args()
	suite_ids = [evaluation.LEGACY_SUITE_ID, "safeguards-eval-v1"] if args.suite == "all" else [args.suite]
	ok = True
	for suite_id in suite_ids:
		try:
			suite = evaluation.load_suite(suite_id)
			inspection = evaluation.suite_inspection(suite)
			print(f"{suite_id}: valid")
			print(f"  version: {inspection['suite_version']}")
			print(f"  cases: {inspection['case_count']}")
			print(f"  dataset_hash: {inspection['dataset_hash']}")
			print(f"  label_status_counts: {inspection['label_status_counts']}")
			if inspection["noncanonical_labels"]:
				print(f"  noncanonical_labels: {inspection['noncanonical_labels']}")
		except Exception as exc:
			ok = False
			print(f"{suite_id}: invalid: {exc}", file=sys.stderr)
	return 0 if ok else 1


if __name__ == "__main__":
	raise SystemExit(main())
