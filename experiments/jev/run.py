#!/usr/bin/env python3
"""Run a non-customer source directory or the Jev pilot through staging Gateway."""

import argparse
import csv
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def main():
    experiment = Path(__file__).resolve().parent
    repo = experiment.parent.parent
    workspace = repo.parent / "benchmark-workspace"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--prompts", type=Path, default=experiment / "prompts/v1.json")
    parser.add_argument("--binary", type=Path, default=repo / "bin/datadog-saist-prefilter-jev")
    inputs = parser.add_mutually_exclusive_group()
    inputs.add_argument("--pilot", type=Path, help="Prepared pilot; defaults to benchmark-workspace/jev-pilot")
    inputs.add_argument("--directory", type=Path, help="Repository or source directory; non-customer data only")
    parser.add_argument("--max-files", type=int, default=0, help="Directory mode: first N candidate files; zero means all")
    parser.add_argument("--rules-json", type=Path,
                        default=workspace / "prefilter-results/2026-09-28-go-catalog/go-rules.json")
    parser.add_argument("--model", default="typesafe/jev-latest")
    parser.add_argument("--threshold", type=float, default=0.1)
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument("--cases", nargs="+")
    scope.add_argument("--all", action="store_true", help="Run all 50 file revisions")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", args.run_id):
        parser.error("run ID must contain only letters, numbers, underscores, or hyphens")
    if not 0 <= args.threshold <= 1:
        parser.error("threshold must be between 0 and 1")
    if not args.binary.is_file():
        parser.error("build bin/datadog-saist-prefilter-jev first")
    if args.max_files < 0 or (args.max_files and not args.directory):
        parser.error("--max-files must be nonnegative and is only supported with --directory")
    if args.directory and args.cases:
        parser.error("--cases is only supported for the prepared pilot")
    if os.environ.get("DATADOG_DRIVER_ENABLED") == "true":
        parser.error("unset DATADOG_DRIVER_ENABLED for local experiments")
    prompts = json.loads(args.prompts.read_text())
    rules = json.loads(args.rules_json.read_text())["rules"]
    if any(not isinstance(prompts.get(rule["id"]), str) or not prompts[rule["id"]].strip() for rule in rules):
        parser.error("provide a nonempty prompt for every rule")
    expected = {}
    if args.directory:
        root = args.directory.resolve()
        if not root.is_dir():
            parser.error("--directory must be an existing directory")
        discovery = subprocess.run(
            [str(args.binary.resolve()), "--directory", str(root), "--rules-json", str(args.rules_json.resolve()),
             "--prefilter", "none", "--max-files", str(args.max_files)],
            capture_output=True, text=True, timeout=180)
        if discovery.returncode:
            parser.error(f"offline discovery failed: {discovery.stderr.strip()}")
        discovered = [json.loads(line) for line in discovery.stdout.splitlines() if line.strip()]
        if not discovered or discovered[-1].get("type") != "summary":
            parser.error("offline discovery did not complete")
        for row in discovered:
            if row["type"] == "decision":
                decision = row["decision"]
                expected.setdefault(decision["path"], {})[decision["rule_id"]] = decision
        selected = sorted(expected)
        if not selected:
            parser.error("no candidate files for the selected rules")
        roots = [root] * len(selected)
        scope_notes = f"directory={root}"
        print(f"{len(selected)} candidate files, {sum(map(len, expected.values()))} file/rule pairs", flush=True)
    else:
        pilot = args.pilot or workspace / "jev-pilot"
        downloads = json.loads((pilot / "downloads.json").read_text())
        if not downloads.get("complete") or downloads.get("errors"):
            parser.error("pilot downloads are incomplete")
        cases = {item["id"]: item for item in json.loads((pilot / "manifest.json").read_text())["files"]}
        selected = sorted(cases) if args.all else (args.cases or ["case-001-a", "case-001-b"])
        if len(set(selected)) != len(selected) or any(case not in cases for case in selected):
            parser.error("case IDs must be unique and present in the pilot manifest")
        roots = []
        for case in selected:
            root = (pilot / "sources" / case).resolve()
            source = (pilot / cases[case]["local_path"]).resolve()
            if root.parent != (pilot / "sources").resolve() or not source.is_relative_to(root) or not source.is_file():
                parser.error(f"invalid or missing source for {case}")
            roots.append(root)
        scope_notes = f"pilot={pilot.resolve()}"
    output = experiment / "results" / f"{args.run_id}.jsonl"
    models, completed = set(), []
    status, notes = "failed", ""
    started = datetime.now(timezone.utc).isoformat()
    with output.open("x") as handle, tempfile.TemporaryDirectory(prefix="saist-jev-") as temporary:
        try:
            for case, root in zip(selected, roots):
                print(f"{case}: staging Jev, {args.prompts.name}", flush=True)
                auth = subprocess.run(
                    ["ddtool", "auth", "token", "rapid-ai-platform", "--datacenter", "us1.staging.dog"],
                    capture_output=True, text=True, timeout=30)
                if auth.returncode or not auth.stdout.strip():
                    raise RuntimeError("staging ddtool authentication failed; check your login")
                env = dict(os.environ, OPENAI_BEARER_TOKEN=auth.stdout.strip())
                extra = []
                if args.directory:
                    driver = Path(temporary) / "driver.json"
                    driver.write_text(json.dumps({"files": {case: sorted(expected[case])}}))
                    extra = ["--driver", str(driver)]
                result = subprocess.run(
                    [str(args.binary.resolve()), "--directory", str(root), "--rules-json", str(args.rules_json.resolve()),
                     "--prefilter", "jev", "--questions", str(args.prompts.resolve()),
                     "--jev-model", args.model, "--threshold", str(args.threshold), *extra],
                    env=env, capture_output=True, text=True, timeout=180)
                rows = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
                for row in rows:
                    if row.get("type") == "manifest":
                        row["input_directory"] = str(root)
                    handle.write(json.dumps(dict(row, case_id=case)) + "\n")
                    if row.get("type") == "file" and row.get("model"):
                        models.add(row["model"])
                handle.flush()
                print(result.stderr, end="", file=sys.stderr)
                if result.returncode or not rows or rows[-1].get("type") != "summary":
                    raise RuntimeError(f"{case} failed; see saved decisions and command errors")
                summary = rows[-1]["summary"]
                expected_count = len(expected[case]) if args.directory else len(rules)
                if summary["candidate_files"] != 1 or summary["candidate_pairs"] != expected_count or summary["error_pairs"]:
                    raise RuntimeError(f"{case} did not produce the expected complete file/rule scores")
                if args.directory:
                    decisions = [row["decision"] for row in rows if row["type"] == "decision"]
                    if len(decisions) != expected_count or {d["rule_id"] for d in decisions} != set(expected[case]):
                        raise RuntimeError(f"{case}: candidate rules changed after offline discovery")
                    for decision in decisions:
                        original = expected[case][decision["rule_id"]]
                        if any(decision[field] != original[field] for field in ("path", "file_hash", "rule_hash", "language")):
                            raise RuntimeError(f"{case}: inputs changed after offline discovery")
                completed.append(case)
            status = "completed"
        except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired, KeyboardInterrupt) as exc:
            status = "partial" if completed else "failed"
            notes = str(exc) or "interrupted"
            print(notes, file=sys.stderr)
        finally:
            with (experiment / "runs.csv").open("a", newline="") as index:
                csv.writer(index).writerow([
                    args.run_id, started, str(args.prompts.resolve()), args.model, ";".join(sorted(models)),
                    args.threshold, ";".join(selected), str(output.relative_to(repo)), status,
                    f"staging; {scope_notes}; completed {len(completed)}/{len(selected)} files; {notes}"])
    print(f"{status}: {output}")
    return 0 if status == "completed" else 1


if __name__ == "__main__":
    sys.exit(main())
