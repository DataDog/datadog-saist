#!/usr/bin/env python3
"""
LLMObs evaluation runner for datadog-saist.

Replaces the ddeval CLI (which requires internal Datadog packages from
binaries.ddbuild.io) with a self-contained script that only depends on
public PyPI packages (ddtrace>=4.8.4).

Flow:
  1. Load dataset records from the local k9-saist-benchmark.json file
     (checked out from the datadog-saist-evals repo).
  2. For each record, invoke the datadog-saist-evals binary using the same
     CLI flags that SAISTEvalsExecutor.execute_single uses internally.
  3. Read the JSON report written to --json-output and compute scores,
     replicating the evaluator.py logic.
  4. Submit scores to LLMObs via ddtrace.

Environment variables (required):
  DD_API_KEY       Datadog API key
  DD_APP_KEY       Datadog application key
  DD_SITE          Datadog site (e.g. datadoghq.com)
  DETECTION_MODEL  Model name for detection and validation
  EVALS_BIN        Absolute path to the datadog-saist-evals binary
  SAIST_BIN        Absolute path to the datadog-saist binary
  EVALS_ROOT       Absolute path to the datadog-saist-evals repo root
"""

import json
import logging
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from ddtrace.llmobs import LLMObs

DD_API_KEY = os.environ["DD_API_KEY"]
DD_SITE = os.environ.get("DD_SITE") or "datadoghq.com"
DETECTION_MODEL = os.environ["DETECTION_MODEL"]
EVALS_BIN = os.environ["EVALS_BIN"]
SAIST_BIN = os.environ["SAIST_BIN"]
EVALS_ROOT = Path(os.environ["EVALS_ROOT"])

ML_APP = "k9-saist"
DATASET_PATH = EVALS_ROOT / "eval" / "datasets" / "k9-saist-benchmark.json"
FILE_CONCURRENCY = 50
EXECUTOR_TIMEOUT_SECS = 3600

# Set to a repo name to run only that record (useful for local testing).
# Set to None or empty string to run all records.
FILTER_REPO = os.environ.get("FILTER_REPO", "")


def init_llmobs():
    # Silence the APM tracer's "failed to send" warnings — there is no local
    # agent, but LLMObs uses its own agentless writer and is unaffected.
    logging.getLogger("ddtrace").setLevel(logging.CRITICAL)

    print(f"[llmobs] Initializing: ml_app={ML_APP} site={DD_SITE} agentless=True")
    LLMObs.enable(
        ml_app=ML_APP,
        agentless_enabled=True,
        api_key=DD_API_KEY,
        site=DD_SITE,
    )
    print("[llmobs] Initialized successfully")


def load_dataset() -> list:
    with open(DATASET_PATH) as f:
        return json.load(f)


def run_executor(record: dict) -> dict:
    """
    Invoke the datadog-saist-evals binary for a single dataset record.

    Mirrors SAISTEvalsExecutor.execute_single: passes CLI flags, reads the
    JSON report written to --json-output.
    """
    input_data = record["input"]
    repo = input_data["repo"]
    vulnerabilities = input_data.get("vulnerabilities", [])

    with tempfile.TemporaryDirectory(prefix="saist-eval-") as tmpdir:
        json_output = Path(tmpdir) / "result.json"
        cmd = [
            EVALS_BIN,
            "--repo", repo,
            "--detection-model", DETECTION_MODEL,
            "--validation-model", DETECTION_MODEL,
            "--saist-bin", SAIST_BIN,
            "--json-output", str(json_output),
            "--file-concurrency", str(FILE_CONCURRENCY),
        ]
        if vulnerabilities:
            cmd.extend(["--vulnerabilities", ",".join(vulnerabilities)])

        completed = subprocess.run(
            cmd,
            cwd=str(EVALS_ROOT),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=EXECUTOR_TIMEOUT_SECS,
        )
        print(completed.stdout)
        if completed.returncode != 0:
            raise RuntimeError(
                f"datadog-saist-evals failed (exit {completed.returncode})"
            )

        with open(json_output) as f:
            return json.load(f)


def compute_scores(output: dict, expected_output: dict) -> dict:
    """
    Compute evaluation scores from the binary's JSON output.
    Replicates the logic in eval/projects/k9-saist/evaluator.py.
    """
    precision = float(output.get("precision", 0.0))
    recall = float(output.get("recall", 0.0))
    f1 = float(output.get("f1", 0.0))
    false_positives = int(output.get("false_positives", 0))
    false_negatives = int(output.get("false_negatives", 0))
    execution_failures = int(output.get("execution_failures", 0))
    duration_seconds = float(output.get("duration_seconds", 0.0))
    expected_positives = int(output.get("expected_positives", 0))

    threshold_pass = True
    min_recall = expected_output.get("min_recall")
    if min_recall is not None and recall < float(min_recall):
        threshold_pass = False
    min_f1 = expected_output.get("min_f1")
    if min_f1 is not None and f1 < float(min_f1):
        threshold_pass = False
    max_fp = expected_output.get("max_false_positives")
    if max_fp is not None and false_positives > int(max_fp):
        threshold_pass = False
    max_ef = expected_output.get("max_execution_failures")
    if max_ef is not None and execution_failures > int(max_ef):
        threshold_pass = False

    ep_expected = expected_output.get("expected_positives")
    expected_positives_match = (
        ep_expected is None or expected_positives == int(ep_expected)
    )

    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positives": float(false_positives),
        "false_negatives": float(false_negatives),
        "execution_failures": float(execution_failures),
        "duration_seconds": duration_seconds,
        "threshold_pass": "pass" if threshold_pass else "fail",
        "expected_positives_match": "pass" if expected_positives_match else "fail",
    }


def submit_evaluations(record: dict, scores: dict, span_context: dict):
    """Submit per-record scores to LLMObs."""
    repo = record["input"]["repo"]
    tags = {
        "detection_model": DETECTION_MODEL,
        "repo": repo,
        "sha": os.environ.get("GITHUB_SHA", ""),
    }

    print(f"[llmobs] Submitting {len(scores)} evaluations for repo={repo}")
    print(f"[llmobs]   span_id={span_context['span_id']} trace_id={span_context['trace_id']}")
    print(f"[llmobs]   tags={tags}")

    for label, value in scores.items():
        metric_type = "categorical" if isinstance(value, str) else "score"
        print(f"[llmobs]   submit_evaluation label={label} metric_type={metric_type} value={value}")
        try:
            LLMObs.submit_evaluation(
                span=span_context,
                ml_app=ML_APP,
                label=label,
                metric_type=metric_type,
                value=value,
                tags=tags,
            )
            print(f"[llmobs]   -> ok")
        except Exception as e:
            print(f"[llmobs]   -> ERROR: {e}", file=sys.stderr)


def process_record(record: dict) -> bool:
    repo = record["input"]["repo"]
    print(f"\n--- repo={repo} model={DETECTION_MODEL} ---")

    # Create a real LLMObs task span so evaluations have a valid span to link to.
    with LLMObs.task(name=f"saist.eval.{repo}") as task_span:
        span_context = LLMObs.export_span(span=task_span)
        print(f"[llmobs] Created span: span_id={span_context['span_id']} trace_id={span_context['trace_id']}")
        try:
            output = run_executor(record)
            scores = compute_scores(output, record.get("expected_output", {}))
        except Exception as e:
            print(f"  ERROR: {e}", file=sys.stderr)
            return False

    # Span is finished here — flush it before submitting evaluations so it's
    # ingested in Datadog before the eval processor tries to look it up.
    print(f"[llmobs] Flushing span...")
    LLMObs.flush()
    print(f"[llmobs] Flush complete")

    submit_evaluations(record, scores, span_context)

    print(f"[llmobs] Flushing evaluations...")
    LLMObs.flush()
    print(f"[llmobs] Flush complete")

    print(
        f"  precision={scores['precision']:.2f}"
        f"  recall={scores['recall']:.2f}"
        f"  f1={scores['f1']:.2f}"
        f"  threshold_pass={scores['threshold_pass']}"
    )
    return True


def main():
    init_llmobs()

    records = load_dataset()
    if FILTER_REPO:
        records = [r for r in records if r["input"]["repo"] == FILTER_REPO]
        if not records:
            print(f"ERROR: no record found for repo '{FILTER_REPO}'", file=sys.stderr)
            sys.exit(1)
    print(f"Loaded {len(records)} record(s) from {DATASET_PATH}")

    successes = 0
    errors = 0
    for record in records:
        if process_record(record):
            successes += 1
        else:
            errors += 1

    print(f"\nFinished: {successes} succeeded, {errors} failed out of {len(records)} records.")
    sys.exit(1 if errors > 0 else 0)


if __name__ == "__main__":
    main()
