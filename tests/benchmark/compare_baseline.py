#!/usr/bin/env python3
"""
Cobalto SOC/MDR — Baseline Comparison Script

Compares benchmark results against stored baselines and reports
regressions. Used by both local runner and CI pipeline.

Usage:
    # Compare results against baseline
    compare_baseline.py --baseline baselines/v1.json \\
        --results-dir reports/ --timestamp 20260706T120000

    # Update baseline with latest results
    compare_baseline.py --results-dir reports/ --timestamp 20260706T120000 \\
        --update-baseline baselines/v1.json
"""

import argparse
import json
import os
import sys
from pathlib import Path


# ── Helpers ──────────────────────────────────────────────────────────────────

def load_json(path: str) -> dict:
    """Load and validate a JSON file."""
    with open(path) as f:
        return json.load(f)


def find_result_file(results_dir: str, test_name: str, timestamp: str) -> str | None:
    """Find the result file for a given test and timestamp."""
    pattern = f"{test_name}-{timestamp}.json"
    for f in os.listdir(results_dir):
        # Also match k6 summary export files
        if f == pattern or f == f"{test_name}-{timestamp}.json.summary":
            return os.path.join(results_dir, f)
    return None


def extract_metric(summary: dict, test_name: str, metric_name: str) -> float | None:
    """Extract a metric from k6 summary export."""
    # k6 summary export format
    metrics = summary.get("metrics", summary)
    if metric_name in metrics:
        data = metrics[metric_name]
        if isinstance(data, dict):
            # Try p(X) values
            for key in ("p(50)", "p(95)", "p(99)", "avg", "max"):
                if key in data:
                    return data[key]
            return data.get("value")
    return None


def extract_thresholds(summary: dict) -> dict:
    """Extract all relevant metrics from a k6 summary export."""
    result = {}
    metrics = summary.get("metrics", summary)

    # HTTP metrics
    for metric_key in ("http_req_duration",):
        if metric_key in metrics:
            d = metrics[metric_key]
            result[f"{metric_key}_avg"] = d.get("avg")
            result[f"{metric_key}_p50"] = d.get("p(50)")
            result[f"{metric_key}_p95"] = d.get("p(95)")
            result[f"{metric_key}_p99"] = d.get("p(99)")
            result[f"{metric_key}_max"] = d.get("max")
            result[f"{metric_key}_min"] = d.get("min")

    # Custom metrics (cobalto_*)
    for metric_key, metric_data in metrics.items():
        if metric_key.startswith("cobalto_") and isinstance(metric_data, dict):
            if "p(95)" in metric_data:
                result[f"{metric_key}_p95"] = metric_data.get("p(95)")
            if "p(50)" in metric_data:
                result[f"{metric_key}_p50"] = metric_data.get("p(50)")
            if "p(99)" in metric_data:
                result[f"{metric_key}_p99"] = metric_data.get("p(99)")
            if "avg" in metric_data:
                result[f"{metric_key}_avg"] = metric_data.get("avg")
            if "rate" in metric_data and not metric_key.endswith("_rate"):
                result[f"{metric_key}_rate"] = metric_data.get("rate")

    # Failure rate
    if "http_req_failed" in metrics:
        result["failure_rate"] = metrics["http_req_failed"].get("rate", 0)

    return result


def compare_metric(
    test_name: str,
    metric_name: str,
    current_value: float,
    baseline_value: float,
    tolerance_pct: float,
    thresholds: dict,
) -> list[str]:
    """Compare a single metric against its baseline. Returns list of warnings."""
    warnings = []
    if current_value is None or baseline_value is None:
        return warnings

    if baseline_value <= 0:
        return warnings

    ratio = current_value / baseline_value
    regression_pct = (ratio - 1.0) * 100

    if regression_pct > tolerance_pct:
        warnings.append(
            f"  ✗ {test_name}/{metric_name}: {current_value:.1f}ms "
            f"(baseline: {baseline_value:.1f}ms, "
            f"regression: +{regression_pct:.1f}%, "
            f"tolerance: +{tolerance_pct:.0f}%)"
        )
    elif regression_pct > tolerance_pct * 0.5:
        warnings.append(
            f"  ⚠ {test_name}/{metric_name}: {current_value:.1f}ms "
            f"(baseline: {baseline_value:.1f}ms, "
            f"regression: +{regression_pct:.1f}%, "
            f"within tolerance +{tolerance_pct:.0f}%)"
        )
    else:
        print(
            f"  ✓ {test_name}/{metric_name}: {current_value:.1f}ms "
            f"(baseline: {baseline_value:.1f}ms, "
            f"change: {regression_pct:+.1f}%)"
        )
    return warnings


def compare_failure_rate(
    test_name: str,
    current_rate: float | None,
    baseline_max_rate: float,
) -> list[str]:
    """Compare failure rate against maximum allowed."""
    warnings = []
    if current_rate is None:
        return warnings

    if current_rate > baseline_max_rate:
        warnings.append(
            f"  ✗ {test_name}/failure_rate: {current_rate*100:.2f}% "
            f"(max allowed: {baseline_max_rate*100:.2f}%)"
        )
    else:
        print(
            f"  ✓ {test_name}/failure_rate: {current_rate*100:.2f}% "
            f"(max: {baseline_max_rate*100:.2f}%)"
        )
    return warnings


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Compare benchmark results against baselines"
    )
    parser.add_argument(
        "--baseline",
        help="Baseline JSON file path",
    )
    parser.add_argument(
        "--results-dir",
        required=True,
        help="Directory containing benchmark result files",
    )
    parser.add_argument(
        "--timestamp",
        required=True,
        help="Timestamp of the benchmark run (format: YYYYMMDDTHHMMSS)",
    )
    parser.add_argument(
        "--update-baseline",
        help="Update the baseline file with current results",
    )
    parser.add_argument(
        "--summary",
        help="Path to write the summary JSON file",
    )
    args = parser.parse_args()

    results_dir = args.results_dir
    timestamp = args.timestamp
    all_warnings: list[str] = []

    # ── Load baseline ──────────────────────────────────────────────────
    baseline = {}
    if args.baseline:
        baseline = load_json(args.baseline)
        print(f"\nLoaded baseline: {args.baseline}")
        print(f"  Version: {baseline.get('version')}")
        print(f"  Established: {baseline.get('metadata', {}).get('established')}")
    else:
        print("\nNo baseline provided — extracting metrics only")

    # ── Load current results ───────────────────────────────────────────
    test_results = {}
    test_names = ["health_check", "auth_burst", "alert_ingestion", "agent_latency"]

    for test_name in test_names:
        result_file = find_result_file(results_dir, test_name, timestamp)
        if not result_file:
            print(f"  [SKIP] {test_name}: no result file found")
            continue

        summary = load_json(result_file)
        metrics = extract_thresholds(summary)
        test_results[test_name] = metrics

        # Compare failure rate
        baseline_thresholds = baseline.get("thresholds", {}).get(test_name, {})
        max_failure_rate = baseline_thresholds.get("max_failure_rate", 0.05)

        warnings = compare_failure_rate(
            test_name,
            metrics.get("failure_rate"),
            max_failure_rate,
        )
        all_warnings.extend(warnings)

        # Compare metrics
        if args.baseline and test_name in baseline.get("thresholds", {}):
            test_baseline = baseline["thresholds"][test_name]
            tolerance = test_baseline.get("regression_tolerance_pct", 20)

            for metric_key in ("p50_ms", "p95_ms", "p99_ms", "avg_ms", "max_ms"):
                # Map baseline key to current metrics key
                current_key = f"http_req_duration_{metric_key}"
                current_val = metrics.get(current_key)

                if current_val is None:
                    # Try custom metric keys
                    custom_key_map = {
                        "alert_ingestion": "cobalto_ingestion_latency",
                        "agent_latency": "cobalto_latency_all",
                        "auth_burst": "cobalto_auth_login_latency",
                        "health_check": "cobalto_health_latency",
                    }
                    custom_key = custom_key_map.get(test_name)
                    if custom_key:
                        current_val = metrics.get(
                            f"{custom_key}_{metric_key.replace('_ms', '')}"
                        )

                # Also try baseline key directly
                if current_val is None:
                    # Direct key match
                    for mkey, mval in metrics.items():
                        if metric_key.replace("_ms", "") in mkey:
                            current_val = mval
                            break

                baseline_val = test_baseline.get(metric_key) or test_baseline.get(
                    metric_key.replace("_ms", "")
                )

                if baseline_val is not None:
                    warnings = compare_metric(
                        test_name, metric_key, current_val, baseline_val, tolerance, {}
                    )
                    all_warnings.extend(warnings)

    # ── Update baseline ────────────────────────────────────────────────
    if args.update_baseline:
        if not test_results:
            print("ERROR: No test results to update baseline with")
            sys.exit(1)

        # Preserve metadata, update thresholds with observed values
        updated_baseline = {
            "version": baseline.get("version", 1) + 1 if baseline else 1,
            "metadata": {
                "comment": f"Updated from benchmark run at {timestamp}",
                "established": timestamp[:8],
                "environment": os.environ.get(
                    "COBALTO_BENCH_ENV", "manual"
                ),
            },
            "thresholds": {},
            "alerts": baseline.get("alerts", {
                "regression_warning_pct": 15,
                "regression_fail_pct": 20,
                "max_consecutive_regressions": 3,
            }),
        }

        for test_name, metrics in test_results.items():
            updated_baseline["thresholds"][test_name] = {
                "description": f"Updated at {timestamp}",
                "regression_tolerance_pct": 20,
                "max_failure_rate": 0.01,
            }
            # Store observed p95 as baseline
            for key, val in metrics.items():
                if "_p95" in key and val is not None:
                    clean_key = key.replace("http_req_duration_", "").replace("_p95", "_ms")
                    updated_baseline["thresholds"][test_name][clean_key] = round(val, 1)

        with open(args.update_baseline, "w") as f:
            json.dump(updated_baseline, f, indent=2)
        print(f"\nBaseline updated: {args.update_baseline}")

    # ── Write summary ──────────────────────────────────────────────────
    summary_data = {
        "timestamp": timestamp,
        "baseline": args.baseline,
        "results": test_results,
        "warnings": all_warnings,
        "passed": len(all_warnings) == 0,
    }

    if args.summary:
        with open(args.summary, "w") as f:
            json.dump(summary_data, f, indent=2)

    # ── Report ─────────────────────────────────────────────────────────
    print(f"\n{'=' * 60}")
    print("Baseline Comparison Results")
    print(f"{'=' * 60}")

    if all_warnings:
        print("\nRegressions detected:")
        for w in all_warnings:
            print(w)
        print(f"\n❌ {len(all_warnings)} metric(s) exceeded tolerance")
        sys.exit(1)
    else:
        print("\n✅ All metrics within baseline thresholds")
        sys.exit(0)


if __name__ == "__main__":
    main()
