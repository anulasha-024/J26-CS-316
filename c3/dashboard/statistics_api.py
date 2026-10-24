from pathlib import Path
from collections import Counter
from statistics import mean
import json
import math

from flask import Blueprint, jsonify


statistics_bp = Blueprint(
    "n3_statistics",
    __name__
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REPORTS_DIR = PROJECT_ROOT / "reports"

VERDICTS = ("VALID", "MODIFIED", "UNKNOWN")


@statistics_bp.route("/api/statistics")
def api_statistics():

    verdict_counts = Counter()
    family_counts = Counter()
    changed_layer_counts = Counter()

    latencies = []
    total_reports = 0
    skipped_reports = 0

    REPORTS_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    for report_path in REPORTS_DIR.glob(
        "N3_REPORT_*.json"
    ):

        try:
            with report_path.open(
                "r",
                encoding="utf-8"
            ) as file:
                report = json.load(file)

            if not isinstance(report, dict):
                raise ValueError("Invalid report structure")

        except (
            OSError,
            json.JSONDecodeError,
            ValueError
        ):
            skipped_reports += 1
            continue

        total_reports += 1

        decision = report.get("final_decision") or {}
        if not isinstance(decision, dict):
            decision = {}

        verdict = str(
            decision.get("verdict") or "UNKNOWN"
        ).upper()

        if verdict not in VERDICTS:
            verdict = "UNKNOWN"

        verdict_counts[verdict] += 1

        card = report.get("card") or {}
        if not isinstance(card, dict):
            card = {}

        family = (
            card.get("card_family") or "UNKNOWN"
        )
        family_counts[str(family)] += 1

        for field, label in (
            ("raw_memory", "RAW_MEMORY"),
            ("application_ndef", "APPLICATION_NDEF"),
            ("security_state", "SECURITY_STATE"),
        ):
            layer = report.get(field) or {}

            if (
                isinstance(layer, dict)
                and str(layer.get("status", "")).upper()
                in ("MODIFIED", "MISMATCH", "CHANGED")
            ):
                changed_layer_counts[label] += 1

        performance = (
            report.get("performance_metrics") or {}
        )

        if isinstance(performance, dict):
            latency = performance.get(
                "verification_latency_ms"
            )

            if (
                isinstance(latency, (int, float))
                and not isinstance(latency, bool)
                and math.isfinite(latency)
                and latency >= 0
            ):
                latencies.append(float(latency))

    return jsonify({
        "status": "SUCCESS",
        "total_scans": total_reports,
        "skipped_reports": skipped_reports,
        "verdict_counts": {
            verdict: verdict_counts[verdict]
            for verdict in VERDICTS
        },
        "card_families": dict(family_counts),
        "changed_layer_counts": {
            label: changed_layer_counts[label]
            for label in (
                "RAW_MEMORY",
                "APPLICATION_NDEF",
                "SECURITY_STATE"
            )
        },
        "performance": {
            "sample_count": len(latencies),
            "average_latency_ms": (
                round(mean(latencies), 3)
                if latencies else None
            ),
            "minimum_latency_ms": (
                round(min(latencies), 3)
                if latencies else None
            ),
            "maximum_latency_ms": (
                round(max(latencies), 3)
                if latencies else None
            )
        }
    })
