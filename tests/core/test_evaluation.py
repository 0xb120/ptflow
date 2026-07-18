import json
from pathlib import Path

import pytest

from ptflow.cli import main
from ptflow.core import evaluation, reporting, tools
from ptflow.core.paths import Activity


def _write_manifest(path, *, expected_url="https://example.test/search"):
    manifest = {
        "schema_version": 1,
        "benchmark": "m0-smoke",
        "target": {"id": "fixture-app", "description": "offline golden fixture"},
        "expected_findings": [
            {
                "id": "xss-positive",
                "class": "xss",
                "target": expected_url,
                "minimum_confidence": "verified",
            },
        ],
        "negative_findings": [
            {"id": "sqli-negative", "class": "sqli", "target": expected_url},
        ],
        "expected_requests": [
            {
                "id": "json-search-request",
                "method": "POST",
                "url": expected_url,
                "content_type": "application/json",
                "source": "browser",
            },
        ],
        "expected_oast_callbacks": [
            {"id": "blind-callback", "marker": "m0.ssrf.123", "protocol": "dns"},
        ],
        "expected_detector_coverage": [{
            "id": "dalfox-query-coverage",
            "detector": "dalfox",
            "location": "query",
            "minimum_attempted": 1,
            "minimum_completed": 1,
        }],
        "forbidden_actions": ["delete-account", "submit-payment"],
        "artifacts": {
            "report": "reports/report.json",
            "requests": ["scans/*/requests_full.jsonl"],
            "oast_callbacks": ["oast/callbacks.jsonl"],
        },
    }
    path.write_text(json.dumps(manifest))
    return manifest


def _passing_activity(tmp_path):
    activity = Activity.named("activity", root=tmp_path).ensure()
    tools.write_jsonl(activity.findings / "dast.jsonl", [{
        "template-id": "reflected-xss",
        "url": "https://example.test/search",
        "verified": True,
        "verification_method": "browser-execution",
        "request_ref": "scans/app/request.txt",
    }])
    reporting.write_report(activity)
    app = activity.app("app").ensure()
    tools.write_jsonl(app.canonical("requests_full.jsonl"), [{
        "method": "POST",
        "url": "https://example.test/search",
        "headers": {"Content-Type": "application/json; charset=utf-8"},
        "sources": ["browser", "xhr"],
    }])
    tools.write_jsonl(activity.base / "oast" / "callbacks.jsonl", [{
        "marker": "m0.ssrf.123",
        "protocol": "dns",
    }])
    tools.write_text(activity.base / "coverage.json", json.dumps({
        "started_at": "2026-07-18T10:00:00Z",
        "finished_at": "2026-07-18T10:00:05Z",
        "stages": [{
            "duration_seconds": 3.0,
            "network": True,
            "commands": [{"duration_seconds": 2.0}],
            "detectors": [{
                "detector": "dalfox",
                "location": "query",
                "attempted": 1,
                "completed": 1,
                "partial_results": 1,
                "status": "success",
                "reason": None,
            }],
            "caps": [{"applied": True}],
        }],
    }))
    return activity


def test_evaluate_passes_and_writes_machine_metrics(tmp_path):
    activity = _passing_activity(tmp_path)
    manifest_path = tmp_path / "manifest.json"
    _write_manifest(manifest_path)

    result = evaluation.evaluate(activity.base, manifest_path)

    assert result["status"] == "pass"
    assert result["summary"] == {
        "expected_findings": 1,
        "true_positives": 1,
        "false_positives": 0,
        "false_negatives": 0,
        "precision": 1.0,
        "recall": 1.0,
        "negative_cases": 1,
        "negative_cases_passed": 1,
        "expected_requests": 1,
        "requests_matched": 1,
        "expected_oast_callbacks": 1,
        "oast_callbacks_matched": 1,
        "expected_detector_coverage": 1,
        "detector_coverage_matched": 1,
    }
    assert result["metrics"]["by_class"]["xss"]["recall"] == 1.0
    assert result["metrics"]["cost"] == {
        "wall_clock_seconds": 5.0,
        "stage_duration_seconds": 3.0,
        "network_stage_duration_seconds": 3.0,
        "commands": 1,
        "command_duration_seconds": 2.0,
        "request_shapes_observed": 1,
        "caps_applied": 1,
    }
    assert result["policy"]["forbidden_actions"] == ["delete-account", "submit-payment"]
    assert (activity.reports / "evaluation.json").exists()


def test_evaluate_fails_on_missed_positive_negative_violation_and_missing_surface(tmp_path):
    activity = Activity.named("failed", root=tmp_path).ensure()
    tools.write_jsonl(activity.findings / "sqli.jsonl", [{
        "type": "sqli",
        "url": "https://example.test/search",
    }])
    reporting.write_report(activity)
    manifest_path = tmp_path / "manifest.json"
    _write_manifest(manifest_path, expected_url="https://example.test/search")

    result = evaluation.evaluate(activity.base, manifest_path)

    assert result["status"] == "fail"
    assert result["summary"]["true_positives"] == 0
    assert result["summary"]["false_negatives"] == 1
    assert result["summary"]["false_positives"] == 1
    assert result["summary"]["negative_cases_passed"] == 0
    assert [item["id"] for item in result["requests"]["missed"]] == ["json-search-request"]
    assert [item["id"] for item in result["oast_callbacks"]["missed"]] == ["blind-callback"]
    assert [item["id"] for item in result["detector_coverage"]["missed"]] == [
        "dalfox-query-coverage",
    ]


def test_evaluate_fails_when_detector_is_degraded(tmp_path):
    activity = _passing_activity(tmp_path)
    coverage_path = activity.base / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage["stages"][0]["detectors"][0].update({
        "completed": 0,
        "status": "timeout",
        "reason": "deadline exceeded",
    })
    tools.write_text(coverage_path, json.dumps(coverage))
    manifest_path = tmp_path / "manifest.json"
    _write_manifest(manifest_path)

    result = evaluation.evaluate(activity.base, manifest_path)

    assert result["status"] == "fail"
    missed = result["detector_coverage"]["missed"]
    assert [item["id"] for item in missed] == ["dalfox-query-coverage"]
    assert missed[0]["observed"]["statuses"] == {"timeout": 1}


def test_manifest_rejects_duplicate_ids_and_artifact_escape(tmp_path):
    manifest_path = tmp_path / "manifest.json"
    manifest = _write_manifest(manifest_path)
    manifest["negative_findings"][0]["id"] = "xss-positive"
    manifest["artifacts"]["requests"] = ["../outside.jsonl"]
    manifest_path.write_text(json.dumps(manifest))

    with pytest.raises(evaluation.EvaluationError, match="duplicate benchmark case id"):
        evaluation.load_manifest(manifest_path)

    manifest["negative_findings"][0]["id"] = "sqli-negative"
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(evaluation.EvaluationError, match="must stay inside the activity"):
        evaluation.load_manifest(manifest_path)


def test_cli_evaluate_exit_codes_and_output(tmp_path, capsys):
    activity = _passing_activity(tmp_path)
    manifest_path = tmp_path / "manifest.json"
    _write_manifest(manifest_path)

    assert main(["evaluate", str(activity.base), str(manifest_path)]) == 0
    assert "PASS m0-smoke" in capsys.readouterr().out

    broken = json.loads(manifest_path.read_text())
    broken["expected_findings"][0]["target"] = "https://wrong.test/"
    manifest_path.write_text(json.dumps(broken))
    assert main(["evaluate", str(activity.base), str(manifest_path)]) == 1
    assert "FAIL m0-smoke" in capsys.readouterr().out


def test_versioned_m0_smoke_benchmark_passes(tmp_path):
    root = Path(__file__).parents[2]
    benchmark = root / "benchmarks" / "m0-smoke"

    result = evaluation.evaluate(
        benchmark / "activity",
        benchmark / "manifest.json",
        output=tmp_path / "evaluation.json",
    )

    assert result["status"] == "pass"
    assert result["summary"]["true_positives"] == 2
    assert result["summary"]["negative_cases_passed"] == 2
