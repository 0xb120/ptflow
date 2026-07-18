"""Offline golden-set evaluation for detection quality and surface coverage."""

from __future__ import annotations

import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path, PurePath
from typing import Any

from ptflow.core import evidence, tools

_CONFIDENCE = ("lead", "probable", "verified")
_FINDING_MATCH_KEYS = ("class", "target", "detector", "request_ref", "finding_id", "title")


class EvaluationError(ValueError):
    """Raised when a benchmark manifest or activity artifact violates the evaluation contract."""


def _read_object(path: Path, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except OSError as exc:
        msg = f"cannot read {label} {path}: {exc}"
        raise EvaluationError(msg) from exc
    except json.JSONDecodeError as exc:
        msg = f"invalid JSON in {label} {path}: {exc}"
        raise EvaluationError(msg) from exc
    if not isinstance(value, dict):
        msg = f"{label} must contain a JSON object: {path}"
        raise EvaluationError(msg)
    return value


def _object_list(manifest: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = manifest.get(key, [])
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        msg = f"manifest field {key!r} must be a list of objects"
        raise EvaluationError(msg)
    return value


def _nonempty_text(record: dict[str, Any], key: str, *, context: str) -> str:
    value = record.get(key)
    if not isinstance(value, str) or not value.strip():
        msg = f"{context} requires a non-empty {key!r}"
        raise EvaluationError(msg)
    return value.strip()


def _register_case_id(item: dict[str, Any], context: str, all_ids: set[str]) -> None:
    case_id = _nonempty_text(item, "id", context=context)
    if case_id in all_ids:
        msg = f"duplicate benchmark case id {case_id!r}"
        raise EvaluationError(msg)
    all_ids.add(case_id)


def _validate_finding_cases(manifest: dict[str, Any], all_ids: set[str]) -> None:
    for section in ("expected_findings", "negative_findings"):
        for index, item in enumerate(_object_list(manifest, section)):
            context = f"{section}[{index}]"
            _register_case_id(item, context, all_ids)
            _nonempty_text(item, "class", context=context)
            confidence = item.get("minimum_confidence", "lead")
            if confidence not in _CONFIDENCE:
                msg = f"{context} has invalid minimum_confidence {confidence!r}"
                raise EvaluationError(msg)
            pattern = item.get("target_pattern")
            if pattern:
                try:
                    re.compile(str(pattern))
                except re.error as exc:
                    msg = f"{context} has invalid target_pattern: {exc}"
                    raise EvaluationError(msg) from exc


def _validate_request_cases(manifest: dict[str, Any], all_ids: set[str]) -> None:
    for index, item in enumerate(_object_list(manifest, "expected_requests")):
        context = f"expected_requests[{index}]"
        _register_case_id(item, context, all_ids)
        _nonempty_text(item, "method", context=context)
        _nonempty_text(item, "url", context=context)


def _validate_oast_cases(manifest: dict[str, Any], all_ids: set[str]) -> None:
    for index, item in enumerate(_object_list(manifest, "expected_oast_callbacks")):
        context = f"expected_oast_callbacks[{index}]"
        _register_case_id(item, context, all_ids)
        _nonempty_text(item, "marker", context=context)


def _validate_policy(manifest: dict[str, Any]) -> None:
    forbidden = manifest.get("forbidden_actions", [])
    if not isinstance(forbidden, list) or any(not isinstance(item, str) for item in forbidden):
        msg = "manifest field 'forbidden_actions' must be a list of strings"
        raise EvaluationError(msg)


def _validate_options(manifest: dict[str, Any]) -> None:
    options = manifest.get("options", {})
    if not isinstance(options, dict):
        msg = "manifest field 'options' must be an object"
        raise EvaluationError(msg)
    if not isinstance(options.get("allow_unexpected_findings", False), bool):
        msg = "manifest options.allow_unexpected_findings must be a boolean"
        raise EvaluationError(msg)


def _validate_artifacts(manifest: dict[str, Any]) -> None:
    artifacts = manifest.get("artifacts", {})
    if not isinstance(artifacts, dict):
        msg = "manifest field 'artifacts' must be an object"
        raise EvaluationError(msg)
    for key in ("requests", "oast_callbacks"):
        patterns = artifacts.get(key, [])
        if not isinstance(patterns, list) or any(not isinstance(item, str) for item in patterns):
            msg = f"manifest artifacts.{key} must be a list of relative glob strings"
            raise EvaluationError(msg)
        for pattern in patterns:
            _validate_relative_pattern(pattern, context=f"artifacts.{key}")
    report = artifacts.get("report", "reports/report.json")
    if not isinstance(report, str):
        msg = "manifest artifacts.report must be a relative path"
        raise EvaluationError(msg)
    _validate_relative_pattern(report, context="artifacts.report")
    if any(marker in report for marker in "*?["):
        msg = "manifest artifacts.report must be a path, not a glob"
        raise EvaluationError(msg)


def load_manifest(path: Path) -> dict[str, Any]:
    """Load and validate a version-1 benchmark manifest."""
    manifest = _read_object(path, label="benchmark manifest")
    if manifest.get("schema_version") != 1:
        msg = "benchmark manifest schema_version must be 1"
        raise EvaluationError(msg)
    _nonempty_text(manifest, "benchmark", context="manifest")
    target = manifest.get("target")
    if not isinstance(target, dict):
        msg = "manifest field 'target' must be an object"
        raise EvaluationError(msg)
    _nonempty_text(target, "id", context="manifest target")
    all_ids: set[str] = set()
    _validate_finding_cases(manifest, all_ids)
    _validate_request_cases(manifest, all_ids)
    _validate_oast_cases(manifest, all_ids)
    _validate_policy(manifest)
    _validate_options(manifest)
    _validate_artifacts(manifest)
    return manifest


def _validate_relative_pattern(pattern: str, *, context: str) -> None:
    pure = PurePath(pattern)
    if not pattern or pure.is_absolute() or ".." in pure.parts:
        msg = f"{context} must stay inside the activity: {pattern!r}"
        raise EvaluationError(msg)


def _artifact_paths(activity: Path, patterns: list[str]) -> list[Path]:
    activity = activity.resolve()
    paths: dict[str, Path] = {}
    for pattern in patterns:
        _validate_relative_pattern(pattern, context="artifact pattern")
        for path in activity.glob(pattern):
            if path.is_file():
                if not path.resolve().is_relative_to(activity):
                    msg = f"artifact resolves outside the activity: {path}"
                    raise EvaluationError(msg)
                paths[str(path.relative_to(activity))] = path
    return [paths[key] for key in sorted(paths)]


def _actual_findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    raw = report.get("findings")
    if not isinstance(raw, list) or any(not isinstance(item, dict) for item in raw):
        msg = "assessment report field 'findings' must be a list of objects"
        raise EvaluationError(msg)
    findings: list[dict[str, Any]] = []
    for item in raw:
        confidence = item.get("confidence", "lead")
        if confidence not in _CONFIDENCE:
            confidence = "lead"
        findings.append({
            **item,
            "finding_id": str(item.get("finding_id") or item.get("id") or ""),
            "class": str(item.get("class") or item.get("category") or "unknown"),
            "target": item.get("target") or item.get("subject"),
            "detector": str(item.get("detector") or item.get("category") or "unknown"),
            "request_ref": item.get("request_ref"),
            "confidence": confidence,
        })
    return findings


def _finding_matches(expected: dict[str, Any], actual: dict[str, Any]) -> bool:
    for key in _FINDING_MATCH_KEYS:
        if key in expected and str(actual.get(key) or "") != str(expected[key]):
            return False
    if (
        (pattern := expected.get("target_pattern"))
        and re.search(str(pattern), str(actual.get("target") or "")) is None
    ):
        return False
    minimum = str(expected.get("minimum_confidence", "lead"))
    return evidence.confidence_rank(actual["confidence"]) >= evidence.confidence_rank(minimum)


def _match_cases(
    expected: list[dict[str, Any]], actual: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], set[int]]:
    matched: list[dict[str, Any]] = []
    missed: list[dict[str, Any]] = []
    used: set[int] = set()
    for case in expected:
        found = next(
            (index for index, finding in enumerate(actual)
             if index not in used and _finding_matches(case, finding)),
            None,
        )
        if found is None:
            missed.append(case)
            continue
        used.add(found)
        matched.append({
            "case_id": case["id"],
            "finding_id": actual[found]["finding_id"],
            "class": actual[found]["class"],
            "confidence": actual[found]["confidence"],
        })
    return matched, missed, used


def _negative_violations(
    negative: list[dict[str, Any]], actual: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], set[int]]:
    violations: list[dict[str, Any]] = []
    indexes: set[int] = set()
    for case in negative:
        matches = [
            index for index, finding in enumerate(actual) if _finding_matches(case, finding)
        ]
        if not matches:
            continue
        indexes.update(matches)
        violations.append({
            "case_id": case["id"],
            "finding_ids": [actual[index]["finding_id"] for index in matches],
            "class": case["class"],
        })
    return violations, indexes


def _header_content_type(headers: Any) -> str | None:
    if isinstance(headers, dict):
        for key, value in headers.items():
            if str(key).casefold() == "content-type":
                return str(value).split(";", 1)[0].strip().casefold()
    if isinstance(headers, list):
        for header in headers:
            name, separator, value = str(header).partition(":")
            if separator and name.strip().casefold() == "content-type":
                return value.split(";", 1)[0].strip().casefold()
    return None


def _normalize_request(record: dict[str, Any], ref: str) -> dict[str, Any] | None:
    url = record.get("url") or record.get("endpoint")
    if not url:
        return None
    sources = record.get("sources") or record.get("source") or []
    if isinstance(sources, str):
        sources = [sources]
    if not isinstance(sources, list):
        sources = []
    content_type = record.get("content_type") or record.get("content-type")
    content_type = content_type or _header_content_type(record.get("headers"))
    return {
        "method": str(record.get("method") or "GET").upper(),
        "url": str(url),
        "content_type": str(content_type).split(";", 1)[0].strip().casefold()
        if content_type else None,
        "sources": sorted({str(source) for source in sources}),
        "ref": ref,
    }


def _default_request_paths(activity: Path) -> list[Path]:
    paths: list[Path] = []
    scans = activity / "scans"
    if not scans.is_dir():
        return paths
    for app in sorted(path for path in scans.iterdir() if path.is_dir()):
        full = app / "requests_full.jsonl"
        surface = app / "requests.jsonl"
        if full.is_file():
            paths.append(full)
        elif surface.is_file():
            paths.append(surface)
    return paths


def _load_requests(activity: Path, patterns: list[str]) -> list[dict[str, Any]]:
    paths = _artifact_paths(activity, patterns) if patterns else _default_request_paths(activity)
    unique: dict[tuple[Any, ...], dict[str, Any]] = {}
    for path in paths:
        relative = path.relative_to(activity)
        for line, record in enumerate(tools.read_jsonl(path), start=1):
            normalized = _normalize_request(record, f"{relative}:{line}")
            if normalized is None:
                continue
            key = (
                normalized["method"], normalized["url"], normalized["content_type"],
                tuple(normalized["sources"]),
            )
            unique.setdefault(key, normalized)
    return [unique[key] for key in sorted(unique, key=lambda item: tuple(str(part) for part in item))]


def _request_matches(expected: dict[str, Any], actual: dict[str, Any]) -> bool:
    if actual["method"] != str(expected["method"]).upper() or actual["url"] != expected["url"]:
        return False
    if "content_type" in expected:
        wanted = str(expected["content_type"]).split(";", 1)[0].strip().casefold()
        if actual["content_type"] != wanted:
            return False
    return "source" not in expected or str(expected["source"]) in actual["sources"]


def _evaluate_requests(
    expected: list[dict[str, Any]], actual: list[dict[str, Any]],
) -> dict[str, Any]:
    matched: list[dict[str, Any]] = []
    missed: list[dict[str, Any]] = []
    used: set[int] = set()
    for case in expected:
        found = next(
            (index for index, request in enumerate(actual)
             if index not in used and _request_matches(case, request)),
            None,
        )
        if found is None:
            missed.append(case)
        else:
            used.add(found)
            matched.append({"case_id": case["id"], "request_ref": actual[found]["ref"]})
    return {"matched": matched, "missed": missed, "observed_unique": len(actual)}


def _load_oast(activity: Path, patterns: list[str]) -> list[dict[str, Any]]:
    callbacks: list[dict[str, Any]] = []
    for path in _artifact_paths(activity, patterns):
        relative = path.relative_to(activity)
        callbacks.extend(
            {**record, "_ref": f"{relative}:{line}"}
            for line, record in enumerate(tools.read_jsonl(path), start=1)
        )
    return callbacks


def _evaluate_oast(
    expected: list[dict[str, Any]], actual: list[dict[str, Any]],
) -> dict[str, Any]:
    matched: list[dict[str, Any]] = []
    missed: list[dict[str, Any]] = []
    for case in expected:
        marker = str(case["marker"])
        protocol = str(case.get("protocol") or "").casefold()
        found = next(
            (
                callback for callback in actual
                if marker in json.dumps(callback, sort_keys=True, default=str)
                and (
                    not protocol
                    or protocol == str(callback.get("protocol") or callback.get("type") or "").casefold()
                )
            ),
            None,
        )
        if found is None:
            missed.append(case)
        else:
            matched.append({"case_id": case["id"], "callback_ref": found["_ref"]})
    return {"matched": matched, "missed": missed, "observed": len(actual)}


def _seconds_between(start: Any, finish: Any) -> float | None:
    if not isinstance(start, str) or not isinstance(finish, str):
        return None
    try:
        first = datetime.fromisoformat(start)
        last = datetime.fromisoformat(finish)
    except ValueError:
        return None
    return round(max(0.0, (last - first).total_seconds()), 3)


def _cost_metrics(activity: Path, request_count: int) -> dict[str, Any]:
    coverage_path = activity / "coverage.json"
    coverage = _read_object(coverage_path, label="coverage") if coverage_path.is_file() else {}
    raw_stages = coverage.get("stages")
    stages = raw_stages if isinstance(raw_stages, list) else []
    valid_stages = [stage for stage in stages if isinstance(stage, dict)]
    commands = [
        command for stage in valid_stages
        for command in stage.get("commands", []) if isinstance(command, dict)
    ]
    return {
        "wall_clock_seconds": _seconds_between(
            coverage.get("started_at"), coverage.get("finished_at"),
        ),
        "stage_duration_seconds": round(sum(
            float(stage.get("duration_seconds") or 0) for stage in valid_stages
        ), 3),
        "network_stage_duration_seconds": round(sum(
            float(stage.get("duration_seconds") or 0)
            for stage in valid_stages if stage.get("network")
        ), 3),
        "commands": len(commands),
        "command_duration_seconds": round(sum(
            float(command.get("duration_seconds") or 0) for command in commands
        ), 3),
        "request_shapes_observed": request_count,
        "caps_applied": sum(
            bool(cap.get("applied")) for stage in valid_stages
            for cap in stage.get("caps", []) if isinstance(cap, dict)
        ),
    }


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 1.0


def _class_metrics(
    expected: list[dict[str, Any]], actual: list[dict[str, Any]], matched: list[dict[str, Any]],
    missed: list[dict[str, Any]], false_positive_indexes: set[int],
) -> dict[str, dict[str, Any]]:
    true_positives = Counter(item["class"] for item in matched)
    false_negatives = Counter(item["class"] for item in missed)
    false_positives = Counter(actual[index]["class"] for index in false_positive_indexes)
    classes = sorted({
        *(str(item["class"]) for item in expected),
        *(str(item["class"]) for item in actual),
    })
    metrics: dict[str, dict[str, Any]] = {}
    for class_name in classes:
        tp = true_positives[class_name]
        fp = false_positives[class_name]
        fn = false_negatives[class_name]
        metrics[class_name] = {
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "precision": _ratio(tp, tp + fp),
            "recall": _ratio(tp, tp + fn),
        }
    return metrics


def evaluate(activity: Path, manifest_path: Path, *, output: Path | None = None) -> dict[str, Any]:
    """Compare one completed activity with its golden manifest and write a machine report."""
    activity = activity.resolve()
    if not activity.is_dir():
        msg = f"activity directory does not exist: {activity}"
        raise EvaluationError(msg)
    manifest = load_manifest(manifest_path)
    artifacts = manifest.get("artifacts", {})
    report_relative = str(artifacts.get("report", "reports/report.json"))
    report_path = (activity / report_relative).resolve()
    if not report_path.is_relative_to(activity):
        msg = f"assessment report resolves outside the activity: {report_path}"
        raise EvaluationError(msg)
    report = _read_object(report_path, label="assessment report")
    actual = _actual_findings(report)
    expected = _object_list(manifest, "expected_findings")
    negative = _object_list(manifest, "negative_findings")
    matched, missed, matched_indexes = _match_cases(expected, actual)
    negative_violations, negative_indexes = _negative_violations(negative, actual)

    options = manifest.get("options", {})
    allow_unexpected = options.get("allow_unexpected_findings", False)
    unexpected_indexes = set(range(len(actual))) - matched_indexes - negative_indexes
    false_positive_indexes = set(negative_indexes)
    if not allow_unexpected:
        false_positive_indexes.update(unexpected_indexes)
    unexpected = [actual[index] for index in sorted(unexpected_indexes)]

    request_patterns = list(artifacts.get("requests", []))
    requests = _load_requests(activity, request_patterns)
    request_results = _evaluate_requests(
        _object_list(manifest, "expected_requests"), requests,
    )
    callbacks = _load_oast(activity, list(artifacts.get("oast_callbacks", [])))
    oast_results = _evaluate_oast(
        _object_list(manifest, "expected_oast_callbacks"), callbacks,
    )

    tp = len(matched)
    fn = len(missed)
    fp = len(false_positive_indexes)
    failed = bool(
        fn
        or fp
        or negative_violations
        or request_results["missed"]
        or oast_results["missed"]
    )
    confidence_counts = Counter(item["confidence"] for item in actual)
    result = {
        "schema_version": 1,
        "benchmark": {
            "name": manifest["benchmark"],
            "target": manifest["target"],
            "manifest": str(manifest_path),
        },
        "status": "fail" if failed else "pass",
        "summary": {
            "expected_findings": len(expected),
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "precision": _ratio(tp, tp + fp),
            "recall": _ratio(tp, tp + fn),
            "negative_cases": len(negative),
            "negative_cases_passed": len(negative) - len(negative_violations),
            "expected_requests": len(_object_list(manifest, "expected_requests")),
            "requests_matched": len(request_results["matched"]),
            "expected_oast_callbacks": len(_object_list(manifest, "expected_oast_callbacks")),
            "oast_callbacks_matched": len(oast_results["matched"]),
        },
        "findings": {
            "matched": matched,
            "missed": missed,
            "negative_violations": negative_violations,
            "unexpected": unexpected,
            "unexpected_allowed": allow_unexpected,
        },
        "requests": request_results,
        "oast_callbacks": oast_results,
        "metrics": {
            "by_class": _class_metrics(
                expected, actual, matched, missed, false_positive_indexes,
            ),
            "by_confidence": {label: confidence_counts[label] for label in _CONFIDENCE},
            "cost": _cost_metrics(activity, len(requests)),
        },
        "policy": {"forbidden_actions": manifest.get("forbidden_actions", [])},
        "inputs": {
            "activity": str(activity),
            "report": report_relative,
            "request_artifacts": [str(path.relative_to(activity)) for path in (
                _artifact_paths(activity, request_patterns)
                if request_patterns else _default_request_paths(activity)
            )],
            "oast_artifacts": [str(path.relative_to(activity)) for path in _artifact_paths(
                activity, list(artifacts.get("oast_callbacks", [])),
            )],
        },
    }
    destination = output or activity / "reports" / "evaluation.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    tools.write_text(destination, json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def render_summary(result: dict[str, Any]) -> str:
    """Render a compact CLI summary while keeping evaluation.json authoritative."""
    summary = result["summary"]
    status = str(result["status"]).upper()
    return (
        f"{status} {result['benchmark']['name']} — "
        f"findings TP={summary['true_positives']} FP={summary['false_positives']} "
        f"FN={summary['false_negatives']} · precision={summary['precision']:.4f} "
        f"recall={summary['recall']:.4f} · requests "
        f"{summary['requests_matched']}/{summary['expected_requests']} · OAST "
        f"{summary['oast_callbacks_matched']}/{summary['expected_oast_callbacks']}"
    )
