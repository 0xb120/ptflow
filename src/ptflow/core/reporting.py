"""Deterministic, offline assessment report from consolidated finding JSONL files."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ptflow.core import evidence, tools

if TYPE_CHECKING:
    from ptflow.core.paths import Activity

_SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")
_SEVERITY_ALIASES = {
    "informational": "info",
    "moderate": "medium",
    "important": "high",
}
_CVSS_THRESHOLDS = ((9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low"))
_IDENTITY_KEYS = (
    "type",
    "template-id",
    "template_id",
    "cve",
    "cve_id",
    "rule_id",
    "RuleID",
    "name",
    "title",
    "component",
    "product",
    "version",
    "param",
    "parameter",
    "inject_type",
    "poc_kind",
)
_TARGET_KEYS = (
    "app_id",
    "url",
    "matched-at",
    "matched_at",
    "endpoint",
    "host",
    "ip",
    "port",
    "path",
    "bucket",
    "share",
    "module",
    "user",
    "username",
    "subject",
)
_EVIDENCE_KEYS = (
    "evidence",
    "description",
    "matcher-name",
    "matcher_name",
    "extracted-results",
    "extracted_results",
    "payload",
    "rationale",
    "message",
)
_VOLATILE_KEYS = frozenset({"timestamp", "time", "duration", "duration_ms", "curl-command"})
_SPACE_RE = re.compile(r"\s+")
_MAX_INLINE = 500


def normalize_severity(record: dict[str, Any]) -> str:
    """Map scanner-specific severities (or CVSS when absent) to one stable scale."""
    value: Any = record.get("severity")
    if not value and isinstance(record.get("info"), dict):
        value = record["info"].get("severity")
    if isinstance(value, dict):
        value = next((value.get(k) for k in ("type", "level", "value") if value.get(k)), None)
    if value is not None:
        normalized = _SEVERITY_ALIASES.get(str(value).strip().lower(), str(value).strip().lower())
        if normalized in _SEVERITIES:
            return normalized
    score = next(
        (record.get(k) for k in ("cvss", "cvss_score", "cvss-score") if record.get(k) is not None),
        None,
    )
    if score is None:
        return "unknown"
    try:
        numeric = float(score)
    except (TypeError, ValueError):
        return "unknown"
    for threshold, severity in _CVSS_THRESHOLDS:
        if numeric >= threshold:
            return severity
    return "info"


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def _finding_key(category: str, record: dict[str, Any]) -> str:
    identifiers = {k: record[k] for k in _IDENTITY_KEYS if record.get(k) not in (None, "", [])}
    targets = {k: record[k] for k in _TARGET_KEYS if record.get(k) not in (None, "", [])}
    if identifiers:
        identity = {**identifiers, **targets}
    else:
        # Unknown scanner shapes are deduped exactly. A target alone (often only app_id) is not enough
        # identity: collapsing on it would merge distinct secrets/default-credential leads for one app.
        identity = {k: v for k, v in record.items() if k not in _VOLATILE_KEYS and k != "severity"}
    raw = _canonical({"category": category, "identity": identity})
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _text(value: Any) -> str:
    text = value if isinstance(value, str) else _canonical(value)
    text = _SPACE_RE.sub(" ", text).strip()
    return text if len(text) <= _MAX_INLINE else f"{text[: _MAX_INLINE - 3]}..."


def _title(category: str, record: dict[str, Any]) -> str:
    for key in ("title", "name", "template-id", "template_id", "cve", "type", "rule_id", "RuleID"):
        if record.get(key):
            return _text(record[key])
    return category.replace("_", " ").replace("-", " ")


def _subject(record: dict[str, Any]) -> str | None:
    for key in ("url", "matched-at", "matched_at", "endpoint", "host", "subject"):
        if record.get(key):
            return _text(record[key])
    if record.get("ip"):
        return f"{record['ip']}:{record['port']}" if record.get("port") else str(record["ip"])
    return str(record["app_id"]) if record.get("app_id") else None


def _evidence(record: dict[str, Any]) -> list[str]:
    return list(
        dict.fromkeys(
            _text(record[k]) for k in _EVIDENCE_KEYS if record.get(k) not in (None, "", [])
        )
    )


def _poc_paths(record: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    for key, value in record.items():
        label = key.lower().replace("-", "_")
        if not any(token in label for token in ("poc", "screenshot", "request_file", "artifact")):
            continue
        values: Iterable[Any] = value if isinstance(value, list) else (value,)
        paths.extend(
            str(item) for item in values if isinstance(item, (str, Path)) and str(item).strip()
        )
    return list(dict.fromkeys(paths))


def gather_findings(
    activity: Activity, *, findings_dir: Path | None = None,
) -> list[dict[str, Any]]:
    """Normalize and conservatively deduplicate consolidated findings in stable order."""
    merged: dict[str, dict[str, Any]] = {}
    source_dir = findings_dir or activity.findings
    for path in sorted(source_dir.glob("*.jsonl")):
        if path.name == "hypotheses.jsonl":
            continue
        category = path.stem
        for line, record in enumerate(tools.read_jsonl(path), start=1):
            key = _finding_key(category, record)
            source = {"path": str(path.relative_to(activity.base)), "line": line}
            subject = _subject(record)
            poc_paths = _poc_paths(record)
            normalized = evidence.normalize_finding(
                finding_id=key,
                category=category,
                record=record,
                target=subject,
                source_refs=(f"{source['path']}:{source['line']}",),
                poc_refs=tuple(poc_paths),
            )
            if key not in merged:
                merged[key] = {
                    "id": key,
                    **normalized.as_dict(),
                    "category": category,
                    "severity": normalize_severity(record),
                    "title": _title(category, record),
                    "subject": subject,
                    "evidence": _evidence(record),
                    "poc_paths": poc_paths,
                    "sources": [source],
                    "details": record,
                }
                continue
            current = merged[key]
            if source not in current["sources"]:
                current["sources"].append(source)
            current["evidence"] = list(dict.fromkeys([*current["evidence"], *_evidence(record)]))
            current["poc_paths"] = list(dict.fromkeys([*current["poc_paths"], *poc_paths]))
            current["evidence_refs"] = list(dict.fromkeys([
                *current["evidence_refs"], *normalized.evidence_refs,
            ]))
            current["control_evidence_refs"] = list(dict.fromkeys([
                *current["control_evidence_refs"], *normalized.control_evidence_refs,
            ]))
            current["confidence"] = evidence.strongest_confidence(
                current["confidence"], normalized.confidence,
            )
            current["request_ref"] = current["request_ref"] or normalized.request_ref
            current["verification_method"] = (
                current["verification_method"] or normalized.verification_method
            )
    rank = {severity: i for i, severity in enumerate(_SEVERITIES)}
    return sorted(
        merged.values(),
        key=lambda finding: (
            rank[finding["severity"]],
            finding["category"],
            finding["title"].lower(),
            finding["subject"] or "",
            finding["id"],
        ),
    )


def build_report(activity: Activity, *, findings_dir: Path | None = None) -> dict[str, Any]:
    findings = gather_findings(activity, findings_dir=findings_dir)
    counts = Counter(finding["severity"] for finding in findings)
    confidence = Counter(finding["confidence"] for finding in findings)
    return {
        "schema_version": 2,
        "summary": {
            "total": len(findings),
            "by_severity": {severity: counts[severity] for severity in _SEVERITIES},
            "by_confidence": {
                label: confidence[label] for label in ("verified", "probable", "lead")
            },
        },
        "findings": findings,
    }


def _render_finding(finding: dict[str, Any]) -> list[str]:
    lines = [
        f"### {finding['title']}",
        "",
        f"- ID: `{finding['id']}`",
        f"- Category: `{finding['category']}`",
        f"- Class: `{finding['class']}`",
        f"- Confidence: `{finding['confidence']}`",
        f"- Detector: `{finding['detector']}`",
    ]
    if finding["subject"]:
        lines.append(f"- Target: `{finding['subject']}`")
    if finding["request_ref"]:
        lines.append(f"- Request: `{finding['request_ref']}`")
    if finding["verification_method"]:
        lines.append(f"- Verification: `{finding['verification_method']}`")
    refs = ", ".join(f"`{src['path']}:{src['line']}`" for src in finding["sources"])
    lines.append(f"- Evidence source: {refs}")
    if finding["evidence"]:
        lines.append(f"- Evidence: {'; '.join(finding['evidence'])}")
    if finding["poc_paths"]:
        poc_refs = ", ".join(f"`{path}`" for path in finding["poc_paths"])
        lines.append(f"- PoC artifacts: {poc_refs}")
    lines.append("")
    return lines


def render_markdown(
    report: dict[str, Any], *, heading: str = "Assessment report",
    intro: str = "This report is generated deterministically from the consolidated on-disk findings.",
) -> str:
    summary = report["summary"]
    lines = [
        f"# {heading}",
        "",
        intro,
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "| --- | ---: |",
    ]
    lines.extend(
        f"| {severity.capitalize()} | {summary['by_severity'][severity]} |"
        for severity in _SEVERITIES
    )
    lines.extend(["", f"**Total findings:** {summary['total']}", ""])
    by_severity = {severity: [] for severity in _SEVERITIES}
    for finding in report["findings"]:
        by_severity[finding["severity"]].append(finding)
    for severity in _SEVERITIES:
        findings = by_severity[severity]
        if not findings:
            continue
        lines.extend([f"## {severity.capitalize()}", ""])
        for finding in findings:
            lines.extend(_render_finding(finding))
    if not report["findings"]:
        lines.extend(["## Findings", "", "No consolidated findings were produced.", ""])
    return "\n".join(lines).rstrip() + "\n"


def write_report(
    activity: Activity, *, stem: str = "report", findings_dir: Path | None = None,
    heading: str = "Assessment report",
    intro: str = "This report is generated deterministically from the consolidated on-disk findings.",
) -> dict[str, Any]:
    """Write a stable named JSON/Markdown report and return its model."""
    if Path(stem).name != stem:
        msg = f"report stem must be a filename stem, got {stem!r}"
        raise ValueError(msg)
    report = build_report(activity, findings_dir=findings_dir)
    activity.reports.mkdir(parents=True, exist_ok=True)
    tools.write_text(
        activity.reports / f"{stem}.json", json.dumps(report, indent=2, sort_keys=True) + "\n"
    )
    tools.write_text(
        activity.reports / f"{stem}.md", render_markdown(report, heading=heading, intro=intro)
    )
    # Generated reports used to live in the activity root. Remove those legacy copies only after both
    # dedicated-directory outputs have been written successfully, so an upgraded existing workspace
    # never exposes two conflicting sources of truth.
    for suffix in ("json", "md"):
        (activity.base / f"{stem}.{suffix}").unlink(missing_ok=True)
    return report
