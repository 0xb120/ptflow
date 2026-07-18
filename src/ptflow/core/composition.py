"""Persistent lineage and summary reporting for parent -> follow-up pipeline composition."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ptflow.core import tools

if TYPE_CHECKING:
    from ptflow.core.paths import Activity
    from ptflow.core.stage import Followup

_SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")


def _relative(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except (OSError, ValueError):
        return str(path)


def _scope_sha(path: str) -> str | None:
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return None


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _hydrate_coverage(record: dict[str, Any], base: Path) -> None:
    coverage = _read_json(base / "coverage.json")
    if not coverage:
        return
    raw_failures = coverage.get("failures")
    record.update({
        "run_id": coverage.get("run_id"),
        "started_at": coverage.get("started_at"),
        "finished_at": coverage.get("finished_at"),
        "failure_labels": list(raw_failures) if isinstance(raw_failures, list) else [],
    })


def _write_manifest(activity: Activity, manifest: dict[str, Any]) -> None:
    tools.write_text(
        activity.reports / "composition.json",
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    )


def begin(
    activity: Activity, *, parent_pipeline: str, parent_failures: int,
    followups: list[Followup],
) -> dict[str, Any]:
    """Create the parent/child lineage before the first child starts and persist it immediately."""
    parent_status = "failed" if parent_failures else "completed"
    parent = {
        "role": "parent",
        "pipeline": parent_pipeline,
        "activity": activity.base.name,
        "path": ".",
        "coverage": "coverage.json",
        "report": "reports/report.json",
        "status": parent_status,
        "failure_count": max(0, parent_failures),
        "failure_labels": [],
    }
    _hydrate_coverage(parent, activity.base)
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "parent": parent,
        "followups": [
            {
                "role": "followup",
                "pipeline": followup.pipeline,
                "activity": followup.activity,
                "path": followup.activity,
                "scope": _relative(Path(followup.scope), activity.base),
                "scope_sha256": _scope_sha(followup.scope),
                "coverage": f"{followup.activity}/coverage.json",
                "report": f"{followup.activity}/reports/report.json",
                "status": "pending",
                "failure_count": 0,
                "failure_labels": [],
            }
            for followup in followups
        ],
    }
    write_outputs(activity, manifest)
    return manifest


def update_followup(  # noqa: PLR0913
    activity: Activity, manifest: dict[str, Any], index: int, *, status: str,
    failure_count: int = 0, child_base: Path | None = None, error: str | None = None,
) -> None:
    """Persist one child transition; safe to call for running, failure and interruption states."""
    record = manifest["followups"][index]
    record["status"] = status
    record["failure_count"] = max(0, failure_count)
    if error:
        record["error"] = error
    else:
        record.pop("error", None)
    if child_base is not None:
        child_path = _relative(child_base, activity.base)
        record.update({
            "path": child_path,
            "coverage": f"{child_path}/coverage.json",
            "report": f"{child_path}/reports/report.json",
        })
        _hydrate_coverage(record, child_base)
    write_outputs(activity, manifest)


def _run_summary(activity: Activity, record: dict[str, Any]) -> dict[str, Any]:
    report = _read_json(activity.base / str(record["report"]))
    raw_summary = report.get("summary")
    summary: dict[str, Any] = raw_summary if isinstance(raw_summary, dict) else {}
    raw_severity = summary.get("by_severity")
    severity: dict[str, Any] = raw_severity if isinstance(raw_severity, dict) else {}

    def count(value: Any) -> int:
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    return {
        **record,
        "summary": {
            "total": count(summary.get("total")),
            "by_severity": {name: count(severity.get(name)) for name in _SEVERITIES},
        },
    }


def build_report(activity: Activity, manifest: dict[str, Any]) -> dict[str, Any]:
    """Build a summary-only portfolio: child reports stay authoritative and are linked, not copied."""
    runs = [
        _run_summary(activity, manifest["parent"]),
        *(_run_summary(activity, record) for record in manifest["followups"]),
    ]
    severity = Counter()
    statuses = Counter()
    for run in runs:
        severity.update(run["summary"]["by_severity"])
        statuses[run["status"]] += 1
    return {
        "schema_version": 1,
        "summary": {
            "runs": len(runs),
            "followups": len(manifest["followups"]),
            "findings": sum(run["summary"]["total"] for run in runs),
            "failures": sum(run["failure_count"] for run in runs),
            "by_status": dict(sorted(statuses.items())),
            "by_severity": {name: severity[name] for name in _SEVERITIES},
        },
        "runs": runs,
    }


def _report_link(path: str) -> str:
    markdown = str(Path(path).with_suffix(".md"))
    if markdown.startswith("reports/"):
        return markdown.removeprefix("reports/")
    return f"../{markdown}"


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Composed assessment report",
        "",
        "This portfolio links the authoritative reports produced by the parent and its follow-up runs.",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "| --- | ---: |",
        *(f"| {name.capitalize()} | {summary['by_severity'][name]} |" for name in _SEVERITIES),
        "",
        f"**Total findings:** {summary['findings']}",
        "",
        "## Runs",
        "",
        "| Role | Activity | Pipeline | Status | Failures | Findings | Report |",
        "| --- | --- | --- | --- | ---: | ---: | --- |",
    ]
    for run in report["runs"]:
        link = _report_link(run["report"])
        lines.append(
            f"| {run['role']} | `{run['activity']}` | `{run['pipeline']}` | {run['status']} | "
            f"{run['failure_count']} | {run['summary']['total']} | [open]({link}) |"
        )
    return "\n".join(lines).rstrip() + "\n"


def write_outputs(activity: Activity, manifest: dict[str, Any]) -> dict[str, Any]:
    """Refresh lineage plus JSON/Markdown portfolio after every child transition."""
    _write_manifest(activity, manifest)
    report = build_report(activity, manifest)
    tools.write_text(
        activity.reports / "report-composed.json",
        json.dumps(report, indent=2, sort_keys=True) + "\n",
    )
    tools.write_text(activity.reports / "report-composed.md", render_markdown(report))
    return report


def clear(activity: Activity) -> None:
    """Remove stale composition deliverables when the latest parent run declares no follow-up."""
    for name in ("composition.json", "report-composed.json", "report-composed.md"):
        (activity.reports / name).unlink(missing_ok=True)
