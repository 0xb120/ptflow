import json

from ptflow.core import composition, reporting, tools
from ptflow.core.paths import Activity
from ptflow.core.stage import Followup


def _finding(activity: Activity, name: str, severity: str) -> None:
    tools.write_jsonl(
        activity.findings / f"{name}.jsonl",
        [{"template-id": name, "severity": severity}],
    )
    reporting.write_report(activity)


def test_composition_persists_lineage_and_aggregates_child_summaries(tmp_path):
    parent = Activity.named("parent", root=tmp_path).ensure()
    child = Activity.named("child", root=parent.base).ensure()
    scope = parent.base / "child-scope.txt"
    scope.write_text("https://late.example\n")
    _finding(parent, "parent-finding", "high")
    _finding(child, "child-finding", "critical")
    tools.write_text(parent.base / "coverage.json", json.dumps({
        "run_id": "parent-run", "started_at": "start", "finished_at": "finish", "failures": [],
    }))
    tools.write_text(child.base / "coverage.json", json.dumps({
        "run_id": "child-run", "started_at": "start", "finished_at": "finish", "failures": [],
    }))

    manifest = composition.begin(
        parent, parent_pipeline="external", parent_failures=0,
        followups=[Followup("webscan", "child", str(scope))],
    )
    assert manifest["followups"][0]["status"] == "pending"
    composition.update_followup(
        parent, manifest, 0, status="completed", child_base=child.base,
    )

    persisted = json.loads((parent.reports / "composition.json").read_text())
    assert persisted["parent"]["run_id"] == "parent-run"
    assert persisted["followups"][0]["scope"] == "child-scope.txt"
    assert len(persisted["followups"][0]["scope_sha256"]) == 64
    assert persisted["followups"][0]["run_id"] == "child-run"
    report = json.loads((parent.reports / "report-composed.json").read_text())
    assert report["summary"]["findings"] == 2
    assert report["summary"]["by_severity"]["critical"] == 1
    assert report["summary"]["by_severity"]["high"] == 1
    assert report["summary"]["by_status"] == {"completed": 2}
    markdown = (parent.reports / "report-composed.md").read_text()
    assert "[open](report.md)" in markdown
    assert "[open](../child/reports/report.md)" in markdown


def test_composition_records_failed_and_interrupted_transitions(tmp_path):
    parent = Activity.named("parent", root=tmp_path).ensure()
    reporting.write_report(parent)
    first_scope = parent.base / "one.txt"
    second_scope = parent.base / "two.txt"
    first_scope.write_text("one")
    second_scope.write_text("two")
    manifest = composition.begin(
        parent, parent_pipeline="internal", parent_failures=1,
        followups=[
            Followup("webscan", "one", str(first_scope)),
            Followup("webscan", "two", str(second_scope)),
        ],
    )

    composition.update_followup(
        parent, manifest, 0, status="failed", failure_count=2, error="boom",
    )
    composition.update_followup(parent, manifest, 1, status="interrupted")

    report = json.loads((parent.reports / "report-composed.json").read_text())
    assert report["summary"]["failures"] == 3
    assert report["summary"]["by_status"] == {
        "failed": 2,
        "interrupted": 1,
    }


def test_clear_removes_stale_composition_outputs(tmp_path):
    activity = Activity.named("parent", root=tmp_path).ensure()
    for name in ("composition.json", "report-composed.json", "report-composed.md"):
        tools.write_text(activity.reports / name, "stale")

    composition.clear(activity)

    assert list(activity.reports.glob("*compos*")) == []
