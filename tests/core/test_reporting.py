import json

from ptflow.core import reporting, tools
from ptflow.core.paths import Activity


def test_normalize_severity_scanner_alias_nested_and_cvss():
    assert reporting.normalize_severity({"severity": "IMPORTANT"}) == "high"
    assert reporting.normalize_severity({"info": {"severity": "informational"}}) == "info"
    assert reporting.normalize_severity({"cvss_score": 9.1}) == "critical"
    assert reporting.normalize_severity({}) == "unknown"


def test_build_report_deduplicates_identity_and_merges_evidence(tmp_path):
    act = Activity.named("acme", root=tmp_path).ensure()
    tools.write_jsonl(
        act.findings / "dast.jsonl",
        [
            {
                "app_id": "shop",
                "template-id": "xss-reflected",
                "matched-at": "https://x.test/q",
                "severity": "medium",
                "evidence": "first",
                "poc": "poc/xss.txt",
            },
            {
                "app_id": "shop",
                "template-id": "xss-reflected",
                "matched-at": "https://x.test/q",
                "severity": "moderate",
                "evidence": "second",
                "poc": "poc/xss.txt",
            },
        ],
    )
    tools.write_jsonl(act.findings / "hypotheses.jsonl", [{"title": "not a scanner finding"}])

    report = reporting.build_report(act)

    assert report["summary"]["total"] == 1
    assert report["summary"]["by_severity"]["medium"] == 1
    finding = report["findings"][0]
    assert report["schema_version"] == 2
    assert report["summary"]["by_confidence"] == {
        "verified": 0, "probable": 0, "lead": 1,
    }
    assert finding["finding_id"] == finding["id"]
    assert finding["class"] == "xss"
    assert finding["confidence"] == "lead"
    assert finding["detector"] == "nuclei"
    assert finding["evidence_refs"] == [
        "findings/dast.jsonl:1", "poc/xss.txt", "findings/dast.jsonl:2",
    ]
    assert finding["evidence"] == ["first", "second"]
    assert finding["poc_paths"] == ["poc/xss.txt"]
    assert len(finding["sources"]) == 2


def test_write_report_is_byte_stable_and_keeps_source_references(tmp_path):
    act = Activity.named("stable", root=tmp_path).ensure()
    tools.write_jsonl(
        act.findings / "cve.jsonl",
        [
            {"app_id": "api", "cve": "CVE-2026-1", "cvss": 7.5, "description": "upgrade component"},
        ],
    )

    reporting.write_report(act)
    first_json = (act.reports / "report.json").read_bytes()
    first_markdown = (act.reports / "report.md").read_bytes()
    reporting.write_report(act)

    assert (act.reports / "report.json").read_bytes() == first_json
    assert (act.reports / "report.md").read_bytes() == first_markdown
    model = json.loads(first_json)
    assert model["findings"][0]["sources"] == [{"line": 1, "path": "findings/cve.jsonl"}]
    assert b"findings/cve.jsonl:1" in first_markdown


def test_unknown_scanner_shape_does_not_collapse_distinct_records_on_app_id(tmp_path):
    act = Activity.named("secrets", root=tmp_path).ensure()
    tools.write_jsonl(
        act.findings / "secrets.jsonl",
        [
            {"app_id": "shop", "kind": "aws", "value": "first"},
            {"app_id": "shop", "kind": "github", "value": "second"},
        ],
    )
    assert reporting.build_report(act)["summary"]["total"] == 2


def test_empty_report_is_still_a_valid_deliverable(tmp_path):
    act = Activity.named("empty", root=tmp_path).ensure()
    report = reporting.write_report(act)
    assert report["summary"]["total"] == 0
    assert "No consolidated findings were produced." in (act.reports / "report.md").read_text()


def test_named_report_reads_isolated_findings_directory(tmp_path):
    act = Activity.named("surface", root=tmp_path).ensure()
    surface = act.checkpoints / "surface" / "findings"
    tools.write_jsonl(surface / "dast.jsonl", [{"template-id": "surface", "severity": "high"}])
    tools.write_jsonl(act.findings / "dast.jsonl", [{"template-id": "final-only"}])

    report = reporting.write_report(
        act, stem="report-surface", findings_dir=surface, heading="Surface checkpoint",
    )

    assert report["summary"]["total"] == 1
    assert report["findings"][0]["title"] == "surface"
    assert report["findings"][0]["sources"] == [
        {"path": "checkpoints/surface/findings/dast.jsonl", "line": 1},
    ]
    assert (act.reports / "report-surface.json").exists()
    assert (act.reports / "report-surface.md").read_text().startswith("# Surface checkpoint")


def test_write_report_removes_legacy_root_copies_after_success(tmp_path):
    act = Activity.named("legacy", root=tmp_path).ensure()
    (act.base / "report.json").write_text("stale")
    (act.base / "report.md").write_text("stale")

    reporting.write_report(act)

    assert (act.reports / "report.json").exists()
    assert (act.reports / "report.md").exists()
    assert not (act.base / "report.json").exists()
    assert not (act.base / "report.md").exists()
