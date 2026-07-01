# tests/core/test_requirements.py
from ptflow.core import requirements as rq


def test_version_satisfies_compares_numerically_not_lexically():
    assert rq.version_satisfies("1.3.0", "1.3")
    assert rq.version_satisfies("1.10", "1.3")      # 10 > 3 numerically (lexical would fail)
    assert rq.version_satisfies("2.0", "1.3")
    assert not rq.version_satisfies("1.2.9", "1.3")


def test_parse_version_extracts_dotted_number():
    assert rq.parse_version("interactsh-client 1.3.2") == "1.3.2"
    assert rq.parse_version("Current Version: v2.6.1\n") == "2.6.1"
    assert rq.parse_version("no version here") is None


def test_check_marks_core_tool_present_and_optional_missing():
    reqs = [
        rq.Requirement("httpx", "/x/httpx", "core"),
        rq.Requirement("dalfox", "dalfox", "optional"),
    ]
    rep = rq.check(reqs, resolve=lambda req: "/x/httpx" if req.name == "httpx" else None)
    by = {r.req.name: r for r in rep.results}
    assert by["httpx"].found
    assert by["httpx"].ok
    assert by["httpx"].resolved == "/x/httpx"
    assert not by["dalfox"].found
    assert not by["dalfox"].ok


def test_report_fails_only_on_missing_core():
    opt_only = rq.check([rq.Requirement("opt", "opt", "optional")], resolve=lambda _req: None)
    assert opt_only.ok                              # optional missing → still passes
    assert opt_only.exit_code == 0

    core_gone = rq.check([rq.Requirement("c", "c", "core")], resolve=lambda _req: None)
    assert not core_gone.ok                         # core missing → fails
    assert core_gone.exit_code == 1
    assert [r.req.name for r in core_gone.core_missing] == ["c"]


def test_core_dataset_missing_fails_by_path_existence(tmp_path):
    present = tmp_path / "resolvers.txt"
    present.write_text("8.8.8.8\n")
    reqs = [
        rq.Requirement("resolvers", str(present), "core", category="dataset"),
        rq.Requirement("templates", str(tmp_path / "missing"), "core", category="dataset"),
    ]
    rep = rq.check(reqs)   # default resolver → real path-existence check for datasets
    by = {r.req.name: r for r in rep.results}
    assert by["resolvers"].ok
    assert not by["templates"].ok
    assert rep.exit_code == 1


def test_version_floor_violation_on_optional_is_not_fatal():
    reqs = [rq.Requirement("interactsh-client", "ic", "optional", min_version="1.3")]
    rep = rq.check(reqs, resolve=lambda _req: "ic", version_of=lambda _req, _path: "1.2.4")
    r = rep.results[0]
    assert r.found
    assert r.version == "1.2.4"
    assert r.version_ok is False
    assert not r.ok        # the item itself is flagged (outdated)
    assert rep.ok          # but it's optional → the report still passes


def test_version_floor_met_marks_ok():
    reqs = [rq.Requirement("interactsh-client", "ic", "optional", min_version="1.3")]
    rep = rq.check(reqs, resolve=lambda _req: "ic", version_of=lambda _req, _path: "1.3.2")
    r = rep.results[0]
    assert r.version_ok is True
    assert r.ok


def test_render_report_groups_marks_and_names_pipeline():
    reqs = [
        rq.Requirement("httpx", "httpx", "core"),
        rq.Requirement("dalfox", "dalfox", "optional"),
    ]
    rep = rq.check(reqs, resolve=lambda req: "httpx" if req.name == "httpx" else None)
    text = rq.render_report(rep, pipeline="external")
    assert "external" in text
    assert "httpx" in text
    assert "dalfox" in text
    assert "✓" in text   # ✓ present
    assert "✗" in text   # ✗ missing
