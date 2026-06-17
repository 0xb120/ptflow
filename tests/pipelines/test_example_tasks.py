# tests/pipelines/test_example_tasks.py
import json

from pipt.core.paths import Engagement
from pipt.core.scope import Target
from pipt.pipelines.example import tasks


def test_discover_writes_hosts_jsonl(tmp_path):
    eng = Engagement.for_scan("demo", root=tmp_path).ensure()
    t = Target(raw="example.com", kind="domain", normalized="example.com", tid="t_aaa111")
    tasks.discover(eng, [t])
    records = [json.loads(ln) for ln in eng.surface_canonical("hosts.jsonl").read_text().splitlines()]
    names = {r["name"] for r in records}
    assert names == {"example.com", "www.example.com"}
    assert all(r["targets"] == ["t_aaa111"] for r in records)
    assert (eng.surface_raw("discover") / "out.jsonl").exists()


def test_enum_reads_hosts_txt_writes_services(tmp_path):
    eng = Engagement.for_scan("demo", root=tmp_path).ensure()
    t = Target(raw="example.com", kind="domain", normalized="example.com", tid="t_aaa111")
    ws = eng.target(t.tid).ensure()
    ws.canonical("hosts.txt").write_text("example.com\nwww.example.com\n")
    tasks.enum(eng, t)
    records = [json.loads(ln) for ln in ws.canonical("services.jsonl").read_text().splitlines()]
    assert len(records) == 2
    assert all(r["port"] == 443 for r in records)
    assert (ws.raw("enum") / "out.jsonl").exists()


def test_pipeline_object_shape():
    from pipt.pipelines.example.pipeline import PIPELINE

    assert PIPELINE.name == "example"
    assert [s.name for s in PIPELINE.stages] == ["discover", "enum"]
    assert "example_note" in PIPELINE.extension_schema()
