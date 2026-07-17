import json
import subprocess
from concurrent.futures import ThreadPoolExecutor

import pytest

from ptflow.core import telemetry, tools
from ptflow.core.paths import Activity
from ptflow.core.stage import Stage


class _Pipeline:
    name = "test"
    stages = (
        Stage("collect", lambda *_: None, net=False),
        Stage("scan", lambda *_: None, needs=("collect",), per_app=True),
    )


def test_trace_collects_io_commands_and_malformed_drops_without_argv(tmp_path):
    act = Activity.named("trace", root=tmp_path).ensure()
    run_id = "run-1"
    data = act.base / "data.jsonl"

    def work():
        tools.write_text(data, '{"ok": 1}\nnot-json\n')
        assert tools.read_jsonl(data) == [{"ok": 1}]
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = telemetry.submit(pool, tools.run, ["sh", "-c", "printf sensitive-value"])
            assert future.result() == "sensitive-value"
        with pytest.raises(subprocess.TimeoutExpired):
            tools.run(["sh", "-c", "sleep 1"], timeout=0)
        with pytest.raises(tools.ToolNotFoundError):
            tools.require("ptflow-tool-that-does-not-exist")
        telemetry.record_cap("candidate_set", limit=2, observed=5, selected=2)
        telemetry.record_drop("candidate_cap", 3)

    telemetry.trace_call(
        act,
        run_id,
        stage="collect",
        app_id=None,
        band="breadth",
        net=False,
        call=work,
    )
    fragment = json.loads(next((act.state / "coverage" / run_id).glob("*.json")).read_text())

    assert fragment["status"] == "success"
    assert fragment["reads"] == [
        {"count": 1, "kind": "jsonl", "path": "data.jsonl", "present": True}
    ]
    assert fragment["drops"] == {"candidate_cap": 3, "malformed_jsonl": 1}
    assert fragment["caps"] == [
        {
            "applied": True,
            "limit": 2,
            "name": "candidate_set",
            "observed": 5,
            "selected": 2,
        }
    ]
    assert fragment["commands"][0]["tool"] == "sh"
    assert [command["status"] for command in fragment["commands"]] == [
        "success",
        "timeout",
        "missing",
    ]
    assert "sensitive-value" not in json.dumps(fragment)


def test_trace_persists_failure_and_reraises(tmp_path):
    act = Activity.named("failed", root=tmp_path).ensure()

    def fail():
        msg = "stage broke"
        raise RuntimeError(msg)

    with pytest.raises(RuntimeError, match="stage broke"):
        telemetry.trace_call(
            act,
            "run-2",
            stage="scan",
            app_id="app",
            band="loop:1",
            net=True,
            call=fail,
        )
    fragment = json.loads(next((act.state / "coverage" / "run-2").glob("*.json")).read_text())
    assert fragment["status"] == "failed"
    assert fragment["error"] == "RuntimeError: stage broke"


def test_finalize_manifest_includes_limits_disabled_and_stage_summary(tmp_path):
    act = Activity.named("manifest", root=tmp_path).ensure()
    pipeline = _Pipeline()
    run = telemetry.begin_run(
        act,
        pipeline,
        scope_text="example.com\n",
        resume_requested=True,
        resume_effective=False,
        disabled=("scan",),
        fanout=3,
        net_limit=4,
        config_fingerprint="config-hash",
    )
    telemetry.trace_call(
        act,
        run.run_id,
        stage="collect",
        app_id=None,
        band="breadth",
        net=False,
        call=lambda: tools.write_lines(act.base / "targets.txt", ["example.com"]),
    )

    manifest = telemetry.finalize_run(
        act,
        run,
        pipeline.stages,
        status="completed",
        failures=(),
        disabled=("scan",),
    )

    assert manifest["limits"]["fanout_workers"] == 3
    assert manifest["limits"]["network_stages"] == 4
    assert manifest["resume"] == {"requested": True, "effective": False}
    assert manifest["config_sha256"] == "config-hash"
    assert manifest["summary"]["stage_statuses"] == {"disabled": 1, "success": 1}
    disabled = next(stage for stage in manifest["stages"] if stage["status"] == "disabled")
    assert disabled["stage"] == "scan"
    assert disabled["scope"] == "all-apps"
    assert json.loads((act.base / "coverage.json").read_text()) == manifest
