import os

from ptflow.cli import _apply_ai_flag, main
from ptflow.core import tools
from ptflow.core.orchestrator import orchestrate
from ptflow.pipelines import load_pipeline


def _scope(tmp_path):
    p = tmp_path / "scope.txt"
    p.write_text("https://example.com/\nnmap.org\n")
    return p


def test_orchestrate_end_to_end(tmp_path):
    scope_file = _scope(tmp_path)
    base, failures = orchestrate(
        load_pipeline("example"), "acme", str(scope_file), root=str(tmp_path / "runs")
    )
    assert base == tmp_path / "runs" / "acme"
    assert failures == 0  # clean run → no stage failures

    # scope expansion
    assert base.joinpath("scope.txt").exists()
    assert tools.read_lines(base / "scope" / "scope_init.txt") == ["https://example.com/", "nmap.org"]
    assert tools.read_lines(base / "scope" / "scope_dns.txt") == ["nmap.org"]
    assert tools.read_lines(base / "scope" / "scope_urls.txt") == ["https://example.com/"]

    # asset discovery: 2 targets x (apex + www) = 4 hosts (top-level, not under scans/)
    hosts = tools.read_jsonl(base / "asset_discovery" / "hosts.jsonl")
    assert len(hosts) == 4

    # clustered app groups: scans/ holds ONLY app groups now → 2 apexes -> 2 app dirs
    app_dirs = [d for d in (base / "scans").iterdir() if d.is_dir()]
    assert len(app_dirs) == 2
    for d in app_dirs:
        assert (d / "services.jsonl").exists()
        assert (d / "raw" / "enum" / "out.jsonl").exists()

    # spanning stage ran ∥ clustering + per-app and was joined at the fan-in
    scope = tools.read_jsonl(base / "findings" / "scope_scan.jsonl")
    assert len(scope) == 4  # one finding per discovered host (2 targets x apex+www)

    # agent output
    hyp = tools.read_jsonl(base / "findings" / "hypotheses.jsonl")
    assert len(hyp) >= 1
    assert all(h["source"] == "stub" for h in hyp)

    # standard activity dirs
    for sub in ("poc", "tmp", "wl_global", "logs"):
        assert (base / sub).is_dir()


def test_cli_run(tmp_path):
    scope_file = _scope(tmp_path)
    root = str(tmp_path / "runs")
    assert main(["run", "example", "acme", str(scope_file), "--root", root]) == 0
    assert (tmp_path / "runs" / "acme" / "findings" / "hypotheses.jsonl").exists()


def test_cli_run_verbose(tmp_path):
    scope_file = _scope(tmp_path)
    root = str(tmp_path / "runs")
    assert main(["run", "example", "acme", str(scope_file), "--root", root, "--verbose"]) == 0


def test_cli_resume_reruns_cleanly(tmp_path):
    scope_file = _scope(tmp_path)
    root = str(tmp_path / "runs")
    assert main(["run", "example", "acme", str(scope_file), "--root", root]) == 0
    base = tmp_path / "runs" / "acme"
    assert (base / ".state").is_dir()                      # completion markers were written
    assert list((base / ".state").glob("*.done"))          # at least one stage marked done
    # a --resume rerun completes cleanly (skipping done stages) and keeps the outputs
    assert main(["run", "example", "acme", str(scope_file), "--root", root, "--resume"]) == 0
    assert (base / "findings" / "hypotheses.jsonl").exists()


def test_cli_run_returns_nonzero_on_failure(tmp_path, monkeypatch):
    # orchestrate is imported inside cli._run (after run config is applied), so patch it at the source
    monkeypatch.setattr("ptflow.core.orchestrator.orchestrate", lambda *_a, **_k: (tmp_path, 3))
    scope_file = _scope(tmp_path)
    assert main(["run", "example", "acme", str(scope_file), "--root", str(tmp_path)]) == 1


def test_cli_observe_forwards_api_url_to_orchestrate(tmp_path, monkeypatch):
    captured: dict = {}
    monkeypatch.setattr("ptflow.core.orchestrator.orchestrate",
                        lambda *_a, **k: captured.update(k) or (tmp_path, 0))
    scope_file = _scope(tmp_path)
    rc = main(["run", "example", "acme", str(scope_file), "--root", str(tmp_path), "--observe"])
    assert rc == 0
    assert captured["observe"] == "http://127.0.0.1:4200/api"  # default local server, forwarded through

    captured.clear()
    main(["run", "example", "acme", str(scope_file), "--root", str(tmp_path)])
    assert captured["observe"] is None  # no --observe → no redirect (plain ephemeral run)


def test_cli_interrupted_returns_130(tmp_path, monkeypatch):
    # orchestrate returns the interrupted sentinel (-1) → CLI exits 130 (patched at the source — it's
    # imported inside cli._run after the run config is applied)
    monkeypatch.setattr("ptflow.core.orchestrator.orchestrate", lambda *_a, **_k: (tmp_path, -1))
    scope_file = _scope(tmp_path)
    assert main(["run", "example", "acme", str(scope_file), "--root", str(tmp_path)]) == 130


def test_apply_ai_flag_does_not_override_explicit_set():
    # --set ai=off must win over the --ai convenience flag (an explicit override outranks sugar for it)
    assert _apply_ai_flag(["ai=off"], ai=True) == ["ai=off"]


def test_apply_ai_flag_appends_when_absent():
    assert _apply_ai_flag([], ai=True) == ["ai=on"]
    assert _apply_ai_flag(["profile=home"], ai=False) == ["profile=home"]


def test_cli_run_set_ai_off_beats_ai_flag(tmp_path, monkeypatch):
    # End-to-end: `--set ai=off --ai` must resolve to PTFLOW_AI=off, not be silently clobbered by --ai.
    monkeypatch.setenv("PTFLOW_AI", "off")
    monkeypatch.setattr("ptflow.core.orchestrator.orchestrate", lambda *_a, **_k: (tmp_path, 0))
    monkeypatch.delenv("PTFLOW_AI", raising=False)
    scope_file = _scope(tmp_path)
    rc = main([
        "run", "example", "acme", str(scope_file), "--root", str(tmp_path),
        "--set", "ai=off", "--ai",
    ])
    assert rc == 0
    assert os.environ["PTFLOW_AI"] == "off"


def test_cli_serve_starts_prefect_server(monkeypatch):
    from ptflow import cli

    calls: dict = {}

    class _Result:
        returncode = 0

    monkeypatch.setattr(cli.subprocess, "run", lambda cmd, **_k: calls.update(cmd=cmd) or _Result())
    assert main(["serve"]) == 0
    assert "server" in calls["cmd"]
    assert "start" in calls["cmd"]
