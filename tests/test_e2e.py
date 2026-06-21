from pipt.cli import main
from pipt.core import tools
from pipt.core.orchestrator import orchestrate
from pipt.pipelines import load_pipeline


def _scope(tmp_path):
    p = tmp_path / "scope.txt"
    p.write_text("https://example.com/\nnmap.org\n")
    return p


def test_orchestrate_end_to_end(tmp_path):
    scope_file = _scope(tmp_path)
    base = orchestrate(load_pipeline("example"), "acme", str(scope_file), root=str(tmp_path / "runs"))
    assert base == tmp_path / "runs" / "acme"

    # scope expansion
    assert base.joinpath("scope.txt").exists()
    assert tools.read_lines(base / "scope" / "scope_init.txt") == ["https://example.com/", "nmap.org"]
    assert tools.read_lines(base / "scope" / "scope_dns.txt") == ["nmap.org"]
    assert tools.read_lines(base / "scope" / "scope_urls.txt") == ["https://example.com/"]

    # asset discovery: 2 targets x (apex + www) = 4 hosts
    hosts = tools.read_jsonl(base / "scans" / "asset_discovery" / "hosts.jsonl")
    assert len(hosts) == 4

    # clustered app groups: 2 apexes -> 2 app dirs, each enumerated
    app_dirs = [d for d in (base / "scans").iterdir() if d.is_dir() and d.name != "asset_discovery"]
    assert len(app_dirs) == 2
    for d in app_dirs:
        assert (d / "services.jsonl").exists()
        assert (d / "raw" / "enum" / "out.jsonl").exists()

    # agent output
    hyp = tools.read_jsonl(base / "findings" / "hypotheses.jsonl")
    assert len(hyp) >= 1
    assert all(h["source"] == "stub" for h in hyp)

    # standard activity dirs
    for sub in ("poc", "tmp", "wl", "logs"):
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
