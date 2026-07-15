import importlib
import json

from ptflow.core import tools
from ptflow.core.ai.client import LLMResult
from ptflow.core.paths import Activity
from ptflow.pipelines.external import ai


class _FakeClient:
    name = "fake"
    model = "fake-model"
    remote = False

    def __init__(self, json_out=None, text_out=None, *, remote=False):
        self._json = json_out
        self._text = text_out
        self.remote = remote
        self.last_user = None

    def complete_json(self, system, user, schema):  # noqa: ARG002
        self.last_user = user
        return LLMResult(value=self._json, provider=self.name, model=self.model)

    def complete_text(self, system, user, *, max_tokens=64000):  # noqa: ARG002
        return LLMResult(value=self._text, provider=self.name, model=self.model)


def test_llm_provider_maps_hypotheses():
    out = ai.HypothesesOut(hypotheses=[
        ai.Hypothesis(title="chain", subject="shop-1a2b", rationale="cve+secret",
                      technique="rce", confidence=0.9, finding_ids=["f1"], severity="high"),
    ])
    prov = ai.LLMHypothesisProvider(_FakeClient(json_out=out))
    drafts = prov.propose([{"id": "f1", "type": "cve", "app_id": "shop-1a2b",
                            "cve": "CVE-1"}])
    assert len(drafts) == 1
    assert drafts[0].title == "chain"
    assert drafts[0].confidence == "high"
    assert drafts[0].confidence_score == 0.9
    assert drafts[0].finding_ids == ["f1"]
    assert prov.name == "fake"


def test_llm_provider_empty_on_no_records():
    prov = ai.LLMHypothesisProvider(_FakeClient(json_out=None))
    assert prov.propose([]) == []


def test_llm_provider_empty_on_client_failure():
    prov = ai.LLMHypothesisProvider(_FakeClient(json_out=None))
    assert prov.propose([{"type": "cve"}]) == []


def test_llm_provider_drops_hypothesis_with_unknown_finding_id():
    out = ai.HypothesesOut(hypotheses=[
        ai.Hypothesis(title="invented", finding_ids=["not-present"], confidence=0.8),
    ])
    prov = ai.LLMHypothesisProvider(_FakeClient(json_out=out))
    assert prov.propose([{"id": "real-id", "type": "cve"}]) == []


def test_report_writes_markdown(tmp_path, monkeypatch):
    act = Activity.named("r", root=tmp_path).ensure()
    tools.write_jsonl(act.findings / "cve.jsonl", [{"app_id": "a", "cve": "CVE-1"}])
    finding = ai.reporting.gather_findings(act)[0]
    output = ai.AIReportOut(
        executive_summary="Prioritize the confirmed issue.",
        overall_risk="high",
        priorities=[ai.ReportPriority(
            finding_id=finding["id"], impact="impact", remediation="fix it",
        )],
    )
    monkeypatch.setattr(ai, "make_client", lambda *_args: _FakeClient(json_out=output))
    ai.report(act)
    text = (act.base / "report-ai.md").read_text(encoding="utf-8")
    assert "Prioritize the confirmed issue" in text
    assert finding["id"] in text
    assert "Evidence source" in text


def test_report_noop_when_client_none(tmp_path, monkeypatch):
    act = Activity.named("r2", root=tmp_path).ensure()
    tools.write_jsonl(act.findings / "cve.jsonl", [{"app_id": "a", "cve": "CVE-1"}])
    monkeypatch.setattr(ai, "make_client", lambda *_args: None)
    ai.report(act)
    assert not (act.base / "report-ai.md").exists()


def test_ai_wordlist_writes_seed(tmp_path, monkeypatch):
    act = Activity.named("w", root=tmp_path).ensure()
    ws = act.app("shop-1a2b").ensure()
    tools.write_lines(ws.canonical("endpoints.txt"), ["https://x/checkout", "https://x/cart"])
    (ws.meta).write_text(json.dumps({"tech": ["php"], "hosts": ["shop.example"]}), encoding="utf-8")
    out = ai.WordlistOut(candidates=["coupon", "giftcard", "voucher"])
    monkeypatch.setattr(ai, "make_client", lambda *_args: _FakeClient(json_out=out))
    ai.ai_wordlist(act, "shop-1a2b")
    assert tools.read_lines(ws.wl_custom / "ai_seed.txt") == ["coupon", "giftcard", "voucher"]


def test_ai_wordlist_noop_when_client_none(tmp_path, monkeypatch):
    act = Activity.named("w2", root=tmp_path).ensure()
    ws = act.app("a").ensure()
    tools.write_lines(ws.canonical("endpoints.txt"), ["https://x/y"])
    monkeypatch.setattr(ai, "make_client", lambda *_args: None)
    ai.ai_wordlist(act, "a")
    assert not (ws.wl_custom / "ai_seed.txt").exists()


def test_build_content_wordlist_folds_ai_seed(tmp_path):
    from ptflow.pipelines.external import tasks

    act = Activity.named("wl", root=tmp_path).ensure()
    ws = act.app("a").ensure()
    tools.write_lines(ws.wl_custom / "seed.txt", ["login"])
    tools.write_lines(ws.wl_custom / "ai_seed.txt", ["coupon"])
    combined = tasks.build_content_wordlist(act, ws, [])
    assert "coupon" in combined
    assert "login" in combined


def test_safe_http_probe_policy_accepts_read_only_and_rejects_dangerous_shapes():
    probe, reason = ai.validate_safe_http_probe(ai.SafeHTTPProbe(
        method="GET", path="/api/version", expected_statuses=[200],
        expected_body_contains=["1.13.0"],
    ))
    assert reason == "allowed"
    assert probe["path"] == "/api/version"

    for unsafe in (
        ai.SafeHTTPProbe(method="GET", path="//evil.test/x", expected_body_contains=["owned"]),
        ai.SafeHTTPProbe(method="GET", path="/api/delete", expected_body_contains=["deleted"]),
        ai.SafeHTTPProbe(method="GET", path="/fetch?url=http%3A%2F%2F127.0.0.1",
                         expected_body_contains=["metadata"]),
        ai.SafeHTTPProbe(method="GET", path="/%252e%252e/etc/passwd",
                         expected_body_contains=["root:"]),
        ai.SafeHTTPProbe(method="GET", path="/api/version"),
    ):
        assert ai.validate_safe_http_probe(unsafe)[0] is None


def test_ai_cve_poc_downgrades_unsafe_model_probe_without_execution(tmp_path, monkeypatch):
    act = Activity.named("poc-policy", root=tmp_path).ensure()
    ws = act.app("a").ensure()
    tools.write_jsonl(ws.findings / "cve.jsonl", [{
        "cve": "CVE-2026-1", "product": "Arcane API", "version": "1.13.0",
        "poc": ["https://example.test/poc"], "description": "unsafe PoC",
    }])
    output = ai.CVEPocOut(decisions=[ai.CVEPocDecision(
        index=0, action="safe_http_probe", rationale="try traversal",
        probe=ai.SafeHTTPProbe(
            method="GET", path="/read?file=/etc/passwd", expected_body_contains=["root:"],
        ),
    )])
    monkeypatch.setattr(ai, "make_client", lambda *_args: _FakeClient(json_out=output))
    monkeypatch.setattr(
        ai, "_execute_safe_http_probe",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must not execute")),
    )

    ai.ai_cve_poc(act, "a")

    [triage] = tools.read_jsonl(ws.canonical("cve_poc_triage.jsonl"))
    assert triage["action"] == "safe_http_probe"
    assert triage["effective_action"] == "manual_review"
    assert triage["outcome"]["executed"] is False
    assert tools.read_jsonl(ws.findings / "cve_verified.jsonl") == []


def test_ai_cve_poc_persists_only_matched_policy_validated_probe(tmp_path, monkeypatch):
    act = Activity.named("poc-match", root=tmp_path).ensure()
    ws = act.app("a").ensure()
    poc = "https://github.com/example/advisory"
    tools.write_jsonl(ws.findings / "cve.jsonl", [{
        "cve": "CVE-2026-2", "product": "Arcane API", "version": "1.13.0", "cvss": 9.8,
        "poc": [poc], "description": "GET /api/version exposes the vulnerable build",
    }])
    output = ai.CVEPocOut(decisions=[ai.CVEPocDecision(
        index=0, action="safe_http_probe", rationale="version endpoint is read-only",
        probe=ai.SafeHTTPProbe(
            method="GET", path="/api/version", expected_statuses=[200],
            expected_body_contains=["1.13.0"],
        ),
    )])
    client = _FakeClient(json_out=output)
    monkeypatch.setattr(ai, "make_client", lambda *_args: client)
    monkeypatch.setattr(ai, "_execute_safe_http_probe", lambda *_args, **_kwargs: {
        "executed": True, "matched": True, "status": 200,
        "target": "https://arcane.test/api/version",
        "body_artifact": "raw/cve_poc/surface/CVE-2026-2/body.txt",
    })

    ai.ai_cve_poc(act, "a")

    assert poc in client.last_user
    [verified] = tools.read_jsonl(ws.findings / "cve_verified.jsonl")
    assert verified["verification"] == "llm-planned-safe-http"
    assert verified["probe_result"]["matched"] is True


def test_safe_http_probe_executor_uses_one_curl_request_and_no_nuclei(tmp_path, monkeypatch):
    from pathlib import Path

    from ptflow.pipelines.external import tasks

    act = Activity.named("poc-curl", root=tmp_path).ensure()
    act.app("a").ensure()
    monkeypatch.setattr(tasks, "_scan_hosts", lambda _ws: ["https://arcane.test"])
    monkeypatch.setattr(ai.shutil, "which", lambda _name: "/usr/bin/curl")
    calls = []

    def fake_run(cmd, **_kwargs):
        calls.append(cmd)
        header_path = cmd[cmd.index("-D") + 1]
        body_path = cmd[cmd.index("-o") + 1]
        tools.write_text(Path(header_path), "HTTP/1.1 200 OK\nContent-Type: application/json\n")
        tools.write_text(Path(body_path), '{"version":"1.13.0"}')
        return "200"

    monkeypatch.setattr(ai.tools, "run", fake_run)
    result = ai._execute_safe_http_probe(
        act, "a", {"cve": "CVE-2026-2"}, {
            "method": "GET", "path": "/api/version", "expected_statuses": [200],
            "expected_body_contains": ["1.13.0"], "expected_header_contains": [],
        }, "surface",
    )

    assert len(calls) == 1
    assert calls[0][0] == "curl"
    assert "nuclei" not in calls[0]
    assert calls[0][-1] == "https://arcane.test/api/version"
    assert result["matched"] is True


def test_ai_secret_triage_writes_verdicts(tmp_path, monkeypatch):
    act = Activity.named("s", root=tmp_path).ensure()
    ws = act.app("a").ensure()
    tools.write_jsonl(ws.canonical("secrets.jsonl"),
                      [{"kind": "aws", "value": "AKIA..."}, {"kind": "test", "value": "test123"}])
    out = ai.SecretTriageOut(verdicts=[
        ai.SecretVerdict(index=0, verdict="likely_credential", rationale="live AWS key shape"),
        ai.SecretVerdict(index=1, verdict="example", rationale="obvious test value"),
    ])
    monkeypatch.setattr(ai, "make_client", lambda *_args: _FakeClient(json_out=out))
    ai.ai_secret_triage(act, "a")
    recs = tools.read_jsonl(ws.findings / "secrets_triage.jsonl")
    assert len(recs) == 2
    assert recs[0]["verdict"] == "likely_credential"
    assert recs[0]["secret"]["kind"] == "aws"        # original payload preserved
    assert recs[1]["verdict"] == "example"


def test_ai_secret_triage_noop_when_no_secrets(tmp_path, monkeypatch):
    act = Activity.named("s2", root=tmp_path).ensure()
    ws = act.app("a").ensure()
    monkeypatch.setattr(ai, "make_client", lambda *_args: _FakeClient(json_out=None))
    ai.ai_secret_triage(act, "a")
    assert not (ws.findings / "secrets_triage.jsonl").exists()


def test_remote_secret_triage_redacts_prompt_but_preserves_local_evidence(tmp_path, monkeypatch):
    monkeypatch.setenv("PTFLOW_AI_REMOTE_SECRETS", "redacted")
    act = Activity.named("remote-secret", root=tmp_path).ensure()
    ws = act.app("a").ensure()
    original = "AKIA-VERY-SENSITIVE"
    tools.write_jsonl(ws.canonical("secrets.jsonl"), [{"kind": "aws", "value": original}])
    out = ai.SecretTriageOut(verdicts=[
        ai.SecretVerdict(index=0, verdict="unknown", rationale="redacted input"),
    ])
    client = _FakeClient(json_out=out, remote=True)
    monkeypatch.setattr(ai, "make_client", lambda *_args: client)

    ai.ai_secret_triage(act, "a")

    assert original not in client.last_user
    assert '"redacted": true' in client.last_user
    record = tools.read_jsonl(ws.findings / "secrets_triage.jsonl")[0]
    assert record["secret"]["value"] == original
    assert record["ai_input"] == "redacted"


def test_remote_secret_policy_off_skips_call(tmp_path, monkeypatch):
    monkeypatch.setenv("PTFLOW_AI_REMOTE_SECRETS", "off")
    act = Activity.named("remote-off", root=tmp_path).ensure()
    ws = act.app("a").ensure()
    tools.write_jsonl(ws.canonical("secrets.jsonl"), [{"kind": "aws", "value": "secret"}])
    client = _FakeClient(remote=True)
    monkeypatch.setattr(ai, "make_client", lambda *_args: client)

    ai.ai_secret_triage(act, "a")

    assert client.last_user is None
    assert not (ws.findings / "secrets_triage.jsonl").exists()


def test_consolidate_lifts_secrets_triage(tmp_path):
    from ptflow.pipelines.external import tasks

    act = Activity.named("c", root=tmp_path).ensure()
    ws = act.app("a").ensure()
    tools.write_jsonl(ws.findings / "secrets_triage.jsonl",
                      [{"index": 0, "verdict": "real", "rationale": "x", "secret": {"kind": "aws"}}])
    tasks.consolidate(act)
    lifted = tools.read_jsonl(act.findings / "secrets_triage.jsonl")
    assert len(lifted) == 1
    assert lifted[0]["app_id"] == "a"
    assert lifted[0]["verdict"] == "real"


def _reload_pipeline():
    import ptflow.pipelines.external.pipeline as p
    return importlib.reload(p)


def test_ai_stages_absent_when_off(monkeypatch):
    monkeypatch.delenv("PTFLOW_AI", raising=False)
    p = _reload_pipeline()
    names = {s.name for s in p.PIPELINE.stages}
    assert "ai_wordlist" not in names
    assert "ai_secret_triage" not in names
    assert "ai_cve_poc" not in names
    assert "ai_cve_poc_full" not in names


def test_ai_stages_present_when_on(monkeypatch):
    monkeypatch.setenv("PTFLOW_AI", "on")
    p = _reload_pipeline()
    names = {s.name for s in p.PIPELINE.stages}
    assert "ai_wordlist" in names
    assert "ai_secret_triage" in names
    assert "ai_cve_poc" in names
    assert "ai_cve_poc_full" in names
    by_name = {s.name: s for s in p.PIPELINE.stages}
    assert by_name["ai_wordlist"].phase == 2
    assert by_name["ai_wordlist"].net is False
    assert by_name["ai_secret_triage"].phase == 4
    assert by_name["ai_cve_poc"].phase == 2
    assert by_name["ai_cve_poc"].needs == ("cve_lookup",)
    assert by_name["ai_cve_poc"].net is True
    assert by_name["ai_cve_poc_full"].phase == 4
    assert by_name["ai_cve_poc_full"].needs == ("cve_lookup_full",)
    monkeypatch.delenv("PTFLOW_AI", raising=False)
    _reload_pipeline()  # restore module state for later tests


def test_per_stage_toggle_removes_only_selected_stage(monkeypatch):
    monkeypatch.setenv("PTFLOW_AI", "on")
    monkeypatch.setenv("PTFLOW_AI_STAGE_WORDLIST_ENABLED", "off")
    monkeypatch.setenv("PTFLOW_AI_STAGE_SECRET_TRIAGE_ENABLED", "on")
    p = _reload_pipeline()
    names = {stage.name for stage in p.PIPELINE.stages}
    assert "ai_wordlist" not in names
    assert "ai_secret_triage" in names
    monkeypatch.delenv("PTFLOW_AI", raising=False)
    monkeypatch.delenv("PTFLOW_AI_STAGE_WORDLIST_ENABLED", raising=False)
    monkeypatch.delenv("PTFLOW_AI_STAGE_SECRET_TRIAGE_ENABLED", raising=False)
    _reload_pipeline()


def test_provider_is_stub_without_ai(monkeypatch):
    monkeypatch.delenv("PTFLOW_AI", raising=False)
    p = _reload_pipeline()
    assert p.PIPELINE.provider().name == "stub"
