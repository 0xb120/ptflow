import importlib
import json

from ptflow.core import tools
from ptflow.core.paths import Activity
from ptflow.pipelines.external import ai


class _FakeClient:
    name = "fake"

    def __init__(self, json_out=None, text_out=None):
        self._json = json_out
        self._text = text_out

    def complete_json(self, system, user, schema):  # noqa: ARG002
        return self._json

    def complete_text(self, system, user, *, max_tokens=64000):  # noqa: ARG002
        return self._text


def test_claude_provider_maps_hypotheses():
    out = ai.HypothesesOut(hypotheses=[
        ai.Hypothesis(title="chain", subject="shop-1a2b", rationale="cve+secret",
                      technique="rce", confidence="high"),
    ])
    prov = ai.ClaudeHypothesisProvider(_FakeClient(json_out=out))
    drafts = prov.propose([{"type": "cve", "app_id": "shop-1a2b", "cve": "CVE-1"}])
    assert len(drafts) == 1
    assert drafts[0].title == "chain"
    assert drafts[0].confidence == "high"


def test_claude_provider_empty_on_no_records():
    prov = ai.ClaudeHypothesisProvider(_FakeClient(json_out=None))
    assert prov.propose([]) == []


def test_claude_provider_empty_on_client_failure():
    prov = ai.ClaudeHypothesisProvider(_FakeClient(json_out=None))
    assert prov.propose([{"type": "cve"}]) == []


def test_report_writes_markdown(tmp_path, monkeypatch):
    act = Activity.named("r", root=tmp_path).ensure()
    tools.write_jsonl(act.findings / "cve.jsonl", [{"app_id": "a", "cve": "CVE-1"}])
    monkeypatch.setattr(ai, "make_client", lambda: _FakeClient(text_out="# Report\n\nok"))
    ai.report(act)
    assert (act.base / "report.md").read_text(encoding="utf-8") == "# Report\n\nok"


def test_report_noop_when_client_none(tmp_path, monkeypatch):
    act = Activity.named("r2", root=tmp_path).ensure()
    tools.write_jsonl(act.findings / "cve.jsonl", [{"app_id": "a", "cve": "CVE-1"}])
    monkeypatch.setattr(ai, "make_client", lambda: None)
    ai.report(act)
    assert not (act.base / "report.md").exists()


def test_ai_wordlist_writes_seed(tmp_path, monkeypatch):
    act = Activity.named("w", root=tmp_path).ensure()
    ws = act.app("shop-1a2b").ensure()
    tools.write_lines(ws.canonical("endpoints.txt"), ["https://x/checkout", "https://x/cart"])
    (ws.meta).write_text(json.dumps({"tech": ["php"], "hosts": ["shop.example"]}), encoding="utf-8")
    out = ai.WordlistOut(candidates=["coupon", "giftcard", "voucher"])
    monkeypatch.setattr(ai, "make_client", lambda: _FakeClient(json_out=out))
    ai.ai_wordlist(act, "shop-1a2b")
    assert tools.read_lines(ws.wl_custom / "ai_seed.txt") == ["coupon", "giftcard", "voucher"]


def test_ai_wordlist_noop_when_client_none(tmp_path, monkeypatch):
    act = Activity.named("w2", root=tmp_path).ensure()
    ws = act.app("a").ensure()
    tools.write_lines(ws.canonical("endpoints.txt"), ["https://x/y"])
    monkeypatch.setattr(ai, "make_client", lambda: None)
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


def test_ai_secret_triage_writes_verdicts(tmp_path, monkeypatch):
    act = Activity.named("s", root=tmp_path).ensure()
    ws = act.app("a").ensure()
    tools.write_jsonl(ws.canonical("secrets.jsonl"),
                      [{"kind": "aws", "value": "AKIA..."}, {"kind": "test", "value": "test123"}])
    out = ai.SecretTriageOut(verdicts=[
        ai.SecretVerdict(index=0, verdict="real", rationale="live AWS key shape"),
        ai.SecretVerdict(index=1, verdict="test", rationale="obvious test value"),
    ])
    monkeypatch.setattr(ai, "make_client", lambda: _FakeClient(json_out=out))
    ai.ai_secret_triage(act, "a")
    recs = tools.read_jsonl(ws.findings / "secrets_triage.jsonl")
    assert len(recs) == 2
    assert recs[0]["verdict"] == "real"
    assert recs[0]["secret"]["kind"] == "aws"        # original payload preserved
    assert recs[1]["verdict"] == "test"


def test_ai_secret_triage_noop_when_no_secrets(tmp_path, monkeypatch):
    act = Activity.named("s2", root=tmp_path).ensure()
    ws = act.app("a").ensure()
    monkeypatch.setattr(ai, "make_client", lambda: _FakeClient(json_out=None))
    ai.ai_secret_triage(act, "a")
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


def test_ai_stages_present_when_on(monkeypatch):
    monkeypatch.setenv("PTFLOW_AI", "on")
    p = _reload_pipeline()
    names = {s.name for s in p.PIPELINE.stages}
    assert "ai_wordlist" in names
    assert "ai_secret_triage" in names
    by_name = {s.name: s for s in p.PIPELINE.stages}
    assert by_name["ai_wordlist"].phase == 2
    assert by_name["ai_wordlist"].net is False
    assert by_name["ai_secret_triage"].phase == 4
    monkeypatch.delenv("PTFLOW_AI", raising=False)
    _reload_pipeline()  # restore module state for later tests


def test_provider_is_stub_without_ai(monkeypatch):
    monkeypatch.delenv("PTFLOW_AI", raising=False)
    p = _reload_pipeline()
    assert p.PIPELINE.provider().name == "stub"
