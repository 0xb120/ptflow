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
