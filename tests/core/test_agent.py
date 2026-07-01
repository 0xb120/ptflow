from ptflow.core import agent, tools
from ptflow.core.paths import Activity


def _activity_with_services(tmp_path):
    act = Activity.named("demo", root=tmp_path).ensure()
    ws = act.app("app_aaa").ensure()
    tools.write_jsonl(
        ws.canonical("services.jsonl"),
        [
            {"ip": "10.0.0.1", "port": 22, "service": "ssh"},
            {"ip": "10.0.0.1", "port": 443, "service": "https"},
        ],
    )
    return act


def test_stub_proposes_one_per_service(tmp_path):
    act = _activity_with_services(tmp_path)
    n = agent.propose_hypotheses(act)
    assert n == 2
    records = tools.read_jsonl(act.findings / "hypotheses.jsonl")
    assert len(records) == 2
    assert all(r["source"] == "stub" for r in records)
    assert {r["subject"] for r in records} == {"10.0.0.1:22", "10.0.0.1:443"}


def test_custom_provider_used(tmp_path):
    act = _activity_with_services(tmp_path)

    class P:
        name = "custom"

        def propose(self, services):  # noqa: ARG002
            return [agent.HypothesisDraft(title="x", confidence="high")]

    n = agent.propose_hypotheses(act, P())
    assert n == 1
    records = tools.read_jsonl(act.findings / "hypotheses.jsonl")
    assert records[0]["source"] == "custom"
    assert records[0]["title"] == "x"
