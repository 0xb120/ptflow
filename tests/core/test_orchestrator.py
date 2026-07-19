from ptflow.core import orchestrator
from ptflow.core.stage import Stage


def test_topo_order_respects_deps():
    a = Stage("a", lambda *_: None)
    b = Stage("b", lambda *_: None, needs=("a",))
    c = Stage("c", lambda *_: None, needs=("a",))
    d = Stage("d", lambda *_: None, needs=("b", "c"))
    order = [s.name for s in orchestrator.topo_order([d, c, b, a])]
    assert order.index("a") < order.index("b")
    assert order.index("a") < order.index("c")
    assert order.index("b") < order.index("d")
    assert order.index("c") < order.index("d")


def test_topo_order_ignores_foreign_needs():
    # a need that isn't in the given set (e.g. a cross-scope dep) is skipped
    s = Stage("only", lambda *_: None, needs=("not_here",))
    assert [x.name for x in orchestrator.topo_order([s])] == ["only"]


def test_await_isolates_and_records_failure():
    class _OkFut:
        def result(self):
            return "ok"

    class _BadFut:
        def result(self):
            msg = "boom"
            raise RuntimeError(msg)

    failures: list[str] = []
    orchestrator._await(_OkFut(), "good", failures)
    orchestrator._await(_BadFut(), "bad", failures)
    assert failures == ["bad"]  # the good stage didn't abort; the bad one is recorded, not raised


def test_server_reachable_false_for_dead_port():
    # nothing listens on :1 → --observe falls back to ephemeral instead of stalling
    assert orchestrator._server_reachable("http://127.0.0.1:1/api", timeout=0.5) is False


def test_pool_size_adds_spanning_headroom():
    stages = [
        Stage("a", lambda *_: None),                      # breadth — not counted
        Stage("b", lambda *_: None, spanning=True),
        Stage("c", lambda *_: None, spanning=True),
        Stage("d", lambda *_: None, cluster_scope=True),
        Stage("e", lambda *_: None, per_app=True),        # fan-out — not counted
    ]
    assert orchestrator._pool_size(stages, 3) == 3 + 3     # 3 fan-out + (2 spanning + 1 cluster_scope)
    assert orchestrator._pool_size([Stage("x", lambda *_: None)], 3) == 3  # no spanning → just fan-out


def test_fanout_semaphore_bound_matches_config():
    from ptflow.core.config import CONFIG

    # the per-app fan-out cap is enforced by this semaphore (pool is larger), so it must equal max_workers
    assert orchestrator._FANOUT_SLOTS._initial_value == CONFIG.fanout.max_workers


def test_stage_tags_omit_net_for_offline():
    netty = Stage("a", lambda *_: None)               # net defaults True
    offline = Stage("b", lambda *_: None, net=False)
    assert "net" in orchestrator._stage_tags(netty)
    assert "net" not in orchestrator._stage_tags(offline)   # offline stage not counted against net cap


def test_stage_tags_include_declared_agents():
    tagged = Stage("research", lambda *_: None, net=False, agents=("research",))
    assert orchestrator._stage_tags(tagged) == ["breadth", "agent:research"]


def test_net_slots_is_bounded_semaphore():
    import threading

    assert isinstance(orchestrator._NET_SLOTS, threading.BoundedSemaphore)
    assert orchestrator._NET_SLOTS._initial_value == orchestrator._NET_LIMIT


def test_stage_tags_by_band():
    base = Stage("a", lambda *_: None)
    span = Stage("b", lambda *_: None, spanning=True)
    clus = Stage("c", lambda *_: None, cluster_scope=True)
    loop2 = Stage("d", lambda *_: None, per_app=True, phase=2)
    checkpoint2 = Stage("e", lambda *_: None, after_phase=2, net=False)
    assert orchestrator._stage_tags(base) == ["net", "breadth"]      # UI band tags for the run graph
    assert orchestrator._stage_tags(span) == ["net", "spanning"]
    assert orchestrator._stage_tags(clus) == ["net", "post-cluster"]
    assert orchestrator._stage_tags(loop2) == ["net", "loop:2"]
    assert orchestrator._stage_tags(checkpoint2) == ["checkpoint:2"]


def test_marker_path(tmp_path):
    from ptflow.core.paths import Activity

    act = Activity.named("acme", root=tmp_path)
    assert orchestrator._marker(act, "httpx", None) == act.state / "httpx.done"
    assert orchestrator._marker(act, "crawl", "app1") == act.app("app1").state / "crawl.done"


def test_run_stage_injects_only_declared_agents(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from ptflow.core.paths import Activity

    captured = {}
    custom = SimpleNamespace(name="custom", available=True)

    def run(activity, *, agents):
        captured["activity"] = activity.base
        captured["agent"] = agents.require("custom")

    class Pipeline:
        name = "p"
        stages = (Stage("use_agent", run, net=False, agents=("custom",)),)

        @staticmethod
        def agent_factories():
            return {"custom": lambda _context: custom}

    Activity.named("a", root=tmp_path).ensure()
    monkeypatch.setattr(orchestrator, "load_pipeline", lambda _name: Pipeline())

    orchestrator._run_stage.fn("p", "a", str(tmp_path), "use_agent", None, None, resume=False)

    assert captured == {"activity": tmp_path / "a", "agent": custom}


def test_resume_ok_invalidates_on_scope_change(tmp_path):
    from ptflow.core.paths import Activity

    act = Activity.named("acme", root=tmp_path).ensure()
    assert orchestrator._resume_ok(act, "scopeA", resume=True) == (True, None)
    assert orchestrator._resume_ok(act, "scopeA", resume=True) == (True, None)
    assert orchestrator._resume_ok(act, "scopeB", resume=True) == (False, "scope_changed")
    assert orchestrator._resume_ok(act, "scopeB", resume=False) == (False, None)


def test_resume_ok_invalidates_on_config_change_and_migrates_legacy_state(tmp_path):
    from ptflow.core.paths import Activity

    act = Activity.named("configured", root=tmp_path).ensure()
    assert orchestrator._resume_ok(
        act, "scope", resume=True, config_fingerprint="config-a") == (True, None)
    assert (act.state / "config.sha").read_text() == "config-a"
    activity_marker = act.state / "httpx.done"
    app_marker = act.app("app").ensure().state / "crawl.done"
    activity_marker.write_text("")
    app_marker.parent.mkdir(parents=True)
    app_marker.write_text("")
    assert orchestrator._resume_ok(
        act, "scope", resume=True, config_fingerprint="config-a") == (True, None)
    assert activity_marker.exists()
    assert app_marker.exists()
    assert orchestrator._resume_ok(
        act, "scope", resume=True, config_fingerprint="config-b") == (False, "config_changed")
    assert not activity_marker.exists()
    assert not app_marker.exists()
    assert orchestrator._resume_ok(
        act, "scope", resume=True, config_fingerprint="config-b") == (True, None)

    legacy = Activity.named("legacy", root=tmp_path).ensure()
    assert orchestrator._resume_ok(legacy, "scope", resume=False) == (False, None)
    assert not (legacy.state / "config.sha").exists()
    assert orchestrator._resume_ok(
        legacy, "scope", resume=True,
        config_fingerprint="config-a",
    ) == (False, "legacy_config_missing")
    assert (legacy.state / "config.sha").read_text() == "config-a"


def test_resume_ok_invalidates_on_pipeline_contract_change_and_migrates_legacy_state(tmp_path):
    from ptflow.core.paths import Activity

    act = Activity.named("contract", root=tmp_path).ensure()
    assert orchestrator._resume_ok(
        act, "scope", resume=False, config_fingerprint="config",
        pipeline_fingerprint="pipeline-a",
    ) == (False, None)
    marker = act.state / "httpx.done"
    marker.write_text("")
    assert orchestrator._resume_ok(
        act, "scope", resume=True, config_fingerprint="config",
        pipeline_fingerprint="pipeline-a",
    ) == (True, None)
    assert marker.exists()

    assert orchestrator._resume_ok(
        act, "scope", resume=True, config_fingerprint="config",
        pipeline_fingerprint="pipeline-b",
    ) == (False, "pipeline_contract_changed")
    assert not marker.exists()
    assert (act.state / "pipeline.sha").read_text() == "pipeline-b"
    assert orchestrator._resume_ok(
        act, "scope", resume=True, config_fingerprint="config",
        pipeline_fingerprint="pipeline-b",
    ) == (True, None)

    (act.state / "pipeline.sha").unlink()
    marker.write_text("")
    assert orchestrator._resume_ok(
        act, "scope", resume=True, config_fingerprint="config",
        pipeline_fingerprint="pipeline-b",
    ) == (False, "legacy_pipeline_contract_missing")
    assert not marker.exists()
    assert (act.state / "pipeline.sha").read_text() == "pipeline-b"


def test_per_app_loops_groups_by_phase_in_order():
    stages = [
        Stage("expand", lambda *_: None),                          # activity → excluded
        Stage("a", lambda *_: None, per_app=True, phase=1),
        Stage("b", lambda *_: None, needs=("a",), per_app=True, phase=1),
        Stage("c", lambda *_: None, per_app=True, phase=2),
        Stage("checkpoint", lambda *_: None, after_phase=2),
    ]
    loops = orchestrator.per_app_loops(stages)
    assert [phase for phase, _ in loops] == [1, 2]
    assert [[s.name for s in ss] for _, ss in loops] == [["a", "b"], ["c"]]
    assert [s.name for s in orchestrator.phase_checkpoints(stages, 2)] == ["checkpoint"]


def test_run_loops_awaits_checkpoint_before_next_phase(monkeypatch):
    events: list[str] = []
    stages = [
        Stage("p1", lambda *_: None, per_app=True, phase=1),
        Stage("p2", lambda *_: None, per_app=True, phase=2),
        Stage("checkpoint", lambda *_: None, after_phase=2),
        Stage("p3", lambda *_: None, per_app=True, phase=3),
    ]

    class _Future:
        def __init__(self, label):
            self.label = label

        def result(self):
            events.append(f"await:{self.label}")

    def _submit(items, _pipeline, _activity, _root, app_id, _run_id, *, resume):
        label = ",".join(stage.name for stage in items)
        scope = app_id or "activity"
        events.append(f"submit:{label}:{scope}:resume={resume}")
        return {stage.name: _Future(f"{stage.name}:{scope}") for stage in items}

    monkeypatch.setattr(orchestrator, "_submit_dag", _submit)
    failures: list[str] = []
    orchestrator._run_loops(
        stages, ["app"], "pipeline", "activity", None, failures, None, resume=True,
    )

    assert failures == []
    assert events.index("await:p2:app") < events.index("submit:checkpoint:activity:resume=False")
    assert events.index("await:checkpoint:activity") < events.index("submit:p3:app:resume=True")


def test_terminal_fanin_isolates_agent_and_calls_report(tmp_path):
    from ptflow.core import orchestrator
    from ptflow.core.paths import Activity

    act = Activity.named("t", root=tmp_path).ensure()
    called = {"report": False}

    class P:
        name = "p"

        def provider(self):
            class Prov:
                name = "boom"

                def propose(self, records):  # noqa: ARG002
                    msg = "agent blew up"
                    raise RuntimeError(msg)

            return Prov()

        def report(self, activity):  # noqa: ARG002
            called["report"] = True

    failures: list[str] = []
    orchestrator._terminal_fanin(P(), act, failures)
    assert "agent" in failures          # agent failure isolated, not raised
    assert called["report"] is True     # report hook still ran
    assert (act.reports / "report.md").exists()  # deterministic report is independent of the AI hook
    assert (act.reports / "report.json").exists()


def test_enabled_stages_topo_tolerates_removed_dep():
    from ptflow.core.stage import Stage, enabled_stages
    a = Stage("a", lambda *_: None)
    b = Stage("b", lambda *_: None, needs=("a",))
    kept = enabled_stages([a, b], {"a"})
    order = [s.name for s in orchestrator.topo_order(kept)]
    assert order == ["b"]  # 'b' survives; its now-missing dep 'a' is ignored, no KeyError
