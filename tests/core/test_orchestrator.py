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


def test_net_slots_is_bounded_semaphore():
    import threading

    assert isinstance(orchestrator._NET_SLOTS, threading.BoundedSemaphore)
    assert orchestrator._NET_SLOTS._initial_value == orchestrator._NET_LIMIT


def test_stage_tags_by_band():
    base = Stage("a", lambda *_: None)
    span = Stage("b", lambda *_: None, spanning=True)
    clus = Stage("c", lambda *_: None, cluster_scope=True)
    loop2 = Stage("d", lambda *_: None, per_app=True, phase=2)
    assert orchestrator._stage_tags(base) == ["net", "breadth"]      # UI band tags for the run graph
    assert orchestrator._stage_tags(span) == ["net", "spanning"]
    assert orchestrator._stage_tags(clus) == ["net", "post-cluster"]
    assert orchestrator._stage_tags(loop2) == ["net", "loop:2"]


def test_marker_path(tmp_path):
    from ptflow.core.paths import Activity

    act = Activity.named("acme", root=tmp_path)
    assert orchestrator._marker(act, "httpx", None) == act.state / "httpx.done"
    assert orchestrator._marker(act, "crawl", "app1") == act.app("app1").state / "crawl.done"


def test_resume_ok_invalidates_on_scope_change(tmp_path):
    from ptflow.core.paths import Activity

    act = Activity.named("acme", root=tmp_path).ensure()
    assert orchestrator._resume_ok(act, "scopeA", resume=True) is True   # first run: records hash, honored
    assert orchestrator._resume_ok(act, "scopeA", resume=True) is True   # same scope → resume honored
    assert orchestrator._resume_ok(act, "scopeB", resume=True) is False  # changed scope → markers stale
    assert orchestrator._resume_ok(act, "scopeB", resume=False) is False  # never resumes when not asked


def test_per_app_loops_groups_by_phase_in_order():
    stages = [
        Stage("expand", lambda *_: None),                          # activity → excluded
        Stage("a", lambda *_: None, per_app=True, phase=1),
        Stage("b", lambda *_: None, needs=("a",), per_app=True, phase=1),
        Stage("c", lambda *_: None, per_app=True, phase=2),
    ]
    loops = orchestrator.per_app_loops(stages)
    assert [phase for phase, _ in loops] == [1, 2]
    assert [[s.name for s in ss] for _, ss in loops] == [["a", "b"], ["c"]]
