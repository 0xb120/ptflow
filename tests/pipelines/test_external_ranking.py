import json

from ptflow.core import telemetry, tools
from ptflow.core.paths import Activity
from ptflow.pipelines.external import ranking, tasks


def _request(  # noqa: PLR0913
    method, url, *, sources=None, headers=None, body="", params=None, **extra,
):
    return {
        "method": method,
        "url": url,
        "sources": sources or [],
        "headers": headers or {},
        "body": body,
        "params": params or [],
        **extra,
    }


def test_score_prioritizes_authenticated_stateful_structured_requests():
    rich = _request(
        "POST",
        "https://app.test/admin/import",
        sources=["katana-headless", "openapi"],
        headers={"Authorization": "Bearer secret", "Content-Type": "application/json"},
        body='{"url":"https://callback.test"}',
        params=[{"name": "url", "loc": "json"}, {"name": "role", "loc": "json"}],
    )
    plain = _request("GET", "https://app.test/static/logo.png", sources=["url"])

    ranked_rich = ranking.score_request(rich)
    ranked_plain = ranking.score_request(plain)

    assert ranked_rich.score > ranked_plain.score
    assert "+35:authenticated" in ranked_rich.score_reasons
    assert "+24:state-changing:POST" in ranked_rich.score_reasons
    assert "+24:json-body" in ranked_rich.score_reasons
    assert "-25:static-fetch" in ranked_plain.score_reasons


def test_allocate_is_input_order_independent_and_does_not_leak_values():
    records = [
        _request("GET", "https://a.test/search?token=top-secret", sources=["katana"]),
        _request("POST", "https://a.test/api", sources=["xhr"], body="q=private-value",
                 headers={"Content-Type": "application/x-www-form-urlencoded"}),
        _request("GET", "https://b.test/health", sources=["url"]),
    ]

    first = ranking.allocate(records, cap=2)
    second = ranking.allocate(list(reversed(records)), cap=2)

    assert [decision.request_id for decision in first.decisions] == [
        decision.request_id for decision in second.decisions
    ]
    assert [record["url"] for record in first.records] == [record["url"] for record in second.records]
    audit = json.dumps([decision.as_dict() for decision in first.decisions])
    assert "top-secret" not in audit
    assert "private-value" not in audit


def test_audit_redacts_url_credentials_and_opaque_path_values():
    record = _request(
        "GET",
        "https://operator:password@a.test/reset/super-secret-token-123456?q=private-query",
    )

    [decision] = ranking.allocate([record], cap=1).decisions
    audit = json.dumps(decision.as_dict())

    assert decision.shape == "GET https://a.test/reset/*?q"
    assert decision.dimensions["authority"] == ("https://a.test",)
    assert "operator" not in audit
    assert "password" not in audit
    assert "super-secret" not in audit
    assert "private-query" not in audit


def test_authority_quota_prevents_late_host_starvation():
    noisy = [
        _request("GET", f"https://a.test/item/{index}?id={index}", sources=["katana"],
                 params=[{"name": "id", "loc": "query"}])
        for index in range(20)
    ]
    late = _request("GET", "https://late.test/", sources=["url"])

    selection = ranking.allocate([*noisy, late], cap=2)

    assert {record["url"].split("/", 3)[2] for record in selection.records} == {
        "a.test", "late.test",
    }
    late_decision = next(decision for decision in selection.decisions if "late.test" in decision.shape)
    assert late_decision.selected
    assert any(reason.startswith("authority:https://late.test")
               for reason in late_decision.quota_reasons)


def test_quota_covers_method_location_content_and_source_when_budget_allows():
    records = [
        _request("GET", "https://a.test/search?q=1", sources=["katana"],
                 params=[{"name": "q", "loc": "query"}]),
        _request("POST", "https://a.test/form", sources=["html-form"], body="name=x",
                 headers={"Content-Type": "application/x-www-form-urlencoded"},
                 params=[{"name": "name", "loc": "body"}]),
        _request("POST", "https://a.test/api", sources=["openapi"], body='{"id":1}',
                 headers={"Content-Type": "application/json"},
                 params=[{"name": "id", "loc": "json"}]),
        _request("GET", "https://a.test/debug", sources=["param_fuzz"],
                 params=[{"name": "X-Debug", "loc": "header"}]),
    ]

    summary = ranking.allocate(records, cap=4).summary()
    selected = summary["distributions"]

    assert selected["method_class"]["selected"] == {"GET": 2, "NON_GET": 2}
    assert selected["location"]["selected"] == {"body": 1, "header": 1, "json": 1, "query": 1}
    assert selected["content_type"]["selected"] == {"form": 1, "json": 1, "none": 2}
    assert selected["source"]["selected"] == {
        "form": 1, "katana": 1, "openapi": 1, "param-fuzz": 1,
    }


def test_scanner_specific_parameter_signal_breaks_equal_generic_score():
    id_request = _request(
        "GET", "https://a.test/items?id=1", params=[{"name": "id", "loc": "query"}],
    )
    neutral = _request(
        "GET", "https://a.test/items?colour=red",
        params=[{"name": "colour", "loc": "query"}],
    )

    selected = ranking.allocate([neutral, id_request], cap=1, purpose="sqli")

    assert selected.records[0]["url"].endswith("?id=1")
    assert "+24:sqli-relevant-parameter" in selected.decisions[0].score_reasons


def test_group_budget_moves_unused_capacity_to_richer_apps():
    allocations = ranking.allocate_group_budgets(
        {"small": 5, "rich-a": 100, "rich-b": 100}, per_group_cap=50,
    )

    assert allocations == {"rich-a": 73, "rich-b": 72, "small": 5}
    assert sum(allocations.values()) == 150
    assert all(allocations[group] <= demand for group, demand in {
        "small": 5, "rich-a": 100, "rich-b": 100,
    }.items())


def test_same_budget_ranking_finds_late_high_risk_request_first_n_misses():
    ordinary = [
        _request("GET", f"https://app.test/catalog/{index}", sources=["url"])
        for index in range(20)
    ]
    known_vulnerable = _request(
        "POST", "https://app.test/admin/import", sources=["openapi"],
        headers={"Authorization": "Bearer value", "Content-Type": "application/json"},
        body='{"url":"https://example.test"}',
        params=[{"name": "url", "loc": "json"}],
    )
    cap = 5

    legacy_first_n = [*ordinary, known_vulnerable][:cap]
    selected = ranking.allocate([*ordinary, known_vulnerable], cap=cap)

    assert known_vulnerable not in legacy_first_n
    assert known_vulnerable in selected.records
    assert len(selected.records) == len(legacy_first_n) == cap


def test_stage_budget_redistributes_against_complete_engagement_catalogs(tmp_path):
    activity = Activity.named("budgets", root=tmp_path).ensure()
    small = activity.app("small").ensure()
    rich = activity.app("rich").ensure()
    tools.write_jsonl(small.canonical("requests_full.jsonl"), [
        _request("GET", f"https://small.test/item-{index}") for index in range(5)
    ])
    tools.write_jsonl(rich.canonical("requests_full.jsonl"), [
        _request("GET", f"https://rich.test/item-{index}") for index in range(100)
    ])

    small_cap = tasks._stage_request_budget(
        activity, "small", per_app_cap=50, name="test", deep=True,
    )
    rich_cap = tasks._stage_request_budget(
        activity, "rich", per_app_cap=50, name="test", deep=True,
    )

    assert (small_cap, rich_cap) == (5, 95)
    assert small_cap + rich_cap == 100
    assert json.loads((rich.raw("ranking") / "budget-test.json").read_text())["redistributed"] == 45


def test_endpoint_budget_uses_same_complete_catalog_as_param_selector(tmp_path):
    activity = Activity.named("param-budget", root=tmp_path).ensure()
    app = activity.app("app").ensure()
    tools.write_jsonl(app.canonical("requests_full.jsonl"), [
        _request("GET", f"https://app.test/asset-{index}.png") for index in range(60)
    ])

    cap = tasks._stage_request_budget(
        activity,
        "app",
        per_app_cap=50,
        name="param_query",
        deep=True,
        demand_kind="endpoint",
    )

    assert cap == 50
    rationale = json.loads((app.raw("ranking") / "budget-param_query.json").read_text())
    assert rationale["app_demand"] == 60
    assert rationale["applied"] is True


def test_deep_scanner_budget_includes_all_synthesized_params(tmp_path):
    activity = Activity.named("deep-budget", root=tmp_path).ensure()
    app = activity.app("app").ensure()
    tools.write_jsonl(app.canonical("requests.jsonl"), [])
    tools.write_jsonl(app.canonical("requests_xref.jsonl"), [])
    tools.write_jsonl(app.canonical("requests_full.jsonl"), [])
    tools.write_jsonl(app.canonical("params.jsonl"), [
        {"url": f"https://app.test/path-{index}", "param": "id", "loc": "query"}
        for index in range(11)
    ])

    cap = tasks._stage_request_budget(
        activity,
        "app",
        per_app_cap=40,
        name="sqli_full",
        deep=True,
        demand_kind="parameterized",
    )

    assert cap == 11
    rationale = json.loads((app.raw("ranking") / "budget-sqli_full.json").read_text())
    assert rationale["app_demand"] == 11
    assert rationale["applied"] is False


def test_task_integration_persists_audit_and_coverage_distribution(tmp_path):
    activity = Activity.named("ranking", root=tmp_path).ensure()
    audit = activity.base / "ranking.jsonl"
    records = [
        _request("GET", "https://a.test/?q=secret-one", sources=["katana"],
                 params=[{"name": "q", "loc": "query"}]),
        _request("POST", "https://a.test/api", sources=["openapi"], body='{"id":"secret-two"}',
                 headers={"Content-Type": "application/json"},
                 params=[{"name": "id", "loc": "json"}]),
        _request("GET", "https://b.test/health", sources=["url"]),
    ]

    telemetry.trace_call(
        activity,
        "run-ranking",
        stage="dast",
        app_id="app",
        band="loop:2",
        call=lambda: tasks.dast_requests(
            records, [], cap=2, name="dast_surface_requests", audit_path=audit,
        ),
    )

    decisions = tools.read_jsonl(audit)
    assert len(decisions) == 3
    assert sum(decision["selected"] for decision in decisions) == 2
    assert {decision["exclusion_reason"] for decision in decisions if not decision["selected"]} == {
        "budget-exhausted",
    }
    assert "secret-one" not in audit.read_text()
    assert "secret-two" not in audit.read_text()
    fragment = json.loads(next(
        (activity.state / "coverage" / "run-ranking").glob("*.json")
    ).read_text())
    [selection] = fragment["selections"]
    assert selection["name"] == "dast_surface_requests"
    assert selection["distributions"]["authority"]["selected"] == {
        "https://a.test": 1,
        "https://b.test": 1,
    }
