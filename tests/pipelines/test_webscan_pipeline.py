import importlib

from ptflow.pipelines import load_pipeline
from ptflow.pipelines.webscan.pipeline import PIPELINE

# Stages deliberately OMITTED vs external: scope expansion, active network scan, and per-app OSINT.
_OMITTED = {"expand", "subdomain_bruteforce", "resolve", "portscan", "portscan_full",
            "portscan_exhaustive", "httpx_late", "fingerprint_late", "cve_late", "nerva",
            "nuclei_scope", "passive_probe", "subenum",
            "takeover", "fetch_delta"}
# The web-depth loops webscan keeps (reused from external.tasks unchanged).
_KEPT_LOOPS = {"crawl", "crawl_headless", "api_spec", "mine_responses", "request_catalog",
               "dast", "xss", "sqli", "cve_lookup", "wordlist", "tech_enum", "content_discovery",
               "recrawl", "request_catalog_full", "param_fuzz", "dast_full", "xss_full",
               "sqli_full", "cve_lookup_full", "tech_vulnscan"}


def test_webscan_loads_and_names():
    assert load_pipeline("webscan").name == "webscan"


def test_webscan_omits_expansion_and_active_scan():
    names = {s.name for s in PIPELINE.stages}
    assert names.isdisjoint(_OMITTED)


def test_webscan_keeps_the_depth_loops():
    names = {s.name for s in PIPELINE.stages}
    assert names >= _KEPT_LOOPS


def test_webscan_breadth_is_just_ingest():
    # the only non-per-app, non-spanning stages are the minimal breadth: provision_wl + ingest
    breadth = [s.name for s in PIPELINE.stages
               if not s.per_app and not s.spanning and not s.cluster_scope
               and s.after_phase is None]
    assert breadth == ["provision_wl", "ingest"]


def test_webscan_reuses_external_task_functions():
    from ptflow.pipelines.external import tasks as external

    by_name = {s.name: s for s in PIPELINE.stages}
    assert by_name["ingest"].run is external.ingest_httpx
    assert by_name["crawl"].run is external.crawl
    assert by_name["dast"].run is external.dast


def test_webscan_phases_preserved():
    by_name = {s.name: s for s in PIPELINE.stages}
    assert by_name["crawl"].phase == 1
    assert by_name["dast"].phase == 2
    assert by_name["content_discovery"].phase == 3
    assert by_name["request_catalog_full"].phase == 4
    assert by_name["param_fuzz"].phase == 5
    assert by_name["dast_full"].phase == 6
    assert by_name["dast_full"].needs == ()
    assert by_name["surface_checkpoint"].after_phase == 2


def test_webscan_has_composition_hooks():
    assert callable(PIPELINE.cluster)
    assert callable(PIPELINE.consolidate)
    assert callable(PIPELINE.provider)
    assert callable(PIPELINE.report)


def test_webscan_requirements_narrow_core_to_depth_tools():
    from ptflow.pipelines.external import tasks as external

    reqs = PIPELINE.requirements()
    # only the depth toolchain is CORE — webscan's loops fail without these four
    assert {r.name for r in reqs if r.kind == "core"} == {"httpx", "katana", "feroxbuster", "nuclei"}
    by = {r.name: r for r in reqs}
    # external's breadth/OSINT CORE tools are demoted to optional (webscan never runs them → no FAIL)
    assert by["naabu"].kind == "optional"
    assert by["subfinder"].kind == "optional"
    # same coverage as external — reclassified, nothing dropped
    assert {r.name for r in reqs} == {r.name for r in external.requirements()}


def _reload_pipeline():
    from ptflow.pipelines.webscan import pipeline

    return importlib.reload(pipeline)


def test_webscan_ai_stages_absent_when_off(monkeypatch):
    monkeypatch.delenv("PTFLOW_AI", raising=False)
    pipeline = _reload_pipeline()

    names = {stage.name for stage in pipeline.PIPELINE.stages}

    assert "ai_wordlist" not in names
    assert "ai_secret_triage" not in names
    assert "ai_cve_poc" not in names
    assert "ai_cve_poc_full" not in names
    assert "ai_credential_research" not in names


def test_webscan_ai_stages_reuse_external_ai_when_on(monkeypatch):
    from ptflow.pipelines.external import ai

    monkeypatch.setenv("PTFLOW_AI", "on")
    pipeline = _reload_pipeline()

    by_name = {stage.name: stage for stage in pipeline.PIPELINE.stages}

    assert by_name["ai_wordlist"].run is ai.ai_wordlist
    assert by_name["ai_wordlist"].phase == 2
    assert by_name["ai_wordlist"].net is False
    assert by_name["ai_secret_triage"].run is ai.ai_secret_triage
    assert by_name["ai_secret_triage"].phase == 4
    assert by_name["ai_secret_triage"].net is False
    assert by_name["ai_credential_research"].needs == ("cve_lookup",)
    assert by_name["ai_credential_research"].agents == ("research",)
    assert by_name["ai_cve_poc"].run is ai.ai_cve_poc
    assert by_name["ai_cve_poc"].phase == 2
    assert by_name["ai_cve_poc"].net is True
    assert by_name["ai_cve_poc_full"].run is ai.ai_cve_poc_full
    assert by_name["ai_cve_poc_full"].phase == 4
    assert by_name["ai_cve_poc_full"].net is True
    assert isinstance(pipeline.PIPELINE.provider(), ai.LLMHypothesisProvider)
    assert {"ai_wordlist", "ai_secret_triage", "ai_cve_poc", "ai_cve_poc_full",
            "ai_credential_research"} <= (
        pipeline.PIPELINE.flowmap_spec().steps.keys()
    )

    monkeypatch.delenv("PTFLOW_AI", raising=False)
    _reload_pipeline()


def test_webscan_ai_stage_toggle_is_honoured(monkeypatch):
    monkeypatch.setenv("PTFLOW_AI", "on")
    monkeypatch.setenv("PTFLOW_AI_STAGE_WORDLIST_ENABLED", "off")
    monkeypatch.setenv("PTFLOW_AI_STAGE_SECRET_TRIAGE_ENABLED", "on")
    pipeline = _reload_pipeline()

    names = {stage.name for stage in pipeline.PIPELINE.stages}

    assert "ai_wordlist" not in names
    assert "ai_secret_triage" in names

    monkeypatch.delenv("PTFLOW_AI", raising=False)
    monkeypatch.delenv("PTFLOW_AI_STAGE_WORDLIST_ENABLED", raising=False)
    monkeypatch.delenv("PTFLOW_AI_STAGE_SECRET_TRIAGE_ENABLED", raising=False)
    _reload_pipeline()


def test_webscan_report_delegates_to_external_ai(monkeypatch):
    from ptflow.pipelines.external import ai

    pipeline = _reload_pipeline()
    activity = object()
    called = []
    monkeypatch.setattr(ai, "report", called.append)

    pipeline.PIPELINE.report(activity)

    assert called == [activity]
