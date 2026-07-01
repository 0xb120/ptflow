from pipt.pipelines import load_pipeline
from pipt.pipelines.webscan.pipeline import PIPELINE

# Stages deliberately OMITTED vs external: scope expansion, active network scan, and per-app OSINT.
_OMITTED = {"expand", "resolve", "portscan", "portscan_full", "nerva", "nuclei_scope",
            "passive_probe", "subenum", "takeover", "fetch_delta"}
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
               if not s.per_app and not s.spanning and not s.cluster_scope]
    assert breadth == ["provision_wl", "ingest"]


def test_webscan_reuses_external_task_functions():
    from pipt.pipelines.external import tasks as external

    by_name = {s.name: s for s in PIPELINE.stages}
    assert by_name["ingest"].run is external.ingest_httpx
    assert by_name["crawl"].run is external.crawl
    assert by_name["dast"].run is external.dast


def test_webscan_phases_preserved():
    by_name = {s.name: s for s in PIPELINE.stages}
    assert by_name["crawl"].phase == 1
    assert by_name["dast"].phase == 2
    assert by_name["content_discovery"].phase == 3
    assert by_name["param_fuzz"].phase == 4


def test_webscan_has_composition_hooks():
    assert callable(PIPELINE.cluster)
    assert callable(PIPELINE.consolidate)
    assert callable(PIPELINE.provider)
