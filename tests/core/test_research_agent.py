import socket
from types import SimpleNamespace

import pytest

from ptflow.core.agents import AgentAccess, build_agent_access
from ptflow.core.agents.credential_research import (
    CredentialProposal,
    CredentialResearchOut,
    validate_proposals,
)
from ptflow.core.agents.research import (
    DirectSearchBackend,
    PlaywrightBrowser,
    ResearchAgent,
    ResearchBrowserError,
    ResearchDecision,
    ResearchDocument,
    ResearchLimits,
    ResearchRun,
    SafeWebFetcher,
    SearchHit,
    _parse_search_results,
    _validate_fetch_url,
)
from ptflow.core.ai.client import LLMResult
from ptflow.core.paths import Activity
from ptflow.core.stage import Stage


class _Client:
    name = "fake"
    model = "fake"
    remote = False

    def __init__(self, decisions, output):
        self.decisions = list(decisions)
        self.output = output

    def complete_json(self, _system, _user, schema, **_kwargs):
        value = self.decisions.pop(0) if schema is ResearchDecision else self.output
        return LLMResult(value=value, provider=self.name, model=self.model)


class _Search:
    engines = ("duckduckgo", "google")
    direct_engines = engines

    def search(self, query, *, limit, engine):
        assert query == "Acme Router default credentials"
        assert limit == 3
        assert engine == "duckduckgo"
        return [SearchHit(
            url="https://docs.example.test/router", title="Manual",
            snippet="Default username admin and password acme123", query=query,
        )]


class _Fetcher:
    def fetch(self, url):
        assert url == "https://docs.example.test/router"
        return ResearchDocument(
            url=url, title="Manual", text="Default username admin and password acme123",
            content_type="text/html", sha256="abc", fetched_at="2026-01-01T00:00:00Z",
        )


def _proposal(secret_value, source="https://docs.example.test/router"):
    return CredentialProposal(
        product="Acme Router", protocol="http", username="admin", password=secret_value,
        source_urls=[source], confidence=0.95, rationale="vendor manual",
    )


def test_research_agent_runs_bounded_search_fetch_finish_and_synthesis():
    output = CredentialResearchOut(proposals=[_proposal("acme123")])
    client = _Client([
        ResearchDecision(action="search", query="Acme Router default credentials"),
        ResearchDecision(action="fetch", url="https://docs.example.test/router"),
        ResearchDecision(action="finish", rationale="enough evidence"),
    ], output)
    agent = ResearchAgent(
        client, _Search(), _Fetcher(),
        limits=ResearchLimits(max_steps=5, max_searches=1, max_fetches=1, max_results=3),
    )

    run = agent.research("find defaults", CredentialResearchOut, output_system="extract")

    assert run.output == output
    assert [step.action for step in run.trace] == ["search", "fetch", "finish"]
    assert run.documents[0].sha256 == "abc"


def test_research_agent_rejects_fetch_not_returned_by_search():
    client = _Client([
        ResearchDecision(action="fetch", url="https://unseen.example.test/"),
        ResearchDecision(action="finish"),
    ], CredentialResearchOut(proposals=[]))
    agent = ResearchAgent(client, _Search(), _Fetcher(), limits=ResearchLimits(max_steps=2))

    run = agent.research("find defaults", CredentialResearchOut, output_system="extract")

    assert run.trace[0].status == "rejected"
    assert run.documents == ()


def test_credential_validation_requires_known_literal_source():
    good = _proposal("acme123")
    invented = _proposal("invented")
    unknown_source = _proposal("acme123", source="https://elsewhere.example/")
    run = ResearchRun(
        objective="x",
        output=CredentialResearchOut(proposals=[good, invented, unknown_source]),
        hits=(SearchHit(url=good.source_urls[0], snippet="Search snippet"),),
        documents=(ResearchDocument(
            url=good.source_urls[0], text="Default username admin password acme123",
            sha256="source", fetched_at="2026-01-01T00:00:00Z",
        ),),
        trace=(),
    )
    accepted = validate_proposals(
        run, [{"product": "Acme Router", "version": "1", "protocol": "http"}],
    )
    assert accepted == [good]


def test_fetch_url_blocks_private_resolution(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kwargs: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80)),
    ])
    with pytest.raises(ValueError, match="non-public"):
        _validate_fetch_url("http://example.test/", allow_private=False)
    _validate_fetch_url("http://example.test/", allow_private=True)


def test_headless_browser_blocks_private_websockets(monkeypatch):
    class Route:
        url = "ws://private.example.test/socket"
        connected = False
        closed = None

        def close(self, **kwargs):
            self.closed = kwargs

        def connect_to_server(self):
            self.connected = True

    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kwargs: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80)),
    ])
    route = Route()

    PlaywrightBrowser()._websocket_route(route)

    assert route.connected is False
    assert route.closed["code"] == 1008


def test_agent_access_supports_pipeline_factory_override(tmp_path):
    custom = SimpleNamespace(name="custom", available=True)
    stage = Stage("use", lambda *_args, **_kwargs: None, agents=("custom",))

    class Pipeline:
        name = "p"

        @staticmethod
        def agent_factories():
            return {"custom": lambda _context: custom}

    activity = Activity.named("a", root=tmp_path).ensure()
    access = build_agent_access(Pipeline(), stage, activity)
    assert isinstance(access, AgentAccess)
    assert access.require("custom") is custom


def test_safe_fetcher_is_unavailable_without_network_call():
    # Construction itself is side-effect free; DNS/fetch happens only after an explicit fetch action.
    assert SafeWebFetcher(timeout_seconds=1) is not None


def test_direct_search_parses_duckduckgo_redirects_and_google_results():
    ddg = """
      <a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fdocs.example%2Fmanual">
        Product manual
      </a>
      <a class="result__snippet">Factory credentials documentation</a>
    """
    google = """
      <a href="/url?q=https%3A%2F%2Fsupport.example%2Fdefaults&amp;sa=U">
        <h3>Vendor support</h3>
      </a>
    """
    ddg_hits = _parse_search_results(ddg, engine="duckduckgo", query="defaults", limit=5)
    google_hits = _parse_search_results(google, engine="google", query="defaults", limit=5)

    assert ddg_hits[0].url == "https://docs.example/manual"
    assert ddg_hits[0].snippet == "Factory credentials documentation"
    assert google_hits[0].url == "https://support.example/defaults"
    direct = DirectSearchBackend(("duckduckgo", "google"))
    assert direct.direct_engines == ("duckduckgo",)
    with pytest.raises(ValueError, match="requires headless browser"):
        direct.search("defaults", limit=1, engine="google")


def test_google_headless_challenge_is_reported_for_model_fallback(monkeypatch):
    browser = PlaywrightBrowser()
    monkeypatch.setattr(browser, "_render", lambda _url: (
        "https://www.google.com/sorry/index", "Google", b"unusual traffic",
    ))

    with pytest.raises(ResearchBrowserError, match="retry with DuckDuckGo"):
        browser.search("defaults", limit=3, engine="google")


def test_model_can_choose_google_headless_and_follow_a_discovered_link():
    first = "https://docs.example.test/index"
    second = "https://docs.example.test/defaults"

    class Browser:
        available = True

        def search(self, query, *, limit, engine):
            assert (query, limit, engine) == ("Acme defaults", 3, "google")
            return [SearchHit(url=first, title="Documentation", query=query)]

        def fetch(self, url):
            if url == first:
                return ResearchDocument(
                    url=url, text="See the defaults guide", content_type="text/html",
                    sha256="one", fetched_at="2026-01-01T00:00:00Z", links=[second],
                )
            assert url == second
            return ResearchDocument(
                url=url, text="Default username admin and password acme123",
                content_type="text/html", sha256="two", fetched_at="2026-01-01T00:00:01Z",
            )

    output = CredentialResearchOut(proposals=[_proposal("acme123", source=second)])
    client = _Client([
        ResearchDecision(
            action="search", query="Acme defaults", engine="google", use_browser=True,
        ),
        ResearchDecision(action="fetch", url=first, use_browser=True),
        ResearchDecision(action="fetch", url=second, use_browser=True),
        ResearchDecision(action="finish"),
    ], output)
    agent = ResearchAgent(
        client, _Search(), _Fetcher(), browser=Browser(),
        limits=ResearchLimits(max_steps=4, max_searches=1, max_fetches=2, max_results=3),
    )

    run = agent.research("find defaults", CredentialResearchOut, output_system="extract")

    assert [item.action for item in run.trace] == [
        "search-browser", "fetch-browser", "fetch-browser", "finish",
    ]
    assert [document.url for document in run.documents] == [first, second]
