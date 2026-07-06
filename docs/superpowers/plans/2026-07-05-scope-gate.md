# Scope Authorization Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enforce the engagement's authorization boundary — derived from the scope file — at the discovery→active-scanning seam of the external pipeline, so third-party names/IPs pulled in by TLS-SAN/PTR/subfinder are dropped before any active scan.

**Architecture:** Pure helpers in `core/scope.py` build an allowlist (exact host / `*.apex` suffix / IP-CIDR) and decide membership by four rules (exact host, wildcard subtree, explicit IP net, and the IP→names pivot so IP-only scopes recover their vhosts). A new offline `scope_gate` stage runs between `resolve` and `portscan`, filters the discovery outputs into authorized `inscope_*` files (plus an RoE audit), and the active stages are rewired to read those. It complements — does not replace — the existing CDN filters.

**Tech Stack:** Python 3.12+, Prefect ≥3, `uv`, `ruff` (select=ALL), `ty` (type checker, not mypy), `pytest`, stdlib `ipaddress` + `str.encode("idna")` (no PSL/`tldextract`).

## Global Constraints

- Dev gate (must pass before a task is done): `uv run ruff check . && uv run ty check src/ && uv run pytest`.
- Ruff runs `select = ["ALL"]`; respect existing `ignore`/`per-file-ignores` in `pyproject.toml` — no blanket `# noqa`.
- No new heavy dependency — semantics need exact-match + suffix-match + `ipaddress`, NOT the Public Suffix List / `tldextract`.
- **Membership rules (verbatim):** an asset is in scope if ANY of — (1) name ∈ `exact_hosts` (a `domain`/`url` entry, exact FQDN, NOT its subdomains); (2) name matches a `wildcard_apex` (`*.x`): `host == apex or host.endswith("." + apex)` (apex + every depth); (3) IP ∈ a scope `net` (`ip`/`cidr`); (4) the name's resolved IP ∈ a scope `net`.
- **Decisions:** (a) a recovered name resolving OFF the authorized IPs is dropped (no Host-header pinning in v1); (b) recovering a name does NOT auto-expand to its apex. **Anti-transitivity:** rule 4 uses ONLY explicitly-listed `nets`; domain-derived IPs are scanned but never authorize further names.
- **CDN:** the gate does NOT classify CDN — it keeps domain-derived IPs and lets the existing `naabu -exclude-cdn` + `split_cdn_ip_records` drop CDN ones. The gate is offline (`net=False`).
- **Write-once:** `scope_gate` is the SINGLE writer of `inscope_subdomains.txt`, `inscope_tls_names.txt`, `inscope_ips.txt`, `inscope_domain_ip_map.txt`, and `excluded_out_of_scope.jsonl`. No path literals — all paths via `Activity`/`activity.asset_discovery_canonical(...)`.
- **Scope of change:** external pipeline only. `webscan` (uses `ingest`, not expand/resolve) and `internal` (own IP/CIDR model) are untouched.
- Test files: `tests/core/test_scope.py` (pure scope helpers), `tests/pipelines/test_external_tasks.py` (stage + wiring). Test convention: `Activity.named(name, root=tmp_path).ensure()`, `tools.write_lines`/`write_jsonl`, imports inside the test where the existing file does so.
- Branch: `feat/scope-gate` (already created; the design spec is committed there). Spec: `docs/superpowers/specs/2026-07-05-scope-gate-design.md`.

---

### Task 1: Allowlist + membership predicates + IPv6 `classify` (pure)

**Files:**
- Modify: `src/ptflow/core/scope.py`
- Test: `tests/core/test_scope.py`

**Interfaces:**
- Produces: `Allowlist(exact_hosts: frozenset[str], wildcard_apexes: frozenset[str], nets: tuple[IPv4Network|IPv6Network, ...])`; `norm_host(host: str) -> str`; `build_allowlist(targets: list[Target]) -> Allowlist`; `host_in_scope(host: str, allow: Allowlist) -> bool`; `ip_in_scope(ip: str, allow: Allowlist) -> bool`. Tightened `classify(token) -> str` (IPv6-aware, rejects bad octets).

- [ ] **Step 1: Write the failing tests**

Add to `tests/core/test_scope.py`:

```python
def test_classify_recognizes_ipv6_and_rejects_bad_octets():
    from ptflow.core import scope
    assert scope.classify("2001:db8::1") == "ip"
    assert scope.classify("2001:db8::/32") == "cidr"
    assert scope.classify("192.0.2.5") == "ip"
    assert scope.classify("192.0.2.0/24") == "cidr"
    assert scope.classify("999.0.0.1") == "domain"   # invalid octets → not an IP
    assert scope.classify("acme.com") == "domain"
    assert scope.classify("*.acme.com") == "wildcard"


def test_build_allowlist_buckets_by_kind():
    from ptflow.core import scope
    allow = scope.build_allowlist(scope.parse_scope(
        "acme.com\nhttps://app.acme.com:8443/x\n*.evil.test\n192.0.2.0/24\n2001:db8::1\n"))
    assert "acme.com" in allow.exact_hosts
    assert "app.acme.com" in allow.exact_hosts        # url → bare host
    assert "evil.test" in allow.wildcard_apexes        # *.x → apex
    assert any(str(n) == "192.0.2.0/24" for n in allow.nets)
    assert any(n.version == 6 for n in allow.nets)     # ipv6 net present


def test_host_in_scope_exact_is_not_its_subdomains():
    from ptflow.core import scope
    allow = scope.build_allowlist(scope.parse_scope("acme.com\n"))
    assert scope.host_in_scope("acme.com", allow) is True
    assert scope.host_in_scope("ACME.com.", allow) is True     # case + trailing dot normalized
    assert scope.host_in_scope("app.acme.com", allow) is False  # bare domain ≠ its subdomains


def test_host_in_scope_wildcard_matches_apex_and_every_depth():
    from ptflow.core import scope
    allow = scope.build_allowlist(scope.parse_scope("*.acme.com\n"))
    assert scope.host_in_scope("acme.com", allow) is True        # apex included
    assert scope.host_in_scope("a.acme.com", allow) is True
    assert scope.host_in_scope("a.b.c.acme.com", allow) is True  # any depth
    assert scope.host_in_scope("acme.com.evil.test", allow) is False  # suffix-trick rejected


def test_ip_in_scope_v4_and_v6():
    from ptflow.core import scope
    allow = scope.build_allowlist(scope.parse_scope("192.0.2.0/24\n2001:db8::/32\n"))
    assert scope.ip_in_scope("192.0.2.5", allow) is True
    assert scope.ip_in_scope("192.0.3.5", allow) is False
    assert scope.ip_in_scope("2001:db8::dead", allow) is True
    assert scope.ip_in_scope("not-an-ip", allow) is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/core/test_scope.py -k "allowlist or in_scope or ipv6" -v`
Expected: FAIL (`AttributeError: module 'ptflow.core.scope' has no attribute 'build_allowlist'`, etc.).

- [ ] **Step 3: Implement the helpers and tighten `classify`**

In `src/ptflow/core/scope.py`, add `import ipaddress` at the top (with the other imports) and replace the `classify` body, then add the new helpers. Replace `classify`:

```python
def classify(token: str) -> str:
    t = token.strip()
    if t.startswith(("http://", "https://")):
        return "url"
    if t.startswith("*."):
        return "wildcard"
    try:
        ipaddress.ip_network(t, strict=False)
    except ValueError:
        return "domain"
    return "cidr" if "/" in t else "ip"
```

Delete the now-unused `_IP` / `_CIDR` module regexes and the `TODO(domain)` comment above `normalize` (the octet-range gap they flagged is now closed by `ipaddress`). Those regexes are `re`'s only use in this file, so also remove `import re` (ruff flags the orphan import). If a grep (`grep -n 're\.\|_IP\b\|_CIDR\b' src/ptflow/core/scope.py`) shows any surviving use, keep what's needed.

Add, after `parse_scope`/`target_from_meta`:

```python
@dataclass(frozen=True)
class Allowlist:
    exact_hosts: frozenset[str]
    wildcard_apexes: frozenset[str]
    nets: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]


def norm_host(host: str) -> str:
    """Canonical host for scope comparison: lower-case, no trailing dot, IDN→punycode."""
    h = host.strip().lower().rstrip(".")
    try:
        return h.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return h


def build_allowlist(targets: list[Target]) -> Allowlist:
    """Bucket classified scope targets into the authorization allowlist. domain/url → exact host;
    *.x → wildcard apex; ip/cidr → an ipaddress network (bad entries skipped)."""
    exact: set[str] = set()
    wild: set[str] = set()
    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for t in targets:
        if t.kind in ("domain", "url"):
            exact.add(norm_host(t.normalized))
        elif t.kind == "wildcard":
            wild.add(norm_host(t.normalized))
        elif t.kind in ("ip", "cidr"):
            try:
                nets.append(ipaddress.ip_network(t.raw, strict=False))
            except ValueError:
                continue
    return Allowlist(frozenset(exact), frozenset(wild), tuple(nets))


def host_in_scope(host: str, allow: Allowlist) -> bool:
    """Rules 1+2: exact-host match, or a suffix match under a *.apex (apex included)."""
    h = norm_host(host)
    if h in allow.exact_hosts:
        return True
    return any(h == w or h.endswith("." + w) for w in allow.wildcard_apexes)


def ip_in_scope(ip: str, allow: Allowlist) -> bool:
    """Rule 3: the IP is inside an explicitly-listed scope network (v4 or v6)."""
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return False
    return any(addr in net for net in allow.nets)
```

- [ ] **Step 4: Run tests to verify they pass + no regression**

Run: `uv run pytest tests/core/test_scope.py -v`
Expected: all PASS (new tests + the pre-existing `classify`/`parse_scope`/`normalize` tests — confirm none asserted the old buggy `999.0.0.1 → ip` behavior; if one does, it was asserting a bug — update it to expect `"domain"`).

- [ ] **Step 5: Commit**

```bash
git add src/ptflow/core/scope.py tests/core/test_scope.py
git commit -m "feat(scope-gate): allowlist + host/ip membership predicates, IPv6-aware classify

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: `filter_assets` — the membership filter (pure)

**Files:**
- Modify: `src/ptflow/core/scope.py`
- Test: `tests/core/test_scope.py`

**Interfaces:**
- Consumes: `Allowlist`, `host_in_scope`, `ip_in_scope`, `norm_host` (Task 1).
- Produces: `ScopeVerdict(kept_names: frozenset[str], kept_ips: frozenset[str], dropped: tuple[dict, ...])`; `filter_assets(names: Iterable[str], name_ips: dict[str, list[str]], ips: Iterable[str], allow: Allowlist) -> ScopeVerdict`. `kept_names` holds `norm_host`-normalized names. Each `dropped` record is `{"asset": str, "kind": "name"|"ip", "reason": "out-of-scope", "resolved_ips": [...]?}`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/core/test_scope.py`:

```python
def test_filter_assets_domain_scope_drops_thirdparty_name_and_ip():
    from ptflow.core import scope
    allow = scope.build_allowlist(scope.parse_scope("acme.com\n"))
    name_ips = {"acme.com": ["192.0.2.9"], "cdn.other.test": ["203.0.113.5"]}
    v = scope.filter_assets(["acme.com", "cdn.other.test"], name_ips,
                            ["192.0.2.9", "203.0.113.5"], allow)
    assert "acme.com" in v.kept_names
    assert "cdn.other.test" not in v.kept_names        # third-party apex dropped
    assert "192.0.2.9" in v.kept_ips                    # domain→IP kept
    assert "203.0.113.5" not in v.kept_ips              # third-party IP dropped


def test_filter_assets_ip_only_scope_recovers_vhost_by_rule4():
    from ptflow.core import scope
    allow = scope.build_allowlist(scope.parse_scope("192.0.2.0/24\n"))   # IP-only scope
    name_ips = {"mail.acme.com": ["192.0.2.5"],      # SAN on an in-scope IP
                "www.acme.com": ["203.0.113.7"]}     # public DNS points off-scope
    v = scope.filter_assets(["mail.acme.com", "www.acme.com"], name_ips,
                            ["192.0.2.5", "203.0.113.7"], allow)
    assert "mail.acme.com" in v.kept_names            # rule 4: resolves to an in-scope IP
    assert "www.acme.com" not in v.kept_names          # decision (a): resolves off-scope → dropped
    assert "192.0.2.5" in v.kept_ips
    assert "203.0.113.7" not in v.kept_ips


def test_filter_assets_anti_transitivity():
    from ptflow.core import scope
    allow = scope.build_allowlist(scope.parse_scope("acme.com\n"))  # a DOMAIN, no IP net
    # acme.com → 192.0.2.9 (domain-derived, scanned) — but that IP must NOT authorize other names
    name_ips = {"acme.com": ["192.0.2.9"], "hitchhiker.other.test": ["192.0.2.9"]}
    v = scope.filter_assets(["acme.com", "hitchhiker.other.test"], name_ips,
                            ["192.0.2.9"], allow)
    assert "acme.com" in v.kept_names
    assert "hitchhiker.other.test" not in v.kept_names   # rule 4 uses EXPLICIT nets only


def test_filter_assets_empty_allowlist_drops_all():
    from ptflow.core import scope
    allow = scope.build_allowlist([])
    v = scope.filter_assets(["a.test"], {"a.test": ["192.0.2.1"]}, ["192.0.2.1"], allow)
    assert not v.kept_names and not v.kept_ips
    assert len(v.dropped) == 2
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/core/test_scope.py -k filter_assets -v`
Expected: FAIL (`AttributeError: ... has no attribute 'filter_assets'`).

- [ ] **Step 3: Implement `filter_assets` + `ScopeVerdict`**

In `src/ptflow/core/scope.py`, ensure `from collections.abc import Iterable` is imported, then add after the Task-1 helpers:

```python
@dataclass(frozen=True)
class ScopeVerdict:
    kept_names: frozenset[str]
    kept_ips: frozenset[str]
    dropped: tuple[dict, ...]


def filter_assets(names: Iterable[str], name_ips: dict[str, list[str]],
                  ips: Iterable[str], allow: Allowlist) -> ScopeVerdict:
    """Partition discovered assets into (kept, dropped) by the four membership rules. A NAME is kept if
    host_in_scope (rules 1+2) or any of its resolved IPs is in an explicit scope net (rule 4 — uses
    EXPLICIT nets only, so domain-derived IPs never authorize further names). An IP is kept if it is in
    an explicit scope net (rule 3) or is a resolved IP of a kept name (domain→IP; CDN exclusion is left
    to naabu -exclude-cdn / split_cdn_ip_records downstream). Pure."""
    kept_names: set[str] = set()
    dropped: list[dict] = []
    for raw in names:
        n = norm_host(raw)
        resolved = name_ips.get(n, [])
        if host_in_scope(n, allow) or any(ip_in_scope(ip, allow) for ip in resolved):
            kept_names.add(n)
        else:
            dropped.append({"asset": raw, "kind": "name", "reason": "out-of-scope",
                            "resolved_ips": resolved})
    kept_name_ips = {ip for n in kept_names for ip in name_ips.get(n, [])}
    kept_ips: set[str] = set()
    for ip in ips:
        if ip_in_scope(ip, allow) or ip in kept_name_ips:
            kept_ips.add(ip)
        else:
            dropped.append({"asset": ip, "kind": "ip", "reason": "out-of-scope"})
    return ScopeVerdict(frozenset(kept_names), frozenset(kept_ips), tuple(dropped))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/core/test_scope.py -k filter_assets -v`
Expected: all 4 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ptflow/core/scope.py tests/core/test_scope.py
git commit -m "feat(scope-gate): filter_assets — the four-rule membership filter

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: `parse_domain_ip_map` + the `scope_gate` stage

**Files:**
- Modify: `src/ptflow/pipelines/external/tasks.py` (add helper + stage; place `parse_domain_ip_map` near `map_hosts_to_ips` ~line 552, and `scope_gate` right after `resolve` ~line 1791)
- Test: `tests/pipelines/test_external_tasks.py`

**Interfaces:**
- Consumes: `scope.parse_scope`, `scope.build_allowlist`, `scope.filter_assets`, `scope.norm_host` (Tasks 1-2); the module regex `_IPV4_RE` (exists, used by `map_hosts_to_ips`).
- Produces: `parse_domain_ip_map(lines: Iterable[str]) -> dict[str, list[str]]` (host→IPv4s, keyed by lower-cased host); `scope_gate(activity: Activity) -> None` writing `inscope_subdomains.txt` / `inscope_tls_names.txt` / `inscope_ips.txt` / `inscope_domain_ip_map.txt` / `excluded_out_of_scope.jsonl`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/pipelines/test_external_tasks.py`:

```python
def test_parse_domain_ip_map_extracts_host_and_ips():
    got = tasks.parse_domain_ip_map([
        "acme.com [A] [192.0.2.9] [192.0.2.10]",
        "mail.acme.com [A] [192.0.2.5]",
        "",
    ])
    assert got == {"acme.com": ["192.0.2.9", "192.0.2.10"], "mail.acme.com": ["192.0.2.5"]}


def test_scope_gate_keeps_inscope_drops_thirdparty(tmp_path):
    from ptflow.core import tools
    from ptflow.core.paths import Activity

    act = Activity.named("gate", root=tmp_path).ensure()
    act.scope_init.parent.mkdir(parents=True, exist_ok=True)
    act.scope_init.write_text("acme.com\n192.0.2.0/24\n")
    canon = act.asset_discovery_canonical
    tools.write_lines(canon("subdomains.txt"), ["acme.com", "evil.test"])          # evil = third-party
    tools.write_lines(canon("tls_names.txt"), ["mail.acme.com", "cdn.other.test"]) # mail on scope IP (rule 4)
    tools.write_lines(canon("unique_ips.txt"), ["192.0.2.9", "203.0.113.5"])
    tools.write_lines(canon("domain_ip_map.txt"), [
        "acme.com [A] [192.0.2.9]",
        "mail.acme.com [A] [192.0.2.5]",       # 192.0.2.5 ∈ 192.0.2.0/24 → rule 4 keeps the name
        "evil.test [A] [203.0.113.5]",
        "cdn.other.test [A] [203.0.113.5]",
    ])
    tasks.scope_gate(act)
    subs = tools.read_lines(canon("inscope_subdomains.txt"))
    tls = tools.read_lines(canon("inscope_tls_names.txt"))
    ips = tools.read_lines(canon("inscope_ips.txt"))
    dropped = {d["asset"] for d in tools.read_jsonl(canon("excluded_out_of_scope.jsonl"))}
    assert subs == ["acme.com"]                      # evil.test dropped
    assert tls == ["mail.acme.com"]                  # rule 4 kept it; cdn.other.test dropped
    assert "192.0.2.9" in ips and "203.0.113.5" not in ips
    assert {"evil.test", "cdn.other.test", "203.0.113.5"} <= dropped
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/pipelines/test_external_tasks.py -k "parse_domain_ip_map or scope_gate" -v`
Expected: FAIL (`AttributeError: ... has no attribute 'parse_domain_ip_map'` / `scope_gate`).

- [ ] **Step 3: Implement `parse_domain_ip_map`**

In `src/ptflow/pipelines/external/tasks.py`, add near `map_hosts_to_ips` (which documents the `<host> [A] [<ip>] …` format):

```python
def parse_domain_ip_map(lines: Iterable[str]) -> dict[str, list[str]]:
    """Parse a dnsx `-a -resp` map (domain_ip_map.txt: ``<host> [A] [<ip>] …``) into {host: [ipv4, …]},
    host lower-cased. Reuses _IPV4_RE over the rest of each line (bracket-agnostic). Pure."""
    out: dict[str, list[str]] = {}
    for line in lines:
        head, _, rest = line.strip().partition(" ")
        if head:
            out.setdefault(head.lower(), []).extend(_IPV4_RE.findall(rest))
    return out
```

- [ ] **Step 4: Implement the `scope_gate` stage**

In `src/ptflow/pipelines/external/tasks.py`, add right after `resolve` (before `portscan`):

```python
def scope_gate(activity: Activity) -> None:
    """Breadth — enforce the RoE authorization boundary between discovery and active scanning. Build the
    scope allowlist (exact host / *.apex suffix / IP-CIDR) from scope_init, then keep only authorized
    names+IPs from resolve's discovery output: a name survives if it matches a domain/wildcard entry OR
    resolves to an in-scope IP (rule 4 — recovers vhosts on IP-only scopes); an IP survives if it is an
    explicit scope IP or a resolved IP of a kept name. Third-party pull-in (SAN/PTR of an unlisted apex,
    cloud IPs) is dropped to excluded_out_of_scope.jsonl (RoE audit). Offline (net=False); complements the
    CDN filters (naabu -exclude-cdn / split_cdn_ip_records)."""
    canon = activity.asset_discovery_canonical
    targets = scope.parse_scope(activity.scope_init.read_text(encoding="utf-8", errors="replace"))
    allow = scope.build_allowlist(targets)
    subdomains = tools.read_lines(canon("subdomains.txt"))
    tls_names = tools.read_lines(canon("tls_names.txt"))
    ips = tools.read_lines(canon("unique_ips.txt"))
    dim_lines = tools.read_lines(canon("domain_ip_map.txt"))
    name_ips = parse_domain_ip_map(dim_lines)
    verdict = scope.filter_assets([*subdomains, *tls_names], name_ips, ips, allow)

    tools.write_lines(canon("inscope_subdomains.txt"),
                      [s for s in subdomains if scope.norm_host(s) in verdict.kept_names])
    tools.write_lines(canon("inscope_tls_names.txt"),
                      [t for t in tls_names if scope.norm_host(t) in verdict.kept_names])
    tools.write_lines(canon("inscope_ips.txt"), [ip for ip in ips if ip in verdict.kept_ips])
    tools.write_lines(canon("inscope_domain_ip_map.txt"),
                      [ln for ln in dim_lines
                       if scope.norm_host(ln.strip().partition(" ")[0]) in verdict.kept_names])
    tools.write_jsonl(canon("excluded_out_of_scope.jsonl"), list(verdict.dropped))

    if not (allow.exact_hosts or allow.wildcard_apexes or allow.nets):
        log.warning("⚠ scope_gate: EMPTY allowlist (malformed/empty scope?) — all discovered assets dropped")
    log.info("  → scope_gate: kept %d name(s) + %d ip(s), dropped %d → excluded_out_of_scope.jsonl",
             len(verdict.kept_names), len(verdict.kept_ips), len(verdict.dropped))
```

Confirm `scope` is imported in `tasks.py` (it is — `scope.parse_scope` is used by `expand`). No path literals: every file goes through `canon(...)`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/pipelines/test_external_tasks.py -k "parse_domain_ip_map or scope_gate" -v`
Expected: both PASS.

- [ ] **Step 6: Commit**

```bash
git add src/ptflow/pipelines/external/tasks.py tests/pipelines/test_external_tasks.py
git commit -m "feat(scope-gate): parse_domain_ip_map + scope_gate stage (writes inscope_* + audit)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: Wire `scope_gate` into the graph + flow map

**Files:**
- Modify: `src/ptflow/pipelines/external/pipeline.py` (the breadth stages ~lines 33-36)
- Modify: `src/ptflow/pipelines/external/flowmeta.py` (add a `StepMeta`)
- Regenerate: `docs/external-pipeline-*` (and `docs/webscan-pipeline-*` if the shared FLOWMETA touch changes them)
- Test: `tests/pipelines/test_external_tasks.py` + the flow-map gate `tests/pipelines/test_flowmap.py`

**Interfaces:**
- Consumes: `tasks.scope_gate` (Task 3).
- Produces: a `scope_gate` `Stage` (`net=False`, `needs=("resolve",)`); `portscan` now `needs=("scope_gate",)`.

- [ ] **Step 1: Write the failing test**

Add to `tests/pipelines/test_external_tasks.py`:

```python
def test_scope_gate_is_wired_between_resolve_and_portscan():
    from ptflow.pipelines.external.pipeline import PIPELINE

    stages = {s.name: s for s in PIPELINE.stages}
    assert "scope_gate" in stages
    assert stages["scope_gate"].needs == ("resolve",)
    assert not stages["scope_gate"].net
    assert not stages["scope_gate"].per_app
    assert stages["portscan"].needs == ("scope_gate",)   # portscan now gated
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/pipelines/test_external_tasks.py::test_scope_gate_is_wired_between_resolve_and_portscan -v`
Expected: FAIL (`scope_gate` not in stages).

- [ ] **Step 3: Add the stage and re-point portscan's `needs`**

In `src/ptflow/pipelines/external/pipeline.py`, in the breadth block, insert `scope_gate` after `resolve` and change `portscan`'s `needs`:

```python
        Stage("resolve", tasks.resolve, needs=("expand",)),
        Stage("scope_gate", tasks.scope_gate, needs=("resolve",), net=False),  # RoE authorization gate
        Stage("portscan", tasks.portscan, needs=("scope_gate",)),
        Stage("httpx", tasks.httpx_fingerprint, needs=("portscan",)),
```

(Leave `portscan_full`'s `needs=("portscan",)` and all other stages unchanged.)

- [ ] **Step 4: Add the `StepMeta`**

In `src/ptflow/pipelines/external/flowmeta.py`, add to `FLOWMETA` immediately after the `"resolve"` entry:

```python
    "scope_gate": StepMeta(
        summary="Gate di AUTORIZZAZIONE (RoE) tra discovery e scan attivo. Costruisce l'allowlist dallo "
                "scope (host esatto / *.apex a suffisso / IP-CIDR) e tiene solo gli asset autorizzati: un "
                "nome sopravvive se matcha un dominio/wildcard OPPURE risolve a un IP in-scope (regola 4 — "
                "recupera i vhost negli scope solo-IP); un IP se è esplicito o risolto da un nome tenuto. "
                "Il pull-in di terzi (SAN/PTR di apex non elencati, IP cloud) va in excluded_out_of_scope.jsonl.",
        commands=(
            "# build_allowlist(scope_init) + filter_assets(subdomains ∪ tls_names, domain_ip_map, unique_ips)",
            "# offline (net=False) · complementa naabu -exclude-cdn / split_cdn_ip_records (niente check CDN qui)",
        ),
        outputs=("inscope_subdomains.txt", "inscope_tls_names.txt", "inscope_ips.txt",
                 "inscope_domain_ip_map.txt", "excluded_out_of_scope.jsonl"),
        notes=("gli stage attivi (portscan/httpx/nuclei_scope/cve_lookup) leggono i file inscope_* · "
               "allowlist vuota ⇒ scarta tutto + WARNING",),
    ),
```

- [ ] **Step 5: Regenerate the flow-map docs**

Run: `uv run python -m ptflow.core.flowdocs`
Expected: updates `docs/external-pipeline-*` (a new `scope_gate` node between resolve and portscan). `docs/webscan-pipeline-*` should be unchanged (webscan has no scope_gate stage; an extra FLOWMETA entry is harmless).

- [ ] **Step 6: Run the wiring test + flow-map gate**

Run: `uv run pytest tests/pipelines/test_external_tasks.py::test_scope_gate_is_wired_between_resolve_and_portscan tests/pipelines/test_flowmap.py -v`
Expected: PASS (the gate confirms every Stage — including `scope_gate` — has a `StepMeta`).

- [ ] **Step 7: Commit**

```bash
git add src/ptflow/pipelines/external/pipeline.py src/ptflow/pipelines/external/flowmeta.py docs/external-pipeline-* docs/webscan-pipeline-* tests/pipelines/test_external_tasks.py
git commit -m "feat(scope-gate): wire scope_gate between resolve and portscan + flow map

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: Rewire the active stages to read the `inscope_*` set + full gate

At this point `scope_gate` writes the authorized files but the active stages still read the raw discovery files, so the gate has no effect. This task switches the five downstream read sites and fixes any tests that depended on the old flow.

**Files:**
- Modify: `src/ptflow/pipelines/external/tasks.py` (5 read sites)
- Test: `tests/pipelines/test_external_tasks.py` (adjust affected tests)

**Interfaces:**
- Consumes: the `inscope_*` files written by `scope_gate` (Task 3).
- Produces: no new API — `portscan`/`portscan_full`/`httpx_fingerprint`/`nuclei_scope`/`cve_lookup` read the authorized set.

- [ ] **Step 1: Capture the baseline**

Run: `uv run pytest tests/pipelines/test_external_tasks.py -q` and note it is green before changes (so any post-rewire failure is attributable to this task).

- [ ] **Step 2: Rewire the five read sites**

In `src/ptflow/pipelines/external/tasks.py` make exactly these read-path swaps (writes and everything else unchanged):

- In `portscan` — the `unique_ips` read:
  ```python
  unique_ips = tools.read_lines(canon("inscope_ips.txt"))
  ```
- In `portscan_full` — the valid-IPs read:
  ```python
  valid = [ip for ip in tools.read_lines(canon("inscope_ips.txt")) if ip not in honeypots]
  ```
- In `httpx_fingerprint` — the two name reads inside the `httpx_input` dedupe list:
  ```python
      *tools.read_lines(canon("inscope_tls_names.txt")),
      *tools.read_lines(canon("inscope_subdomains.txt")),
  ```
- In `nuclei_scope` — the `subdomains.txt` read (~line 1908):
  ```python
  ...tools.read_lines(canon("inscope_subdomains.txt"))...
  ```
  (swap `"subdomains.txt"` → `"inscope_subdomains.txt"` in that `tools.dedupe([...])` expression; leave the other elements as they are.)
- In the CVE software collector — the `domain_ip_map.txt` read (~line 4626, `dim = canon("domain_ip_map.txt")`):
  ```python
  dim = canon("inscope_domain_ip_map.txt")
  ```

Do NOT change `resolve`'s own read of `tls_names.txt` (~line 1782) — it runs BEFORE `scope_gate` and consumes `expand`'s raw output. After editing, grep to confirm no OTHER downstream reader remains:
`grep -n 'read_lines(canon("subdomains.txt")\|read_lines(canon("unique_ips.txt")\|read_lines(canon("tls_names.txt")\|canon("domain_ip_map.txt")' src/ptflow/pipelines/external/tasks.py` — the only surviving raw reads should be inside `resolve` (tls_names, upstream of the gate).

- [ ] **Step 3: Run the suite and fix affected tests**

Run: `uv run pytest tests/pipelines/test_external_tasks.py -q`
Expected: some tests that set up `unique_ips.txt` / `subdomains.txt` / `tls_names.txt` / `domain_ip_map.txt` and then call `portscan`/`httpx_fingerprint`/`nuclei_scope`/the CVE collector will now read empty `inscope_*` files and fail. For each failure, fix the TEST by making the authorized set present — either call `tasks.scope_gate(act)` after writing a matching `scope_init`, or write the `inscope_*` file directly with the same content the test intends to scan. Preserve each test's original intent and assertions; do NOT weaken them. (A test whose fixture wrote `unique_ips.txt` to exercise portscan should now write `inscope_ips.txt`, or run the gate.)

- [ ] **Step 4: Run the full dev gate**

Run: `uv run ruff check . && uv run ty check src/ && uv run pytest`
Expected: ruff clean, ty clean, all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ptflow/pipelines/external/tasks.py tests/pipelines/test_external_tasks.py
git commit -m "feat(scope-gate): active stages read the authorized inscope_* set

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Post-implementation (outside the task loop)

- Update `CLAUDE.md`: the external breadth flow (add `scope_gate` between resolve and portscan), the workspace-layout map (`inscope_*.txt` + `excluded_out_of_scope.jsonl`), and a design-decision entry (the four membership rules, IP→names rule 4 for IP-only scopes, CDN delegated to existing filters, no PSL). The post-merge doc-sync hook drafts this on merge — review its output.
- Update the `recon-backlog` memory (#6): mark the per-apex scope gate DONE, leaving the deferred items (Host-header/SNI pinning, early cdncheck, apex auto-expansion, broader IPv6) as roadmap.
