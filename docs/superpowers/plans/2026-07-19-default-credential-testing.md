# Default-Credential Testing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add opt-in phase-3 stages to the `internal` pipeline that test the research agent's
source-grounded default-credential proposals — non-HTTP + HTTP Basic via Brutus, HTTP form-based login via
a new Playwright `FormLoginProbe` (no Anthropic key).

**Architecture:** `pipelines/internal/creds.py` holds pure planners (candidate→socket matching, routing,
protocol/mode mapping, lockout budget, Brutus JSONL parsing) and two per-app phase-3 stages:
`creds_test_brutus` (Brutus, flat CLI) and `creds_test_forms` (drives `core/agents/form_login.py`).
`pipeline.py` splices them in only when `PTFLOW_CREDS_TEST` is set. Brutus is fed only our validated
pairs (never its defaults or `--experimental-ai`). Part A = everything except the form probe (independently
mergeable); Part B = `FormLoginProbe` + `creds_test_forms`.

**Tech Stack:** Python 3, Prefect ≥3, Brutus (`~/go/bin/brutus`, flat CLI), Playwright (already a dep of
the research agent), pytest, ruff (`select=ALL`), ty.

## Global Constraints

- Engines: **Brutus** for non-HTTP + HTTP Basic (`brutus --target <ip:port> --protocol <p> -u <u> -p <p>
  --json <mode-flags>`); **`FormLoginProbe`** (Playwright, `allow_private=True`) for HTTP forms. **Never**
  Brutus `--experimental-ai`, never its embedded defaults, never wordlists.
- Verified Brutus CLI: **no** `creds`/`web` subcommands, **no** `--mode`/`--targets-file`/`-c`. Protocols
  include `http`/`https` (Basic auth only without AI). `PTFLOW_CREDS_MODE` → a real flag bundle:
  `cautious`=`-t 5 --rate-limit 2 --retries 1 --timeout 15s`; `default`=`-t 10 --retries 2`;
  `aggressive`=`-t 20 --retries 3`. Leave TLS default (no `--verify-tls` ⇒ skip verify).
- **Opt-in**: `PTFLOW_CREDS_TEST` ∈ `{1,on,true,yes}`, default OFF ⇒ stages absent from the DAG.
- **Lockout invariant** (SMB/LDAP/RDP/WinRM): never > `threshold-1` attempts/account; `threshold<=1` ⇒
  skip; unknown ⇒ `PTFLOW_CREDS_LOCKOUT_DEFAULT` (default 3). HTTP is not lockout-gated.
- **Files-as-only-state**: read/write only via `Activity`/`AppWorkspace`; each tool output once; Brutus
  scratch → `ws.raw("brutus")`. Findings → `ws.findings`.
- **Secrets**: `credential_candidates.jsonl`, `findings/creds_brutus.jsonl`, `findings/creds_forms.jsonl`,
  consolidated `findings/creds.jsonl` are `chmod 0600`. `redact()` masks passwords for reports. Never log a
  password.
- **Best-effort**: missing binary / Playwright / non-zero exit / timeout ⇒ empty result + debug log, never
  aborts.
- **Imports** (verbatim): `from ptflow.core.log import get_logger, is_verbose`; `AbortedError` is
  `ptflow.core.tools.AbortedError`; `Stage` is `ptflow.core.stage.Stage`; reuse
  `ptflow.core.agents.research._validate_fetch_url` for the form probe's SSRF guard.
- Full gate before finishing: `uv run ruff check . && uv run ty check src/ && uv run pytest`.

---

## Task 0: Verify the installed Brutus CLI — DONE

Verified `~/go/bin/brutus --help` (build `dev`): flat CLI (`--target`/`--protocol`/`--nerva`), protocols
list includes `http`/`https` (Basic only without `--experimental-ai`), credential flags `-u`/`-p`/`-U`/`-P`/
`-k`, performance flags `-t`/`--timeout`/`--rate-limit`/`--retries`/`--max-attempts`/`--stop-on-success`,
output `--json`/`-o`/`-q`, TLS `--verify-tls` (default skip). No `creds`/`web` subcommands, no
`--mode`/`--targets-file`/`-c`. These facts are baked into the tasks below; no code, no commit.

---

## Task 1: Wire `brutus` tool, requirement, and consolidate fold (`tasks.py`)

**Files:**
- Modify: `src/ptflow/pipelines/internal/tasks.py` (tool constant ~line 109; `_OPTIONAL_TOOLS` ~line 112;
  `_CONSOLIDATE_SOURCES` ~line 1484; `consolidate` body ~line 1532)
- Test: `tests/pipelines/test_internal_tasks.py`

**Interfaces:**
- Produces: `BRUTUS: str`; `_OPTIONAL_TOOLS["brutus"]`; `_CONSOLIDATE_SOURCES["creds.jsonl"] =
  ("findings/creds_brutus.jsonl", "findings/creds_forms.jsonl")`; `consolidate` chmods
  `findings/creds.jsonl` to `0o600`.

- [ ] **Step 1: Write the failing test**

Add to `tests/pipelines/test_internal_tasks.py`:
```python
def test_requirements_include_brutus_as_optional():
    from ptflow.pipelines.internal import tasks
    brutus = [r for r in tasks.requirements() if r.name == "brutus"]
    assert brutus and brutus[0].kind == "optional"


def test_consolidate_folds_and_locks_down_creds(tmp_path):
    from ptflow.core.paths import Activity
    from ptflow.core import tools
    from ptflow.pipelines.internal import tasks
    activity = Activity.named("a", root=tmp_path).ensure()
    ws = activity.app("10.0.0.0-24")
    ws.root.mkdir(parents=True, exist_ok=True)
    (ws.root / "meta.json").write_text("{}")
    tools.write_jsonl(ws.findings / "creds_brutus.jsonl",
                      [{"type": "default-credentials", "host": "10.0.0.5", "password": "s3cr3t"}])
    tools.write_jsonl(ws.findings / "creds_forms.jsonl",
                      [{"type": "default-credentials", "host": "10.0.0.6", "password": "admin"}])
    tasks.consolidate(activity)
    out = activity.findings / "creds.jsonl"
    records = tools.read_jsonl(out)
    assert {r["host"] for r in records} == {"10.0.0.5", "10.0.0.6"}
    assert all(r["app_id"] == "10.0.0.0-24" for r in records)
    assert (out.stat().st_mode & 0o777) == 0o600
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/pipelines/test_internal_tasks.py -k "brutus or locks_down_creds" -v`
Expected: FAIL.

- [ ] **Step 3: Add the tool constant + optional entry**

In `tasks.py` after the `DIG` resolve (~line 109):
```python
BRUTUS = _resolve("PTFLOW_BRUTUS", f"{_HOME}/go/bin/brutus", "brutus")  # default-cred tester (opt-in)
```
Extend `_OPTIONAL_TOOLS` (~line 112) with `"brutus": BRUTUS` as the last entry.

- [ ] **Step 4: Add the consolidate fold + 0600 lockdown**

In `_CONSOLIDATE_SOURCES` (~line 1484) add as the last entry:
```python
    "creds.jsonl": ("findings/creds_brutus.jsonl", "findings/creds_forms.jsonl"),
```
In `consolidate`, inside the `if records:` block, after `tools.write_jsonl(...)`:
```python
            if out_name == "creds.jsonl":
                (activity.findings / out_name).chmod(0o600)
```

- [ ] **Step 5: Run to verify it passes**

Run: `uv run pytest tests/pipelines/test_internal_tasks.py -k "brutus or locks_down_creds" -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/ptflow/pipelines/internal/tasks.py tests/pipelines/test_internal_tasks.py
git commit -m "feat(internal): register brutus tool + consolidate creds findings"
```

---

## Task 2: creds.py — constants, mode flags, service sockets, product match, routing

**Files:**
- Create: `src/ptflow/pipelines/internal/creds.py`
- Test: `tests/pipelines/test_internal_creds.py`

**Interfaces:**
- Produces: `creds_test_enabled() -> bool`; `resolve_mode() -> str`; `mode_flags() -> list[str]`;
  `_lockout_default() -> int`; `ServiceSocket(host,port,product,service,banner)`;
  `service_sockets(services) -> list[ServiceSocket]`;
  `_product_matches(candidate_product, socket_product) -> bool`; `socket_proto(sock) -> str | None`;
  `web_urls(services) -> dict[tuple[str,int], str]`; constants `_BRUTUS_PROTO`, `_PORT_PROTO`,
  `_LOCKOUT_PROTOCOLS`, `_MODE_FLAGS`, `DEFAULT_MODE`, `DEFAULT_LOCKOUT`, `BRUTUS_TIMEOUT`, the three env
  names.

- [ ] **Step 1: Write the failing test**

Create `tests/pipelines/test_internal_creds.py`:
```python
from ptflow.pipelines.internal import creds


def test_service_sockets_extracts_product_from_field_or_banner():
    services = [
        {"ip": "10.0.0.5", "port": 22, "service": "ssh",
         "metadata": {"banner": "SSH-2.0-OpenSSH_8.9p1"}},
        {"ip": "10.0.0.5", "port": 8443, "product": "Acme Router", "service": "https"},
        {"host": "10.0.0.6", "port": None},
    ]
    socks = creds.service_sockets(services)
    assert len(socks) == 2
    assert next(s for s in socks if s.port == 22).product == "OpenSSH"
    assert next(s for s in socks if s.port == 8443).product == "Acme Router"


def test_product_match_is_bidirectional_and_casefold():
    assert creds._product_matches("Acme Router", "acme router firmware")
    assert creds._product_matches("OpenSSH 8.9", "openssh")
    assert not creds._product_matches("Acme", "")


def test_socket_proto_prefers_service_then_port():
    assert creds.socket_proto(creds.ServiceSocket("h", 3389, "", "ms-wbt-server", "")) == "rdp"
    assert creds.socket_proto(creds.ServiceSocket("h", 5432, "", "", "")) == "postgres"
    assert creds.socket_proto(creds.ServiceSocket("h", 12345, "", "weird", "")) is None


def test_web_urls_uses_web_targets_rule():
    services = [{"ip": "10.0.0.5", "port": 8443, "service": "https"},
                {"ip": "10.0.0.5", "port": 22, "service": "ssh"}]
    urls = creds.web_urls(services)
    assert urls[("10.0.0.5", 8443)] == "https://10.0.0.5:8443"
    assert ("10.0.0.5", 22) not in urls


def test_mode_flags_bundle(monkeypatch):
    monkeypatch.delenv("PTFLOW_CREDS_MODE", raising=False)
    assert creds.resolve_mode() == "cautious"
    assert creds.mode_flags()[:2] == ["-t", "5"] and "--rate-limit" in creds.mode_flags()
    monkeypatch.setenv("PTFLOW_CREDS_MODE", "aggressive")
    assert creds.mode_flags()[:2] == ["-t", "20"]
    monkeypatch.setenv("PTFLOW_CREDS_MODE", "bogus")
    assert creds.resolve_mode() == "cautious"
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/pipelines/test_internal_creds.py -v`
Expected: FAIL (module missing).

- [ ] **Step 3: Create the module**

Create `src/ptflow/pipelines/internal/creds.py`:
```python
"""Opt-in default-credential testing for the internal pipeline.

Phase-3 per-subnet stages that try the research agent's source-grounded default-credential candidates
(``credential_candidates.jsonl``) against the concrete services they were proposed for. Non-HTTP + HTTP
Basic auth via Brutus (``creds_test_brutus``); HTTP form-based login via a Playwright ``FormLoginProbe``
(``creds_test_forms``). Curated pairs only — never Brutus's embedded defaults or ``--experimental-ai``.
Opt-in (``PTFLOW_CREDS_TEST``), best-effort, lockout-aware.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ptflow.core import tools
from ptflow.core.log import get_logger, is_verbose
from ptflow.core.stage import Stage
from ptflow.pipelines.internal.tasks import BRUTUS, _banner_product, web_targets_from

if TYPE_CHECKING:
    from ptflow.core.paths import Activity

log = get_logger()

CREDS_TEST_ENV = "PTFLOW_CREDS_TEST"
CREDS_MODE_ENV = "PTFLOW_CREDS_MODE"
LOCKOUT_DEFAULT_ENV = "PTFLOW_CREDS_LOCKOUT_DEFAULT"
_TRUTHY = frozenset({"1", "on", "true", "yes"})
DEFAULT_MODE = "cautious"
DEFAULT_LOCKOUT = 3
BRUTUS_TIMEOUT = 120  # per single-target invocation wall-clock cap (one pair, one socket)

# PTFLOW_CREDS_MODE → real Brutus flags (the installed build has no --mode).
_MODE_FLAGS: dict[str, list[str]] = {
    "cautious": ["-t", "5", "--rate-limit", "2", "--retries", "1", "--timeout", "15s"],
    "default": ["-t", "10", "--retries", "2"],
    "aggressive": ["-t", "20", "--retries", "3"],
}

_LOCKOUT_PROTOCOLS = frozenset({"smb", "ldap", "rdp", "winrm"})

_BRUTUS_PROTO = {
    "ssh": "ssh", "ftp": "ftp", "telnet": "telnet", "vnc": "vnc",
    "rdp": "rdp", "ms-wbt-server": "rdp", "snmp": "snmp",
    "smb": "smb", "microsoft-ds": "smb", "netbios-ssn": "smb", "cifs": "smb",
    "ldap": "ldap", "ldaps": "ldap", "winrm": "winrm", "wsman": "winrm",
    "mysql": "mysql", "mariadb": "mysql", "postgresql": "postgres", "postgres": "postgres",
    "mssql": "mssql", "ms-sql-s": "mssql", "mongodb": "mongodb", "mongod": "mongodb", "mongo": "mongodb",
    "redis": "redis", "oracle": "oracle", "oracle-tns": "oracle",
    "neo4j": "neo4j", "cassandra": "cassandra", "couchdb": "couchdb",
    "elasticsearch": "elasticsearch", "influxdb": "influxdb",
    "smtp": "smtp", "imap": "imap", "pop3": "pop3",
}
_PORT_PROTO: dict[int, str] = {
    22: "ssh", 21: "ftp", 23: "telnet", 3389: "rdp", 161: "snmp",
    445: "smb", 139: "smb", 389: "ldap", 636: "ldap", 3306: "mysql",
    5432: "postgres", 1433: "mssql", 6379: "redis", 27017: "mongodb", 27018: "mongodb",
    1521: "oracle", 5985: "winrm", 5986: "winrm", 25: "smtp", 143: "imap", 110: "pop3",
    **{p: "vnc" for p in range(5900, 5907)},
}


def creds_test_enabled() -> bool:
    return os.getenv(CREDS_TEST_ENV, "").strip().lower() in _TRUTHY


def resolve_mode() -> str:
    mode = os.getenv(CREDS_MODE_ENV, "").strip().lower()
    return mode if mode in _MODE_FLAGS else DEFAULT_MODE


def mode_flags() -> list[str]:
    """The Brutus performance/politeness flags for the configured mode (default cautious)."""
    return list(_MODE_FLAGS[resolve_mode()])


def _lockout_default() -> int:
    raw = os.getenv(LOCKOUT_DEFAULT_ENV, "").strip()
    return int(raw) if raw.isdigit() else DEFAULT_LOCKOUT


@dataclass(frozen=True)
class ServiceSocket:
    host: str
    port: int
    product: str
    service: str
    banner: str


def service_sockets(services: list[dict]) -> list[ServiceSocket]:
    """Flatten ``services.jsonl`` into per-socket identities; product from the field else the banner.
    Records missing host or an int port are dropped. Pure."""
    out: list[ServiceSocket] = []
    for r in services:
        host = str(r.get("ip") or r.get("host") or "").strip()
        port = r.get("port")
        if not host or not isinstance(port, int):
            continue
        meta = r.get("metadata") if isinstance(r.get("metadata"), dict) else {}
        banner = str((meta or {}).get("banner") or r.get("banner") or "")
        product = str(r.get("product") or "").strip() or (_banner_product(banner)[0] or "")
        service = str(r.get("service") or r.get("name") or r.get("protocol") or "").strip().lower()
        out.append(ServiceSocket(host, port, product, service, banner))
    return out


def _product_matches(candidate_product: str, socket_product: str) -> bool:
    a, b = candidate_product.casefold().strip(), socket_product.casefold().strip()
    return bool(a) and bool(b) and (a in b or b in a)


def socket_proto(sock: ServiceSocket) -> str | None:
    """Brutus ``--protocol`` for a NON-web socket: nerva service name then well-known port; None if
    unmapped (precision-first)."""
    return _BRUTUS_PROTO.get(sock.service) or _PORT_PROTO.get(sock.port)


def web_urls(services: list[dict]) -> dict[tuple[str, int], str]:
    """(host, port) → ``scheme://host:port`` for every web socket, via the tested ``web_targets_from``."""
    ports = [{"ip": r.get("ip") or r.get("host"), "port": r.get("port")} for r in services]
    out: dict[tuple[str, int], str] = {}
    for url in web_targets_from(ports, services):
        host, _, port = url.split("://", 1)[-1].rpartition(":")
        if host and port.isdigit():
            out[host, int(port)] = url
    return out
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run pytest tests/pipelines/test_internal_creds.py -v`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add src/ptflow/pipelines/internal/creds.py tests/pipelines/test_internal_creds.py
git commit -m "feat(internal): creds matching primitives + mode-flag bundle"
```

---

## Task 3: creds.py — lockout parsing and per-account budget

**Files:** Modify `creds.py`; Test `tests/pipelines/test_internal_creds.py`.

**Interfaces:** `parse_lockout_threshold(records) -> int | None` (None=no policy; 0=disabled/unlimited);
`account_budget(threshold, default) -> int | None` (None=unlimited; 0=skip; N=cap);
`_apply_lockout(net_attempts, threshold, default) -> tuple[list[dict], list[dict]]` → `(kept, skips)`.

- [ ] **Step 1: Write the failing test**

Append to `tests/pipelines/test_internal_creds.py`:
```python
def test_parse_lockout_threshold_reads_ad_password_policy():
    assert creds.parse_lockout_threshold([{"type": "ad-password-policy", "lockout_threshold": "5"}]) == 5
    assert creds.parse_lockout_threshold([{"type": "ad-password-policy", "lockout_threshold": "None"}]) == 0
    assert creds.parse_lockout_threshold([{"type": "ad-users-enumerated"}]) is None
    assert creds.parse_lockout_threshold([]) is None


def test_account_budget_semantics():
    assert creds.account_budget(None, 3) == 2
    assert creds.account_budget(0, 3) is None
    assert creds.account_budget(1, 3) == 0
    assert creds.account_budget(5, 3) == 4


def test_apply_lockout_caps_per_account_and_skips():
    attempts = [
        {"product": "DC", "protocol": "smb", "host": "10.0.0.1", "port": 445,
         "username": "admin", "password": p, "confidence": c}
        for p, c in (("p1", 0.9), ("p2", 0.5), ("p3", 0.1))
    ] + [{"product": "SW", "protocol": "ssh", "host": "10.0.0.2", "port": 22,
          "username": "root", "password": "x", "confidence": 0.9}]
    kept, skips = creds._apply_lockout(attempts, threshold=2, default=3)
    assert [a["password"] for a in kept if a["protocol"] == "smb"] == ["p1"]
    assert {a["password"] for a in kept if a["protocol"] == "ssh"} == {"x"}
    assert any(s["reason"] == "lockout_budget" for s in skips)
    kept2, skips2 = creds._apply_lockout(attempts, threshold=1, default=3)
    assert not [a for a in kept2 if a["protocol"] == "smb"]
    assert all(s["reason"] == "lockout_policy" for s in skips2 if s["protocol"] == "smb")
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/pipelines/test_internal_creds.py -k "lockout or budget" -v` → FAIL.

- [ ] **Step 3: Implement**

Append to `creds.py`:
```python
def parse_lockout_threshold(records: list[dict]) -> int | None:
    """Account-lockout threshold from ``findings/ad_enum.jsonl``'s ``ad-password-policy`` record. None
    when no policy was enumerated (caller uses the default); 0 for None/Disabled (unlimited). Pure."""
    for r in records:
        if r.get("type") == "ad-password-policy":
            raw = str(r.get("lockout_threshold", "")).strip().lower()
            digits = "".join(ch for ch in raw if ch.isdigit())
            if not digits or raw in ("none", "disabled"):
                return 0
            return int(digits)
    return None


def account_budget(threshold: int | None, default: int) -> int | None:
    """Max login attempts per single account: None = unlimited; 0 = must skip; N = cap. Unknown
    threshold uses ``default``."""
    t = default if threshold is None else threshold
    return None if t <= 0 else t - 1


def _apply_lockout(
    net_attempts: list[dict], threshold: int | None, default: int,
) -> tuple[list[dict], list[dict]]:
    """Cap attempts on domain-lockout protocols to ``account_budget`` per (host, protocol, username),
    highest-confidence first. Non-lockout protocols pass through. Returns (kept, skips)."""
    budget = account_budget(threshold, default)
    kept = [a for a in net_attempts if a["protocol"] not in _LOCKOUT_PROTOCOLS]
    skips: list[dict] = []
    groups: dict[tuple[str, str, str], list[dict]] = {}
    for a in net_attempts:
        if a["protocol"] in _LOCKOUT_PROTOCOLS:
            groups.setdefault((a["host"], a["protocol"], a["username"]), []).append(a)
    for (host, proto, user), atts in groups.items():
        ordered = sorted(atts, key=lambda a: (a.get("confidence") or 0), reverse=True)
        if budget is None:
            kept += ordered
            continue
        kept += ordered[:budget]
        reason = "lockout_policy" if budget == 0 else "lockout_budget"
        skips += [{"product": a["product"], "reason": reason, "via": "brutus", "host": host,
                   "port": a["port"], "protocol": proto, "username": user} for a in ordered[budget:]]
    return kept, skips
```

- [ ] **Step 4: Run to verify it passes** — `uv run pytest tests/pipelines/test_internal_creds.py -k "lockout or budget" -v` → PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ptflow/pipelines/internal/creds.py tests/pipelines/test_internal_creds.py
git commit -m "feat(internal): lockout-aware per-account credential budget"
```

---

## Task 4: creds.py — Brutus JSONL parsing, redaction, target split

**Files:** Modify `creds.py`; Test same file.

**Interfaces:** `parse_brutus_jsonl(text) -> list[dict]`; `redact(record) -> dict`;
`_split_target(target) -> tuple[str, int]`.

- [ ] **Step 1: Write the failing test**

Append:
```python
def test_parse_brutus_jsonl_keeps_hits_skips_noise():
    text = ('[*] scanning...\n'
            '{"protocol":"ssh","target":"10.0.0.5:22","username":"root","password":"toor"}\n'
            '{"not":"a hit"}\n\n')
    hits = creds.parse_brutus_jsonl(text)
    assert len(hits) == 1 and hits[0]["username"] == "root"


def test_redact_masks_password():
    assert creds.redact({"username": "a", "password": "s3cr3t"})["password"] == "****"
    assert creds.redact({"username": "a", "password": ""})["password"] == ""


def test_split_target():
    assert creds._split_target("10.0.0.5:22") == ("10.0.0.5", 22)
    assert creds._split_target("https://10.0.0.5:8443") == ("10.0.0.5", 8443)
    assert creds._split_target("10.0.0.5") == ("10.0.0.5", 0)
```

- [ ] **Step 2: Run to verify it fails** → FAIL.

- [ ] **Step 3: Implement**

Append to `creds.py`:
```python
def parse_brutus_jsonl(text: str) -> list[dict]:
    """Brutus ``--json`` stdout → success records (dict lines with a ``username``); noise skipped. Pure."""
    hits: list[dict] = []
    for ln in text.splitlines():
        if not ln.strip():
            continue
        try:
            rec = json.loads(ln)
        except json.JSONDecodeError:
            continue
        if isinstance(rec, dict) and rec.get("username"):
            hits.append(rec)
    return hits


def redact(record: dict) -> dict:
    """Shallow copy with a non-empty ``password`` masked, for any rendered report. Pure."""
    out = dict(record)
    if out.get("password"):
        out["password"] = "****"
    return out


def _split_target(target: str) -> tuple[str, int]:
    tail = target.split("://", 1)[-1]
    host, _, port = tail.rpartition(":")
    return (host, int(port)) if host and port.isdigit() else (tail, 0)
```

- [ ] **Step 4: Run to verify it passes** → PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ptflow/pipelines/internal/creds.py tests/pipelines/test_internal_creds.py
git commit -m "feat(internal): brutus JSONL parsing + password redaction"
```

---

## Task 5: creds.py — the planner and form grouping

**Files:** Modify `creds.py`; Test same file.

**Interfaces:**
- `plan_attempts(candidates, services, *, lockout_threshold, lockout_default) -> tuple[list[dict], list[dict], list[dict]]`
  → `(brutus_attempts, form_attempts, skips)`. A brutus attempt is `{product, protocol, host, port,
  username, password, confidence, source_urls, rationale}` (protocol is a Brutus name; web sockets use the
  URL scheme `http`/`https`). A form attempt is `{product, url, host, port, username, password, confidence,
  source_urls, rationale}`. A skip is `{product, reason, via, host?, port?, protocol?, username?}`.
- `group_forms(form_attempts) -> list[dict]` → `{url, host, port, pairs: list[tuple[str,str]],
  by_pair: dict[tuple[str,str], dict]}`.

- [ ] **Step 1: Write the failing test**

Append:
```python
def _cand(product, user, pw, conf=0.9):
    return {"product": product, "username": user, "password": pw, "confidence": conf,
            "source_urls": ["https://vendor/manual"], "rationale": "manual"}


def test_plan_routes_web_to_both_and_net_to_brutus():
    services = [{"ip": "10.0.0.5", "port": 8443, "product": "Acme Router", "service": "https"},
                {"ip": "10.0.0.5", "port": 22, "product": "Acme Router", "service": "ssh"}]
    candidates = [_cand("Acme Router", "admin", "acme"), _cand("Ghost", "root", "x")]
    brutus, forms, skips = creds.plan_attempts(
        candidates, services, lockout_threshold=None, lockout_default=3)
    assert {(a["protocol"], a["port"]) for a in brutus} == {("https", 8443), ("ssh", 22)}
    assert {a["url"] for a in forms} == {"https://10.0.0.5:8443"}
    assert any(s["reason"] == "no_match" and s["product"] == "Ghost" for s in skips)


def test_group_forms_shape():
    forms = [{"product": "P", "url": "https://10.0.0.5:8443", "host": "10.0.0.5", "port": 8443,
              "username": "admin", "password": "a", "confidence": 0.9,
              "source_urls": ["u"], "rationale": "r"}]
    (job,) = creds.group_forms(forms)
    assert job["url"] == "https://10.0.0.5:8443" and job["pairs"] == [("admin", "a")]
    assert job["by_pair"][("admin", "a")]["product"] == "P"
```

- [ ] **Step 2: Run to verify it fails** → FAIL.

- [ ] **Step 3: Implement**

Append to `creds.py`:
```python
def _place_candidate(
    candidate: dict, sockets: list[ServiceSocket], web_map: dict[tuple[str, int], str],
) -> tuple[list[dict], list[dict], list[dict]]:
    """Route one candidate's pair onto matching sockets: web sockets → a Brutus http/https (Basic) attempt
    AND a form attempt; mapped non-web sockets → a Brutus attempt; unmapped → skip; no match → no_match."""
    product = str(candidate.get("product") or "")
    base = {"product": product, "username": str(candidate.get("username") or ""),
            "password": str(candidate.get("password") or ""), "confidence": candidate.get("confidence"),
            "source_urls": list(candidate.get("source_urls") or []),
            "rationale": str(candidate.get("rationale") or "")}
    matched = [s for s in sockets if _product_matches(product, s.product)]
    if not matched:
        return [], [], [{"product": product, "reason": "no_match", "via": "brutus"}]
    brutus, forms, skips = [], [], []
    for s in matched:
        if (url := web_map.get((s.host, s.port))):
            scheme = url.split("://", 1)[0]
            brutus.append({**base, "protocol": scheme, "host": s.host, "port": s.port})
            forms.append({**base, "url": url, "host": s.host, "port": s.port})
        elif (proto := socket_proto(s)):
            brutus.append({**base, "protocol": proto, "host": s.host, "port": s.port})
        else:
            skips.append({"product": product, "reason": "unmapped_protocol", "via": "brutus",
                          "host": s.host, "port": s.port})
    return brutus, forms, skips


def plan_attempts(
    candidates: list[dict], services: list[dict], *,
    lockout_threshold: int | None, lockout_default: int,
) -> tuple[list[dict], list[dict], list[dict]]:
    """Curated candidates + fingerprinted services → concrete Brutus/form attempts, applying the
    per-account lockout budget to the Brutus set. Pure."""
    sockets = service_sockets(services)
    web_map = web_urls(services)
    brutus_attempts: list[dict] = []
    form_attempts: list[dict] = []
    skips: list[dict] = []
    for c in candidates:
        b, f, s = _place_candidate(c, sockets, web_map)
        brutus_attempts += b
        form_attempts += f
        skips += s
    brutus_attempts, lockout_skips = _apply_lockout(brutus_attempts, lockout_threshold, lockout_default)
    return brutus_attempts, form_attempts, skips + lockout_skips


def group_forms(form_attempts: list[dict]) -> list[dict]:
    """One browser session per web panel URL; try all its pairs, keeping per-pair metadata for finding
    attribution."""
    jobs: dict[str, dict] = {}
    for a in form_attempts:
        job = jobs.setdefault(a["url"], {"url": a["url"], "host": a["host"], "port": a["port"],
                                         "pairs": [], "by_pair": {}})
        pair = (a["username"], a["password"])
        if pair not in job["pairs"]:
            job["pairs"].append(pair)
        job["by_pair"][pair] = {"confidence": a["confidence"], "source_urls": a["source_urls"],
                                "rationale": a["rationale"], "product": a["product"]}
    return list(jobs.values())
```

- [ ] **Step 4: Run to verify it passes** → PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ptflow/pipelines/internal/creds.py tests/pipelines/test_internal_creds.py
git commit -m "feat(internal): plan brutus + form credential attempts"
```

---

## Task 6: creds.py — the Brutus stage (`creds_test_brutus`)

**Files:** Modify `creds.py`; Test same file.

**Interfaces:** `_run_brutus(cmd, *, dest, label) -> str`; `_chmod_600(path) -> None`;
`_enrich_brutus(hits, attempt, app_id) -> list[dict]`; `creds_test_brutus(activity, app_id) -> None`.

- [ ] **Step 1: Write the failing test**

Append:
```python
import pytest
from ptflow.core.paths import Activity
from ptflow.core import tools


@pytest.fixture
def activity_with_candidates(tmp_path, monkeypatch):
    monkeypatch.setattr(creds.shutil, "which", lambda _b: "/fake/brutus")
    activity = Activity.named("a", root=tmp_path).ensure()
    ws = activity.app("10.0.0.0-24")
    ws.root.mkdir(parents=True, exist_ok=True)
    tools.write_jsonl(ws.canonical("services.jsonl"),
                      [{"ip": "10.0.0.5", "port": 22, "product": "Acme NAS", "service": "ssh"}])
    tools.write_jsonl(ws.canonical("credential_candidates.jsonl"),
                      [{"product": "Acme NAS", "protocol": "ssh", "username": "admin",
                        "password": "acme", "confidence": 0.95,
                        "source_urls": ["https://vendor/manual"], "rationale": "manual"}])
    return activity, ws


def test_creds_test_brutus_writes_hit_and_locks_down(activity_with_candidates, monkeypatch):
    activity, ws = activity_with_candidates
    monkeypatch.setattr(creds, "_run_brutus", lambda *_a, **_k:
        '{"protocol":"ssh","target":"10.0.0.5:22","username":"admin","password":"acme"}\n')
    creds.creds_test_brutus(activity, "10.0.0.0-24")
    findings = tools.read_jsonl(ws.findings / "creds_brutus.jsonl")
    hit = next(f for f in findings if not f.get("skipped"))
    assert hit["type"] == "default-credentials" and hit["severity"] == "high"
    assert hit["host"] == "10.0.0.5" and hit["product"] == "Acme NAS"
    assert hit["source_urls"] == ["https://vendor/manual"]
    assert ((ws.findings / "creds_brutus.jsonl").stat().st_mode & 0o777) == 0o600
```

- [ ] **Step 2: Run to verify it fails** → FAIL.

- [ ] **Step 3: Implement**

Append to `creds.py`:
```python
def _run_brutus(cmd: list[str], *, dest, label: str) -> str:
    """Best-effort Brutus run (bounded), stdout persisted to ``dest``. '' on any error."""
    try:
        out = tools.run(cmd, stream_stderr=is_verbose(), timeout=BRUTUS_TIMEOUT)
    except (OSError, subprocess.SubprocessError, tools.AbortedError) as exc:
        log.debug("  · %s failed: %s", label, exc)
        return ""
    tools.write_text(dest, out)
    return out


def _chmod_600(path) -> None:
    try:
        path.chmod(0o600)
    except OSError as exc:  # pragma: no cover
        log.debug("  · chmod 600 failed on %s: %s", path, exc)


def _enrich_brutus(hits: list[dict], attempt: dict, app_id: str) -> list[dict]:
    out: list[dict] = []
    for h in hits:
        host, port = _split_target(str(h.get("target", "")))
        out.append({
            "app_id": app_id, "type": "default-credentials", "severity": "high", "via": "brutus",
            "tool": "brutus", "host": host or attempt["host"], "port": port or attempt["port"],
            "protocol": attempt["protocol"], "product": attempt["product"],
            "username": h.get("username", attempt["username"]),
            "password": h.get("password", attempt["password"]), "confidence": attempt["confidence"],
            "source_urls": attempt["source_urls"], "rationale": attempt["rationale"],
            "banner": h.get("banner", ""),
            "evidence": f"default credentials accepted on {attempt['protocol']}"})
    return out


def _load(activity: Activity, app_id: str):
    ws = activity.app(app_id)
    if shutil.which(BRUTUS) is None:
        return ws, None, None
    return (ws, tools.read_jsonl(ws.canonical("credential_candidates.jsonl")),
            tools.read_jsonl(ws.canonical("services.jsonl")))


def creds_test_brutus(activity: Activity, app_id: str) -> None:
    """LOOP 3 (opt-in) — try curated default credentials on non-HTTP services and HTTP Basic-auth panels
    via Brutus (one invocation per pair × socket). Lockout-aware, best-effort → findings/creds_brutus.jsonl
    (0600)."""
    ws, candidates, services = _load(activity, app_id)
    if not candidates or not services:
        log.debug("  · skip creds_test_brutus [%s] (brutus/candidates/services absent)", app_id)
        return
    threshold = parse_lockout_threshold(tools.read_jsonl(ws.findings / "ad_enum.jsonl"))
    brutus_attempts, _forms, skips = plan_attempts(
        candidates, services, lockout_threshold=threshold, lockout_default=_lockout_default())
    flags = mode_flags()
    findings: list[dict] = []
    for i, a in enumerate(brutus_attempts):
        out = _run_brutus(
            [BRUTUS, "--target", f'{a["host"]}:{a["port"]}', "--protocol", a["protocol"],
             "-u", a["username"], "-p", a["password"], "--json", *flags],
            dest=ws.raw("brutus") / f'{a["protocol"]}-{i}.jsonl', label=f'creds-{a["protocol"]}')
        findings += _enrich_brutus(parse_brutus_jsonl(out), a, app_id)
    hits = len(findings)
    findings += [{"app_id": app_id, "skipped": True, **s} for s in skips if s.get("via") == "brutus"]
    tools.write_jsonl(ws.findings / "creds_brutus.jsonl", findings)
    _chmod_600(ws.findings / "creds_brutus.jsonl")
    log.info("  → creds_test_brutus [%s] — %d attempt(s) → %d hit(s)", app_id, len(brutus_attempts), hits)
```

- [ ] **Step 4: Run to verify it passes** → PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ptflow/pipelines/internal/creds.py tests/pipelines/test_internal_creds.py
git commit -m "feat(internal): brutus credential-testing stage (non-HTTP + HTTP Basic)"
```

---

## Task 7: `FormLoginProbe` — Playwright form login + success heuristic (`core/agents/form_login.py`)

**Files:**
- Create: `src/ptflow/core/agents/form_login.py`
- Test: `tests/core/test_form_login.py`

**Interfaces:**
- Produces: `PageState(url, has_password_field, cookie_names, body_text)` (frozen);
  `LoginOutcome(applicable, success, confidence, reason)` (frozen);
  `judge_login(before: PageState, after: PageState) -> LoginOutcome` (pure);
  `FormLoginProbe(timeout_ms=15000, settle_ms=1000)` with `.available: bool` and
  `.attempt(url, username, password) -> LoginOutcome`.

- [ ] **Step 1: Write the failing test (the pure judge + availability)**

Create `tests/core/test_form_login.py`:
```python
import importlib.util
from ptflow.core.agents.form_login import FormLoginProbe, LoginOutcome, PageState, judge_login


def _state(url, has_pw, cookies=(), body=""):
    return PageState(url=url, has_password_field=has_pw, cookie_names=tuple(cookies), body_text=body)


def test_judge_still_on_login_is_failure():
    before = _state("https://h/login", True)
    after = _state("https://h/login", True, body="please sign in")
    assert judge_login(before, after).success is False


def test_judge_error_marker_is_failure():
    before = _state("https://h/login", True)
    after = _state("https://h/dashboard", False, cookies=["session"], body="Invalid credentials")
    out = judge_login(before, after)
    assert out.success is False and out.reason == "error_marker"


def test_judge_redirect_plus_cookie_is_probable():
    before = _state("https://h/login", True)
    after = _state("https://h/dashboard", False, cookies=["session"], body="Welcome, admin — Logout")
    out = judge_login(before, after)
    assert out.success is True and out.confidence == "probable"


def test_judge_password_gone_only_is_lead():
    before = _state("https://h/login", True, cookies=["csrf"])
    after = _state("https://h/home", False, cookies=["csrf"], body="home")
    out = judge_login(before, after)
    assert out.success is True and out.confidence == "lead"


def test_probe_unavailable_without_playwright(monkeypatch):
    monkeypatch.setattr(importlib.util, "find_spec", lambda name: None)
    probe = FormLoginProbe()
    assert probe.available is False
    outcome = probe.attempt("http://10.0.0.5/", "admin", "admin")
    assert outcome.applicable is False and outcome.reason == "playwright_absent"
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/core/test_form_login.py -v`
Expected: FAIL (module missing).

- [ ] **Step 3: Implement the module**

Create `src/ptflow/core/agents/form_login.py`:
```python
"""Deterministic HTTP form-login probe (Playwright) for default-credential testing.

Reused by the internal pipeline's ``creds_test_forms`` stage. Provider-agnostic — no LLM / no Anthropic
key (unlike Brutus's ``--experimental-ai``). Success detection is a conservative heuristic, so findings
are lead-grade unless a strong signal (redirect + session cookie / dashboard marker) fires. Targets are
internal (private) by design, so the SSRF guard runs with ``allow_private=True``.
"""

from __future__ import annotations

import importlib
import importlib.util
from dataclasses import dataclass

from ptflow.core.agents.research import _validate_fetch_url
from ptflow.core.log import get_logger

log = get_logger()

_ERROR_MARKERS = ("invalid", "incorrect", "failed", "denied", "try again", "wrong",
                  "not authorized", "authentication error")
_DASHBOARD_MARKERS = ("logout", "sign out", "signout", "dashboard", "welcome")
_USERNAME_SELECTORS = ("input[type=email]", "input[name*=user i]", "input[name*=login i]",
                       "input[name*=email i]", "input[id*=user i]", "input[type=text]")
_SUBMIT_SELECTORS = ("button[type=submit]", "input[type=submit]", "button")


@dataclass(frozen=True)
class PageState:
    url: str
    has_password_field: bool
    cookie_names: tuple[str, ...]
    body_text: str


@dataclass(frozen=True)
class LoginOutcome:
    applicable: bool
    success: bool
    confidence: str
    reason: str


def _same_path(a: str, b: str) -> bool:
    return a.split("?", 1)[0].rstrip("/") == b.split("?", 1)[0].rstrip("/")


def judge_login(before: PageState, after: PageState) -> LoginOutcome:
    """Conservative success heuristic from the before/after page state. Pure."""
    body = after.body_text.casefold()
    if after.has_password_field and _same_path(before.url, after.url):
        return LoginOutcome(True, False, "", "still_on_login")
    if any(m in body for m in _ERROR_MARKERS):
        return LoginOutcome(True, False, "", "error_marker")
    new_cookie = bool(set(after.cookie_names) - set(before.cookie_names))
    url_changed = not _same_path(before.url, after.url)
    password_gone = not after.has_password_field
    if password_gone and url_changed and (new_cookie or any(m in body for m in _DASHBOARD_MARKERS)):
        return LoginOutcome(True, True, "probable", "redirect+session")
    if password_gone and (url_changed or new_cookie):
        return LoginOutcome(True, True, "lead", "password_gone")
    return LoginOutcome(True, False, "", "no_success_signal")


class FormLoginProbe:
    """Navigate a login panel, submit one credential pair, and judge success. Best-effort."""

    def __init__(self, *, timeout_ms: int = 15000, settle_ms: int = 1000) -> None:
        self.available = importlib.util.find_spec("playwright") is not None
        self._timeout_ms = timeout_ms
        self._settle_ms = settle_ms

    def _username_field(self, page):  # noqa: ANN001 - playwright Page
        for sel in _USERNAME_SELECTORS:
            if (el := page.query_selector(sel)) is not None:
                return el
        return None

    def _submit(self, page, password_el) -> None:  # noqa: ANN001
        for sel in _SUBMIT_SELECTORS:
            if (btn := page.query_selector(sel)) is not None:
                btn.click()
                return
        password_el.press("Enter")

    def attempt(self, url: str, username: str, password: str) -> LoginOutcome:
        if not self.available:
            return LoginOutcome(False, False, "", "playwright_absent")
        try:
            _validate_fetch_url(url, allow_private=True)
        except ValueError:
            return LoginOutcome(False, False, "", "invalid_url")
        try:
            return self._drive(url, username, password)
        except Exception as exc:  # noqa: BLE001 - best-effort; any browser error → no finding
            log.debug("  · form login on %s failed: %s", url, exc)
            return LoginOutcome(True, False, "", "browser_error")

    def _drive(self, url: str, username: str, password: str) -> LoginOutcome:
        api = importlib.import_module("playwright.sync_api")
        with api.sync_playwright() as runtime:
            browser = runtime.chromium.launch(headless=True)
            try:
                context = browser.new_context(ignore_https_errors=True)
                page = context.new_page()
                page.set_default_timeout(self._timeout_ms)
                page.goto(url, wait_until="domcontentloaded")
                password_el = page.query_selector("input[type=password]")
                if password_el is None:
                    return LoginOutcome(False, False, "", "no_form")
                before = PageState(page.url, True,
                                   tuple(c["name"] for c in context.cookies()), "")
                if (user_el := self._username_field(page)) is not None:
                    user_el.fill(username)
                password_el.fill(password)
                self._submit(page, password_el)
                try:
                    page.wait_for_load_state("networkidle", timeout=self._timeout_ms)
                except Exception:  # noqa: BLE001 - settle is best-effort
                    pass
                page.wait_for_timeout(self._settle_ms)
                after = PageState(page.url, page.query_selector("input[type=password]") is not None,
                                  tuple(c["name"] for c in context.cookies()), page.content())
                return judge_login(before, after)
            finally:
                browser.close()
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run pytest tests/core/test_form_login.py -v`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add src/ptflow/core/agents/form_login.py tests/core/test_form_login.py
git commit -m "feat(agents): deterministic HTTP form-login probe (Playwright)"
```

---

## Task 8: creds.py — the form stage (`creds_test_forms`) + `per_app_stages()`

**Files:** Modify `creds.py`; Test `tests/pipelines/test_internal_creds.py`.

**Interfaces:** `_enrich_form(outcome, url, host, port, pair, meta, app_id) -> dict`;
`creds_test_forms(activity, app_id) -> None`; `per_app_stages() -> tuple[Stage, ...]` (both phase-3 stages).

- [ ] **Step 1: Write the failing test**

Append to `tests/pipelines/test_internal_creds.py`:
```python
def test_creds_test_forms_writes_hit(tmp_path, monkeypatch):
    from ptflow.core.agents.form_login import LoginOutcome
    monkeypatch.setattr(creds.shutil, "which", lambda _b: "/fake/brutus")
    activity = Activity.named("f", root=tmp_path).ensure()
    ws = activity.app("10.0.0.0-24")
    ws.root.mkdir(parents=True, exist_ok=True)
    tools.write_jsonl(ws.canonical("services.jsonl"),
                      [{"ip": "10.0.0.5", "port": 8443, "product": "Acme Router", "service": "https"}])
    tools.write_jsonl(ws.canonical("credential_candidates.jsonl"),
                      [{"product": "Acme Router", "protocol": "https", "username": "admin",
                        "password": "acme", "confidence": 0.9, "source_urls": ["u"], "rationale": "r"}])

    class _Probe:
        available = True
        def attempt(self, url, user, pw):
            return LoginOutcome(True, True, "probable", "redirect+session")
    monkeypatch.setattr(creds, "FormLoginProbe", lambda **_k: _Probe())

    creds.creds_test_forms(activity, "10.0.0.0-24")
    findings = tools.read_jsonl(ws.findings / "creds_forms.jsonl")
    assert findings and findings[0]["via"] == "form" and findings[0]["confidence"] == "probable"
    assert findings[0]["host"] == "10.0.0.5" and findings[0]["port"] == 8443
    assert ((ws.findings / "creds_forms.jsonl").stat().st_mode & 0o777) == 0o600


def test_per_app_stages_are_phase_3():
    stages = creds.per_app_stages()
    assert {s.name for s in stages} == {"creds_test_brutus", "creds_test_forms"}
    assert all(s.phase == 3 and s.per_app for s in stages)
```

- [ ] **Step 2: Run to verify it fails** → FAIL.

- [ ] **Step 3: Implement (add `FormLoginProbe` import + the stage + factory)**

At the top of `creds.py`, extend the imports:
```python
from ptflow.core.agents.form_login import FormLoginProbe
```
Append to `creds.py`:
```python
def _enrich_form(outcome, url: str, host: str, port: int, pair, meta: dict, app_id: str) -> dict:
    return {"app_id": app_id, "type": "default-credentials", "severity": "high", "via": "form",
            "tool": "form-login", "host": host, "port": port, "protocol": "http",
            "url": url, "product": meta.get("product", ""), "username": pair[0], "password": pair[1],
            "confidence": outcome.confidence or meta.get("confidence"),
            "source_urls": meta.get("source_urls", []), "rationale": meta.get("rationale", ""),
            "evidence": f"default credentials accepted on web login form ({outcome.reason})"}


def creds_test_forms(activity: Activity, app_id: str) -> None:
    """LOOP 3 (opt-in) — try curated default credentials on HTTP FORM login panels via the Playwright
    FormLoginProbe (provider-agnostic, no Anthropic key). Best-effort → findings/creds_forms.jsonl (0600)."""
    ws = activity.app(app_id)
    candidates = tools.read_jsonl(ws.canonical("credential_candidates.jsonl"))
    services = tools.read_jsonl(ws.canonical("services.jsonl"))
    if not candidates or not services:
        log.debug("  · skip creds_test_forms [%s] (no candidates/services)", app_id)
        return
    probe = FormLoginProbe(settle_ms=2000 if resolve_mode() == "cautious" else 1000)
    if not probe.available:
        log.debug("  · skip creds_test_forms [%s] (playwright absent)", app_id)
        return
    threshold = parse_lockout_threshold(tools.read_jsonl(ws.findings / "ad_enum.jsonl"))
    _brutus, form_attempts, _skips = plan_attempts(
        candidates, services, lockout_threshold=threshold, lockout_default=_lockout_default())
    findings: list[dict] = []
    for job in group_forms(form_attempts):
        for pair in job["pairs"]:
            outcome = probe.attempt(job["url"], pair[0], pair[1])
            if outcome.success:
                findings.append(_enrich_form(outcome, job["url"], job["host"], job["port"], pair,
                                             job["by_pair"][pair], app_id))
    tools.write_jsonl(ws.findings / "creds_forms.jsonl", findings)
    _chmod_600(ws.findings / "creds_forms.jsonl")
    log.info("  → creds_test_forms [%s] — %d panel(s) → %d hit(s)",
             app_id, len(group_forms(form_attempts)), len(findings))


def per_app_stages() -> tuple[Stage, ...]:
    """The opt-in phase-3 credential-testing stages (spliced by pipeline.py only when enabled)."""
    return (
        Stage("creds_test_brutus", creds_test_brutus, per_app=True, phase=3, net=True),
        Stage("creds_test_forms", creds_test_forms, per_app=True, phase=3, net=True),
    )
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run pytest tests/pipelines/test_internal_creds.py -v`
Expected: PASS (all creds tests).

- [ ] **Step 5: Commit**

```bash
git add src/ptflow/pipelines/internal/creds.py tests/pipelines/test_internal_creds.py
git commit -m "feat(internal): form-login credential-testing stage + phase-3 factory"
```

---

## Task 9: Splice the stages into the pipeline behind the opt-in flag

**Files:** Modify `src/ptflow/pipelines/internal/pipeline.py`; Test `tests/pipelines/test_internal_tasks.py`.

**Interfaces:** `InternalPipeline.stages` includes `creds_test_brutus`/`creds_test_forms` iff
`PTFLOW_CREDS_TEST` is set at import.

- [ ] **Step 1: Write the failing test**

Add to `tests/pipelines/test_internal_tasks.py`:
```python
import importlib


def test_creds_stages_absent_by_default(monkeypatch):
    monkeypatch.delenv("PTFLOW_CREDS_TEST", raising=False)
    from ptflow.pipelines.internal import pipeline as pl
    pl = importlib.reload(pl)
    assert "creds_test_brutus" not in {s.name for s in pl.PIPELINE.stages}


def test_creds_stages_present_when_opt_in(monkeypatch):
    monkeypatch.setenv("PTFLOW_CREDS_TEST", "on")
    from ptflow.pipelines.internal import pipeline as pl
    pl = importlib.reload(pl)
    names = {s.name for s in pl.PIPELINE.stages}
    assert {"creds_test_brutus", "creds_test_forms"} <= names
    assert all(s.phase == 3 for s in pl.PIPELINE.stages if s.name.startswith("creds_test"))
    monkeypatch.delenv("PTFLOW_CREDS_TEST", raising=False)
    importlib.reload(pl)
```

- [ ] **Step 2: Run to verify it fails** → FAIL.

- [ ] **Step 3: Wire the gate**

In `pipeline.py`, extend the import (line 11) to `from ptflow.pipelines.internal import ai, creds, tasks`.
After `_AI_STAGES = ai.per_app_stages()` (~line 21):
```python
_CREDS = creds.creds_test_enabled()
_CREDS_STAGES = creds.per_app_stages()
```
In the `stages` tuple, after the `*(_AI_STAGES if _AI else ())` line:
```python
        # LOOP 3 — opt-in default-credential testing (PTFLOW_CREDS_TEST): try the research agent's
        # source-grounded candidates against the services they were proposed for (Brutus + form probe).
        *(_CREDS_STAGES if _CREDS else ()),
```

- [ ] **Step 4: Run to verify it passes** → PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ptflow/pipelines/internal/pipeline.py tests/pipelines/test_internal_tasks.py
git commit -m "feat(internal): splice opt-in credential-testing loop (phase 3)"
```

---

## Task 10: Flow-map metadata

**Files:** Modify `src/ptflow/pipelines/internal/flowmeta.py`; verify `tests/pipelines/test_flowmap.py`.

- [ ] **Step 1: Add the two StepMeta** after the `"ai_credential_research"` entry in `FLOWMETA`:
```python
    "creds_test_brutus": StepMeta(
        summary="[opt-in PTFLOW_CREDS_TEST] LOOP 3 — prova le credenziali default source-grounded "
                "dell'agente sui servizi non-HTTP e sui pannelli HTTP Basic-auth via Brutus. Solo il set "
                "curato (mai wordlist / mai --experimental-ai), una invocazione per coppia×socket, lockout-aware.",
        commands=("brutus --target <ip:port> --protocol <p> -u <u> -p <p> --json <mode-flags>",
                  "# match prodotto→socket · budget lockout (threshold-1/account su smb/ldap/rdp/winrm)"),
        outputs=("findings/creds_brutus.jsonl", "raw/brutus/*.jsonl"),
        notes=("net=True · best-effort (salta se brutus/candidati/servizi assenti) · findings 0600",
               "PTFLOW_CREDS_MODE→flag reali (cautious=-t 5 --rate-limit 2 …); TLS skip di default"),
    ),
    "creds_test_forms": StepMeta(
        summary="[opt-in PTFLOW_CREDS_TEST] LOOP 3 — prova le credenziali default sui pannelli HTTP "
                "FORM-based via un FormLoginProbe Playwright NOSTRO (deterministico, niente chiave "
                "Anthropic): naviga, compila, invia e giudica il successo per euristica (lead/probable).",
        commands=("FormLoginProbe.attempt(url, user, pass) → judge_login(before, after)",
                  "# routing socket→web via web_targets_from · allow_private (target interni)"),
        outputs=("findings/creds_forms.jsonl",),
        notes=("net=True · best-effort (salta se playwright/chromium assente o nessun form) · findings 0600",
               "consolidate folda creds_brutus + creds_forms → findings/creds.jsonl (0600)"),
    ),
```

- [ ] **Step 2: Add the phase-3 label** in `SPEC.phase_labels`:
```python
    phase_labels={1: "inventario servizi", 2: "frutti bassi", 3: "test credenziali default"},
```

- [ ] **Step 3: Regenerate + gate**

Run:
```bash
uv run python -m ptflow.core.flowdocs
PTFLOW_CREDS_TEST=on uv run pytest tests/pipelines/test_flowmap.py -v
uv run pytest tests/pipelines/test_flowmap.py -v
```
Expected: PASS both.

- [ ] **Step 4: Commit**

```bash
git add src/ptflow/pipelines/internal/flowmeta.py docs/internal-pipeline-*
git commit -m "docs(internal): flow-map metadata for credential-testing stages"
```

---

## Task 11: Docs + full dev gate

**Files:** Modify `CLAUDE.md`, `ptflow.toml.example`; full gate.

- [ ] **Step 1: CLAUDE.md** — add under the `internal` pipeline a Loop-3 bullet:
```markdown
  - **Loop 3 — default-credential testing** (`phase=3`, **OPT-IN `PTFLOW_CREDS_TEST`**, default OFF):
    `creds_test_brutus` (Brutus: non-HTTP + HTTP **Basic** auth) ∥ `creds_test_forms` (our Playwright
    `FormLoginProbe`: HTTP **form** login, provider-agnostic, no Anthropic key). Both try the `research`
    agent's source-grounded candidates (`credential_candidates.jsonl`) against the services they were
    proposed for — **curated pairs only**, never wordlists / never Brutus `--experimental-ai`. Matching is
    per-product→socket; HTTP vs non-HTTP routing reuses `web_targets_from`; lockout-aware (never
    > `threshold-1` attempts/account on SMB/LDAP/RDP/WinRM, from `ad_enum`'s `parse_nxc_pass_pol`; unknown
    ⇒ `PTFLOW_CREDS_LOCKOUT_DEFAULT`, default 3). `PTFLOW_CREDS_MODE` (cautious|default|aggressive, default
    cautious) → Brutus flags + probe settle. Best-effort → `findings/creds_{brutus,forms}.jsonl` (`0600`);
    `consolidate` folds both → `findings/creds.jsonl` (`0600`; password redacted in reports). Form success
    detection is heuristic (lead-grade); an LLM-assisted variant on our provider-agnostic seam is a follow-up.
```
Also add under the tools/gotchas:
```markdown
- **Default-credential testing (opt-in)** uses **Brutus** (`~/go/bin/brutus`, `PTFLOW_BRUTUS`; flat CLI —
  no subcommands) for non-HTTP + HTTP Basic, and our **Playwright `FormLoginProbe`** for HTTP forms. Brutus
  is fed only the agent's validated pairs; its own AI/defaults are never used. Forms need Playwright/Chromium
  (already present). Opt-in `PTFLOW_CREDS_TEST`; `PTFLOW_CREDS_MODE` is the RoE noise/lockout lever.
```

- [ ] **Step 2: ptflow.toml.example** — add a comment block:
```toml
# --- internal default-credential testing (opt-in, env-only in v1) ----------------
# PTFLOW_CREDS_TEST=on            # enable phase-3 credential testing (default OFF)
# PTFLOW_CREDS_MODE=cautious      # cautious|default|aggressive (brutus flags + probe settle)
# PTFLOW_CREDS_LOCKOUT_DEFAULT=3  # max attempts/account when the lockout policy is unknown
# PTFLOW_BRUTUS=/path/to/brutus   # override the brutus binary
```

- [ ] **Step 3: Full dev gate**

Run:
```bash
uv run ruff check .
uv run ty check src/
uv run pytest
```
Expected: all clean/PASS. Fix any ruff finding in `creds.py`/`form_login.py` by factoring or a targeted
`# noqa` consistent with the file's neighbours — never a blanket ignore. Likely candidates: `PLR0913`
(argument count on `_enrich_form` — pass a small dict if it trips), `BLE001` (already annotated on the
best-effort browser catch).

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md ptflow.toml.example
git commit -m "docs: document opt-in internal credential testing (Brutus + form probe)"
```

---

## Self-Review

**Spec coverage** (against `2026-07-19-default-credential-testing-design.md`, rev b):
- §3a Brutus flat CLI + mode-flag bundle → Task 2 (`mode_flags`), Task 6 (invocation). ✅
- §3b `FormLoginProbe` (Playwright, allow_private, heuristic, lead-grade) → Task 7. ✅
- §4 two phase-3 stages, absent-when-off → Task 8 (`per_app_stages`), Task 9 (gate). ✅
- §5 gating + lockout rule + curated-only + no Brutus AI → Task 2/3, Task 6/8 (no `--experimental-ai`). ✅
- §6 matching/routing/protocol-map/planner → Task 2, Task 5. ✅
- §7 invocation + form heuristic + record shape → Task 6, Task 7, Task 8. ✅
- §8 consolidate fold (creds_brutus + creds_forms) + 0600 + redact → Task 1, Task 4, Tasks 6/8. ✅
- §9 requirements/doctor + flow map + knobs → Task 1, Task 10, Task 11. ✅
- §10 testing → tests in every task; pure `judge_login` fully covered. ✅

**Placeholder scan:** none — every code step shows complete code; every test has real assertions.

**Type consistency:** stage fns `(activity: Activity, app_id: str) -> None`; `plan_attempts(...,
lockout_threshold, lockout_default)` kw names match callers in Tasks 6/8; `plan_attempts` returns
`(brutus_attempts, form_attempts, skips)` consumed as such; `group_forms` job keys (`url/host/port/pairs/
by_pair`) produced in Task 5, consumed in Task 8; `judge_login(before, after) -> LoginOutcome` and
`FormLoginProbe.attempt -> LoginOutcome` consistent; `_split_target -> (host, int)` used by `_enrich_brutus`.

**Sequencing:** Tasks 1-6 + 9-11 (minus form specifics) = **Part A** (Brutus, mergeable alone if Task 8's
form stage is temporarily a no-op); Tasks 7-8 = **Part B** (form probe). Execute in order; Part A is usable
after Task 9 even before Part B is polished.
