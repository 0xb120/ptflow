# Default-Credential Testing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add opt-in phase-3 stages to the `internal` pipeline that test the research agent's
source-grounded default-credential proposals against the services they were proposed for — non-HTTP via
`brutus creds`, HTTP login panels via `brutus web`.

**Architecture:** One new deterministic module `pipelines/internal/creds.py` holds pure planners
(candidate→socket matching, HTTP/non-HTTP routing, protocol mapping, lockout budgeting, Brutus JSONL
parsing) plus two per-app phase-3 stages that invoke Brutus and write findings. `pipeline.py` splices the
stages in only when `PTFLOW_CREDS_TEST` is set (absent otherwise, mirroring the AI stages). `tasks.py`
gains the `brutus` tool constant, its `doctor` requirement, and the `consolidate` fold. Brutus is fed
**only** our validated pairs — never its embedded defaults or `--experimental-ai`.

**Tech Stack:** Python 3, Prefect ≥3 (via ptflow's orchestrator), Brutus (`~/go/bin/brutus`, Go binary),
pytest, ruff (`select=ALL`), ty.

## Global Constraints

- Engine is **Brutus for both** HTTP and non-HTTP. Never invoke Brutus `--experimental-ai`; never use its
  embedded default wordlists. Feed only the agent's curated pairs.
- **Opt-in**: `PTFLOW_CREDS_TEST` ∈ `{1,on,true,yes}`, default OFF ⇒ stages absent from the DAG.
- **Mode**: `PTFLOW_CREDS_MODE` ∈ `{cautious,default,aggressive}`, default `cautious` → Brutus `--mode`.
- **Lockout invariant**: never more than `threshold-1` attempts against a single account on SMB/LDAP/RDP/
  WinRM; `threshold<=1` ⇒ skip that protocol; unknown policy ⇒ `PTFLOW_CREDS_LOCKOUT_DEFAULT` (default 3).
- **Files-as-only-state**: read/write only via `Activity`/`AppWorkspace`; no path literals. Each tool
  output written once; Brutus scratch → `ws.raw("brutus")`. Findings → `ws.findings`.
- **Secret handling**: `credential_candidates.jsonl` and `findings/creds_*.jsonl` and the consolidated
  `findings/creds.jsonl` are `chmod 0600`. Passwords are plaintext only in those files; `redact()` masks
  them for any rendered report. Never log a password.
- **Best-effort**: a missing `brutus` binary, non-zero exit, or timeout degrades to an empty result and
  logs at debug — never aborts the stage/run. No per-tool timeout babysitting beyond `BRUTUS_TIMEOUT`.
- **Imports** (verbatim origins): `from ptflow.core.log import get_logger, is_verbose`;
  `AbortedError` is `ptflow.core.tools.AbortedError`; `Stage` is `ptflow.core.stage.Stage`.
- Run the full gate before finishing: `uv run ruff check . && uv run ty check src/ && uv run pytest`.

---

## Task 0: Verify the installed Brutus CLI surface

Brutus versions vary; confirm the flag names this host's binary actually accepts before coding
invocations. This is investigation only — no code, no commit.

- [ ] **Step 1: Inspect the two subcommands**

Run:
```bash
~/go/bin/brutus --version || true
~/go/bin/brutus creds --help 2>&1 | head -60
~/go/bin/brutus web --help 2>&1 | head -60
```
Expected: confirm these flags exist (adjust the invocation constants in Task 6 if a name differs):
`--protocol`, `--targets-file`, `-u`, `-p`, `--mode`, `--json` for `creds`; `--targets-file`, `-c`,
`--mode`, `--json` for `web`. Note the exact success-record JSON keys (`target`, `username`, `password`,
`banner`, and for web possibly `llm_suggested`).

- [ ] **Step 2: Record any deviations**

If a flag name differs from the plan (e.g. `-t/--targets-file`), write the actual name here in the plan
file next to Task 6's command and use it there. Do not commit.

---

## Task 1: Wire the `brutus` tool, requirement, and consolidate fold (`tasks.py`)

**Files:**
- Modify: `src/ptflow/pipelines/internal/tasks.py` (tool constant ~line 110; `_OPTIONAL_TOOLS` ~line 112;
  `_CONSOLIDATE_SOURCES` ~line 1484; `consolidate` body ~line 1532)
- Test: `tests/pipelines/test_internal_tasks.py`

**Interfaces:**
- Produces: module constant `BRUTUS: str`; `_OPTIONAL_TOOLS["brutus"]`; `_CONSOLIDATE_SOURCES["creds.jsonl"]
  = ("findings/creds_net.jsonl", "findings/creds_web.jsonl")`; `consolidate` chmods `findings/creds.jsonl`
  to `0o600`.

- [ ] **Step 1: Write the failing test**

Add to `tests/pipelines/test_internal_tasks.py`:
```python
def test_requirements_include_brutus_as_optional():
    from ptflow.pipelines.internal import tasks
    reqs = tasks.requirements()
    brutus = [r for r in reqs if r.name == "brutus"]
    assert brutus and brutus[0].kind == "optional"


def test_consolidate_folds_and_locks_down_creds(tmp_path):
    from ptflow.core.paths import Activity
    from ptflow.core import tools
    from ptflow.pipelines.internal import tasks
    activity = Activity.named("a", root=tmp_path).ensure()
    ws = activity.app("10.0.0.0-24")
    ws.root.mkdir(parents=True, exist_ok=True)
    (ws.root / "meta.json").write_text("{}")
    tools.write_jsonl(ws.findings / "creds_net.jsonl",
                      [{"type": "default-credentials", "host": "10.0.0.5", "password": "s3cr3t"}])
    tools.write_jsonl(ws.findings / "creds_web.jsonl",
                      [{"type": "default-credentials", "host": "10.0.0.6", "password": "admin"}])
    tasks.consolidate(activity)
    out = activity.findings / "creds.jsonl"
    records = tools.read_jsonl(out)
    assert {r["host"] for r in records} == {"10.0.0.5", "10.0.0.6"}
    assert all(r["app_id"] == "10.0.0.0-24" for r in records)
    assert (out.stat().st_mode & 0o777) == 0o600
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/pipelines/test_internal_tasks.py::test_requirements_include_brutus_as_optional tests/pipelines/test_internal_tasks.py::test_consolidate_folds_and_locks_down_creds -v`
Expected: FAIL (`brutus` not in requirements; `creds.jsonl` not written).

- [ ] **Step 3: Add the tool constant and optional-tool entry**

In `tasks.py`, after the `SNMPWALK`/`DIG` resolves (~line 109), add:
```python
BRUTUS = _resolve("PTFLOW_BRUTUS", f"{_HOME}/go/bin/brutus", "brutus")  # default-cred tester (opt-in)
```
Then extend `_OPTIONAL_TOOLS` (~line 112) with the new entry:
```python
_OPTIONAL_TOOLS = {"nuclei": NUCLEI, "netexec": NXC, "search_vulns": SEARCH_VULNS,
                   "onesixtyone": ONESIXTYONE, "ldapsearch": LDAPSEARCH,
                   "scrying": SCRYING, "rsync": RSYNC, "showmount": SHOWMOUNT, "snmpwalk": SNMPWALK,
                   "dig": DIG, "brutus": BRUTUS}
```

- [ ] **Step 4: Add the consolidate fold + 0600 lockdown**

In `_CONSOLIDATE_SOURCES` (~line 1484) add the entry (place it last):
```python
    "remote_desktop.jsonl": ("findings/remote_desktop.jsonl",),
    "creds.jsonl": ("findings/creds_net.jsonl", "findings/creds_web.jsonl"),
}
```
In `consolidate` (~line 1532), inside the `if records:` block, after the `tools.write_jsonl(...)` call,
add the lockdown so the aggregated secret file is not world-readable:
```python
        if records:                            # never delete on empty — see docstring (--resume safety)
            counts[out_name.removesuffix(".jsonl")] = tools.write_jsonl(
                activity.findings / out_name, records)
            if out_name == "creds.jsonl":
                (activity.findings / out_name).chmod(0o600)
```

- [ ] **Step 5: Run to verify it passes**

Run: `uv run pytest tests/pipelines/test_internal_tasks.py::test_requirements_include_brutus_as_optional tests/pipelines/test_internal_tasks.py::test_consolidate_folds_and_locks_down_creds -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/ptflow/pipelines/internal/tasks.py tests/pipelines/test_internal_tasks.py
git commit -m "feat(internal): register brutus tool + consolidate creds findings"
```

---

## Task 2: creds.py — constants, service sockets, product match, routing (`creds.py`)

**Files:**
- Create: `src/ptflow/pipelines/internal/creds.py`
- Test: `tests/pipelines/test_internal_creds.py`

**Interfaces:**
- Produces: `creds_test_enabled() -> bool`; `resolve_mode() -> str`; `_lockout_default() -> int`;
  `ServiceSocket` (frozen dataclass: `host:str, port:int, product:str, service:str, banner:str`);
  `service_sockets(services: list[dict]) -> list[ServiceSocket]`;
  `_product_matches(candidate_product: str, socket_product: str) -> bool`;
  `socket_proto(sock: ServiceSocket) -> str | None`;
  `web_urls(services: list[dict]) -> dict[tuple[str, int], str]`;
  module constants `_BRUTUS_PROTO`, `_PORT_PROTO`, `_LOCKOUT_PROTOCOLS`, `DEFAULT_MODE`, `DEFAULT_LOCKOUT`,
  `BRUTUS_TIMEOUT`, `CREDS_TEST_ENV`, `CREDS_MODE_ENV`, `LOCKOUT_DEFAULT_ENV`.

- [ ] **Step 1: Write the failing test**

Create `tests/pipelines/test_internal_creds.py`:
```python
from ptflow.pipelines.internal import creds


def test_service_sockets_extracts_product_from_field_or_banner():
    services = [
        {"ip": "10.0.0.5", "port": 22, "service": "ssh",
         "metadata": {"banner": "SSH-2.0-OpenSSH_8.9p1"}},
        {"ip": "10.0.0.5", "port": 8443, "product": "Acme Router", "service": "https"},
        {"host": "10.0.0.6", "port": None},  # dropped (bad port)
    ]
    socks = creds.service_sockets(services)
    assert len(socks) == 2
    ssh = next(s for s in socks if s.port == 22)
    assert ssh.product == "OpenSSH" and ssh.service == "ssh"
    assert next(s for s in socks if s.port == 8443).product == "Acme Router"


def test_product_match_is_bidirectional_and_casefold():
    assert creds._product_matches("Acme Router", "acme router firmware")
    assert creds._product_matches("OpenSSH 8.9", "openssh")
    assert not creds._product_matches("Acme", "")
    assert not creds._product_matches("", "OpenSSH")


def test_socket_proto_prefers_service_then_port():
    assert creds.socket_proto(creds.ServiceSocket("h", 3389, "", "ms-wbt-server", "")) == "rdp"
    assert creds.socket_proto(creds.ServiceSocket("h", 5432, "", "", "")) == "postgres"
    assert creds.socket_proto(creds.ServiceSocket("h", 12345, "", "weird", "")) is None


def test_web_urls_uses_web_targets_rule():
    services = [
        {"ip": "10.0.0.5", "port": 8443, "service": "https"},
        {"ip": "10.0.0.5", "port": 22, "service": "ssh"},
    ]
    urls = creds.web_urls(services)
    assert urls[("10.0.0.5", 8443)] == "https://10.0.0.5:8443"
    assert ("10.0.0.5", 22) not in urls


def test_resolve_mode_defaults_to_cautious(monkeypatch):
    monkeypatch.delenv("PTFLOW_CREDS_MODE", raising=False)
    assert creds.resolve_mode() == "cautious"
    monkeypatch.setenv("PTFLOW_CREDS_MODE", "aggressive")
    assert creds.resolve_mode() == "aggressive"
    monkeypatch.setenv("PTFLOW_CREDS_MODE", "bogus")
    assert creds.resolve_mode() == "cautious"
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/pipelines/test_internal_creds.py -v`
Expected: FAIL (`No module named 'ptflow.pipelines.internal.creds'`).

- [ ] **Step 3: Create the module with constants + these helpers**

Create `src/ptflow/pipelines/internal/creds.py`:
```python
"""Opt-in default-credential testing for the internal pipeline (Brutus executor).

Phase-3 per-subnet stages that try the research agent's source-grounded default-credential candidates
(``credential_candidates.jsonl``) against the concrete services they were proposed for. Non-HTTP via
``brutus creds``; HTTP login panels via ``brutus web``. Curated pairs only — never Brutus's embedded
defaults or ``--experimental-ai``. Opt-in (``PTFLOW_CREDS_TEST``), best-effort, lockout-aware.
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

# --- gating knobs --------------------------------------------------------------------------------
CREDS_TEST_ENV = "PTFLOW_CREDS_TEST"
CREDS_MODE_ENV = "PTFLOW_CREDS_MODE"
LOCKOUT_DEFAULT_ENV = "PTFLOW_CREDS_LOCKOUT_DEFAULT"
_TRUTHY = frozenset({"1", "on", "true", "yes"})
_MODES = frozenset({"cautious", "default", "aggressive"})
DEFAULT_MODE = "cautious"
DEFAULT_LOCKOUT = 3
BRUTUS_TIMEOUT = 600  # per-invocation wall-clock cap (web form-mode drives headless chrome)

# protocols whose failed logins can lock a DOMAIN account → gated on the enumerated pass-pol
_LOCKOUT_PROTOCOLS = frozenset({"smb", "ldap", "rdp", "winrm"})

# candidate/nerva service name → brutus `--protocol`
_BRUTUS_PROTO = {
    "ssh": "ssh", "ftp": "ftp", "telnet": "telnet", "vnc": "vnc",
    "rdp": "rdp", "ms-wbt-server": "rdp",
    "snmp": "snmp",
    "smb": "smb", "microsoft-ds": "smb", "netbios-ssn": "smb", "cifs": "smb",
    "ldap": "ldap", "ldaps": "ldap",
    "winrm": "winrm", "wsman": "winrm",
    "mysql": "mysql", "mariadb": "mysql",
    "postgresql": "postgres", "postgres": "postgres",
    "mssql": "mssql", "ms-sql-s": "mssql",
    "mongodb": "mongodb", "mongod": "mongodb", "mongo": "mongodb",
    "redis": "redis", "oracle": "oracle", "oracle-tns": "oracle",
}
# well-known port → brutus `--protocol` (nerva service names vary; the port is the reliable signal)
_PORT_PROTO: dict[int, str] = {
    22: "ssh", 21: "ftp", 23: "telnet", 3389: "rdp", 161: "snmp",
    445: "smb", 139: "smb", 389: "ldap", 636: "ldap", 3306: "mysql",
    5432: "postgres", 1433: "mssql", 6379: "redis", 27017: "mongodb",
    27018: "mongodb", 1521: "oracle", 5985: "winrm", 5986: "winrm",
    **{p: "vnc" for p in range(5900, 5907)},
}


def creds_test_enabled() -> bool:
    """True when the opt-in default-credential testing flag is set."""
    return os.getenv(CREDS_TEST_ENV, "").strip().lower() in _TRUTHY


def resolve_mode() -> str:
    """The Brutus ``--mode`` preset; unknown/blank falls back to the conservative default."""
    mode = os.getenv(CREDS_MODE_ENV, "").strip().lower()
    return mode if mode in _MODES else DEFAULT_MODE


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
    """Flatten ``services.jsonl`` into per-socket identities; product from the explicit field else the
    banner (``_banner_product``). Records missing host or an int port are dropped. Pure."""
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
    """Bidirectional casefold substring — the ``_product_is_observed`` rule the agent used to observe."""
    a, b = candidate_product.casefold().strip(), socket_product.casefold().strip()
    return bool(a) and bool(b) and (a in b or b in a)


def socket_proto(sock: ServiceSocket) -> str | None:
    """Brutus ``--protocol`` for a NON-web socket: nerva service name first, then well-known port. None
    if unmapped (precision-first — never guessed)."""
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
git commit -m "feat(internal): creds matching primitives (sockets, product match, routing)"
```

---

## Task 3: creds.py — lockout parsing and per-account budget

**Files:**
- Modify: `src/ptflow/pipelines/internal/creds.py`
- Test: `tests/pipelines/test_internal_creds.py`

**Interfaces:**
- Consumes: `_LOCKOUT_PROTOCOLS`.
- Produces: `parse_lockout_threshold(records: list[dict]) -> int | None` (None = no policy record; 0 =
  disabled/unlimited); `account_budget(threshold: int | None, default: int) -> int | None` (None =
  unlimited attempts; 0 = must skip; N = max attempts per account);
  `_apply_lockout(net_attempts: list[dict], threshold: int | None, default: int) -> tuple[list[dict], list[dict]]`
  returning `(kept, skips)`.

- [ ] **Step 1: Write the failing test**

Append to `tests/pipelines/test_internal_creds.py`:
```python
def test_parse_lockout_threshold_reads_ad_password_policy():
    assert creds.parse_lockout_threshold(
        [{"type": "ad-password-policy", "lockout_threshold": "5"}]) == 5
    assert creds.parse_lockout_threshold(
        [{"type": "ad-password-policy", "lockout_threshold": "None"}]) == 0
    assert creds.parse_lockout_threshold([{"type": "ad-users-enumerated"}]) is None
    assert creds.parse_lockout_threshold([]) is None


def test_account_budget_semantics():
    assert creds.account_budget(None, 3) == 2      # unknown → default cap 2 attempts
    assert creds.account_budget(0, 3) is None      # disabled → unlimited
    assert creds.account_budget(1, 3) == 0         # one failure locks → skip
    assert creds.account_budget(5, 3) == 4


def test_apply_lockout_caps_per_account_and_skips():
    attempts = [
        {"product": "DC", "protocol": "smb", "host": "10.0.0.1", "port": 445,
         "username": "admin", "password": "p1", "confidence": 0.9},
        {"product": "DC", "protocol": "smb", "host": "10.0.0.1", "port": 445,
         "username": "admin", "password": "p2", "confidence": 0.5},
        {"product": "DC", "protocol": "smb", "host": "10.0.0.1", "port": 445,
         "username": "admin", "password": "p3", "confidence": 0.1},
        {"product": "SW", "protocol": "ssh", "host": "10.0.0.2", "port": 22,
         "username": "root", "password": "x", "confidence": 0.9},
    ]
    kept, skips = creds._apply_lockout(attempts, threshold=2, default=3)
    smb_kept = [a for a in kept if a["protocol"] == "smb"]
    assert [a["password"] for a in smb_kept] == ["p1"]       # cap = threshold-1 = 1, highest confidence
    assert {a["password"] for a in kept if a["protocol"] == "ssh"} == {"x"}  # ssh not gated
    assert any(s["reason"] == "lockout_budget" for s in skips)

    kept2, skips2 = creds._apply_lockout(attempts, threshold=1, default=3)
    assert not [a for a in kept2 if a["protocol"] == "smb"]   # threshold 1 → skip all smb
    assert all(s["reason"] == "lockout_policy" for s in skips2 if s["protocol"] == "smb")
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/pipelines/test_internal_creds.py -k "lockout or budget" -v`
Expected: FAIL (`AttributeError: ... has no attribute 'parse_lockout_threshold'`).

- [ ] **Step 3: Implement the three functions**

Append to `creds.py`:
```python
def parse_lockout_threshold(records: list[dict]) -> int | None:
    """The account-lockout threshold from ``findings/ad_enum.jsonl``'s ``ad-password-policy`` record.
    Returns None when no policy was enumerated (unknown → caller uses the default), 0 for None/Disabled
    (unlimited), else the integer. Pure."""
    for r in records:
        if r.get("type") == "ad-password-policy":
            raw = str(r.get("lockout_threshold", "")).strip().lower()
            digits = "".join(ch for ch in raw if ch.isdigit())
            if not digits or raw in ("none", "disabled"):
                return 0
            return int(digits)
    return None


def account_budget(threshold: int | None, default: int) -> int | None:
    """Max login attempts allowed per single account: None = unlimited (no/disabled policy); 0 = must
    skip (one failure locks); N = cap. Unknown threshold uses ``default``."""
    t = default if threshold is None else threshold
    return None if t <= 0 else t - 1


def _apply_lockout(
    net_attempts: list[dict], threshold: int | None, default: int,
) -> tuple[list[dict], list[dict]]:
    """Cap attempts on domain-lockout protocols to ``account_budget`` per (host, protocol, username),
    keeping highest-confidence first. Non-lockout protocols pass through untouched. Returns (kept, skips)."""
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
        allowed, dropped = ordered[:budget], ordered[budget:]
        kept += allowed
        reason = "lockout_policy" if budget == 0 else "lockout_budget"
        skips += [{"product": a["product"], "reason": reason, "via": "net",
                   "host": host, "port": a["port"], "protocol": proto, "username": user}
                  for a in dropped]
    return kept, skips
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run pytest tests/pipelines/test_internal_creds.py -k "lockout or budget" -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ptflow/pipelines/internal/creds.py tests/pipelines/test_internal_creds.py
git commit -m "feat(internal): lockout-aware per-account credential budget"
```

---

## Task 4: creds.py — Brutus JSONL parsing and redaction

**Files:**
- Modify: `src/ptflow/pipelines/internal/creds.py`
- Test: `tests/pipelines/test_internal_creds.py`

**Interfaces:**
- Produces: `parse_brutus_jsonl(text: str) -> list[dict]` (keeps dict lines with a `username`, skips
  unparseable lines); `redact(record: dict) -> dict` (masks a non-empty `password` to `"****"`);
  `_split_target(target: str) -> tuple[str, int]` (`"h:22"`/`"http://h:80"` → `("h", 22/80)`, `("h", 0)`
  when no numeric port).

- [ ] **Step 1: Write the failing test**

Append to `tests/pipelines/test_internal_creds.py`:
```python
def test_parse_brutus_jsonl_keeps_hits_skips_noise():
    text = (
        'progress: scanning...\n'
        '{"protocol":"ssh","target":"10.0.0.5:22","username":"root","password":"toor",'
        '"banner":"SSH-2.0-OpenSSH_8.9p1"}\n'
        '{"not":"a hit"}\n'
        '\n'
    )
    hits = creds.parse_brutus_jsonl(text)
    assert len(hits) == 1 and hits[0]["username"] == "root"


def test_redact_masks_password():
    assert creds.redact({"username": "admin", "password": "s3cr3t"})["password"] == "****"
    assert creds.redact({"username": "admin", "password": ""})["password"] == ""


def test_split_target():
    assert creds._split_target("10.0.0.5:22") == ("10.0.0.5", 22)
    assert creds._split_target("https://10.0.0.5:8443") == ("10.0.0.5", 8443)
    assert creds._split_target("10.0.0.5") == ("10.0.0.5", 0)
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/pipelines/test_internal_creds.py -k "brutus_jsonl or redact or split" -v`
Expected: FAIL.

- [ ] **Step 3: Implement**

Append to `creds.py`:
```python
def parse_brutus_jsonl(text: str) -> list[dict]:
    """Brutus ``--json`` stdout → success records. Only lines that parse to a dict with a ``username``
    are kept (Brutus emits one object per successful credential); noise/progress lines are skipped. Pure."""
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
    """A shallow copy with a non-empty ``password`` masked, for any rendered report. Pure."""
    out = dict(record)
    if out.get("password"):
        out["password"] = "****"
    return out


def _split_target(target: str) -> tuple[str, int]:
    host, _, port = target.split("://", 1)[-1].rpartition(":")
    return (host, int(port)) if host and port.isdigit() else (target.split("://", 1)[-1], 0)
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run pytest tests/pipelines/test_internal_creds.py -k "brutus_jsonl or redact or split" -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ptflow/pipelines/internal/creds.py tests/pipelines/test_internal_creds.py
git commit -m "feat(internal): brutus JSONL parsing + password redaction"
```

---

## Task 5: creds.py — the planner (`plan_attempts`) and job grouping

**Files:**
- Modify: `src/ptflow/pipelines/internal/creds.py`
- Test: `tests/pipelines/test_internal_creds.py`

**Interfaces:**
- Consumes: `service_sockets`, `_product_matches`, `socket_proto`, `web_urls`, `_apply_lockout`.
- Produces:
  `plan_attempts(candidates, services, *, lockout_threshold, lockout_default) -> tuple[list[dict], list[dict], list[dict]]`
  returning `(net_attempts, web_attempts, skips)`. A net attempt is `{product, protocol, host, port,
  username, password, confidence, source_urls, rationale}`; a web attempt is the same with `url` instead
  of `protocol`; a skip is `{product, reason, via, host?, port?, protocol?, username?}`.
  `group_net(net_attempts) -> list[dict]` → jobs `{product, protocol, username, password, confidence,
  source_urls, rationale, targets: tuple[str, ...]}` ("ip:port" targets).
  `group_web(web_attempts) -> list[dict]` → jobs `{product, urls: tuple[str, ...], pairs: list[tuple[str,
  str]], by_pair: dict[tuple[str, str], dict]}`.

- [ ] **Step 1: Write the failing test**

Append to `tests/pipelines/test_internal_creds.py`:
```python
def _cand(product, protocol, user, pw, conf=0.9):
    return {"product": product, "protocol": protocol, "username": user, "password": pw,
            "confidence": conf, "source_urls": ["https://vendor/manual"], "rationale": "manual"}


def test_plan_routes_web_and_net_and_reports_no_match():
    services = [
        {"ip": "10.0.0.5", "port": 8443, "product": "Acme Router", "service": "https"},
        {"ip": "10.0.0.5", "port": 22, "product": "Acme Router", "service": "ssh"},
    ]
    candidates = [_cand("Acme Router", "https", "admin", "acme"),
                  _cand("Ghost Device", "ssh", "root", "x")]
    net, web, skips = creds.plan_attempts(
        candidates, services, lockout_threshold=None, lockout_default=3)
    assert {a["url"] for a in web} == {"https://10.0.0.5:8443"}
    assert {(a["protocol"], a["port"]) for a in net} == {("ssh", 22)}
    assert any(s["reason"] == "no_match" and s["product"] == "Ghost Device" for s in skips)


def test_group_net_and_web_shapes():
    net = [{"product": "P", "protocol": "ssh", "host": "10.0.0.5", "port": 22,
            "username": "root", "password": "x", "confidence": 0.9,
            "source_urls": ["u"], "rationale": "r"}]
    (job,) = creds.group_net(net)
    assert job["targets"] == ("10.0.0.5:22",) and job["protocol"] == "ssh"

    web = [{"product": "P", "url": "https://10.0.0.5:8443", "host": "10.0.0.5", "port": 8443,
            "username": "admin", "password": "a", "confidence": 0.9,
            "source_urls": ["u"], "rationale": "r"}]
    (wjob,) = creds.group_web(web)
    assert wjob["urls"] == ("https://10.0.0.5:8443",)
    assert wjob["pairs"] == [("admin", "a")]
    assert wjob["by_pair"][("admin", "a")]["product"] == "P"
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/pipelines/test_internal_creds.py -k "plan_routes or group_net" -v`
Expected: FAIL.

- [ ] **Step 3: Implement the planner + grouping**

Append to `creds.py`:
```python
def _place_candidate(
    candidate: dict, sockets: list[ServiceSocket], web_map: dict[tuple[str, int], str],
) -> tuple[list[dict], list[dict], list[dict]]:
    """Route one candidate's pair onto every matching socket: web sockets → a web attempt, mapped
    non-web sockets → a net attempt, unmapped → a skip. No match at all → a single no_match skip."""
    product = str(candidate.get("product") or "")
    base = {
        "product": product,
        "username": str(candidate.get("username") or ""),
        "password": str(candidate.get("password") or ""),
        "confidence": candidate.get("confidence"),
        "source_urls": list(candidate.get("source_urls") or []),
        "rationale": str(candidate.get("rationale") or ""),
    }
    matched = [s for s in sockets if _product_matches(product, s.product)]
    if not matched:
        return [], [], [{"product": product, "reason": "no_match", "via": "net"}]
    net, web, skips = [], [], []
    for s in matched:
        if (url := web_map.get((s.host, s.port))):
            web.append({**base, "url": url, "host": s.host, "port": s.port})
        elif (proto := socket_proto(s)):
            net.append({**base, "protocol": proto, "host": s.host, "port": s.port})
        else:
            skips.append({"product": product, "reason": "unmapped_protocol", "via": "net",
                          "host": s.host, "port": s.port})
    return net, web, skips


def plan_attempts(
    candidates: list[dict], services: list[dict], *,
    lockout_threshold: int | None, lockout_default: int,
) -> tuple[list[dict], list[dict], list[dict]]:
    """Turn curated candidates + fingerprinted services into concrete web/non-HTTP login attempts,
    applying the per-account lockout budget to the non-HTTP set. Pure — no I/O, no subprocess."""
    sockets = service_sockets(services)
    web_map = web_urls(services)
    net_attempts: list[dict] = []
    web_attempts: list[dict] = []
    skips: list[dict] = []
    for c in candidates:
        net, web, skip = _place_candidate(c, sockets, web_map)
        net_attempts += net
        web_attempts += web
        skips += skip
    net_attempts, lockout_skips = _apply_lockout(net_attempts, lockout_threshold, lockout_default)
    return net_attempts, web_attempts, skips + lockout_skips


def group_net(net_attempts: list[dict]) -> list[dict]:
    """One Brutus ``creds`` invocation per (product, protocol, username, password); targets are that
    pair's matched sockets. Brutus has no combo-file, so one invocation == one pair (minimal volume)."""
    jobs: dict[tuple[str, str, str, str], dict] = {}
    for a in net_attempts:
        key = (a["product"], a["protocol"], a["username"], a["password"])
        job = jobs.setdefault(key, {
            "product": a["product"], "protocol": a["protocol"], "username": a["username"],
            "password": a["password"], "confidence": a["confidence"],
            "source_urls": a["source_urls"], "rationale": a["rationale"], "targets": []})
        sock = f'{a["host"]}:{a["port"]}'
        if sock not in job["targets"]:
            job["targets"].append(sock)
    for job in jobs.values():
        job["targets"] = tuple(sorted(job["targets"]))
    return list(jobs.values())


def group_web(web_attempts: list[dict]) -> list[dict]:
    """One Brutus ``web`` invocation per product; all its URLs and all its pairs (``-c`` takes explicit
    pairs), keeping each pair's candidate metadata for finding attribution."""
    jobs: dict[str, dict] = {}
    for a in web_attempts:
        job = jobs.setdefault(a["product"], {
            "product": a["product"], "urls": [], "pairs": [], "by_pair": {}})
        if a["url"] not in job["urls"]:
            job["urls"].append(a["url"])
        pair = (a["username"], a["password"])
        if pair not in job["pairs"]:
            job["pairs"].append(pair)
        job["by_pair"][pair] = {"confidence": a["confidence"], "source_urls": a["source_urls"],
                                "rationale": a["rationale"], "product": a["product"]}
    for job in jobs.values():
        job["urls"] = tuple(sorted(job["urls"]))
    return list(jobs.values())
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run pytest tests/pipelines/test_internal_creds.py -k "plan_routes or group_net" -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ptflow/pipelines/internal/creds.py tests/pipelines/test_internal_creds.py
git commit -m "feat(internal): plan credential attempts + group into brutus jobs"
```

---

## Task 6: creds.py — the two stages, the Brutus runner, and `per_app_stages()`

**Files:**
- Modify: `src/ptflow/pipelines/internal/creds.py`
- Test: `tests/pipelines/test_internal_creds.py`

**Interfaces:**
- Consumes: everything above; `Activity`/`AppWorkspace`; `tools.read_jsonl`/`write_jsonl`/`write_text`.
- Produces: `_run_brutus(cmd: list[str], *, dest, label) -> str`; `_chmod_600(path) -> None`;
  `_enrich_net(hits, job, app_id) -> list[dict]`; `_enrich_web(hits, job, app_id) -> list[dict]`;
  `creds_test_net(activity, app_id) -> None`; `creds_test_web(activity, app_id) -> None`;
  `per_app_stages() -> tuple[Stage, ...]` (the two phase-3 per-app stages).

- [ ] **Step 1: Write the failing test**

Append to `tests/pipelines/test_internal_creds.py`:
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
    tools.write_jsonl(ws.canonical("services.jsonl"), [
        {"ip": "10.0.0.5", "port": 22, "product": "Acme NAS", "service": "ssh"},
        {"ip": "10.0.0.5", "port": 8443, "product": "Acme NAS", "service": "https"},
    ])
    tools.write_jsonl(ws.canonical("credential_candidates.jsonl"), [
        {"product": "Acme NAS", "protocol": "ssh", "username": "admin", "password": "acme",
         "confidence": 0.95, "source_urls": ["https://vendor/manual"], "rationale": "manual"},
    ])
    return activity, ws


def test_creds_test_net_writes_hit_and_locks_down(activity_with_candidates, monkeypatch):
    activity, ws = activity_with_candidates
    monkeypatch.setattr(creds, "_run_brutus", lambda *_a, **_k:
        '{"protocol":"ssh","target":"10.0.0.5:22","username":"admin","password":"acme"}\n')
    creds.creds_test_net(activity, "10.0.0.0-24")
    findings = tools.read_jsonl(ws.findings / "creds_net.jsonl")
    hit = next(f for f in findings if not f.get("skipped") and not f.get("reason"))
    assert hit["type"] == "default-credentials" and hit["severity"] == "high"
    assert hit["host"] == "10.0.0.5" and hit["product"] == "Acme NAS"
    assert hit["source_urls"] == ["https://vendor/manual"]
    assert ((ws.findings / "creds_net.jsonl").stat().st_mode & 0o777) == 0o600


def test_creds_test_web_attributes_pair(activity_with_candidates, monkeypatch):
    activity, ws = activity_with_candidates
    tools.write_jsonl(ws.canonical("credential_candidates.jsonl"), [
        {"product": "Acme NAS", "protocol": "https", "username": "admin", "password": "acme",
         "confidence": 0.9, "source_urls": ["https://vendor/manual"], "rationale": "manual"}])
    monkeypatch.setattr(creds, "_run_brutus", lambda *_a, **_k:
        '{"protocol":"http","target":"https://10.0.0.5:8443","username":"admin","password":"acme"}\n')
    creds.creds_test_web(activity, "10.0.0.0-24")
    findings = tools.read_jsonl(ws.findings / "creds_web.jsonl")
    assert findings[0]["via"] == "web" and findings[0]["product"] == "Acme NAS"
    assert findings[0]["port"] == 8443


def test_per_app_stages_are_phase_3():
    stages = creds.per_app_stages()
    assert {s.name for s in stages} == {"creds_test_net", "creds_test_web"}
    assert all(s.phase == 3 and s.per_app for s in stages)
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/pipelines/test_internal_creds.py -k "creds_test_net or creds_test_web or per_app_stages" -v`
Expected: FAIL.

- [ ] **Step 3: Implement the runner, enrichers, stages, and factory**

Append to `creds.py`:
```python
def _run_brutus(cmd: list[str], *, dest, label: str) -> str:
    """Best-effort Brutus run (bounded), stdout persisted to ``dest`` for provenance. '' on any error."""
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
    except OSError as exc:  # pragma: no cover - filesystem-dependent
        log.debug("  · chmod 600 failed on %s: %s", path, exc)


def _finding(app_id: str, host: str, port: int, protocol: str, via: str, meta: dict) -> dict:
    return {"app_id": app_id, "type": "default-credentials", "severity": "high", "via": via,
            "tool": "brutus", "host": host, "port": port, "protocol": protocol,
            "product": meta.get("product", ""), "username": meta.get("username", ""),
            "password": meta.get("password", ""), "confidence": meta.get("confidence"),
            "source_urls": meta.get("source_urls", []), "rationale": meta.get("rationale", ""),
            "evidence": f"default credentials accepted on {protocol}"}


def _enrich_net(hits: list[dict], job: dict, app_id: str) -> list[dict]:
    out: list[dict] = []
    for h in hits:
        host, port = _split_target(str(h.get("target", "")))
        out.append({**_finding(app_id, host, port, job["protocol"], "creds", {
            "product": job["product"], "username": h.get("username", job["username"]),
            "password": h.get("password", job["password"]), "confidence": job["confidence"],
            "source_urls": job["source_urls"], "rationale": job["rationale"]}),
            "banner": h.get("banner", "")})
    return out


def _enrich_web(hits: list[dict], job: dict, app_id: str) -> list[dict]:
    out: list[dict] = []
    for h in hits:
        pair = (h.get("username", ""), h.get("password", ""))
        meta = job["by_pair"].get(pair, {"product": job["product"]})
        host, port = _split_target(str(h.get("target", "")))
        out.append({**_finding(app_id, host, port, "http", "web", {
            "product": meta.get("product", job["product"]), "username": pair[0], "password": pair[1],
            "confidence": meta.get("confidence"), "source_urls": meta.get("source_urls", []),
            "rationale": meta.get("rationale", "")}),
            "llm_suggested": bool(h.get("llm_suggested", False)),
            "evidence": "default credentials accepted on web login panel"})
    return out


def _load(activity: Activity, app_id: str) -> tuple:
    """(ws, candidates, services) or None when the stage should skip (brutus/inputs absent)."""
    ws = activity.app(app_id)
    if shutil.which(BRUTUS) is None:
        return ws, None, None
    return (ws,
            tools.read_jsonl(ws.canonical("credential_candidates.jsonl")),
            tools.read_jsonl(ws.canonical("services.jsonl")))


def creds_test_net(activity: Activity, app_id: str) -> None:
    """LOOP 3 (opt-in) — try curated default credentials on NON-HTTP services via ``brutus creds``.
    One invocation per pair, lockout-aware, best-effort → findings/creds_net.jsonl (0600)."""
    ws, candidates, services = _load(activity, app_id)
    if not candidates or not services:
        log.debug("  · skip creds_test_net [%s] (brutus/candidates/services absent)", app_id)
        return
    threshold = parse_lockout_threshold(tools.read_jsonl(ws.findings / "ad_enum.jsonl"))
    net_attempts, _web, skips = plan_attempts(
        candidates, services, lockout_threshold=threshold, lockout_default=_lockout_default())
    mode = resolve_mode()
    findings: list[dict] = []
    for i, job in enumerate(group_net(net_attempts)):
        tfile = ws.raw("brutus") / f"net-{job['protocol']}-{i}-targets.txt"
        tools.write_text(tfile, "\n".join(job["targets"]))
        out = _run_brutus(
            [BRUTUS, "creds", "--protocol", job["protocol"], "--targets-file", str(tfile),
             "-u", job["username"], "-p", job["password"], "--mode", mode, "--json"],
            dest=ws.raw("brutus") / f"net-{job['protocol']}-{i}.jsonl", label=f"creds-{job['protocol']}")
        findings += _enrich_net(parse_brutus_jsonl(out), job, app_id)
    hits = len(findings)
    findings += [{"app_id": app_id, "skipped": True, **s} for s in skips if s.get("via") == "net"]
    tools.write_jsonl(ws.findings / "creds_net.jsonl", findings)
    _chmod_600(ws.findings / "creds_net.jsonl")
    log.info("  → creds_test_net [%s] — %d candidate(s) → %d hit(s)", app_id, len(candidates), hits)


def creds_test_web(activity: Activity, app_id: str) -> None:
    """LOOP 3 (opt-in) — try curated default credentials on HTTP login panels via ``brutus web`` (Basic,
    headless-Chrome form, JSON API). One invocation per product, best-effort → findings/creds_web.jsonl."""
    ws, candidates, services = _load(activity, app_id)
    if not candidates or not services:
        log.debug("  · skip creds_test_web [%s] (brutus/candidates/services absent)", app_id)
        return
    threshold = parse_lockout_threshold(tools.read_jsonl(ws.findings / "ad_enum.jsonl"))
    _net, web_attempts, skips = plan_attempts(
        candidates, services, lockout_threshold=threshold, lockout_default=_lockout_default())
    mode = resolve_mode()
    findings: list[dict] = []
    for i, job in enumerate(group_web(web_attempts)):
        tfile = ws.raw("brutus") / f"web-{i}-targets.txt"
        tools.write_text(tfile, "\n".join(job["urls"]))
        creds_arg = ",".join(f"{u}:{p}" for u, p in job["pairs"])
        out = _run_brutus(
            [BRUTUS, "web", "--targets-file", str(tfile), "-c", creds_arg, "--mode", mode, "--json"],
            dest=ws.raw("brutus") / f"web-{i}.jsonl", label="creds-web")
        findings += _enrich_web(parse_brutus_jsonl(out), job, app_id)
    hits = len(findings)
    findings += [{"app_id": app_id, "skipped": True, **s} for s in skips if s.get("via") == "web"]
    tools.write_jsonl(ws.findings / "creds_web.jsonl", findings)
    _chmod_600(ws.findings / "creds_web.jsonl")
    log.info("  → creds_test_web [%s] — %d candidate(s) → %d hit(s)", app_id, len(candidates), hits)


def per_app_stages() -> tuple[Stage, ...]:
    """The opt-in phase-3 credential-testing stages (spliced by pipeline.py only when enabled)."""
    return (
        Stage("creds_test_net", creds_test_net, per_app=True, phase=3, net=True),
        Stage("creds_test_web", creds_test_web, per_app=True, phase=3, net=True),
    )
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run pytest tests/pipelines/test_internal_creds.py -v`
Expected: PASS (all creds tests).

- [ ] **Step 5: Commit**

```bash
git add src/ptflow/pipelines/internal/creds.py tests/pipelines/test_internal_creds.py
git commit -m "feat(internal): brutus creds/web testing stages"
```

---

## Task 7: Splice the stages into the pipeline behind the opt-in flag

**Files:**
- Modify: `src/ptflow/pipelines/internal/pipeline.py` (imports line 11; module gate ~line 20-21; stages
  tuple ~line 63)
- Test: `tests/pipelines/test_internal_tasks.py`

**Interfaces:**
- Consumes: `creds.per_app_stages()`, `creds.creds_test_enabled()`.
- Produces: `InternalPipeline.stages` includes `creds_test_net`/`creds_test_web` iff `PTFLOW_CREDS_TEST`
  is set at import time; absent otherwise.

- [ ] **Step 1: Write the failing test**

Add to `tests/pipelines/test_internal_tasks.py`:
```python
import importlib


def test_creds_stages_absent_by_default(monkeypatch):
    monkeypatch.delenv("PTFLOW_CREDS_TEST", raising=False)
    from ptflow.pipelines.internal import pipeline as pl
    pl = importlib.reload(pl)
    assert "creds_test_net" not in {s.name for s in pl.PIPELINE.stages}


def test_creds_stages_present_when_opt_in(monkeypatch):
    monkeypatch.setenv("PTFLOW_CREDS_TEST", "on")
    from ptflow.pipelines.internal import pipeline as pl
    pl = importlib.reload(pl)
    names = {s.name for s in pl.PIPELINE.stages}
    assert {"creds_test_net", "creds_test_web"} <= names
    creds_stages = [s for s in pl.PIPELINE.stages if s.name.startswith("creds_test")]
    assert all(s.phase == 3 for s in creds_stages)
    monkeypatch.delenv("PTFLOW_CREDS_TEST", raising=False)
    importlib.reload(pl)  # restore default graph for other tests
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/pipelines/test_internal_tasks.py -k "creds_stages" -v`
Expected: FAIL (stages never present).

- [ ] **Step 3: Wire the gate**

In `pipeline.py`, extend the import (line 11):
```python
from ptflow.pipelines.internal import ai, creds, tasks
```
After `_AI_STAGES = ai.per_app_stages()` (~line 21) add:
```python
_CREDS = creds.creds_test_enabled()
_CREDS_STAGES = creds.per_app_stages()
```
In the `stages` tuple, immediately after the `*(_AI_STAGES if _AI else ())` line (~line 63) add:
```python
        *(_AI_STAGES if _AI else ()),
        # LOOP 3 — opt-in default-credential testing (PTFLOW_CREDS_TEST): try the research agent's
        # source-grounded candidates against the services they were proposed for (Brutus).
        *(_CREDS_STAGES if _CREDS else ()),
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run pytest tests/pipelines/test_internal_tasks.py -k "creds_stages" -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ptflow/pipelines/internal/pipeline.py tests/pipelines/test_internal_tasks.py
git commit -m "feat(internal): splice opt-in credential-testing loop (phase 3)"
```

---

## Task 8: Flow-map metadata for the two stages

**Files:**
- Modify: `src/ptflow/pipelines/internal/flowmeta.py` (`FLOWMETA` dict after `ai_credential_research`
  ~line 268; `phase_labels` in `SPEC` ~line 302)
- Test: `tests/pipelines/test_flowmap.py` (already parametrized; verify it passes with the flag on)

**Interfaces:**
- Consumes: nothing new.
- Produces: `StepMeta` entries for `creds_test_net` and `creds_test_web`; `phase_labels[3]`.

- [ ] **Step 1: Add the two StepMeta**

In `flowmeta.py`, inside `FLOWMETA`, after the `"ai_credential_research": StepMeta(...)` entry (before the
closing `}` at ~line 269) add:
```python
    "creds_test_net": StepMeta(
        summary="[opt-in PTFLOW_CREDS_TEST] LOOP 3 — prova le credenziali default source-grounded "
                "dell'agente sui servizi NON-HTTP (SSH/FTP/DB/SNMP/SMB/RDP…) via `brutus creds`. Solo il "
                "set curato (mai wordlist), una invocazione per coppia, lockout-aware.",
        commands=("brutus creds --protocol <p> --targets-file <ip:port> -u <u> -p <p> --mode cautious --json",
                  "# match prodotto→socket · budget lockout (threshold-1/account su smb/ldap/rdp/winrm)"),
        outputs=("findings/creds_net.jsonl", "raw/brutus/net-*.jsonl"),
        notes=("net=True · best-effort (salta se brutus/candidati/servizi assenti) · file findings 0600",
               "niente --experimental-ai / default di brutus: esecutore deterministico sui nostri candidati"),
    ),
    "creds_test_web": StepMeta(
        summary="[opt-in PTFLOW_CREDS_TEST] LOOP 3 — prova le credenziali default sui PANNELLI HTTP via "
                "`brutus web` (Basic auth · form headless-Chrome · API JSON): gestisce nativamente la "
                "diversità dei login panel. Coppie curate in -c, una invocazione per prodotto.",
        commands=("brutus web --targets-file <url> -c 'u1:p1,u2:p2' --mode cautious --json",
                  "# routing socket→web via web_targets_from · attribuzione hit→coppia per prodotto"),
        outputs=("findings/creds_web.jsonl", "raw/brutus/web-*.jsonl"),
        notes=("net=True · best-effort · file findings 0600 · chromium richiesto per il form-mode",
               "consolidate folda creds_net + creds_web → findings/creds.jsonl (0600)"),
    ),
```

- [ ] **Step 2: Add the phase-3 label**

In `SPEC` (~line 302) extend `phase_labels`:
```python
    phase_labels={1: "inventario servizi", 2: "frutti bassi", 3: "test credenziali default"},
```

- [ ] **Step 3: Regenerate the flow maps and run the gate**

Run:
```bash
uv run python -m ptflow.core.flowdocs
PTFLOW_CREDS_TEST=on uv run pytest tests/pipelines/test_flowmap.py -v
uv run pytest tests/pipelines/test_flowmap.py -v
```
Expected: PASS in both (with the flag the two stages appear and are covered; without it the default graph
still renders). The generated `docs/internal-pipeline-*` files may change — that is expected.

- [ ] **Step 4: Commit**

```bash
git add src/ptflow/pipelines/internal/flowmeta.py docs/internal-pipeline-*
git commit -m "docs(internal): flow-map metadata for credential-testing stages"
```

---

## Task 9: Docs (CLAUDE.md + ptflow.toml.example) and the full dev gate

**Files:**
- Modify: `CLAUDE.md` (internal pipeline section — the loop-2/status notes)
- Modify: `ptflow.toml.example` (operator knobs)
- Test: full gate.

**Interfaces:** none (documentation + verification).

- [ ] **Step 1: Document the feature in CLAUDE.md**

In `CLAUDE.md`, in the `internal` pipeline description, add a bullet after the loop-2 list (and update the
"Destructive/active checks … credentialed auth … deliberately opt-in, not yet wired" sentence to note this
is now the wired first step):
```markdown
  - **Loop 3 — default-credential testing** (`phase=3`, **OPT-IN `PTFLOW_CREDS_TEST`**, default OFF):
    `creds_test_net` (`brutus creds`, non-HTTP) ∥ `creds_test_web` (`brutus web`, HTTP login panels)
    try the `research` agent's source-grounded candidates (`credential_candidates.jsonl`) against the
    services they were proposed for — **curated pairs only**, never wordlists / never Brutus
    `--experimental-ai`. Matching is per-product→socket; routing HTTP vs non-HTTP reuses `web_targets_from`;
    lockout-aware (never > `threshold-1` attempts/account on SMB/LDAP/RDP/WinRM, from `ad_enum`'s
    `parse_nxc_pass_pol`; unknown ⇒ `PTFLOW_CREDS_LOCKOUT_DEFAULT`, default 3). `--mode` via
    `PTFLOW_CREDS_MODE` (default `cautious`). Best-effort → `findings/creds_{net,web}.jsonl` (`0600`);
    `consolidate` folds both → `findings/creds.jsonl` (`0600`, password redacted in reports).
```
Also add a bullet under "External environment gotchas" / internal tools:
```markdown
- **Default-credential testing (`creds_test_net`/`creds_test_web`, opt-in)** uses **Brutus**
  (`~/go/bin/brutus`, `PTFLOW_BRUTUS` override) — one Go binary for both `brutus creds` (27 non-HTTP
  protocols) and `brutus web` (Basic/form/JSON HTTP panels). Fed only the agent's validated pairs; its
  own AI/defaults are never used. Web form-mode needs chromium (`/usr/bin/chromium`). Opt-in via
  `PTFLOW_CREDS_TEST`; `PTFLOW_CREDS_MODE` (cautious|default|aggressive) is the RoE noise/lockout lever.
```

- [ ] **Step 2: Document the knobs in ptflow.toml.example**

Add to `ptflow.toml.example` (near the other `PTFLOW_*`-mirroring notes; these are env-only in v1, so
document them as env vars in a comment block):
```toml
# --- internal default-credential testing (opt-in) --------------------------------
# PTFLOW_CREDS_TEST=on            # enable phase-3 credential testing (default OFF)
# PTFLOW_CREDS_MODE=cautious      # brutus --mode: cautious|default|aggressive (default cautious)
# PTFLOW_CREDS_LOCKOUT_DEFAULT=3  # max attempts/account when the lockout policy is unknown
# PTFLOW_BRUTUS=/path/to/brutus   # override the brutus binary
```

- [ ] **Step 3: Run the full dev gate**

Run:
```bash
uv run ruff check .
uv run ty check src/
uv run pytest
```
Expected: ruff clean (fix any lint in `creds.py` — likely `PLR0913`/complexity: factor or add a targeted
`# noqa` consistent with the file's neighbours, never a blanket ignore), ty clean, all tests PASS.

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md ptflow.toml.example
git commit -m "docs: document opt-in internal credential testing (Brutus)"
```

---

## Self-Review

**Spec coverage** (against `docs/superpowers/specs/2026-07-19-default-credential-testing-design.md`):
- §3 engine = Brutus for both → Task 1 (tool), Task 6 (both subcommands). ✅
- §4 placement, phase-3 sibling stages, absent-when-off → Task 6 (`per_app_stages`), Task 7 (gate). ✅
- §5 gating (`PTFLOW_CREDS_TEST`, `PTFLOW_CREDS_MODE`, lockout rule, curated only, no Brutus AI) → Task 2
  (`creds_test_enabled`/`resolve_mode`), Task 3 (lockout), Task 6 (invocation without `--experimental-ai`). ✅
- §6 matching/routing/protocol-map → Task 2 + Task 5. ✅
- §7 invocation (per-pair net; batched-per-product web; best-effort) → Task 6. ✅
- §8 output + consolidate + 0600 + redaction → Task 1 (consolidate/0600), Task 4 (redact), Task 6 (findings). ✅
- §9 requirements/doctor + flow map + knobs → Task 1 (requirements), Task 8 (flow map), Task 9 (docs). ✅
- §10 testing → tests in every task. ✅

**Placeholder scan:** no TBD/TODO; every code step shows complete code; every test shows real assertions.

**Type consistency:** stage functions are `(activity: Activity, app_id: str) -> None` (matches other
per-app tasks); `parse_lockout_threshold`→`int|None` consumed by `account_budget(threshold, default)`;
`plan_attempts(..., lockout_threshold, lockout_default)` keyword names match the callers in Task 6; job
dict keys (`targets`/`urls`/`pairs`/`by_pair`) are produced in Task 5 and consumed in Task 6 identically;
`_split_target` returns `(host, int)` used by both enrichers.

**Note carried from Task 0:** if the installed Brutus differs from the README flag names, update the two
`_run_brutus([...])` command lists in Task 6 before running Step 4.
