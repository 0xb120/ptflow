# Design — Default-credential testing (internal pipeline)

- **Date:** 2026-07-19
- **Status:** Approved (design); pending implementation plan
- **Scope:** internal pipeline, new phase-3 loop. Active authenticated login attempts (opt-in). RoE-sensitive.
- **Revision (2026-07-19b):** rewritten after verifying the installed Brutus binary (Task 0). The
  installed `brutus dev` build has a **flat CLI** (`--target`/`--protocol`/`--nerva`), **not** the
  `brutus creds`/`brutus web` subcommands an unreliable README summary suggested; and — consistent across
  the binary's own `--help` and the README — **HTTP form-based login requires Brutus's `--experimental-ai`
  (Claude Vision + `ANTHROPIC_API_KEY`)**. We rejected Brutus's AI (provider-agnostic seam; internal-RoE
  screenshot exfiltration). Therefore: **Brutus for non-HTTP + HTTP Basic auth**, and a **new
  Playwright-based `FormLoginProbe`** (reusing the browser the `research` agent already ships) for
  form-based panels — deterministic, no Anthropic key.

## 1. Motivation

The `research` agent (`core/agents/research.py` + `credential_research.py`) already produces
**source-grounded default-credential proposals**: for each fingerprinted product it searches the web,
fetches vendor docs, and `validate_proposals` rejects any credential not appearing *literally* in a
fetched source (anti-hallucination). The `ai_credential_research` stage (`pipelines/internal/ai.py`,
`per_app`, `phase=2`) writes them to `scans/<subnet>/credential_candidates.jsonl` (`chmod 0600`), each
record `{product, version, protocol, username, password, source_urls, confidence, rationale,
conditions}`.

Nothing **tests** these proposals yet. This is exactly the `PTFLOW_CREDS` "credentialed auth … opt-in,
not yet wired" that CLAUDE.md anticipates. This design adds the testing steps for the **internal**
pipeline only.

## 2. Goals / Non-goals

**Goals:**
- Test the agent's curated candidates against the concrete services they were proposed for, across
  **non-HTTP** services, **HTTP Basic-auth** panels, and **HTTP form-based** login panels.
- Precision-first + low volume (only the validated set, never wordlists), hard opt-in gating, lockout
  awareness — minimal account-lockout risk.
- Successes become high-severity findings, consolidated to the activity level, secret-safe (plaintext
  only in `0600` files; redacted in any rendered report).
- Reuse existing conventions (files-on-disk, per-app loops, best-effort) with **zero `core/` changes to
  the orchestrator**; the form probe reuses the `research` agent's Playwright + SSRF-safety helpers.

**Non-goals:**
- No brute-force / spraying / wordlists — only the curated candidate pairs.
- No credential testing in `external`/`webscan` (the agent isn't wired there — later phase).
- **No Brutus `--experimental-ai`** (Claude Vision, `ANTHROPIC_API_KEY`): duplicates our provider-agnostic
  research agent and would exfiltrate internal-panel screenshots to a third party.
- No persistence of successful sessions / no post-auth actions — a hit is reported, nothing more.

## 3. Engines (verified against the installed binary)

Two engines, split by mechanism:

### 3a. Brutus — non-HTTP services **and** HTTP Basic auth
[Brutus](https://github.com/praetorian-inc/brutus) (`~/go/bin/brutus`, Go binary, `PTFLOW_BRUTUS`
override). Verified `--help`: flat CLI, `--protocol` ∈ {ssh, rdp, ftp, telnet, vnc, smb, ldap, winrm,
mysql, postgresql, mssql, mongodb, redis, neo4j, cassandra, couchdb, elasticsearch, influxdb, smtp, imap,
pop3, **http, https**, snmp}. On http/https **without** `--experimental-ai` it tests **HTTP Basic auth**
only. Invocation (single-target mode, one process per curated pair × socket):
```
brutus --target <ip:port> --protocol <proto> -u <user> -p <pass> --json <mode-flags>
```
- **No `--mode`/`--targets-file`/`-c`** exist. Our `PTFLOW_CREDS_MODE` maps to a real flag bundle:
  - `cautious` → `-t 5 --rate-limit 2 --retries 1 --timeout 15s`
  - `default`  → `-t 10 --retries 2`
  - `aggressive` → `-t 20 --retries 3`
- TLS: leave the default (**no `--verify-tls`** ⇒ skip verification, correct for self-signed internal
  panels; nerva TLS auto-upgrades).
- `--stop-on-success` defaults true. `--json` prints one success object per line to stdout. `--max-attempts`
  exists as a tool-side per-user cap; our per-pair invocation already bounds this, so it's not required.

### 3b. `FormLoginProbe` — HTTP form-based login (our own, Playwright)
A new `core/agents/form_login.py`. Reuses the `research` agent's Playwright machinery and SSRF helpers
(`_validate_fetch_url`) but with `allow_private=True` (internal targets are private by design). It
navigates to the panel, locates the login form deterministically, submits each curated pair, and judges
success by a conservative heuristic (below). **Provider-agnostic, no Anthropic key.** Form success
detection is inherently imperfect → findings are **lead-grade** (`confidence:"lead"` unless a strong
signal fires). An optional enhancement (our provider-agnostic LLM seam locating fields / judging success)
is a documented follow-up, not v1.

## 4. Placement in the DAG

New **phase-3 per-app loop** in `internal`, two sibling stages in a new module
`pipelines/internal/creds.py`:
- `creds_test_brutus` — Brutus over matched sockets (non-HTTP + HTTP Basic).
- `creds_test_forms` — `FormLoginProbe` over matched HTTP panels (form login).

Both `per_app=True, phase=3, net=True`. The 2→3 barrier guarantees `credential_candidates.jsonl`
(phase-2) and `services.jsonl` (phase-1) exist. Spliced via `*_CREDS_STAGES` where
`creds.per_app_stages()` is included by `pipeline.py` only when `PTFLOW_CREDS_TEST` is set — **absent from
the DAG when disabled**, mirroring `_AI_STAGES`. **Part A** (`creds_test_brutus` + all wiring) is
independently mergeable; **Part B** (`creds_test_forms` + `FormLoginProbe`) builds on the same
primitives and can land second.

## 5. Gating (safety model)

- **`PTFLOW_CREDS_TEST`** ∈ `{1,on,true,yes}`, default OFF — same parser as `WEB_HANDOFF_ENV`.
- **`PTFLOW_CREDS_MODE`** ∈ `{cautious,default,aggressive}`, default `cautious` → the Brutus flag bundle
  above; the form probe reads it for its own concurrency/timeout (cautious ⇒ 1 worker, longer settle).
- **Lockout-aware (concrete rule)** for SMB/LDAP/RDP/WinRM: read `parse_nxc_pass_pol`'s
  `lockout_threshold` from `findings/ad_enum.jsonl`. Invariant: **never more than `threshold-1` attempts
  per single account**:
  - `threshold <= 1` ⇒ **skip** that protocol on that host (`{skipped:"lockout_policy"}`).
  - `threshold >= 2` ⇒ per account, keep at most `threshold-1` pairs by descending `confidence`
    (excess → `{skipped:"lockout_budget"}`).
  - No enumerated policy ⇒ conservative default `PTFLOW_CREDS_LOCKOUT_DEFAULT` (default `3` ⇒ cap 2/account).
  Lockout-free protocols (SSH/FTP/DB/SNMP/telnet/VNC/HTTP) are not gated.
- **Curated set only** — never wordlists; never Brutus `--experimental-ai`; never Brutus's embedded
  defaults. Candidate `conditions` (e.g. "factory-reset-only") are logged, not blocking.

## 6. Core logic (pure, unit-tested)

Shared by both stages (`pipelines/internal/creds.py`):
1. **`service_sockets(services)`** → per-socket `{host, port, product, service, banner}` (product from the
   explicit field else `_banner_product(banner)`).
2. **`_product_matches(candidate_product, socket_product)`** — bidirectional casefold substring (the
   `_product_is_observed` rule the agent used).
3. **Routing:** `web_urls(services)` reuses the tested `web_targets_from` to know which sockets are web
   (and their `scheme://host:port`). Non-web sockets map to a Brutus `--protocol` via `socket_proto`
   (`_BRUTUS_PROTO` by service name, then `_PORT_PROTO` by well-known port; `None` ⇒ unmapped skip).
   Web sockets go to Brutus (as `http`/`https` = Basic auth) **and** to the form probe.
4. **Lockout budget** (`parse_lockout_threshold` + `account_budget` + `_apply_lockout`) over the
   non-HTTP/Basic attempts.
5. **`plan_attempts(...)`** integrates match → route → lockout → `(brutus_attempts, form_attempts, skips)`.
6. **`parse_brutus_jsonl`** (success records) and **`redact`** (mask password for reports).

## 7. Invocation & output

- **`creds_test_brutus`:** for each curated pair, for each matched socket (non-web via its protocol; web
  via `http`/`https`), run `brutus --target <ip:port> --protocol <p> -u <u> -p <p> --json <mode-flags>`
  via a bounded best-effort runner (stdout persisted to `raw/brutus/`). Parse hits → enrich with product/
  source/confidence → `findings/creds_brutus.jsonl` (`0600`).
- **`creds_test_forms`:** for each matched web panel, `FormLoginProbe.attempt(url, user, pass)` per curated
  pair (sequential; browser is heavy) → `findings/creds_forms.jsonl` (`0600`). Skips cleanly when
  Playwright/Chromium is unavailable or no form is present.
- **`FormLoginProbe.attempt` heuristic:** navigate (`domcontentloaded` + settle); locate
  `input[type=password]` (first visible) and a username field (same form: `input[type=email]`,
  `[name*=user]`, `[name*=login]`, else the preceding text input); fill; submit (click
  `button[type=submit],input[type=submit]` else Enter); wait for load/settle. **Success** =
  password field gone from the result **and** (final URL path changed **or** a new session-looking cookie
  set) **and** no visible error marker; a strong signal (redirect to a dashboard-y path + auth cookie)
  ⇒ `confidence:"probable"`, otherwise `"lead"`. **Failure/again-on-login** ⇒ no finding. No form found
  ⇒ not-applicable (no finding, no error). Per-attempt bounded by the browser timeout.
- **Record** (both stages): `{app_id, type:"default-credentials", severity:"high", via:"brutus"|"form",
  tool, host, port, protocol, product, username, password, confidence, source_urls, rationale, banner?,
  evidence}`. Skip records carry `{skipped:true, reason, ...}` and no password.

## 8. Consolidate & secret handling

- Per-app (write-once): `creds_test_brutus` → `findings/creds_brutus.jsonl`; `creds_test_forms` →
  `findings/creds_forms.jsonl`.
- **`consolidate`** folds both by type → `<activity>/findings/creds.jsonl` (add
  `"creds.jsonl": ("findings/creds_brutus.jsonl", "findings/creds_forms.jsonl")` to
  `_CONSOLIDATE_SOURCES`), each record stamped `app_id`.
- **Secret handling:** `findings/creds_*.jsonl` and the consolidated `findings/creds.jsonl` are
  `chmod 0600`; passwords are plaintext only there; `redact()` masks them for any rendered report; never
  logged.

## 9. Surrounding wiring

- **Requirements/doctor:** add `brutus` to internal `_OPTIONAL_TOOLS` (opt-in ⇒ warns, never fails the
  gate). Playwright/Chromium stay implicit (the form stage degrades if absent).
- **Flow map:** `StepMeta` for `creds_test_brutus`/`creds_test_forms` + `phase_labels[3]` in
  `internal/flowmeta.py`.
- **Knobs (env, v1):** `PTFLOW_CREDS_TEST`, `PTFLOW_CREDS_MODE`, `PTFLOW_CREDS_LOCKOUT_DEFAULT`,
  `PTFLOW_BRUTUS`; documented in `ptflow.toml.example` + CLAUDE.md.

## 10. Testing

- Pure-unit: matching, routing, `socket_proto`, lockout parse/budget, `parse_brutus_jsonl`, mode-flag
  bundle, `redact`, `plan_attempts`, the form success-heuristic decision function (fed synthetic
  before/after page states — pure, no real browser).
- Stage-level with a monkeypatched Brutus runner / a fake browser: findings written + `0600`; consolidate
  fold; `PTFLOW_CREDS_TEST` off ⇒ stages absent.
- Optional e2e-smoke on a loopback HTTP Basic realm + a trivial login form.

## 11. Alternatives rejected

- **Trusting the WebFetch README (`brutus creds`/`web` subcommands, `-c`/`--mode`):** contradicted by the
  installed binary's own `--help` (and the README summary confabulated release notes). The binary is
  ground truth.
- **Brutus `--experimental-ai` for HTTP forms:** the only way to get form login *from Brutus*, but needs
  `ANTHROPIC_API_KEY`, ships internal-panel screenshots to a third party (internal-RoE), duplicates our
  agent, and is non-deterministic. Rejected → we drive forms ourselves.
- **`nxc`+`hydra` hybrid:** superseded; Brutus covers all non-HTTP + Basic in one integration.
- **A single web stage doing Basic+form:** split so Brutus (Basic) and the Playwright probe (form) stay
  single-purpose and independently testable; a web socket is simply tried by both (each yields a finding
  only if its mechanism works).
- **LLM-assisted form field-location/success-judging in v1:** deferred to a follow-up (would reintroduce
  an AI-stage dependency); v1 is a deterministic heuristic, lead-grade.
