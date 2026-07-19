# Design — Default-credential testing (internal pipeline)

- **Date:** 2026-07-19
- **Status:** Approved (design); pending implementation plan
- **Scope:** internal pipeline, new phase-3 loop. Active authenticated login attempts (opt-in). RoE-sensitive.

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
pipeline only (`external`/`webscan` do not run the research agent today — a deliberate later phase).

## 2. Goals / Non-goals

**Goals:**
- Test the agent's curated candidates against the concrete services they were proposed for, for both
  **non-HTTP** services and **HTTP login panels** (the diverse-panel problem).
- Precision-first + low volume (only the validated set, never wordlists) so account-lockout risk stays
  minimal, and hard opt-in gating.
- Successes become high-severity findings, consolidated to the activity level, with the secret handled
  safely (plaintext only in a `0600` file; redacted in any rendered report).
- Reuse the existing file-on-disk / per-app-loop / best-effort conventions with zero `core/` changes.

**Non-goals:**
- No brute-force / password spraying / wordlists — only the curated candidate pairs.
- No credential testing in `external`/`webscan` (later phase; the agent isn't wired there).
- No use of Brutus's own `--experimental-ai` (our provider-agnostic, source-grounded agent already does
  credential research; Brutus stays a deterministic executor fed our validated pairs).
- No persistence of successful sessions / no post-auth actions — a hit is reported, nothing more.

## 3. Engine decision — Brutus for both HTTP and non-HTTP

Chosen engine: **[Brutus](https://github.com/praetorian-inc/brutus)** (Praetorian, Go, single static
binary, already installed at `~/go/bin/brutus`; chromium present at `/usr/bin/chromium`). It replaces
the initially-considered `nxc`+`hydra` hybrid. Rationale (depth + stability):

- **Depth, non-HTTP (`brutus creds`):** 27 protocols in one tool — SSH/FTP/telnet/VNC/RDP/SNMP/SMB/
  LDAP/WinRM + MySQL/Postgres/MSSQL/Mongo/Redis/Oracle/Cassandra/CouchDB/Elasticsearch/InfluxDB/Neo4j/
  Docker/Kubernetes.
- **Depth, HTTP (`brutus web`):** natively handles login-panel diversity — HTTP Basic (via
  `WWW-Authenticate`), **form-based** (headless Chrome renders, analyzes form structure, submits, detects
  success by page-state diff), and JSON APIs. This is the hard part we do **not** hand-roll.
- **Stability / integration:** JSONL output (`--json`) = ptflow convention; native **nerva JSON**
  ingestion — and `internal`'s `fingerprint` stage already writes `services.jsonl` as the output of
  `nerva --json`; `--mode cautious|default|aggressive` rate-limit preset; SOCKS5. One binary, one output
  format, one parser.

**Known constraints designed around:**
- `brutus creds` has **no combo-file** (only cartesian `-U`/`-P` or `-u`/`-p`). To preserve exact
  pairing and keep volume minimal we invoke it **once per curated pair** with `-u`/`-p`.
- `brutus web` **does** accept explicit pairs via `-c "user1:pass1,user2:pass2"` (not cartesian), so the
  web path batches all pairs for a target set into one call.
- Form-mode needs Chromium (present). If absent, web degrades best-effort (Basic-auth still works).

## 4. Placement in the DAG

New **phase-3 per-app loop** in `internal`, two sibling stages in a new deterministic (non-AI) module
`pipelines/internal/creds.py`:

- `creds_test_net` — `brutus creds` over matched non-HTTP sockets.
- `creds_test_web` — `brutus web` over matched HTTP panels.

Both `per_app=True, phase=3, net=True`. The global 2→3 barrier guarantees `credential_candidates.jsonl`
(phase-2 `ai_credential_research`) and `services.jsonl` (phase-1 `fingerprint`) are present. They are
appended to the pipeline stage tuple via `*_CREDS_STAGES`, where `creds.per_app_stages()` returns `()`
when `PTFLOW_CREDS_TEST` is off — **absent from the DAG when disabled**, mirroring `_AI_STAGES`.

## 5. Gating (safety model)

- **`PTFLOW_CREDS_TEST`** ∈ `{1,on,true,yes}`, default OFF — same parser as `WEB_HANDOFF_ENV`
  (`tasks.py:1551`). Off ⇒ stages absent ⇒ no-op.
- **`PTFLOW_CREDS_MODE`** ∈ `cautious|default|aggressive`, default **`cautious`** (5 threads, 2 req/s,
  1 retry) → Brutus `--mode`. Operator-facing (RoE noise/lockout lever, like `PTFLOW_PROFILE`).
- **Lockout-aware (concrete rule):** before testing SMB/LDAP/RDP/WinRM on a host, read the password
  policy `ad_enum` already enumerates (`parse_nxc_pass_pol` → its `lockout_threshold`). The invariant is
  **never make more than `threshold - 1` attempts against any single account**:
  - `threshold <= 1` (any failure locks) ⇒ **skip** that protocol on that host, record
    `{skipped:"lockout_policy"}`.
  - `threshold >= 2` ⇒ for each account, test at most `threshold - 1` pairs, ordered by descending
    `confidence` (excess pairs dropped, recorded as `{skipped:"lockout_budget"}`).
  - No enumerated policy (null-session denied / no AD) ⇒ treat as `threshold` unknown and apply the
    conservative default `PTFLOW_CREDS_LOCKOUT_DEFAULT` (default `3`, i.e. cap at 2 attempts/account).
  Lockout-free protocols (SSH/FTP/DB/SNMP/telnet/VNC) are not gated.
- **Curated set only** — never wordlists; never Brutus `--experimental-ai`; never Brutus's embedded
  defaults. Candidate `conditions` (e.g. "factory-reset-only") are **logged, not blocking** (a device is
  often not reset — that is the point).

## 6. Core logic (pure, unit-tested)

Matching candidate → concrete socket is the real code we own:

1. **Match** each candidate to `services.jsonl` records whose **product matches** (bidirectional
   casefold substring, the `_product_is_observed` rule) → concrete `host:port` sockets where the pair is
   meaningful.
2. **Route** each matched socket HTTP vs non-HTTP reusing the `web_targets_from` rule (protocol
   http/https, web port, banner) — web sockets → `creds_test_web`, others → `creds_test_net`.
3. **Protocol map** candidate/nerva service name → Brutus `--protocol` name (`_BRUTUS_PROTO`, e.g.
   `microsoft-ds`→`smb`, `ms-wbt-server`→`rdp`, `postgresql`→`postgres`). Precision-first: an unmapped
   protocol is skipped with a logged reason (never guessed).

## 7. Invocation

- **`creds_test_net`:** group matched sockets by Brutus protocol; per curated pair invoke
  `brutus creds --protocol <X> --targets-file <sockets.txt> -u <user> -p <pass> --mode <mode> --json
  -o raw/brutus/creds-<X>-<i>.jsonl`. Volume = number of curated pairs (minimal).
- **`creds_test_web`:** one call per matched web-socket group with all pairs inline:
  `brutus web --targets-file <urls.txt> -c "u1:p1,u2:p2,…" --mode <mode> --json -o raw/brutus/web.jsonl`.
  Target URLs are `scheme://host:port` (https for TLS/web port, per `web_targets_from`).
- **Best-effort everywhere:** binary absent / non-zero exit / timeout ⇒ stage logs and writes `[]`,
  never aborts (like every internal check; the teardown-kill contract still applies — no per-tool
  timeout babysitting beyond Brutus's own `--timeout`).

## 8. Output, consolidate, redaction

- Per-app (write-once, one file per writer): `creds_test_net` → `scans/<subnet>/findings/creds_net.jsonl`;
  `creds_test_web` → `scans/<subnet>/findings/creds_web.jsonl`.
- Enriched record: `{app_id, host, port, protocol, product, username, password, confidence,
  source_urls, rationale, conditions, banner, tool:"brutus", via:"creds"|"web"}`. A gate-skip record is
  `{app_id, host, port, protocol, skipped:"lockout_policy"|"unmapped_protocol"|"no_match"}`.
- **`consolidate`** folds both per-app files by type → `<activity>/findings/creds.jsonl` (add `creds` to
  `_CONSOLIDATE_SOURCES`, exactly like cve/dast fold surface+deep). Each activity finding is stamped
  `app_id`.
- **Secret handling:** the findings JSONL is `chmod 0600` and carries the plaintext password (it is the
  finding); **any rendered report masks it (`****`)**. This mirrors `credential_candidates.jsonl`'s
  `0600` treatment.

## 9. Surrounding wiring

- **Requirements/doctor:** add `brutus` to internal `_OPTIONAL_TOOLS` (opt-in feature ⇒ warns, never
  fails the `doctor` gate). Chromium stays implicit (web degrades if absent).
- **Flow map:** add `StepMeta` for `creds_test_net`/`creds_test_web` in `internal/flowmeta.py`
  (documentation; not gate-required since the stages are absent by default, same as `ai_credential_research`).
- **Config snapshot:** `PTFLOW_CREDS_TEST`/`PTFLOW_CREDS_MODE` recorded in `<activity>/config.toml` via
  the existing `runconfig` snapshot if surfaced there; otherwise logged at preflight like `PTFLOW_PROFILE`.

## 10. Testing

- Pure-unit: candidate→socket matching, HTTP/non-HTTP routing, `_BRUTUS_PROTO` mapping, Brutus JSONL
  parsing (fixture corpus, as with the existing `parse_nxc_*`/`parse_*` parsers), the lockout gate, and
  the redaction helper.
- Stage-level: `PTFLOW_CREDS_TEST` off ⇒ stages absent from the graph; on with no candidates ⇒ clean
  no-op; on with a fake Brutus stub ⇒ findings written + consolidated + `0600`.
- Optional e2e-smoke on a loopback service (as `internal`'s existing checks are smoke-tested).

## 11. Alternatives rejected

- **`nxc` + `hydra` hybrid:** its only advantage (reuse of existing `nxc` parsers) is outweighed by two
  engines/outputs, a new hydra parser, and — decisively — no native HTTP-panel handling (we'd hand-roll
  form recipes / drive Playwright). Brutus covers both with one integration.
- **Brutus `--experimental-ai`:** duplicates our source-grounded research agent, is non-deterministic,
  and is Anthropic-key-only (conflicts with the provider-agnostic seam). We feed our validated pairs.
- **Testing in `external`/`webscan` now:** the research agent isn't wired there and internet-facing
  login-spraying is a heavier RoE decision — deliberately a later phase.
- **Combo-file for `brutus creds`:** unsupported; per-pair `-u`/`-p` invocation both preserves exact
  pairing and keeps volume minimal (better for lockout anyway).
