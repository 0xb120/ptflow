# Design — Optional AI layer (`--ai`) for ptflow

- **Date:** 2026-07-04
- **Status:** Approved (design); pending implementation plan
- **Scope:** external pipeline (v1). Reusable core (`core/ai/`) so other pipelines can adopt later.

## 1. Motivation

The external enumeration pipeline is a deterministic, tool-driven DAG whose only state is files on
disk. It already carries a **dormant AI seam** — `core/agent.py`'s `HypothesisProvider`/`StubProvider`,
called at the terminal fan-in (`orchestrator._terminal_fanin`, right after `consolidate`). Today the
seam runs `StubProvider` (one low-confidence draft per service) and produces
`<activity>/findings/hypotheses.jsonl`.

This design introduces an **opt-in AI layer** that adds LLM judgment at the points where the pipeline's
hand-tuned heuristics are weakest (reasoning over findings, interpreting noisy tool output, contextual
guessing), **without touching the proven deterministic core when AI is off**. It is gated behind a
single `--ai` flag: with AI off, `pipeline.stages` is byte-identical to today, so the resume markers,
flow-map gate, and DAG are unchanged.

**Primary SDK is the Anthropic Python SDK (Messages API).** "Any other provider via API" is served by an
internal `LLMClient` seam: today via the Anthropic SDK's `base_url` (Anthropic-compatible gateways,
Bedrock, Vertex) with zero new code; a native non-Anthropic implementation (e.g. OpenAI) is a future
implementation behind the same protocol (see Roadmap).

## 2. Goals / Non-goals

**Goals (v1):**
- A `--ai` flag that turns on four AI stages; off by default, fully additive.
- An `LLMClient` provider seam with one concrete implementation, `AnthropicClient`.
- Four AI stages: `ai_triage`, `ai_report`, `ai_secret_triage`, `ai_wordlist`.
- Every AI stage: reads/writes on-disk artifacts only, best-effort (never aborts the run), respects
  write-once, additive (never deletes prior findings).

**Non-goals (v1) — see Roadmap:**
- Native non-Anthropic provider implementation (OpenAI etc.).
- `ai_mine_bodies`, `ai_cve_rank`, `ai_param_values` stages.
- `ai_screenshot` (vision) — **dropped by request, not deferred.**
- Per-stage AI toggles; global token budget; `ptflow doctor` AI checks.

## 3. Architecture overview

```
                     ┌──────────── core/ai/ (pipeline-agnostic seam) ────────────┐
                     │  LLMClient (Protocol)  ·  AnthropicClient  ·  make_client()│
                     └────────────────────────────────────────────────────────────┘
                                              ▲  used by
        ┌──────────────────────── pipelines/external/ai.py ────────────────────────┐
        │ ai_wordlist(activity, app_id)      · phase 2 · net=False                  │
        │ ai_secret_triage(activity, app_id) · phase 4 · net=False                  │
        │ ClaudeHypothesisProvider           · terminal (agent seam)                │
        │ report(activity)                   · terminal hook (after agent)          │
        │  + per-stage Pydantic schemas + prompts                                   │
        └────────────────────────────────────────────────────────────────────────┘
```

With AI off, none of the per-app AI stages are in `pipeline.stages`, `provider()` returns
`StubProvider`, and `report()` is a no-op.

## 4. Components

### 4.1 Provider seam — `core/ai/`

New package. Pipeline-agnostic; knows nothing about pentest artifacts.

- **`core/ai/client.py`**
  - `class LLMClient(Protocol)`:
    - `name: str`
    - `complete_json(self, system: str, user: str, schema: type[T]) -> T | None` — structured output;
      returns a validated Pydantic model, or `None` on any failure (best-effort).
    - `complete_text(self, system: str, user: str, *, max_tokens: int = 64000) -> str | None` — long
      free text (the report), or `None` on failure.
  - `class AnthropicClient(LLMClient)`:
    - Constructed with `model`, optional `base_url`, optional `effort`.
    - **Lazy, guarded import of `anthropic`** inside `__init__`/methods — an `ImportError` (extra not
      installed) surfaces to `make_client()` as `None`, not a crash.
    - `complete_json` → `client.messages.parse(model=…, max_tokens=…, output_format=schema, …)` →
      `.parsed_output` (validated Pydantic model). Adaptive thinking and per-call `effort` are applied
      via the SDK's supported parameter shape — the exact kwarg combination is verified against the
      installed SDK at implementation time (do not guess the `parse` + `output_config` interaction).
    - `complete_text` → `client.messages.stream(...).get_final_message()`, concatenated text blocks
      (streaming so the large `max_tokens` doesn't hit an HTTP timeout).
    - Prompt caching on the shared, stable `system` block (`cache_control` ephemeral) to cut cost.
    - All API errors caught → logged (via `core.log`) → return `None`. A per-call timeout relies on the
      SDK default (10 min) + retries; the run's teardown-kill still applies.
    - Default model `claude-opus-4-8`; adaptive thinking; effort per call (`high` for reasoning stages,
      lower for mechanical triage).
  - `def make_client() -> LLMClient | None`:
    - Returns `None` when `PTFLOW_AI` is not truthy (same truthiness set as `runconfig._TRUE`).
    - Otherwise builds `AnthropicClient` from `PTFLOW_AI_MODEL` / `PTFLOW_AI_BASE_URL` /
      `PTFLOW_AI_PROVIDER` (v1: only `anthropic`; unknown value → warn + `None`).
    - Any construction failure (missing extra, no credentials) → log + `None`.

- **API key** is resolved by the Anthropic SDK from the standard `ANTHROPIC_API_KEY` env or an
  `ant auth login` profile. It is deliberately **not** a ptflow knob — so it never lands in the
  `config.toml` snapshot. Documented in CLAUDE.md.

- **Dependency:** `anthropic` is an **optional** dependency group/extra (`ai`). `uv sync --all-groups`
  (the dev gate) installs it, so tests run with it present. Production installs without the `ai` extra
  simply can't use `--ai` (best-effort skip). Version floor pinned at implementation (must support
  `messages.parse()`/`output_config`/adaptive thinking + `claude-opus-4-8`).

### 4.2 Config & flag — `cli.py` + `core/runconfig.py`

- **`cli.py`:** add `run.add_argument("--ai", action="store_true", …)`. In `_run`, when `args.ai`,
  prepend `"ai=on"` to the `--set` overrides list so it flows through the normal precedence
  (`--set` > env > file > default) before `runconfig.apply()` writes the env.
- **`runconfig._KNOBS`:** add
  - `Knob("ai", "PTFLOW_AI", "bool")`
  - `Knob("ai.model", "PTFLOW_AI_MODEL", "str")`
  - `Knob("ai.base_url", "PTFLOW_AI_BASE_URL", "str")`
  - `Knob("ai.provider", "PTFLOW_AI_PROVIDER", "str")`
  - `PTFLOW_AI_PROVIDER` added to `_ENUMS` (`("anthropic",)` for now — invalid value exits 2, consistent
    with the existing enum validation).
- The effective values are snapshotted to `<activity>/config.toml` as usual (no secrets among them).

### 4.3 Stage placement in the external DAG — `pipelines/external/pipeline.py`

Per-app AI stages are appended to `stages` **only when `PTFLOW_AI` is truthy at import** (env is
populated by `runconfig.apply()` before the pipeline is imported — the same mechanism the tool-path
constants already rely on):

```python
_AI = os.getenv("PTFLOW_AI", "").strip().lower() in {"1", "on", "true", "yes"}
_AI_STAGES = (
    Stage("ai_wordlist", ai.ai_wordlist, per_app=True, phase=2, net=False),
    Stage("ai_secret_triage", ai.ai_secret_triage, needs=(), per_app=True, phase=4, net=False),
)
stages = (…existing…, *(_AI_STAGES if _AI else ()))
```

Rationale for the phases:
- **`ai_wordlist` → phase 2.** It reads the phase-1 corpus (endpoints/tech/meta), so it can run as soon
  as the phase-1 barrier clears. Putting it in phase 2 means the **phase-3 barrier guarantees**
  `wl_custom/ai_seed.txt` exists before `build_content_wordlist` (phase 3) reads it — so no
  cross-phase / conditional `needs` edge is required; `build_content_wordlist` folds it via a **tolerant
  read** (absent → skipped).
- **`ai_secret_triage` → phase 4.** `secrets.jsonl` is written at the tail of `content_discovery`
  (phase 3); the phase-4 barrier guarantees it present. Reads it, writes the sidecar
  `findings/secrets_triage.jsonl` (**write-once**: it never mutates `secrets.jsonl`).

### 4.4 Terminal stages — `orchestrator._terminal_fanin` + `core/agent.py` + external

- **`ai_triage` (revive the agent seam).**
  - `ExternalPipeline.provider()` returns `ClaudeHypothesisProvider(make_client())` when a client is
    available, else `StubProvider()`.
  - `core/agent.py`: **broaden the provider input from `services` to consolidated findings.**
    `propose_hypotheses(activity, provider)` reads `<activity>/findings/*.jsonl` (each record already
    stamped `app_id` + type by `consolidate`) instead of per-app `services.jsonl` (which external never
    wrote — it was internal-shaped). `HypothesisProvider.propose(findings: Sequence[dict]) ->
    list[HypothesisDraft]`; `StubProvider` updated to iterate findings (drops the `services` read).
  - `ClaudeHypothesisProvider.propose` sends the findings to the model via `complete_json` with a
    `Hypotheses` schema → correlation across finding types + exploitation hypotheses + FP-triage notes.
  - **Failure isolation:** `_terminal_fanin` wraps the agent call in try/except (logged + recorded),
    matching `consolidate`. (Today it is unwrapped — safe only because `StubProvider` never raises.)
  - Output unchanged in location: `<activity>/findings/hypotheses.jsonl`.

- **`ai_report` (new terminal hook).**
  - Duck-typed `report(activity)` on `ExternalPipeline` (same convention as `consolidate`/`preflight` —
    read via `getattr`, off the Protocol). `_terminal_fanin` calls it **after** the agent,
    failure-isolated.
  - Reads consolidated `findings/*.jsonl` + `findings/hypotheses.jsonl` → `complete_text` →
    `<activity>/report.md` (executive summary, prioritized findings, remediation). No-op when
    `make_client()` is `None` (AI off / unavailable).

### 4.5 Downstream fold-ins

- **`build_content_wordlist`** (external `tasks.py`): add `wl_custom/ai_seed.txt` as an additional
  custom-layer source (tolerant read; absent → no change). Additive only.
- **`consolidate`** (external `tasks.py`): add `secrets_triage` to `_CONSOLIDATE_SOURCES` so per-app
  `findings/secrets_triage.jsonl` lifts to `<activity>/findings/secrets_triage.jsonl`.
- **`flowmeta.py`**: add `StepMeta` for `ai_wordlist` and `ai_secret_triage` (the two Stage objects).
  Terminal hooks (`ai_triage`/`ai_report`) are not `Stage`s (like `agent`/`consolidate`), so they need
  no `StepMeta`. Extra `StepMeta` entries are harmless when the stages are absent, so they can be
  declared unconditionally — keeping the parametrized flow-map gate green whether AI is on or off.

## 5. Artifacts (new)

```
<activity>/
  findings/hypotheses.jsonl        # ai_triage (was StubProvider) — now Claude-backed when --ai
  findings/secrets_triage.jsonl    # consolidate lift of per-app secret verdicts
  report.md                        # ai_report
  scans/<app_id>/
    wl_custom/ai_seed.txt          # ai_wordlist → folded by build_content_wordlist
    findings/secrets_triage.jsonl  # ai_secret_triage (sidecar; secrets.jsonl untouched)
```

## 6. Invariant compliance

- **Files-as-only-state:** every AI stage communicates only through on-disk artifacts. ✓
- **Write-once:** all outputs are new files; `secrets.jsonl` is read, never mutated (sidecar). ✓
- **Additive / no-delete-on-resume:** AI stages only create; `--resume` semantics unchanged (per-app AI
  stages get `.state/<stage>.done` markers like any Stage; terminal hooks re-run on resume, cheaply). ✓
- **Network cap:** AI calls hit the API, not the target → `net=False` (they don't consume `_NET_SLOTS`);
  per-app AI stages are still bounded by the fan-out cap (`_FANOUT_SLOTS`). ✓
- **Best-effort:** missing `anthropic` extra / missing credentials / API error → log + skip; terminal
  hooks are failure-isolated. A `--ai` run never fails *because of* the AI layer. ✓
- **Determinism:** LLM output is non-deterministic. This is acceptable because the layer is **off by
  default and purely additive** — the determinism invariant governs the core DAG, and the AI layer is an
  opt-in overlay that adds files without changing any deterministic stage's inputs. Stated explicitly.
- **Flow-map:** with AI off, `stages` is byte-identical to today; with AI on, the two new Stages have
  `StepMeta`. Gate stays green either way. ✓

## 7. Cost model

- Volume is bounded by the number of app groups: `ai_wordlist` and `ai_secret_triage` run once per app;
  `ai_triage`/`ai_report` run once per activity. No corpus-wide LLM passes in v1 (that's `ai_mine_bodies`,
  roadmap).
- Default model `claude-opus-4-8`; overridable via `PTFLOW_AI_MODEL` (a cheaper tier is reasonable for
  the mechanical `ai_secret_triage`; per-stage model selection is roadmap — v1 uses one model).
- Per-stage input caps (corpus sample size for wordlist; secret batch size; findings truncation for
  triage/report) keep prompts bounded.
- Structured outputs (`messages.parse`) avoid brittle parsing; prompt caching on the shared system block
  reduces repeated-prefix cost across per-app calls.

## 8. Testing strategy

- **Pure/injectable:** every stage function takes/looks-up an `LLMClient`; tests inject a **fake client**
  returning canned structured output. This exercises prompt assembly, file I/O, schema handling, and the
  fold-ins (wordlist layer, consolidate lift) **with no network**. Matches the project convention of
  keeping transforms unit-testable apart from I/O plumbing.
- **AI-off path:** `make_client()` returns `None` → per-app AI stages absent from `stages`;
  `provider()` returns `StubProvider`; `report()` no-ops. Assert `stages` is byte-identical to the
  non-AI list. Existing `StubProvider`/`propose_hypotheses` tests updated for the broadened
  findings input.
- **Flow-map gate:** parametrized test still passes; new `StepMeta` present.
- **No live API calls in the test suite.** A live smoke test is manual/opt-in (documented), not in CI.

## 9. Roadmap (deferred; tracked in the `recon-backlog` memory)

- `ai_mine_bodies` — LLM over the `-srd` corpus for API/auth/notes (token-heavy → needs strict caps).
- `ai_cve_rank` — contextual exploitability ranking of `cve_lookup` output.
- `ai_param_values` — semantically plausible parameter seed values.
- Native non-Anthropic provider (e.g. OpenAI) behind `LLMClient`.
- Per-stage AI toggles; global token-budget knob; `ptflow doctor` AI dependency/credential check.

## 10. Open questions

None outstanding — provider shape, v1 stage set, SDK surface, and stage placement are all resolved.
`ai_screenshot` is dropped (not deferred) by request.
