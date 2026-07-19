# AI provider setups

Install the OpenAI-compatible runtime once:

```bash
uv sync --extra ai
```

For both `external` and `webscan`, the presets enable all five additive AI functions: contextual
wordlist generation, policy-gated CVE PoC interpretation, secret-lead triage, cross-finding
hypotheses, and `report-ai.md`. Override any
preset value with `--set ai.model=...` or `--set ai.base_url=...`.

Every preset also enables the run-scoped cache and conservative budgets. Usage is written to
`<activity>/ai/usage.jsonl`; cached validated outputs live under `<activity>/ai/cache/`.

## Ollama (local)

```bash
ollama pull gpt-oss:20b
ollama serve
uv run ptflow run external demo ./scope.txt --config configs/ai/ollama.toml
```

The default endpoint is `http://127.0.0.1:11434/v1`; local Ollama needs no credential. The example
model is about 14 GB, so select a smaller installed chat/instruct model when necessary.

## Ollama Cloud

```bash
export OLLAMA_API_KEY=...
uv run ptflow run external demo ./scope.txt --config configs/ai/ollama-cloud.toml
```

The preset uses Ollama's OpenAI-compatible cloud endpoint at `https://ollama.com/v1` with
`gpt-oss:120b`, reads authentication only from `OLLAMA_API_KEY`, and selects `profile = "home"`.
It connects directly to Ollama Cloud, so no local `ollama serve` process is required. Create the key
in [Ollama's API key settings](https://ollama.com/settings/keys); change `ai.model` when that model is
not available to the account.

## OpenRouter

```bash
export OPENROUTER_API_KEY=...
uv run ptflow run external demo ./scope.txt --config configs/ai/openrouter.toml
```

The default endpoint is `https://openrouter.ai/api/v1`; authentication is read only from
`OPENROUTER_API_KEY`, avoiding accidental reuse of a key belonging to another provider.

## Hugging Face Inference Providers

```bash
export HF_TOKEN=hf_...
uv run ptflow run external demo ./scope.txt --config configs/ai/huggingface.toml
```

The token needs Inference Providers permission. The preset uses automatic fastest-provider routing;
change the model suffix to `:cheapest`, `:preferred`, or a concrete provider when desired.

## Arbitrary OpenAI-compatible endpoint

```toml
[ai]
enabled = true
provider = "openai-compatible"
base_url = "https://llm.example.test/v1"
model = "your-model-id"
```

Set `OPENAI_API_KEY` when that endpoint requires authentication.

## Mixed routing by stage

`configs/ai/mixed.toml` keeps secret triage on local Ollama, sends contextual wordlist generation to
Hugging Face, and uses OpenRouter for cross-finding triage and the executive report. Any stage can
override `enabled`, `provider`, `model`, `base_url`, and `max_output_tokens`:

```toml
[ai.stages.report]
provider = "openrouter"
model = "openai/gpt-oss-20b"
max_output_tokens = 12000
```

The AI route names are `wordlist`, `cve_poc`, `secret_triage`, `research`, `triage`, and `report`.
`research` searches DuckDuckGo directly and/or Google through Playwright/Chromium rendering;
its first consumer proposes source-grounded factory/default credentials without attempting login. `cve_poc` never
executes Nuclei or model-supplied commands: it can issue only one policy-validated target-local
GET/HEAD/OPTIONS request, otherwise it records `manual_review`.

## Data handling

Remote providers receive assessment evidence and endpoint/technology metadata. Secret values are
redacted by default, including when secret-triage findings are later used by triage or reporting.
Set `ai.remote_secrets = "off"` to exclude those findings from remote prompts, or `"full"` only when
the rules of engagement explicitly allow it. Ollama Cloud uses `OLLAMA_API_KEY`; prefer local Ollama
for data that must remain local.

Claude Code is retained only as a legacy provider in the separate `ai-claude` extra. The post-merge
documentation hook is independent of this runtime layer and still uses the `claude` CLI when present.
