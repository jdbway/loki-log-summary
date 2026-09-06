# Loki Log Summary Sidecar

This service reads recent Loki logs, groups them into short quiet-period
windows, asks an Ollama-compatible endpoint for a cautious summary, and writes
the result back to Loki as `job="log_summary"`.

The Compose stack defaults to:

- Loki: `http://loki:3100`
- Provider: Ollama
- LLM endpoint: `http://192.168.5.50:11434/`
- Model: `qwen2.5:7b`
- Analysis interval: 10 seconds
- Allowed interval range: 5 to 30 seconds
- Input: all logs except generated summaries and the sidecar's own container

Override these values in the Compose environment rather than changing the
application. Important settings include `LLM_PROVIDER`, `LLM_BASE_URL`,
`LLM_MODEL`, `LLM_API_KEY_FILE`, `ANALYSIS_INTERVAL_SECONDS`,
`QUIET_PERIOD_SECONDS`, `INPUT_QUERY`, `MAX_ANALYSIS_LINES`,
`MAX_PROMPT_CHARS`, `LLM_MAX_OUTPUT_TOKENS`, and `STATE_PATH`.

`LLM_PROVIDER=ollama` uses Ollama's `/api/generate` endpoint. Set
`LLM_PROVIDER=openai_compatible` or `openrouter` to use an OpenAI-compatible
`/chat/completions` endpoint. This supports OpenRouter and compatible hosted
providers without changing the analyzer. Keep API keys in a mounted secret
file and point `LLM_API_KEY_FILE` at it.

The local Ollama profile intentionally uses smaller prompt and output defaults
for the available 4k context. OpenAI-compatible profiles use larger defaults,
and all three limits remain explicit overrides so a capable model can receive
more context. See `llm-profiles.example.json` for the complete profile format:

```json
active: openrouter
profiles:
  openrouter:
    provider: openai_compatible
    base_url: https://openrouter.ai/api/v1
    model: openai/gpt-4o-mini
    api_key_file: /run/secrets/llm_api_key
    max_analysis_lines: 200
    max_prompt_chars: 30000
    max_output_tokens: 512
```

The active profile is read before each analysis. Edit the mounted profile file
to switch providers or models without rebuilding the image. `LLM_ACTIVE_PROFILE`
can override the file's `active` value when an environment-controlled choice
is preferred. API keys are intentionally referenced by path or environment
variable and are not stored in the profile file.

OpenCode Go can use the `openai_compatible` profile if the selected service
exposes an OpenAI-compatible endpoint. Its endpoint and model name are left as
placeholders because OpenCode Go access details depend on the account/provider
configuration.

The sidecar uses `query_range` with a persistent SQLite cursor and a small
overlap window. Duplicate entries are discarded using a fingerprint of the
stream labels, timestamp, and line content.

## Health

- `GET /healthz` always reports process health.
- `GET /readyz` reports whether a recent Loki poll succeeded.

## Grafana

The HomeLab repository contains an importable Grafana dashboard. Dashboard
variables default to `All` for host, source, container, service, and level.
The level filter uses Loki's existing `detected_level` metadata and does not
require relabeling historical logs.

No pre-labeling in Grafana is required. Labels are assigned by Alloy at
ingestion; the current live labels (`host`, `job`, `container`, and
`service_name`) are sufficient for the first version.
