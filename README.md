# Loki Log Summary Sidecar

This service reads recent Loki logs, groups them into short quiet-period
windows, asks an Ollama-compatible endpoint for a cautious summary, and writes
the result back to Loki as `job="log_summary"`.

The Compose stack defaults to:

- Loki: `http://loki:3100`
- Ollama: `http://192.168.5.50:11434/`
- Model: `qwen2.5:7b`
- Analysis interval: 10 seconds
- Allowed interval range: 5 to 30 seconds
- Input: all logs except generated summaries and the sidecar's own container

Override these values in the Compose environment rather than changing the
application. Important settings include `OLLAMA_URL`, `OLLAMA_MODEL`,
`ANALYSIS_INTERVAL_SECONDS`, `QUIET_PERIOD_SECONDS`, `INPUT_QUERY`,
`MAX_ANALYSIS_LINES`, and `STATE_PATH`.

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
