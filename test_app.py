import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from app import (
    Config,
    LLMSettings,
    LogEntry,
    active_llm_settings,
    collapse_repeats,
    extract_json,
    request_llm,
    select_entries,
)
from report import analyze, failed_report, normalize_report, schedule_times


class AppTests(unittest.TestCase):
    def test_anthropic_request_uses_messages_api(self):
        settings = LLMSettings(
            name="claude",
            provider="anthropic",
            base_url="https://api.anthropic.com/v1",
            model="claude-sonnet-5",
            api_key="test-key",
            api_key_file="",
            api_key_env="",
            max_analysis_lines=20,
            max_prompt_chars=1000,
            max_output_tokens=100,
            timeout_seconds=30,
        )
        with patch("app.request_json", return_value={"content": [{"type": "text", "text": "{}"}]}) as request:
            self.assertEqual(request_llm(settings, "prompt"), "{}")
        request.assert_called_once()
        self.assertEqual(request.call_args.args[0], "https://api.anthropic.com/v1/messages")
        self.assertEqual(request.call_args.kwargs["extra_headers"]["x-api-key"], "test-key")
        self.assertEqual(request.call_args.kwargs["payload"]["model"], "claude-sonnet-5")

    def test_schedule_times_are_validated_and_sorted(self):
        self.assertEqual(schedule_times("20:00,12:00,invalid,12:00,25:00"), [(12, 0), (20, 0)])

    def test_report_counts_are_derived_from_findings(self):
        report = normalize_report({"headline": "degraded", "findings": [
            {"severity": "critical", "title": "Outage"},
            {"severity": "invalid", "title": "Noise"},
        ]}, [])
        self.assertEqual(report["counts"], {"critical": 1, "high": 0, "medium": 0, "low": 1})

    def test_report_preserves_string_findings_from_llm(self):
        report = normalize_report({"findings": ["Prowlarr returned 401 Unauthorized", "Refresh the API key"]}, [])
        self.assertEqual(report["counts"]["medium"], 1)
        self.assertIn("Prowlarr", report["findings"][0]["title"])

    def test_report_rejects_truncated_llm_json(self):
        config = Config(llm_config_path="/does/not/exist")
        entries = [LogEntry(1, {"host": "nixos"}, "error evidence")]
        with patch("report.request_llm", return_value='{"headline":"incomplete"'):
            with self.assertRaisesRegex(ValueError, "invalid or truncated JSON"):
                analyze(config, entries)

    def test_failed_report_is_not_presented_as_healthy(self):
        with TemporaryDirectory() as directory:
            with patch("report.ReportConfig.report_dir", Path(directory)):
                summary = failed_report(
                    "Test",
                    __import__("datetime").datetime(2026, 1, 1),
                    ValueError("invalid or truncated JSON"),
                    16,
                    [LogEntry(1, {"host": "nixos"}, "error evidence")],
                )
            self.assertEqual(summary["counts"]["critical"], 1)
            self.assertIn("unavailable", summary["headline"])

    def test_active_profile_overrides_environment_defaults(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "profiles.json"
            path.write_text(
                '{"active":"cloud","profiles":{"cloud":{"provider":"openai_compatible",'
                '"base_url":"https://example.test/v1","model":"test-model",'
                '"max_prompt_chars":24000}}}',
                encoding="utf-8",
            )
            settings = active_llm_settings(Config(llm_config_path=str(path)))
        self.assertEqual(settings.name, "cloud")
        self.assertEqual(settings.provider, "openai_compatible")
        self.assertEqual(settings.model, "test-model")
        self.assertEqual(settings.max_prompt_chars, 24000)

    def test_extract_json_from_markdown_fence(self):
        self.assertEqual(
            extract_json('```json\n{"status":"normal"}\n```'),
            {"status": "normal"},
        )

    def test_collapse_repeats(self):
        entries = [
            LogEntry(1, {"container": "grafana"}, "same"),
            LogEntry(2, {"container": "grafana"}, "same"),
            LogEntry(3, {"container": "grafana"}, "different"),
        ]
        collapsed = collapse_repeats(entries)
        self.assertEqual([count for _, count in collapsed], [2, 1])

    def test_select_entries_prioritizes_errors(self):
        entries = [
            LogEntry(i, {"detected_level": "info"}, f"info-{i}") for i in range(10)
        ]
        entries.append(LogEntry(20, {"detected_level": "error"}, "failure"))
        selected = select_entries(entries, 3)
        self.assertIn("failure", [entry.line for entry, _ in selected])


if __name__ == "__main__":
    unittest.main()
