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
from report import analyze, failed_report, normalize_report, render_entries, schedule_times


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


class RedactionTests(unittest.TestCase):
    """The provider must never see a credential, and the report must not degrade."""

    def _entries(self):
        return [
            LogEntry(1_700_000_000_000_000_000, {"host": "docker-pve3", "container": "grafana"},
                     "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEF123ghi"),
            LogEntry(1_700_000_001_000_000_000, {"host": "docker-pve3", "container": "loki"},
                     "connect 192.168.5.24:3100 refused"),
            LogEntry(1_700_000_002_000_000_000, {"host": "GNS-v2", "unit": "gns3.service"},
                     "gns3.service failed: stale bind IP 192.168.5.17"),
        ]

    def test_secrets_never_reach_the_prompt(self):
        from redact import Redactor
        entries = self._entries()
        redactor = Redactor.from_entries(entries)
        scrubbed = redactor.scrub(render_entries(collapse_repeats(entries)))
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9", scrubbed)
        self.assertNotIn("192.168.5.24", scrubbed)
        self.assertEqual(redactor.residual_risks(scrubbed), [])

    def test_pseudonyms_are_stable_so_correlation_survives(self):
        from redact import Redactor
        entries = self._entries()
        redactor = Redactor.from_entries(entries)
        scrubbed = redactor.scrub(render_entries(collapse_repeats(entries)))
        # docker-pve3 appears on two lines; both must carry the SAME placeholder,
        # or the model loses the only signal that links them.
        host_token = redactor.maps["host"]["docker-pve3"]
        self.assertEqual(scrubbed.count(host_token), 2)
        self.assertNotEqual(host_token, redactor.maps["host"]["GNS-v2"])
        # Error text is untouched - the report is only as good as what survives.
        self.assertIn("refused", scrubbed)
        self.assertIn("gns3.service failed", scrubbed)

    def test_tuned_rules_share_the_evidence_pseudonyms(self):
        from redact import Redactor
        from report import TUNED_RULES
        entries = self._entries()
        redactor = Redactor.from_entries(entries)
        evidence = redactor.scrub(render_entries(collapse_repeats(entries)))
        rules = redactor.scrub(TUNED_RULES)
        # The GNS-v2 rule must name the same placeholder the evidence uses,
        # otherwise the rule silently stops matching anything.
        token = redactor.maps["host"]["GNS-v2"]
        self.assertIn(token, rules)
        self.assertIn(token, evidence)
        self.assertNotIn("GNS-v2", rules)

    def test_response_is_restored_to_real_names(self):
        from redact import Redactor
        entries = self._entries()
        redactor = Redactor.from_entries(entries)
        redactor.scrub(render_entries(collapse_repeats(entries)))
        token = redactor.maps["host"]["docker-pve3"]
        restored = redactor.restore_obj(
            {"headline": f"{token} is unhealthy",
             "findings": [{"host": token, "evidence": [f"{token} refused"]}]})
        self.assertEqual(restored["headline"], "docker-pve3 is unhealthy")
        self.assertEqual(restored["findings"][0]["host"], "docker-pve3")
        self.assertEqual(restored["findings"][0]["evidence"], ["docker-pve3 refused"])

    def test_disabled_is_a_passthrough(self):
        from redact import Redactor
        redactor = Redactor.from_entries(self._entries(), enabled=False)
        text = "token=hunter2 on 192.168.5.24"
        self.assertEqual(redactor.scrub(text), text)
        self.assertEqual(redactor.restore(text), text)
