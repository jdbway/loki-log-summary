import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from app import LogEntry, active_llm_settings, collapse_repeats, extract_json, select_entries, Config


class AppTests(unittest.TestCase):
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
