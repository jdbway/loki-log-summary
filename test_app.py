import unittest

from app import LogEntry, collapse_repeats, extract_json, select_entries


class AppTests(unittest.TestCase):
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
