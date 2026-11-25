import shutil
import subprocess
import unittest
from pathlib import Path
from dashboard_renderer import chart, donut, pie_items


class DashboardChartTests(unittest.TestCase):
    def test_composition_includes_unlisted_records(self):
        items = [{"label": str(i), "count": 1} for i in range(20)]
        parts = pie_items(items, 10000)
        self.assertEqual(len(parts), 7)
        self.assertEqual(parts[-1], {"label": "Other categories", "count": 9994})
        self.assertEqual(sum(part["count"] for part in parts), 10000)

    def test_no_other_for_complete_small_composition(self):
        self.assertEqual(pie_items([{"label": "one", "count": 3}, {"label": "zero", "count": 0}], 3), [{"label": "one", "count": 3}])
        self.assertEqual(pie_items([], 0), [])

    def test_svg_and_legend_escape_labels_and_preserve_table(self):
        data = [{"label": '</script><img onerror="alert(1)">', "count": 1}]
        rendered = chart("Test", data, 1, pie=True)
        self.assertIn('<svg ', rendered)
        self.assertIn('role="img"', rendered)
        self.assertIn('aria-pressed="true"', rendered)
        self.assertIn('View chart data', rendered)
        self.assertNotIn('<img ', rendered)
        self.assertNotIn('</script>', rendered)
        self.assertIn('stroke-dasharray="100.00000000 0.00000000"', rendered)

    def test_overlapping_chart_stays_a_bar_chart(self):
        rendered = chart("Overlapping", [{"label": "Upper", "count": 4}, {"label": "Lower", "count": 4}], 4)
        self.assertNotIn('donut-chart', rendered)

    def test_mask_key_is_contextual_native_disclosure(self):
        rendered = chart('Most frequent masks', [{'label': '?u?d', 'count': 1}], 1, pie=True, mask_help=True)
        self.assertIn('<details class="mask-help" id="mask-key">', rendered)
        self.assertIn('<summary>Mask key', rendered)
        for token in ('?u', '?l', '?d', '?s', '?b'):
            self.assertIn('<code>'+token+'</code>', rendered)
        self.assertNotIn('mask-help', chart('Other chart', [], 0))

    @unittest.skipUnless(shutil.which("node"), "Node.js is optional for interaction tests")
    def test_interactions(self):
        root = Path(__file__).resolve().parent.parent
        result = subprocess.run([shutil.which("node"), str(root / "tests/check_charts.cjs"), str(root / "web/charts.js")], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
