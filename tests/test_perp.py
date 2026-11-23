import csv
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import perp


class PerpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def file(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def test_masks_preserve_order_and_ascii_case(self):
        row = perp.analyze(b"Ab9!z", "utf-8")
        self.assertEqual(row["mask"], "?u?l?d?s?l")
        self.assertEqual([row[k] for k in ("upper", "lower", "digit", "special")], [1, 2, 1, 1])

    def test_unicode_and_binary_bytes(self):
        row = perp.analyze("é😀".encode(), "utf-8")
        self.assertEqual((row["length"], row["byte_length"], row["mask"]), (2, 6, "?b" * 6))
        row = perp.analyze(b"\xff\x00A", "utf-8")
        self.assertEqual(row["password"], "$HEX[ff0041]")
        self.assertEqual(row["mask"], "?b?b?u")
        self.assertIsNone(row["length"])

    def test_character_set_profiles_are_exclusive_and_order_independent(self):
        cases = {b"ABC": "upper", b"abc": "lower", b"Abc": "upperlower",
                 b"abc123": "alphanum", b"ABC123": "alphanum", b"Abc123": "alphanum",
                 b"Abc123!": "alphanumspecial", b"!123cAb": "alphanumspecial",
                 b"abc!": "alphaspecial", b"123": "numeric", b"123!": "numspecial",
                 b"! ": "special", b"": "empty", b"Abc123!\xff": "non-ASCII/control"}
        for raw, expected in cases.items():
            with self.subTest(expected=expected, length=len(raw)):
                self.assertEqual(perp.analyze(raw, "utf-8")["charset_profile"], expected)
        path = self.file("profiles.txt", b"Abc\nabc123\nABC123\nAbc123!\n\n")
        rows, summary = perp.collect([path], "plaintext", "utf-8", b":", None)
        counts = {item["label"]: item["count"] for item in summary["character_set_profiles"]}
        self.assertEqual(counts, {"upperlower": 1, "alphanum": 2, "alphanumspecial": 1, "empty": 1})
        self.assertEqual(sum(counts.values()), len(rows))
        report = perp.dashboard(rows, summary)
        self.assertIn("Character-set profiles", report)
        self.assertIn("upperlower = both letter cases only", report)

    def test_potfile_colons_hex_and_empty(self):
        path = self.file("hashcat.potfile", b"hash:abc:def\r\nhash:$HEX[4121ff]\nhash:\n\n")
        actual = list(perp.records(path, "auto", "utf-8", b":", 1))
        self.assertEqual([r[1] for r in actual], [b"abc:def", b"A!\xff", b""])
        self.assertEqual([r[0] for r in actual], [1, 2, 3])

    def test_salted_fields_are_explicit(self):
        path = self.file("john.pot", b"hash:salt:pass:word\n")
        self.assertEqual(list(perp.records(path, "potfile", "utf-8", b":", 2))[0][1], b"pass:word")

    def test_plaintext_preserves_whitespace_empty_and_literal_hex(self):
        path = self.file("plain.txt", b"\xef\xbb\xbf a \r\n\n$HEX[4142]\nx:y\n")
        self.assertEqual([r[1] for r in perp.records(path, "auto", "utf-8", b":", 1)],
                         [b" a ", b"", b"$HEX[4142]", b"x:y"])

    def test_trailing_control_byte_without_newline_is_preserved(self):
        path = self.file("plain.txt", b"password\r")
        self.assertEqual(list(perp.records(path, "plaintext", "utf-8", b":", 1))[0][1], b"password\r")

    def test_malformed_potfiles_fail_with_line_context(self):
        for content in (b"missing separator\n", b"h:$HEX[xyz]\n", b"h:$HEX[a]\n"):
            path = self.file("bad.pot", content)
            with self.assertRaisesRegex(ValueError, r"bad.pot:1:"):
                list(perp.records(path, "auto", "utf-8", b":", 1))

    def test_discovery_deduplicates_and_excludes_previous_results(self):
        first = self.file("in/a.txt", b"one")
        second = self.file("in/sub/b.pot", b"h:two")
        self.file("in/results-20260101/passwords.txt", b"old")
        self.file("in/HashcatMasks.txt", b"?l")
        self.file("in/ignore.xlsx", b"not text")
        self.assertEqual(perp.discover([str(self.root / "in"), str(first)], True), sorted([first, second]))
        self.assertEqual(perp.discover([str(self.root / "in" / "*.txt")]), sorted([first, self.root / "in/HashcatMasks.txt"]))
        with self.assertRaises(ValueError):
            perp.discover([str(self.root / "missing*")])

    def test_case_sensitive_frequencies_and_duplicate_records(self):
        path = self.file("plain.txt", b"Pass\npass\nPass\n\n")
        rows, summary = perp.collect([path], "plaintext", "utf-8", b":", 1)
        self.assertEqual((summary["total"], summary["unique"], summary["duplicate_records"], summary["empty_passwords"]), (4, 3, 1, 1))
        self.assertEqual(summary["top_passwords"][0], {"label": "Pass", "count": 2})
        self.assertEqual(sum(i["count"] for i in summary["masks"]), len(rows))
        self.assertEqual(len(summary["sources"][0]["sha256"]), 64)

    def test_outputs_escape_html_and_csv_and_do_not_overwrite(self):
        path = self.file("plain.txt", b"</template><script>alert(1)</script>\n=1+1\n@SUM(1)\n\n")
        rows, summary = perp.collect([path], "auto", "utf-8", b":", 1)
        output = self.root / "out"
        first = perp.write_results(rows, summary, output)
        second = perp.write_results(rows, summary, output)
        self.assertNotEqual(first, second)
        self.assertEqual(len(list(first.iterdir())), 6)
        report = (first / "password_report.html").read_text(encoding="utf-8")
        self.assertNotIn("</template><script>alert", report)
        self.assertIn("&lt;/template&gt;", report)
        self.assertNotIn('<script src=', report)
        with (first / "passwords.csv").open(encoding="utf-8-sig", newline="") as stream:
            exported = list(csv.DictReader(stream))
        self.assertEqual(exported[1]["password"], "'=1+1")
        self.assertEqual(exported[2]["password"], "'@SUM(1)")
        masks = (first / "HashcatMasks.hcmask").read_text().splitlines()
        self.assertNotIn("", masks)
        self.assertEqual(len(masks), len(set(masks)))
        self.assertEqual(json.loads((first / "summary.json").read_text())["total"], 4)

    def test_python_cli_structured_potfile(self):
        hashed = b"$krb5tgs$23$*svc$EXAMPLE.TEST$MSSQLSvc/server:1433*$" + b"a" * 32 + b"$" + b"b" * 128
        path = self.file("input with spaces.potfile", hashed + b":Abc123!\n" + hashed + b":abc123!\n")
        engine = Path(perp.__file__).resolve()
        out = self.root / "python reports"
        completed = subprocess.run([sys.executable, str(engine), str(path), "-o", str(out)], capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        expected = json.loads(next(out.glob("results-*/summary.json")).read_text())
        self.assertEqual({p["label"] for p in expected["top_passwords"]}, {"Abc123!", "abc123!"})

    def test_errors_leave_no_results(self):
        out = self.root / "reports"
        empty = self.file("empty.txt", b"")
        self.assertEqual(perp.main([str(empty), "-o", str(out)]), 1)
        self.assertFalse(out.exists())
        self.assertEqual(perp.main([str(empty), "--password-field", "0", "-o", str(out)]), 1)
        self.assertEqual(perp.main([str(empty), "--encoding", "utf-16", "-o", str(out)]), 1)

    @unittest.skipUnless(shutil.which("node"), "Node.js is optional; needed only for JavaScript interaction checks")
    def test_dashboard_javascript_interactions(self):
        path = self.file("interactive.txt", b"a\n" * 120 + b"</template><script>alert(1)</script>\n" + b"x" * 36 + b"\n")
        rows, summary = perp.collect([path], "plaintext", "utf-8", b":", 1)
        output = perp.write_results(rows, summary, self.root / "out")
        completed = subprocess.run([shutil.which("node"), str(Path(__file__).with_name("check_dashboard.cjs")),
                                    str(output / "password_report.html")], capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_empty_password_dashboard_and_accessible_markup(self):
        path = self.file("empty-passwords.txt", b"\n\n")
        rows, summary = perp.collect([path], "plaintext", "utf-8", b":", None)
        report = perp.dashboard(rows, summary)
        self.assertIn('<meta name="color-scheme" content="light dark">', report)
        self.assertIn('value="system"', report)
        self.assertIn('scope="col"', report)
        self.assertIn('scope="row"', report)
        self.assertIn('role="region" aria-labelledby="records-caption"', report)
        self.assertIn('role="status" aria-atomic="true"', report)
        self.assertIn('for="search"', report)
        self.assertIn('@container', report)
        self.assertNotIn('@@', report)


if __name__ == "__main__":
    unittest.main()
