import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from xml.etree import ElementTree as ET
from zipfile import ZipFile

import perp
import excel_export

NS = {'s': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}


class ExcelExportTests(unittest.TestCase):
    def test_dependency_failure_does_not_create_results(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'reports'
            with patch('excel_export.require_xlsxwriter', side_effect=ValueError('Install Excel dependency')):
                with self.assertRaises(ValueError):
                    perp.write_results([], {}, output, excel=True)
            self.assertFalse(output.exists())

    @unittest.skipUnless(importlib.util.find_spec('xlsxwriter'), 'Optional Excel dependency not installed')
    def test_excel_cli_preserves_literal_passwords_and_exports_charts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'passwords.txt'
            source.write_bytes(b'=1+1\n00123\nhttps://example.test\nAbc123!\n\n')
            command = [sys.executable, str(Path(perp.__file__).resolve()), str(source), '--excel', '-o', str(root/'out')]
            completed = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = next((root/'out').glob('results-*'))
            summary = json.loads((result/'summary.json').read_text())
            self.assertTrue(summary['excel_export'])
            self.assertEqual(summary['product_name'], 'Password Excel(lent) Reporting Python')
            report = (result/'password_report.html').read_text(encoding='utf-8')
            self.assertIn('href="password_report.xlsx"', report)
            self.assertIn('<h1>Password Excel(lent) Reporting Python</h1>', report)
            self.assertIn('brand-logo', report)
            with ZipFile(result/'password_report.xlsx') as archive:
                self.assertIsNone(archive.testzip())
                workbook = ET.fromstring(archive.read('xl/workbook.xml'))
                self.assertEqual([sheet.attrib['name'] for sheet in workbook.findall('s:sheets/s:sheet', NS)], ['Summary', 'Passwords', 'Masks'])
                strings = ET.fromstring(archive.read('xl/sharedStrings.xml'))
                text = [''.join(item.itertext()) for item in strings]
                passwords = ET.fromstring(archive.read('xl/worksheets/sheet2.xml'))
                cells = {cell.attrib['r']: cell for cell in passwords.findall('.//s:c', NS)}
                self.assertEqual(text[int(cells['A2'].find('s:v', NS).text)], '=1+1')
                self.assertEqual(text[int(cells['A3'].find('s:v', NS).text)], '00123')
                self.assertFalse(passwords.findall('.//s:f', NS))
                self.assertFalse(passwords.findall('.//s:hyperlink', NS))
                self.assertTrue(passwords.findall('.//s:pane', NS))
                self.assertEqual(len(passwords.findall('s:sheetData/s:row', NS)), 6)
                overview = ET.fromstring(archive.read('xl/worksheets/sheet1.xml'))
                totals = {cell.attrib['r']: cell for cell in overview.findall('.//s:c', NS)}
                self.assertEqual(totals['B13'].find('s:v', NS).text, '5')
                for formula in overview.findall('.//s:f', NS):
                    self.assertRegex(formula.text, r'^B\d+/\$B\$13$')
                self.assertIn('Hash / credential type', text)
                self.assertIn('Plaintext (no hash)', text)
                self.assertEqual(len([name for name in archive.namelist() if name.startswith('xl/charts/chart') and name.endswith('.xml')]), 3)
                self.assertEqual(len([name for name in archive.namelist() if name.startswith('xl/tables/table') and name.endswith('.xml')]), 2)

    @unittest.skipUnless(importlib.util.find_spec('xlsxwriter'), 'Optional Excel dependency not installed')
    def test_excel_limits_fail_without_silent_truncation(self):
        with self.assertRaisesRegex(ValueError, 'character cell limit'):
            excel_export.validate_export([{'password': 'a'*32768}], {'masks': []})


if __name__ == '__main__':
    unittest.main()
