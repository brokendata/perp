"""Synthetic account/hash fixtures only; no supplied engagement data."""
import csv
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from zipfile import ZipFile

import perp
from account_inventory import (EMPTY_LM, EMPTY_NT, md4, nt_hash, load_inventory,
                               load_directory_context, inventory_type_map, correlate)


class AccountInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def file(self, name, text):
        path = self.root/name
        path.write_text(text, encoding='utf-8')
        return path

    def row(self, name, rid, password=b'Alpha1!', lm=EMPTY_LM, status=None):
        state = f' (status={status})' if status else ''
        return f'{name}:{rid}:{lm}:{nt_hash(password)}:::{state}\n'

    def analyze(self, inventory_text, pot=None, context=None, domain=None):
        path = self.file('inventory.ntds', inventory_text)
        inventory = load_inventory([path], domain)
        if context:
            load_directory_context(inventory, self.file('context.csv', context))
        recoveries = []
        rows, summary = perp.collect([pot] if pot else [], 'auto', 'utf-8', b':', None,
                                     recovery_records=recoveries, inventory_types=inventory_type_map(inventory), allow_empty=True)
        report, seeds = correlate(inventory, recoveries, snapshot_time='2026-11-25T12:00:00+00:00')
        return rows, summary, report, seeds

    def test_md4_rfc_vectors_and_nt_unicode(self):
        for value, digest in ((b'', '31d6cfe0d16ae931b73c59d7e0c089c0'),
                              (b'a', 'bde52cb31de33e46245e05fbdbd6fb24'),
                              (b'abc', 'a448017aaf21d8525fc10ae87aa6729d'),
                              (b'message digest', 'd9130a8164549fe818874806e1c7014b'),
                              (b'abcdefghijklmnopqrstuvwxyz', 'd79e1c308aa5bbcdeea8ed63df412da9'),
                              (b'1234567890'*8, 'e33b4ddc9c38f2199c3e7b164fcc0536')):
            self.assertEqual(md4(value), digest)
        self.assertEqual(nt_hash(b'password'), '8846f7eaee8fb117ad06bdd830b7586c')
        self.assertEqual(nt_hash('páss😀'.encode()), md4('páss😀'.encode('utf-16le')))

    def test_current_status_reuse_and_empty_password(self):
        text = self.row('EXAMPLE.TEST\\service', 1001, status='Enabled')
        text += self.row('EXAMPLE.TEST\\retired', 1002, status='Disabled')
        text += self.row('EXAMPLE.TEST\\unknown', 1003, b'Other2!')
        text += self.row('EXAMPLE.TEST\\blank', 1004, b'', status='Disabled')
        pot = self.file('known.potfile', nt_hash(b'Alpha1!')+':Alpha1!\n')
        rows, summary, report, _ = self.analyze(text, pot)
        states = {r['status']: r for r in report['by_status']}
        self.assertEqual((states['Enabled']['accounts'], states['Enabled']['recovered']), (1, 1))
        self.assertEqual((states['Disabled']['accounts'], states['Disabled']['recovered']), (2, 2))
        self.assertEqual(states['Unknown']['recovered'], 0)
        self.assertEqual(report['metrics']['enabled_disabled_reuse_groups'], 1)
        self.assertEqual(rows[0]['hash_type_basis'], 'inventory')
        self.assertEqual(summary['unique'], 1)
        self.assertEqual(report['accounts'][-1]['recovery_basis'], 'known empty')
        payload = json.dumps(report)
        self.assertNotIn(nt_hash(b'Alpha1!'), payload)
        self.assertNotIn('Alpha1!', payload)

    def test_history_overlaps_not_reuse_and_history_to_current_bridge(self):
        text = self.row('EXAMPLE.TEST\\current', 1001, status='Enabled')
        text += self.row('EXAMPLE.TEST\\current_history0', 1001)
        text += self.row('EXAMPLE.TEST\\past', 1002, b'New2!', status='Disabled')
        text += self.row('EXAMPLE.TEST\\past_history0', 1002)
        text += self.row('EXAMPLE.TEST\\past_history1', 1002, b'Older3!')
        pot = self.file('recovery.potfile', nt_hash(b'Alpha1!')+':Alpha1!\n')
        _, _, report, _ = self.analyze(text, pot)
        self.assertEqual(report['metrics']['history_records'], 3)
        self.assertEqual(report['metrics']['current_history_overlaps'], 1)
        self.assertEqual(report['metrics']['historical_records_recovered'], 1)
        self.assertEqual(report['metrics']['history_to_current_reuse_groups'], 1)
        self.assertEqual(report['metrics']['current_reuse_groups'], 0)
        self.assertEqual(report['reuse_groups'][0]['historical_accounts'], [report['accounts'][1]['id']])

    def test_overlap_alone_does_not_create_reuse_group(self):
        _, _, report, _ = self.analyze(self.row('EXAMPLE.TEST\\demo', 1001)+self.row('EXAMPLE.TEST\\demo_history0', 1001))
        self.assertEqual(report['reuse_groups'], [])
        self.assertEqual(report['metrics']['historical_records_assessed'], 0)

    def test_machine_history_and_history_only_unknown_status(self):
        text = self.row('DCX$', 1001, b'New2!')
        text += self.row('DCX$_history0', 1001)
        text += self.row('orphan_history2', 1002, status='Enabled')
        _, _, report, _ = self.analyze(text)
        self.assertEqual(report['metrics']['current_accounts'], 1)
        self.assertEqual(report['metrics']['history_only_accounts'], 1)
        self.assertEqual(report['accounts'][0]['kind'], '$-suffixed account (unconfirmed)')
        self.assertEqual(report['accounts'][1]['status'], 'Unknown')

    def test_domain_and_file_scoping_prevents_rid_merges(self):
        a = self.file('a.ntds', self.row('one', 1001))
        b = self.file('b.ntds', self.row('one_history0', 1001))
        self.assertEqual(len(load_inventory([a, b])['accounts']), 2)
        self.assertEqual(len(load_inventory([a, b], 'EXAMPLE.TEST')['accounts']), 1)
        a.write_text(self.row('FIRST.TEST\\one', 1001)+self.row('SECOND.TEST\\two', 1001))
        self.assertEqual(len(load_inventory([a])['accounts']), 2)

    def test_exact_duplicate_records_deduplicate_but_keep_provenance(self):
        inventory = load_inventory([self.file('i.ntds', self.row('one', 1001)*2)])
        self.assertEqual(len(inventory['credentials']), 1)
        self.assertEqual(len(inventory['credentials'][0]['record_refs']), 2)

    def test_conflicting_snapshots_status_and_names_fail(self):
        cases = (self.row('one', 1001)+self.row('one', 1001, b'Different!'),
                 self.row('one', 1001, status='Enabled')+self.row('one', 1001, status='Disabled'),
                 self.row('one', 1001)+self.row('two', 1001))
        for text in cases:
            with self.assertRaises(ValueError):
                load_inventory([self.file('conflict.ntds', text)])

    def test_malformed_inventory_and_binary_fail(self):
        for text in ('not an account', 'name:500:bad:bad::: (status=Enabled)', '\x00\x01binary'):
            with self.assertRaises(ValueError):
                load_inventory([self.file('bad.ntds', text)])

    def test_literal_terminal_continuation_and_username_backslashes(self):
        text = self.row('EXAMPLE.TEST\\DCX$_history0', 1001).rstrip()+'\\\n'
        inventory = load_inventory([self.file('i.ntds', text)])
        self.assertEqual(inventory['accounts'][0]['name'], 'DCX$')
        self.assertEqual(inventory['credentials'][0]['history_index'], 0)

    def test_lm_placeholder_partial_and_both_halves_never_claim_nt_recovery(self):
        lm = 'a1'*8+'b2'*8
        text = self.row('EXAMPLE.TEST\\one', 1001, b'NotTheLMCase!', lm, 'Enabled')
        pot = self.file('lm.potfile', lm[:16]+':UPPER\n')
        _, _, report, _ = self.analyze(text, pot)
        self.assertEqual(report['accounts'][0]['lm_recovery'], 'One half matched')
        self.assertFalse(report['accounts'][0]['current_nt_recovered'])
        pot.write_text(lm[:16]+':UPPER\n'+lm[16:]+':PART\n')
        _, _, report, _ = self.analyze(text, pot)
        self.assertEqual(report['accounts'][0]['lm_recovery'], 'Both halves matched (unverified LM)')
        self.assertFalse(report['accounts'][0]['current_nt_recovered'])
        _, _, report, _ = self.analyze(self.row('EXAMPLE.TEST\\one', 1001))
        self.assertEqual(report['metrics']['current_lm_present'], 0)

    def test_invalid_nt_password_claim_does_not_recover_account(self):
        pot = self.file('bad.potfile', nt_hash(b'Alpha1!')+':Wrong!\n')
        _, _, report, seeds = self.analyze(self.row('one', 1001, status='Enabled'), pot)
        self.assertFalse(report['accounts'][0]['current_nt_recovered'])
        self.assertEqual(report['metrics']['invalid_nt_recovery_claims'], 1)
        self.assertEqual(seeds, [])

    def test_plaintext_candidates_are_offline_verified_not_assumed(self):
        candidates = self.file('candidates.txt', 'Wrong!\nAlpha1!\n')
        _, _, report, seeds = self.analyze(self.row('one', 1001, status='Enabled'), candidates)
        self.assertTrue(report['accounts'][0]['current_nt_recovered'])
        self.assertEqual(seeds, [b'Alpha1!'])

    def test_directory_roles_status_age_and_asset_are_explicit(self):
        context = ('domain,rid,privileged,service_account,status,pwd_last_set,password_never_expires,asset,owner\n'
                   'EXAMPLE.TEST,1001,true,false,Enabled,2026-11-20T12:00:00+00:00,true,example-host,Example owner\n')
        _, _, report, _ = self.analyze(self.row('EXAMPLE.TEST\\admin-name', 1001), context=context)
        a = report['accounts'][0]
        self.assertTrue(a['privileged'])
        self.assertEqual(a['status'], 'Enabled')
        self.assertEqual(a['password_age_days'], 5)
        self.assertEqual(a['asset'], 'example-host')
        _, _, plain, _ = self.analyze(self.row('EXAMPLE.TEST\\admin-name', 1001))
        self.assertIsNone(plain['accounts'][0]['privileged'])

    def test_directory_ambiguous_invalid_or_conflicting_rows_fail(self):
        for row in ('EXAMPLE.TEST,9999,true,Enabled', 'EXAMPLE.TEST,1001,maybe,Enabled',
                    'EXAMPLE.TEST,1001,true,Disabled'):
            inventory = load_inventory([self.file('i.ntds', self.row('EXAMPLE.TEST\\one', 1001, status='Enabled'))])
            context = self.file('bad.csv', 'domain,rid,privileged,status\n'+row+'\n')
            with self.assertRaises(ValueError):
                load_directory_context(inventory, context)

    def test_missing_nt_is_not_in_recovery_denominator(self):
        text = f'one:1001:{EMPTY_LM}:::: (status=Enabled)\n'
        _, _, report, _ = self.analyze(text)
        self.assertEqual(report['by_status'][0]['accounts'], 1)
        self.assertEqual(report['by_status'][0]['assessed'], 0)
        self.assertIsNone(report['by_status'][0]['recovery_rate'])

    def test_known_empty_krbtgt_has_special_exposure_not_enable_recommendation(self):
        _, _, report, _ = self.analyze(self.row('krbtgt', 502, b'', status='Disabled'))
        self.assertIn('krbtgt_credential_exposure', report['accounts'][0]['risk_flags'])

    def test_hashcat_show_username_and_hex_password(self):
        path = self.file('show.txt', 'EXAMPLE.TEST\\one:'+nt_hash(b'pass:word')+':$HEX[706173733a776f7264]\n')
        inventory = load_inventory([self.file('i.ntds', self.row('EXAMPLE.TEST\\one', 1001, b'pass:word', status='Enabled'))])
        recovered = []
        rows, _ = perp.collect([path], 'hashcat-show', 'utf-8', b':', None,
                               recovery_records=recovered, inventory_types=inventory_type_map(inventory))
        report, _ = correlate(inventory, recovered)
        self.assertEqual(rows[0]['password'], 'pass:word')
        self.assertTrue(report['accounts'][0]['current_nt_recovered'])
        with self.assertRaises(ValueError):
            perp.collect([path], 'hashcat-show', 'utf-8', b':', 1)

    def test_html_escapes_account_text_and_includes_account_units(self):
        rows, summary, risk, _ = self.analyze(self.row('EXAMPLE.TEST\\<img src=x>', 1001, status='Enabled'))
        summary['account_risk'] = risk
        report = perp.dashboard(rows, summary)
        self.assertIn('Account exposure', report)
        self.assertNotIn('<img src=x>', report)
        self.assertIn('&lt;img src=x&gt;', report)
        self.assertIn('data-unit="accounts"', report)
        self.assertIn('id="account-data"', report)
        self.assertNotIn('NaN', report)

    def run_cli(self, extra=(), include_pot=True):
        inventory = self.file('i.ntds', self.row('EXAMPLE.TEST\\enabled', 1001, status='Enabled')+
                              self.row('EXAMPLE.TEST\\disabled', 1002, status='Disabled'))
        pot = self.file('r.potfile', nt_hash(b'Alpha1!')+':Alpha1!\n')
        command = [sys.executable, str(Path(perp.__file__).resolve())]
        command += [str(pot)] if include_pot else []
        command += ['--inventory', str(inventory), '-o', str(self.root/'out'), *extra]
        completed = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return next((self.root/'out').glob('results-*'))

    def test_cli_seeds_are_opt_in_and_reports_omit_raw_inventory_hashes(self):
        result = self.run_cli()
        self.assertFalse((result/'candidate_seeds.txt').exists())
        self.assertTrue((result/'accounts.csv').is_file())
        self.assertNotIn(nt_hash(b'Alpha1!'), (result/'account_risk.json').read_text())
        with (result/'accounts.csv').open(encoding='utf-8-sig', newline='') as stream:
            self.assertEqual(len(list(csv.DictReader(stream))), 2)

    def test_cli_explicit_seed_export_is_deduplicated(self):
        result = self.run_cli(['--export-seeds'])
        self.assertEqual((result/'candidate_seeds.txt').read_bytes(), b'Alpha1!\n')

    @unittest.skipUnless(importlib.util.find_spec('xlsxwriter'), 'Optional Excel dependency')
    def test_inventory_only_excel_has_account_sheets_and_no_zero_division(self):
        result = self.run_cli(['--excel'], include_pot=False)
        with ZipFile(result/'password_report.xlsx') as archive:
            self.assertIsNone(archive.testzip())
            workbook = archive.read('xl/workbook.xml').decode()
            self.assertIn('Account risk', workbook)
            self.assertIn('Accounts', workbook)
            self.assertIn('History', workbook)
        self.assertEqual(json.loads((result/'summary.json').read_text())['total'], 0)
        self.assertIn('No recovery input records', (result/'password_report.html').read_text(encoding='utf-8'))

    def test_inventory_attackforge_enabled_and_reuse_findings_without_secrets(self):
        result = self.run_cli(['--attackforge'])
        text = (result/'attackforge/bundle.json').read_text()
        bundle = json.loads(text)
        codes = {finding['external_id'] for finding in bundle['findings']}
        self.assertIn('perp:enabled-credentials', codes)
        self.assertIn('perp:cross-status-reuse', codes)
        self.assertNotIn('Alpha1!', text)
        self.assertNotIn(nt_hash(b'Alpha1!'), text)
        self.assertNotIn(str(self.root).replace('\\', '\\\\'), text)
        self.assertTrue(all(f['review_required'] for f in bundle['findings']))

    def test_inventory_option_errors_do_not_create_results(self):
        output = self.root/'out'
        self.assertEqual(perp.main(['--export-seeds', '-o', str(output)]), 1)
        self.assertFalse(output.exists())
        path = self.file('i.ntds', self.row('one', 1001))
        self.assertEqual(perp.main([str(path), '--inventory', str(path), '-o', str(output)]), 1)
        self.assertFalse(output.exists())

    @unittest.skipUnless(shutil.which('node'), 'Optional Node.js interaction checks')
    def test_account_explorer_interactions(self):
        root = Path(perp.__file__).resolve().parent
        result = subprocess.run([shutil.which('node'), str(root/'tests/check_accounts.cjs'), str(root/'web/accounts.js')], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_undecodable_recoveries_and_newline_seed_export(self):
        inventory = load_inventory([self.file('i.ntds', self.row('one', 1001, b'line\nbreak', status='Enabled'))])
        recoveries = [{'hash': None, 'password': b'\xff', 'hash_type': 'Plaintext (no hash)', 'source': 'synthetic', 'line': 1},
                      {'hash': None, 'password': b'line\nbreak', 'hash_type': 'Plaintext (no hash)', 'source': 'synthetic', 'line': 2}]
        risk, seeds = correlate(inventory, recoveries)
        self.assertTrue(risk['accounts'][0]['current_nt_recovered'])
        self.assertEqual(risk['metrics']['undecodable_recovery_records'], 1)
        self.assertEqual(risk['metrics']['seed_records_excluded_newlines'], 1)
        self.assertEqual(seeds, [])

    @unittest.skipUnless(importlib.util.find_spec('xlsxwriter'), 'Optional Excel dependency')
    def test_combined_excel_contains_account_report_and_literal_names(self):
        result = self.run_cli(['--excel'])
        with ZipFile(result/'password_report.xlsx') as archive:
            workbook = archive.read('xl/workbook.xml').decode()
            self.assertIn('Summary', workbook)
            self.assertIn('Account risk', workbook)
            self.assertIn('Reuse', workbook)
            self.assertIn('EXAMPLE.TEST', archive.read('xl/sharedStrings.xml').decode())

    def test_unqualified_scope_cannot_collide_with_a_domain_named_like_source_id(self):
        path = self.file('scope.ntds', self.row('one', 1001)+self.row('inventory-001\\two', 1001))
        self.assertEqual(len(load_inventory([path])['accounts']), 2)

    def test_directory_timestamps_require_timezone_and_coherent_snapshot(self):
        inventory = load_inventory([self.file('i.ntds', self.row('EXAMPLE.TEST\\one', 1001))])
        with self.assertRaises(ValueError):
            load_directory_context(inventory, self.file('bad.csv', 'domain,rid,pwd_last_set\nEXAMPLE.TEST,1001,2026-11-25T12:00:00\n'))
        load_directory_context(inventory, self.file('good.csv', 'domain,rid,pwd_last_set\nEXAMPLE.TEST,1001,2026-11-26T12:00:00Z\n'))
        with self.assertRaises(ValueError):
            correlate(inventory, [], snapshot_time='2026-11-25T12:00:00Z')

    def test_dollar_suffix_does_not_assume_computer_or_service_role(self):
        inventory = load_inventory([self.file('i.ntds', self.row('EXAMPLE.TEST\\managed$', 1001))])
        self.assertIsNone(inventory['accounts'][0]['service_account'])
        self.assertIn('unconfirmed', inventory['accounts'][0]['kind'])
        load_directory_context(inventory, self.file('types.csv', 'domain,rid,account_type\nEXAMPLE.TEST,1001,gmsa\n'))
        self.assertEqual(inventory['accounts'][0]['directory_account_type'], 'gmsa')
        self.assertEqual(inventory['accounts'][0]['kind'], 'Group managed service account (directory)')

    def test_other_hash_family_recovery_can_verify_an_inventory_nt_password(self):
        inventory = load_inventory([self.file('i.ntds', self.row('one', 1001))])
        risk, _ = correlate(inventory, [{'hash': b'$2b$12$'+b'a'*53, 'password': b'Alpha1!', 'hash_type': 'bcrypt', 'source': 'synthetic', 'line': 1}])
        self.assertTrue(risk['accounts'][0]['current_nt_recovered'])

    def test_disabled_and_unknown_roles_are_not_enabled_attackforge_findings(self):
        inventory = self.file('i.ntds', self.row('EXAMPLE.TEST\\retired', 1001, status='Disabled')+self.row('EXAMPLE.TEST\\unclassified', 1002))
        context = self.file('directory.csv', 'domain,rid,privileged,service_account,asset\nEXAMPLE.TEST,1001,true,true,example-host\nEXAMPLE.TEST,1002,true,true,example-host\n')
        pot = self.file('r.potfile', nt_hash(b'Alpha1!')+':Alpha1!\n')
        completed = subprocess.run([sys.executable, str(Path(perp.__file__).resolve()), str(pot), '--inventory', str(inventory), '--directory-context', str(context), '--attackforge', '-o', str(self.root/'out')], capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        bundle = json.loads(next((self.root/'out').glob('results-*/attackforge/bundle.json')).read_text())
        codes = {finding['external_id'] for finding in bundle['findings']}
        self.assertNotIn('perp:enabled-credentials', codes)
        self.assertNotIn('perp:privileged-passwords', codes)
        self.assertNotIn('perp:service-passwords', codes)
        self.assertTrue(any('status is unknown' in check['reason'] for check in bundle['review_checks']))


if __name__ == '__main__':
    unittest.main()
