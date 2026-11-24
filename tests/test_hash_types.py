"""Synthetic format signatures; never real credential material."""
import csv
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import perp
from hash_types import UNKNOWN, PLAINTEXT, identify_hash_type


class HashTypeTests(unittest.TestCase):
    def test_broad_signature_registry(self):
        cases = {
            b'$NT$'+b'a'*32: 'NTLM',
            b'$LM$'+b'a'*16: 'LM (LanMan)',
            b'$2b$12$'+b'a'*53: 'bcrypt',
            b'$1$salt$'+b'a'*22: 'md5crypt',
            b'$apr1$salt$'+b'a'*22: 'Apache MD5 (apr1)',
            b'$5$rounds=5000$salt$'+b'a'*43: 'sha256crypt',
            b'$6$salt$'+b'a'*86: 'sha512crypt',
            b'$y$j9T$salt$hash': 'yescrypt',
            b'$7$paramsandsalt$hash': 'scrypt (crypt)',
            b'SCRYPT:1024:8:1:c2FsdA==:aGFzaA==': 'scrypt',
            b'$P$'+b'a'*31: 'phpass',
            b'$DCC2$10240#demo#'+b'a'*32: 'DCC2 (MS Cache v2)',
            b'0x0100'+b'a'*48: 'MSSQL (2005)',
            b'0x0100'+b'a'*88: 'MSSQL (2000)',
            b'0x0200'+b'a'*136: 'MSSQL (2012+)',
            b'*'+b'a'*40: 'MySQL (4.1+)',
            b'{SHA}'+b'a'*27+b'=': 'LDAP SHA-1',
            b'{SSHA}'+b'a'*40: 'LDAP salted SHA-1',
            b'pbkdf2_sha256$1000$salt$aGFzaA==': 'Django PBKDF2-SHA256',
        }
        for variant in (b'i', b'd', b'id'):
            cases[b'$argon2'+variant+b'$v=19$m=65536,t=3,p=1$c2FsdA$aGFzaA'] = 'Argon2'+variant.decode()
        for bits in (b'1', b'256', b'512'):
            cases[b'sha'+bits+b':1000:c2FsdA==:aGFzaA=='] = 'PBKDF2-HMAC-SHA'+bits.decode()
        cases[b'$pbkdf2-sha256$1000$c2FsdA$aGFzaA'] = 'PBKDF2-HMAC-SHA256'
        for hashed, label in cases.items():
            with self.subTest(label=label):
                self.assertEqual(identify_hash_type(hashed), (label, 'signature'))

    def test_kerberos_and_netntlm_complete_signatures(self):
        cases = (
            (b'$krb5tgs$23$'+b'a'*32+b'$'+b'b'*128, 'Kerberos TGS'),
            (b'$krb5asrep$23$demo@EXAMPLE.TEST:'+b'a'*32+b'$'+b'b'*128, 'Kerberos AS-REP'),
            (b'demo::EXAMPLE:'+b'a'*16+b':'+b'b'*32+b':'+b'c'*64, 'NetNTLMv2'),
            (b'demo::EXAMPLE:'+b'a'*48+b':'+b'b'*48+b':'+b'c'*16, 'NetNTLMv1'),
        )
        for hashed, label in cases:
            self.assertEqual(identify_hash_type(hashed, 'NTLM'), (label, 'signature'))

    def test_ambiguous_digests_are_never_inferred_by_length(self):
        for value in (b'a'*16, b'a'*32, b'a'*40, b'a'*64, b'a'*128,
                      b'$NT$bad', b'$2b$bad', b'$krb5tgs$bad', b'$future$hash'):
            self.assertEqual(identify_hash_type(value), (UNKNOWN, 'unknown'))
        self.assertEqual(identify_hash_type(b'a'*32, 'ntlm'), ('NTLM', 'declared'))
        self.assertEqual(identify_hash_type(b'a'*16, 'LanMan'), ('LM (LanMan)', 'declared'))
        self.assertEqual(identify_hash_type(b'opaque:salt', 'Custom enterprise format'),
                         ('Custom enterprise format', 'declared'))
        for invalid in ('', '\n', 'x'*121, 'NTLM\x00'):
            with self.assertRaises(ValueError):
                identify_hash_type(b'a'*32, invalid)

    def test_mixed_cli_totals_and_exports_preserve_plaintext(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pot = root/'mixed.potfile'
            pot.write_bytes(b'$NT$'+b'a'*32+b':same\n$LM$'+b'a'*16+b':same\n'+b'b'*32+b':same\n')
            plain = root/'plain.txt'
            plain.write_bytes(b'$NT$'+b'a'*32+b'\n')
            completed = subprocess.run([sys.executable, str(Path(perp.__file__).resolve()),
                                        str(pot), str(plain), '--hash-type', 'Custom format',
                                        '-o', str(root/'out')], capture_output=True, text=True)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = next((root/'out').glob('results-*'))
            summary = json.loads((result/'summary.json').read_text())
            self.assertEqual({item['label']: item['count'] for item in summary['hash_types']},
                             {'NTLM': 1, 'LM (LanMan)': 1, 'Custom format': 1, PLAINTEXT: 1})
            self.assertEqual(sum(x['count'] for x in summary['hash_types']), summary['total'])
            self.assertEqual(summary['unique'], 2)
            with (result/'passwords.csv').open(encoding='utf-8-sig', newline='') as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual([row['hash_type_basis'] for row in rows], ['signature', 'signature', 'declared', 'plaintext'])
            self.assertEqual(rows[-1]['password'], '$NT$'+'a'*32)
            report = (result/'password_report.html').read_text(encoding='utf-8')
            self.assertIn('Hash / credential types', report)
            self.assertIn('Custom format', report)
            self.assertNotIn('$LM$'+'a'*16, report)

    def test_unknown_and_many_categories_are_in_complete_html_table(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'unknown.pot'
            path.write_bytes(b'a'*32+b':pw\n')
            rows, summary = perp.collect([path], 'auto', 'utf-8', b':', None)
            self.assertEqual(summary['hash_types'], [{'label': UNKNOWN, 'count': 1}])
            summary['hash_types'] = [{'label': f'Type {i}', 'count': 1} for i in range(20)]
            summary['total'] = 20
            report = perp.dashboard(rows, summary)
            self.assertIn('Type 19', report)
            self.assertIn('Showing 20 of 20 groups', report)
            rows, summary = perp.collect([path], 'auto', 'utf-8', b':', None, '</script><img src=x>')
            report = perp.dashboard(rows, summary)
            self.assertNotIn('<img src=x>', report)
            self.assertIn('&lt;img src=x&gt;', report)


if __name__ == '__main__':
    unittest.main()
