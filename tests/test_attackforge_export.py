import base64
import csv
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import perp
from attackforge_export import load_bundle_helper, write_attackforge_bundle


class AttackForgeExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.helper = load_bundle_helper()
        self.source = self.root/'input.potfile'
        self.source.write_bytes(b'h1:NeverPublishThisPassword!\nh2:AlsoSecret\nh3:\n')
        rows, summary = perp.collect([self.source], 'potfile', 'utf-8', b':', None)
        self.results = perp.write_results(rows, summary, self.root/'reports')

    def tearDown(self):
        self.temp.cleanup()

    def context(self, mappings):
        path = self.root/'context.csv'
        fields = ['source','line','account','asset','hash_type','privileged','service_account','lm_storage_confirmed','recovery_confirmed']
        with path.open('w', newline='', encoding='utf-8') as stream:
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            for mapping in mappings:
                writer.writerow({'source':str(self.source),'line':1,'account':'EXAMPLE\\person','asset':'example-dc',**mapping})
        return path

    def test_no_context_means_no_account_vulnerabilities_or_secrets(self):
        result = write_attackforge_bundle(self.results)
        bundle = self.helper.verify_bundle(result)
        self.assertEqual(bundle['findings'], [])
        self.assertEqual(bundle['metrics']['total_records'],3)
        for path in result.rglob('*'):
            if path.is_file():
                text = path.read_text()
                for secret in ('NeverPublishThisPassword!', 'AlsoSecret', str(self.source), 'h1:'):
                    self.assertNotIn(secret,text)
        self.assertEqual(bundle['evidence'][0]['kind'],'generated_aggregate_graphic')

    def test_lm_privileged_and_service_findings_require_confirmed_context(self):
        context = self.context([
            {'account':'EXAMPLE\\admin','hash_type':'LM','privileged':'true','lm_storage_confirmed':'true'},
            {'line':2,'account':'EXAMPLE\\svc-app','service_account':'true'},
            {'line':3,'account':'EXAMPLE\\svc-unknown'}])
        result = write_attackforge_bundle(self.results,context)
        bundle = self.helper.verify_bundle(result)
        self.assertEqual({f['external_id'] for f in bundle['findings']}, {'perp:lm-storage','perp:privileged-passwords','perp:service-passwords'})
        self.assertEqual(len(bundle['review_checks']),1)
        self.assertTrue(all(f['review_required'] for f in bundle['findings']))
        self.assertNotIn('NeverPublishThisPassword!',(result/'bundle.json').read_text())
        self.assertNotIn('cvss',(result/'bundle.json').read_text().lower())
        self.assertIn('No upload has been performed',(result/'review.txt').read_text())

    def test_names_and_declared_lm_are_review_hints_only(self):
        context = self.context([{'account':'EXAMPLE\\admin-svc','hash_type':'LM'}])
        result = write_attackforge_bundle(self.results,context)
        bundle = self.helper.verify_bundle(result)
        self.assertEqual(bundle['findings'],[])
        self.assertEqual(len(bundle['review_checks']),2)

    def test_plaintext_dictionary_does_not_prove_recovered_privileged_credentials(self):
        plain = self.root/'words.txt'
        plain.write_text('admin\n')
        rows,summary = perp.collect([plain],'plaintext','utf-8',b':',None)
        result = perp.write_results(rows,summary,self.root/'plain')
        context = self.context([{'source':str(plain),'privileged':'true'}])
        output = write_attackforge_bundle(result,context)
        self.assertEqual(self.helper.verify_bundle(output)['findings'],[])
        confirmed = self.context([{'source':str(plain),'privileged':'true','recovery_confirmed':'true'}])
        output = self.helper.build_bundle(result,confirmed,output=result/'confirmed')
        self.assertEqual(len(self.helper.verify_bundle(output)['findings']),1)

    def test_bad_joins_booleans_and_duplicates_do_not_publish_bundle(self):
        for mappings in ([{'line':999}], [{'privileged':'maybe'}], [{},{}]):
            with self.subTest(mappings=mappings):
                with self.assertRaises(ValueError):
                    write_attackforge_bundle(self.results,self.context(mappings))
                self.assertFalse((self.results/'attackforge').exists())

    def test_screenshots_are_copied_verified_and_not_assigned_blindly(self):
        image = self.root/'sensitive-name.png'
        image.write_bytes(base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aZioAAAAASUVORK5CYII='))
        context = self.context([{'privileged':'true'}])
        result = write_attackforge_bundle(self.results,context,[image])
        bundle = self.helper.verify_bundle(result)
        self.assertEqual(bundle['evidence'][1]['path'],'evidence/screenshot-001.png')
        self.assertTrue(bundle['evidence'][1]['association_review_required'])
        self.assertEqual(bundle['findings'][0]['evidence_refs'],['aggregate-summary'])
        (result/'evidence/screenshot-001.png').write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError,'SHA-256'):
            self.helper.verify_bundle(result)

    def test_tampered_bundle_or_escaping_evidence_is_rejected(self):
        result = write_attackforge_bundle(self.results)
        path = result/'bundle.json'
        bundle = json.loads(path.read_text())
        bundle['metrics']['total_records'] = 999
        path.write_text(json.dumps(bundle))
        with self.assertRaisesRegex(ValueError,'fingerprint'):
            self.helper.verify_bundle(result)
        bundle['metrics']['total_records'] = 3
        bundle['evidence'][0]['path'] = '../outside.svg'
        # A self-consistent manifest still cannot escape the bundle directory.
        import hashlib
        stable = json.dumps({key:bundle[key] for key in ('sources','metrics','findings','evidence')},sort_keys=True).encode()
        bundle['bundle_id'] = hashlib.sha256(stable).hexdigest()
        path.write_text(json.dumps(bundle))
        with self.assertRaisesRegex(ValueError,'escapes'):
            self.helper.verify_bundle(result)

    def test_standalone_skill_helper_and_cli_integration(self):
        engine = Path(perp.__file__).resolve()
        completed = subprocess.run([sys.executable,str(engine),str(self.source),'--attackforge','-o',str(self.root/'cli')],capture_output=True,text=True)
        self.assertEqual(completed.returncode,0,completed.stderr)
        output = next((self.root/'cli').glob('results-*/attackforge'))
        # Run copied helper outside the repository, proving the skill is portable.
        helper = self.root/'bundle.py'
        helper.write_bytes((engine.parent/'skills/perp-attackforge/scripts/bundle.py').read_bytes())
        completed = subprocess.run([sys.executable,str(helper),'verify',str(output)],cwd=self.root,capture_output=True,text=True)
        self.assertEqual(completed.returncode,0,completed.stderr)
        self.assertIn('no publication performed',completed.stdout)


if __name__ == '__main__':
    unittest.main()
