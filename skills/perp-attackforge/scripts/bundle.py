#!/usr/bin/env python3
"""Prepare and verify local perp-to-AttackForge review bundles. No network I/O."""
from __future__ import annotations
import argparse
import csv
import hashlib
import html
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile

SCHEMA = 'perp.attackforge.bundle.v1'
BOOL_FIELDS = ('privileged', 'service_account', 'lm_storage_confirmed', 'recovery_confirmed')
REQUIRED = {'source', 'line', 'account', 'asset'}
LM_REFERENCE = 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-do-not-store-lan-manager-hash-value-on-next-password-change'
RULES = {
    'lm-storage': ('Active LAN Manager password hash storage', 'Medium',
        'Confirmed account context identifies active LM hash storage associated with recovered audit records.',
        'LM password representations can make offline recovery substantially easier after hash exposure.',
        'Enable the applicable Network security: Do not store LAN Manager hash value on next password change policy. Validate legacy compatibility, coordinate password changes to remove stored LM representations, and verify removal after policy application and replication.', [LM_REFERENCE]),
    'privileged-passwords': ('Recoverable privileged-account passwords', 'High',
        'Passwords were recovered for accounts whose privileged role was confirmed in the supplied account context.',
        'An exposed privileged credential may permit elevated access where that credential remains valid; unauthorized use was not tested by this export.',
        'Coordinate rotation of exposed privileged credentials. Review reuse and relevant sign-in activity, separate privileged and ordinary credentials, and enforce appropriate MFA and privileged-access controls.', []),
    'service-passwords': ('Recoverable service-account passwords', 'Medium',
        'Passwords were recovered for accounts whose service-account role was confirmed in the supplied account context.',
        'An exposed service credential may provide access through dependent services, tasks, or applications.',
        'Coordinate credential rotation with service owners and update every dependent service, scheduled task, and secret store. Prefer managed service accounts or managed identities where supported, and restrict permissions to required functions.', []),
}


def digest_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024*1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def normalize(path, base):
    value = Path(path)
    return os.path.normcase(str((value if value.is_absolute() else base/value).resolve()))


def boolean(value, label):
    value = (value or '').strip().lower()
    if value not in ('', 'true', 'false'):
        raise ValueError(f'{label} must be true, false, or blank')
    return None if value == '' else value == 'true'


def load_context(path, records, sources):
    if not path:
        return []
    path = Path(path).resolve()
    mapped, seen = [], set()
    with path.open(encoding='utf-8-sig', newline='') as stream:
        reader = csv.DictReader(stream)
        if not REQUIRED.issubset(reader.fieldnames or []):
            raise ValueError('Account CSV requires source,line,account,asset columns')
        for number, item in enumerate(reader, 2):
            try:
                source = normalize(item['source'], path.parent)
                line = int(item['line'])
                key = (source, line)
                if key not in records:
                    raise ValueError('source/line does not match a recovered record')
                account, asset = item['account'].strip(), item['asset'].strip()
                if not account or not asset or any(ord(c) < 32 for c in account+asset):
                    raise ValueError('account and asset must be nonempty single-line values')
                identity = (key, account, asset)
                if identity in seen:
                    raise ValueError('duplicate account mapping')
                seen.add(identity)
                flags = {field: boolean(item.get(field), field) for field in BOOL_FIELDS}
                source_info = sources[source]
                hash_type = (item.get('hash_type') or 'unknown').strip()
                if hash_type.casefold() in ('lm', 'lanman', '3000'):
                    hash_type = 'LM'
                mapped.append({'account': account, 'asset': asset, 'hash_type': hash_type,
                               'record_ref': {'source_id': source_info['id'], 'line': line},
                               'recovered_audit_record': source_info['format'] in ('potfile', 'hashcat', 'john') or flags['recovery_confirmed'] is True,
                               **flags})
            except (ValueError, KeyError, TypeError, AttributeError) as error:
                raise ValueError(f'Account CSV row {number}: {error}') from error
    return mapped


def evidence_type(path):
    with path.open('rb') as stream:
        prefix = stream.read(16)
    suffix = path.suffix.lower()
    if suffix == '.png' and prefix.startswith(b'\x89PNG\r\n\x1a\n'):
        return 'image/png', '.png'
    if suffix in ('.jpg', '.jpeg') and prefix.startswith(b'\xff\xd8\xff'):
        return 'image/jpeg', '.jpg'
    if suffix == '.webp' and prefix[:4] == b'RIFF' and prefix[8:12] == b'WEBP':
        return 'image/webp', '.webp'
    raise ValueError('Evidence must be a PNG, JPEG, or WebP image with a matching file signature')


def summary_svg(metrics, finding_count):
    # Only aggregate integers enter this image; it contains no record text.
    entries = [('Recovered input records', metrics['total_records']), ('Unique password values', metrics['unique_passwords']),
               ('Account-to-record mappings', metrics['account_mappings']), ('Draft findings', finding_count)]
    text = ''.join(f'<text x="42" y="{125+i*62}" font-size="18" fill="#52657b">{html.escape(label)}</text><text x="650" y="{125+i*62}" text-anchor="end" font-size="26" fill="#172638">{value:,}</text>' for i, (label, value) in enumerate(entries))
    return '<svg xmlns="http://www.w3.org/2000/svg" width="720" height="425" viewBox="0 0 720 425"><rect width="720" height="425" fill="#f3f6fa"/><text x="42" y="58" font-family="sans-serif" font-size="26" fill="#087966">perp / password audit evidence summary</text><g font-family="sans-serif">'+text+'<text x="42" y="392" font-size="13" fill="#52657b">Generated aggregate graphic. Not a screenshot or an account crack rate.</text></g></svg>'


def build_bundle(results, context_path=None, evidence_paths=(), output=None):
    results = Path(results).resolve()
    summary = json.loads((results/'summary.json').read_text(encoding='utf-8'))
    sources = {}
    for index, source in enumerate(summary['sources'], 1):
        sources[normalize(source['path'], results)] = {'id': f'source-{index:03d}', 'format': source['format'], 'sha256': source['sha256'], 'records': source['records']}
    records = set()
    with (results/'passwords.csv').open(encoding='utf-8-sig', newline='') as stream:
        for row in csv.DictReader(stream):
            source = normalize(row['source'], results)
            if source not in sources:
                raise ValueError('Detailed CSV source is not listed in summary.json')
            records.add((source, int(row['line'])))
    if len(records) != summary['total']:
        raise ValueError('Detailed CSV record references do not match the summary total')
    accounts = load_context(context_path, records, sources)
    groups = {key: [] for key in RULES}
    checks = []
    for account in accounts:
        if not account['recovered_audit_record']:
            checks.append({'account': account['account'], 'asset': account['asset'], 'reason': 'Plaintext input is not confirmed as an audit recovery'})
            continue
        if account['hash_type'] == 'LM':
            if account['lm_storage_confirmed'] is True:
                groups['lm-storage'].append(account)
            else:
                checks.append({'account': account['account'], 'asset': account['asset'], 'reason': 'Confirm active non-placeholder LM storage; declared hash type alone is insufficient'})
        if account['privileged'] is True:
            groups['privileged-passwords'].append(account)
        if account['service_account'] is True:
            groups['service-passwords'].append(account)
        if account['privileged'] is None and account['service_account'] is None and re.search(r'admin|svc|service', account['account'], re.I):
            checks.append({'account': account['account'], 'asset': account['asset'], 'reason': 'Name hint only; confirm the actual privileged/service role'})
    findings = []
    for code, affected in groups.items():
        if not affected:
            continue
        title, severity, description, impact, remediation, references = RULES[code]
        findings.append({'external_id': 'perp:'+code, 'title': title, 'severity_suggestion': severity,
                         'description': description, 'impact': impact, 'remediation': remediation,
                         'references': references, 'affected_accounts': affected,
                         'affected_assets': sorted({account['asset'] for account in affected}),
                         'evidence_refs': ['aggregate-summary'], 'review_required': True})
    metrics = {'total_records': summary['total'], 'unique_passwords': summary['unique'],
               'duplicate_records': summary['duplicate_records'], 'empty_passwords': summary['empty_passwords'],
               'account_mappings': len(accounts)}
    bundle = {'schema': SCHEMA, 'tool': 'perp', 'version': summary['version'], 'created': summary['created'],
              'publication_status': 'requires_consultant_review', 'metrics': metrics,
              'sources': list(sources.values()), 'findings': findings, 'review_checks': checks,
              'evidence': [], 'privacy': {'password_fields_omitted': True, 'supplied_images_require_review': True},
              'limitations': ['Input records are not unique accounts or an account crack rate.',
                             'No privilege, service role, or hash type is inferred from password values.',
                             'This is a portable review bundle, not an AttackForge-native import schema.']}
    if not accounts:
        bundle['limitations'].append('No account context supplied; no account-specific vulnerabilities were generated.')
    evidence = []
    for path in evidence_paths:
        path = Path(path).resolve()
        mime, suffix = evidence_type(path)
        evidence.append((path, mime, suffix))
    output = Path(output).resolve() if output else results/'attackforge'
    if output.exists():
        raise ValueError('Bundle output already exists; use a new --output directory')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.perp-af-', dir=output.parent) as temporary:
        publish = Path(temporary)/'publish'
        (publish/'evidence').mkdir(parents=True)
        graphic = publish/'evidence/summary.svg'
        graphic.write_text(summary_svg(metrics, len(findings)), encoding='utf-8')
        bundle['evidence'].append({'id': 'aggregate-summary', 'path': 'evidence/summary.svg', 'mime_type': 'image/svg+xml',
                                   'kind': 'generated_aggregate_graphic', 'sha256': digest_file(graphic), 'content_review_required': False})
        for index, (source, mime, suffix) in enumerate(evidence, 1):
            relative = f'evidence/screenshot-{index:03d}{suffix}'
            target = publish/relative
            shutil.copyfile(source, target)
            identifier = f'screenshot-{index:03d}'
            bundle['evidence'].append({'id': identifier, 'path': relative, 'mime_type': mime, 'kind': 'consultant_supplied_image',
                                       'sha256': digest_file(target), 'content_review_required': True, 'association_review_required': True})
        stable = json.dumps({'sources': bundle['sources'], 'metrics': metrics, 'findings': findings,
                             'evidence': bundle['evidence']}, sort_keys=True).encode()
        bundle['bundle_id'] = hashlib.sha256(stable).hexdigest()
        (publish/'bundle.json').write_text(json.dumps(bundle, indent=2)+'\n', encoding='utf-8')
        review = ['perp to AttackForge: local review bundle', f"Bundle: {bundle['bundle_id']}",
                  f"Recovered records: {metrics['total_records']:,}", f"Draft findings: {len(findings)}", '',
                  'No upload has been performed. Review project scope, roles, severity, assets, and images.']
        review += [f"\n{finding['title']}\nSuggested severity: {finding['severity_suggestion']} (review required)\n{finding['remediation']}" for finding in findings]
        review += ['\nOutstanding context checks: '+str(len(checks)), 'Generated summary.svg is a graphic, not a screenshot.',
                   'Do not attach the ordinary perp report or raw CSV/potfiles without explicit sensitive-data scope.']
        (publish/'review.txt').write_text('\n'.join(review)+'\n', encoding='utf-8')
        publish.rename(output)
    return output


def verify_bundle(directory):
    directory = Path(directory).resolve()
    bundle = json.loads((directory/'bundle.json').read_text(encoding='utf-8'))
    if bundle.get('schema') != SCHEMA:
        raise ValueError('Unsupported bundle schema')
    stable = json.dumps({key: bundle[key] for key in ('sources', 'metrics', 'findings', 'evidence')}, sort_keys=True).encode()
    if hashlib.sha256(stable).hexdigest() != bundle.get('bundle_id'):
        raise ValueError('Bundle content fingerprint mismatch; rebuild after editing')
    evidence_ids = set()
    for evidence in bundle['evidence']:
        target = (directory/evidence['path']).resolve()
        if not target.is_relative_to(directory) or not target.is_file():
            raise ValueError('Evidence path escapes bundle or is missing')
        if digest_file(target) != evidence['sha256']:
            raise ValueError('Evidence SHA-256 mismatch')
        if evidence['id'] in evidence_ids:
            raise ValueError('Duplicate evidence ID')
        evidence_ids.add(evidence['id'])
    for finding in bundle['findings']:
        if not set(finding['evidence_refs']).issubset(evidence_ids):
            raise ValueError('Finding references missing evidence')
    return bundle


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    prepare = commands.add_parser('prepare')
    prepare.add_argument('results', type=Path)
    prepare.add_argument('--account-context', type=Path)
    prepare.add_argument('--evidence', action='append', default=[], type=Path)
    prepare.add_argument('--output', type=Path)
    verify = commands.add_parser('verify')
    verify.add_argument('directory', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == 'prepare':
            result = build_bundle(args.results, args.account_context, args.evidence, args.output)
            print(f'Prepared local review bundle: {result}')
        else:
            bundle = verify_bundle(args.directory)
            print(f"Verified {len(bundle['findings'])} draft findings and {len(bundle['evidence'])} evidence files; no publication performed.")
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(f'perp-attackforge: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
