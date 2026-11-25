"""Offline account inventory and credential correlation. No network or authentication."""
from collections import defaultdict
from datetime import datetime
import csv
import hashlib
from pathlib import Path
import re
import struct

EMPTY_LM = 'aad3b435b51404eeaad3b435b51404ee'
EMPTY_NT = '31d6cfe0d16ae931b73c59d7e0c089c0'
LINE = re.compile(r'(?P<name>[^:\r\n]+):(?P<rid>\d+):(?P<lm>(?:[0-9a-fA-F]{32})?):(?P<nt>(?:[0-9a-fA-F]{32})?):{3}(?:\s+\(status=(?P<status>Enabled|Disabled|Unknown|N/A)\))?\s*')
HISTORY = re.compile(r'^(.*)_history(\d+)$')
STATUS = ('Enabled', 'Disabled', 'Unknown')


def md4(data):
    """RFC 1320 MD4, used only for offline verification of NT password hashes."""
    size = len(data)
    data += b'\x80' + b'\0' * ((55-size) % 64) + struct.pack('<Q', size*8)
    state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
    orders = (list(range(16)), [(i % 4)*4+i//4 for i in range(16)],
              [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15])
    shifts = ((3, 7, 11, 19), (3, 5, 9, 13), (3, 9, 11, 15))
    for offset in range(0, len(data), 64):
        words = struct.unpack('<16I', data[offset:offset+64])
        work = state.copy()
        for rnd in range(3):
            for i, word in enumerate(orders[rnd]):
                target = (0, 3, 2, 1)[i % 4]
                b, c, d = (work[(target+j) % 4] for j in (1, 2, 3))
                f = ((b & c) | (~b & d)) if rnd == 0 else ((b & c) | (b & d) | (c & d)) if rnd == 1 else b ^ c ^ d
                value = (work[target]+f+words[word]+(0, 0x5a827999, 0x6ed9eba1)[rnd]) & 0xffffffff
                shift = shifts[rnd][i % 4]
                work[target] = ((value << shift) | (value >> (32-shift))) & 0xffffffff
        state = [(a+b) & 0xffffffff for a, b in zip(state, work)]
    return struct.pack('<4I', *state).hex()


def nt_hash(raw, encoding='utf-8'):
    return md4(raw.decode(encoding).encode('utf-16le'))


def file_digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024*1024), b''):
            value.update(chunk)
    return value.hexdigest()


def timestamp(value, label):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            raise ValueError()
        return parsed.isoformat()
    except ValueError:
        raise ValueError(f'{label} must be an ISO 8601 timestamp with a timezone') from None


def boolean(value, label):
    value = (value or '').strip().lower()
    if value not in ('', 'true', 'false'):
        raise ValueError(f'{label} must be true, false, or blank')
    return None if not value else value == 'true'


def load_inventory(paths, domain=None):
    """Import strict pwdump/secretsdump text; hashes stay in private runtime fields."""
    if domain is not None:
        domain = domain.strip()
        if not domain or any(c in domain for c in ':\\') or any(ord(c) < 32 or ord(c) == 127 for c in domain):
            raise ValueError('Inventory domain must be a nonempty domain name without delimiters')
    accounts, credentials, sources = {}, {}, []
    unique_paths = list(dict.fromkeys(Path(path).resolve() for path in paths))
    for number, path in enumerate(unique_paths, 1):
        source_id = f'inventory-{number:03d}'
        count = 0
        with path.open(encoding='utf-8-sig') as stream:
            for line_number, line in enumerate(stream, 1):
                line = line.rstrip('\r\n')
                if not line.strip() or line.lstrip().startswith('#'):
                    continue
                match = LINE.fullmatch(line)
                # Some copied exports have a presentation continuation after the suffix.
                if not match and line.endswith('\\'):
                    match = LINE.fullmatch(line[:-1])
                if not match:
                    raise ValueError(f'{path.name}:{line_number}: expected account:RID:LM:NT::: with optional status; binary NTDS.dit is not supported')
                item = match.groupdict()
                identity = item['name']
                supplied_domain, name = identity.rsplit('\\', 1) if '\\' in identity else ('', identity)
                account_domain = supplied_domain or domain or ''
                history = HISTORY.fullmatch(name)
                index = int(history[2]) if history else None
                name = history[1] if history else name
                if not name or any(ord(char) < 32 for char in identity):
                    raise ValueError(f'{path.name}:{line_number}: invalid account identity')
                scope = ('domain', account_domain.casefold()) if account_domain else ('file', source_id)
                key = (scope, int(item['rid']))
                if key not in accounts:
                    accounts[key] = {'id': f'account-{len(accounts)+1:04d}',
                        'account': (account_domain+'\\' if account_domain else '')+name,
                        'name': name, 'domain': account_domain, 'rid': int(item['rid']),
                        'status': 'Unknown', 'status_source': 'unknown', 'has_current': False,
                        'kind': '$-suffixed account (unconfirmed)' if name.endswith('$') else 'krbtgt' if int(item['rid']) == 502 else 'built-in Administrator' if int(item['rid']) == 500 else 'account',
                        'directory_account_type': None,
                        'privileged': None, 'service_account': None, 'asset': '', 'owner': '',
                        'pwd_last_set': None, 'password_never_expires': None,
                        'account_expires': None, 'last_logon': None}
                account = accounts[key]
                if account['name'].casefold() != name.casefold():
                    raise ValueError(f'{path.name}:{line_number}: conflicting names for a domain/RID; use one snapshot')
                status = item['status'] if item['status'] in STATUS else 'Unknown'
                if index is None:
                    account['has_current'] = True
                    if status != 'Unknown':
                        if account['status'] not in ('Unknown', status):
                            raise ValueError(f'{path.name}:{line_number}: conflicting current account status')
                        account.update(status=status, status_source='inventory')
                record_key = (key, index)
                hashes = (item['lm'].lower() or None, item['nt'].lower() or None)
                ref = {'source_id': source_id, 'line': line_number}
                if record_key in credentials:
                    old = credentials[record_key]
                    if (old['_lm'], old['_nt']) != hashes:
                        raise ValueError(f'{path.name}:{line_number}: conflicting current/history credential; use one snapshot')
                    old['record_refs'].append(ref)
                else:
                    credentials[record_key] = {'account_id': account['id'], 'history_index': index,
                                              '_lm': hashes[0], '_nt': hashes[1], 'record_refs': [ref]}
                count += 1
        sources.append({'id': source_id, 'path': str(path), 'sha256': file_digest(path), 'records': count, 'format': 'ntds-text'})
    if not accounts:
        raise ValueError('Inventory contains no account records')
    return {'accounts': list(accounts.values()), 'credentials': list(credentials.values()), 'sources': sources}


def load_directory_context(inventory, path):
    if not path:
        return
    seen = set()
    with Path(path).open(encoding='utf-8-sig', newline='') as stream:
        reader = csv.DictReader(stream)
        if not {'domain', 'rid'}.issubset(reader.fieldnames or []):
            raise ValueError('Directory CSV requires domain,rid columns')
        for line, row in enumerate(reader, 2):
            try:
                matches = [a for a in inventory['accounts'] if a['domain'].casefold() == row['domain'].strip().casefold() and a['rid'] == int(row['rid'])]
                if len(matches) != 1 or matches[0]['id'] in seen:
                    raise ValueError('domain/RID is missing, ambiguous, or duplicated')
                account = matches[0]
                seen.add(account['id'])
                if row.get('account') and row['account'].strip().casefold() not in (account['name'].casefold(), account['account'].casefold()):
                    raise ValueError('account name does not match inventory')
                state = (row.get('status') or '').strip()
                if state:
                    if state not in STATUS or account['status'] not in ('Unknown', state):
                        raise ValueError('invalid or conflicting current status')
                    account.update(status=state, status_source='directory')
                for field in ('privileged', 'service_account', 'password_never_expires'):
                    account[field] = boolean(row.get(field), field)
                account_type = (row.get('account_type') or '').strip().lower()
                if account_type:
                    kinds = {'user': 'User (directory)', 'computer': 'Computer (directory)',
                             'gmsa': 'Group managed service account (directory)',
                             'msa': 'Managed service account (directory)', 'service': 'Service account (directory)', 'unknown': 'account'}
                    if account_type not in kinds:
                        raise ValueError('account_type must be user, computer, gmsa, msa, service, or unknown')
                    account['directory_account_type'] = account_type
                    if account['kind'] not in ('krbtgt', 'built-in Administrator'):
                        account['kind'] = kinds[account_type]
                for field in ('pwd_last_set', 'last_logon', 'account_expires'):
                    account[field] = timestamp((row.get(field) or '').strip(), field)
                for field in ('asset', 'owner'):
                    account[field] = (row.get(field) or '').strip()
                    if any(ord(c) < 32 for c in account[field]):
                        raise ValueError(f'{field} must be single-line text')
            except (ValueError, KeyError, TypeError, AttributeError) as error:
                raise ValueError(f'Directory CSV row {line}: {error}') from error
    inventory['sources'].append({'id': 'directory-context', 'path': str(Path(path).resolve()),
                                 'sha256': file_digest(path), 'format': 'directory-csv', 'records': len(seen)})


def inventory_type_map(inventory):
    types = defaultdict(set)
    for record in inventory['credentials']:
        if record['_nt']:
            types[record['_nt']].add('NTLM')
        if record['_lm'] and record['_lm'] != EMPTY_LM:
            for digest in (record['_lm'], record['_lm'][:16], record['_lm'][16:]):
                if digest != EMPTY_LM[:16]:
                    types[digest].add('LM (LanMan)')
    return {digest: next(iter(names)) for digest, names in types.items() if len(names) == 1}


def correlate(inventory, recoveries, encoding='utf-8', snapshot_time=None):
    snapshot_time = timestamp(snapshot_time, 'snapshot time')
    accounts = {item['id']: dict(item) for item in inventory['accounts']}
    records = inventory['credentials']
    targets = {record['_nt'] for record in records if record['_nt']}
    verified, lm_matches, seeds = defaultdict(list), set(), set()
    invalid, undecodable = 0, 0
    lm_targets = {digest for record in records if record['_lm'] and record['_lm'] != EMPTY_LM
                  for digest in (record['_lm'], record['_lm'][:16], record['_lm'][16:])
                  if digest != EMPTY_LM[:16]}
    for recovery in recoveries:
        raw, hashed = recovery['password'], recovery.get('hash')
        payload = hashed.decode('ascii', errors='replace') if hashed is not None else ''
        payload = re.sub(r'^\$(?:NT|LM)\$', '', payload).lower()
        label = recovery['hash_type']
        try:
            computed = nt_hash(raw, encoding)
        except UnicodeError:
            computed = None
            undecodable += 1
        if label == 'NTLM' and computed is not None and computed != payload:
            invalid += 1
            continue
        if computed in targets:
            verified[computed].append({'source': recovery['source'], 'line': recovery['line'], 'method': 'NT hash verified'})
            seeds.add(raw)
        if label == 'LM (LanMan)' and payload in lm_targets:
            # A matching potfile key is evidence, not independent LM/DES verification.
            lm_matches.add(payload)
            seeds.add(raw)
    if EMPTY_NT in targets:
        verified[EMPTY_NT].append({'method': 'known empty NT password'})
        seeds.add(b'')

    current = {r['account_id']: r for r in records if r['history_index'] is None}

    def lm_state(record):
        value = record['_lm']
        if value is None:
            return 'Unknown'
        if value == EMPTY_LM:
            return 'Not stored / placeholder'
        if value in lm_matches:
            return 'Full hash matched (unverified LM)'
        hits = sum(half in lm_matches or half == EMPTY_LM[:16] for half in (value[:16], value[16:]))
        return ('No halves matched', 'One half matched', 'Both halves matched (unverified LM)')[hits]

    for account in accounts.values():
        record = current.get(account['id'])
        value = record['_nt'] if record else None
        account.update(current_nt_recovered=bool(value and value in verified),
                       current_nt_assessed=bool(value),
                       recovery_basis='known empty' if value == EMPTY_NT else 'verified NT password' if value in verified else 'not recovered in supplied results' if value else 'not assessed',
                       lm_present=None if not record or record['_lm'] is None else record['_lm'] != EMPTY_LM,
                       lm_recovery=lm_state(record) if record else 'No current record',
                       record_refs=record['record_refs'] if record else [],
                       recovery_evidence=verified.get(value, []), risk_flags=[], password_age_days=None)
        if account['pwd_last_set'] and snapshot_time:
            days = (datetime.fromisoformat(snapshot_time)-datetime.fromisoformat(account['pwd_last_set'])).days
            if days < 0:
                raise ValueError('Password-last-set is later than the supplied snapshot time')
            account['password_age_days'] = days
        if account['current_nt_recovered']:
            flag = {'Enabled': 'enabled_current_recovered', 'Disabled': 'disabled_current_recovered', 'Unknown': 'unknown_status_current_recovered'}[account['status']]
            account['risk_flags'].append(flag)
            for role in ('privileged', 'service_account'):
                if account[role] is True:
                    account['risk_flags'].append(role+'_current_recovered')
            if account['kind'] == 'krbtgt':
                account['risk_flags'].append('krbtgt_credential_exposure')
        if account['lm_present']:
            account['risk_flags'].append('lm_material_present')
        if value == EMPTY_NT:
            account['risk_flags'].append('known_empty_current_password')

    history, historic = [], defaultdict(set)
    for record in records:
        if record['history_index'] is None:
            continue
        owner = accounts[record['account_id']]
        overlap = bool(record['_nt'] and record['_nt'] == current.get(owner['id'], {}).get('_nt'))
        history.append({'account_id': owner['id'], 'account': owner['account'], 'current_status': owner['status'], 'history_index': record['history_index'],
                        'overlaps_current': overlap, 'nt_recovered': bool(record['_nt'] and record['_nt'] in verified),
                        'nt_assessed': bool(record['_nt']), 'lm_recovery': lm_state(record), 'record_refs': record['record_refs']})
        if record['_nt'] and not overlap:
            historic[record['_nt']].add(owner['id'])
    shared = defaultdict(set)
    for account_id, record in current.items():
        if record['_nt']:
            shared[record['_nt']].add(account_id)
    reuse = []
    for digest, members in shared.items():
        older = historic.get(digest, set())
        if len(members) < 2 and not older:
            continue
        enabled = sorted(member for member in members if accounts[member]['status'] == 'Enabled')
        disabled = sorted(member for member in members if accounts[member]['status'] == 'Disabled')
        group = {'id': f'reuse-{len(reuse)+1:03d}', 'current_accounts': sorted(members),
                 'historical_accounts': sorted(older), 'enabled_current_accounts': enabled,
                 'disabled_current_accounts': disabled, 'password_known': digest in verified}
        reuse.append(group)
        for member in members:
            if len(members) > 1:
                accounts[member]['risk_flags'].append('shared_current_credential')
            if enabled and disabled:
                accounts[member]['risk_flags'].append('enabled_disabled_reuse')
            if older:
                accounts[member]['risk_flags'].append('history_to_current_reuse')

    status_counts = []
    for status in STATUS:
        group = [a for a in accounts.values() if a['has_current'] and a['status'] == status]
        assessed = sum(a['current_nt_assessed'] for a in group)
        recovered = sum(a['current_nt_recovered'] for a in group)
        status_counts.append({'status': status, 'accounts': len(group), 'assessed': assessed,
                              'recovered': recovered, 'not_recovered': assessed-recovered,
                              'not_assessed': len(group)-assessed,
                              'recovery_rate': recovered/assessed if assessed else None})
    usable_history = [r for r in history if not r['overlaps_current']]
    metrics = {'current_accounts': len(current), 'history_only_accounts': len(accounts)-len(current),
               'current_accounts_recovered': sum(a['current_nt_recovered'] for a in accounts.values()),
               'history_records': len(history), 'current_history_overlaps': sum(r['overlaps_current'] for r in history),
               'historical_records_assessed': sum(r['nt_assessed'] for r in usable_history),
               'historical_records_recovered': sum(r['nt_recovered'] for r in usable_history),
               'current_lm_present': sum(a['lm_present'] is True for a in accounts.values()),
               'current_reuse_groups': sum(len(r['current_accounts']) > 1 for r in reuse),
               'enabled_disabled_reuse_groups': sum(bool(r['enabled_current_accounts'] and r['disabled_current_accounts']) for r in reuse),
               'history_to_current_reuse_groups': sum(bool(r['historical_accounts']) for r in reuse),
               'invalid_nt_recovery_claims': invalid, 'undecodable_recovery_records': undecodable,
               'seed_records_excluded_newlines': sum(b'\n' in seed or b'\r' in seed for seed in seeds)}
    for a in accounts.values():
        a['risk_flags'] = sorted(set(a['risk_flags']))
    return {'schema': 'perp.account-risk.v1', 'snapshot_time': snapshot_time,
            'sources': inventory['sources'], 'accounts': list(accounts.values()),
            'history': history, 'reuse_groups': reuse, 'by_status': status_counts, 'metrics': metrics,
            'limitations': ['Status describes the supplied inventory, not live authentication.',
                           'History indices are exporter positions, not dated password changes.',
                           'LM key matches are not independent LM verification or current NT recovery.',
                           'History/current overlaps are excluded from historical recovery totals.',
                           'Unqualified identities are scoped to their inventory file unless a domain is supplied.']}, sorted(seed for seed in seeds if b'\n' not in seed and b'\r' not in seed)


def account_csv_rows(report):
    fields = ('id', 'account', 'domain', 'rid', 'kind', 'directory_account_type', 'status', 'status_source', 'has_current',
              'current_nt_assessed', 'current_nt_recovered', 'recovery_basis', 'lm_present', 'lm_recovery',
              'privileged', 'service_account', 'asset', 'owner', 'pwd_last_set', 'password_age_days',
              'password_never_expires', 'account_expires', 'last_logon', 'risk_flags')
    return [{field: '; '.join(a[field]) if field == 'risk_flags' else a[field] for field in fields}
            for a in report['accounts']]
