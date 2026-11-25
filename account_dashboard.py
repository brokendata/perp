"""Escaped account-risk views for the existing self-contained dashboard."""
import html
import json


def esc(value):
    return html.escape(str(value), quote=True)


def table(identifier, caption, columns, rows, limit=200):
    head = ''.join(f'<th scope="col">{esc(name)}</th>' for name in columns)
    body = ''
    for row in rows[:limit]:
        body += '<tr>'+''.join(f'<th scope="row">{esc(value)}</th>' if index == 0 else
                              f'<td data-label="{esc(columns[index])}">{esc(value)}</td>'
                              for index, value in enumerate(row))+'</tr>'
    return (f'<div class="table-wrapper" tabindex="0" role="region" aria-labelledby="{identifier}">'
            f'<table class="responsive-table"><caption id="{identifier}">{esc(caption)}</caption>'
            f'<thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'
            f'<p class="note">Showing {min(limit, len(rows)):,} of {len(rows):,}; downloads contain all rows.</p>')


def render_accounts(risk, chart, seeds_exported=False):
    metrics = risk['metrics']
    statuses = {row['status']: row for row in risk['by_status']}
    values = [('Current accounts', metrics['current_accounts']),
              ('Enabled accounts with known passwords', statuses['Enabled']['recovered']),
              ('Disabled accounts with known passwords', statuses['Disabled']['recovered']),
              ('Unknown-status accounts with known passwords', statuses['Unknown']['recovered']),
              ('Historical records recovered', metrics['historical_records_recovered']),
              ('Current LM material present', metrics['current_lm_present']),
              ('Enabled / disabled reuse groups', metrics['enabled_disabled_reuse_groups']),
              ('History / current reuse groups', metrics['history_to_current_reuse_groups'])]
    blocks = ''.join(f'<div class="metric"><dt>{esc(name)}</dt><dd>{value:,}</dd></div>' for name, value in values)
    distribution = [{'label': status+' · '+label, 'count': row[key]}
                    for status, row in statuses.items()
                    for label, key in [('password known', 'recovered'), ('not recovered', 'not_recovered'), ('not assessed', 'not_assessed')]]
    picture = chart('Current account recovery', distribution, metrics['current_accounts'], len(distribution), pie=True, unit='accounts',
                    description='Known means a verified current NT password or the known empty-password NT hash. Enabled status is from the supplied snapshot; no live login was tested.')
    status_rows = [(row['status'], row['accounts'], row['assessed'], row['recovered'],
                    row['not_assessed'], f"{row['recovery_rate']:.1%}" if row['recovery_rate'] is not None else 'Not assessed')
                   for row in risk['by_status']]
    status_table = table('account-status-caption', 'Current accounts by status',
                         ('Status', 'Accounts', 'NT hashes assessed', 'Passwords known', 'Not assessed', 'Recovery rate'), status_rows)
    account_names = {a['id']: a['account'] for a in risk['accounts']}
    reuse_rows = [(g['id'], '; '.join(account_names[x] for x in g['current_accounts']),
                   '; '.join(account_names[x] for x in g['historical_accounts']) or 'None',
                   'Yes' if g['enabled_current_accounts'] and g['disabled_current_accounts'] else 'No',
                   'Yes' if g['password_known'] else 'No') for g in risk['reuse_groups']]
    history_rows = [(r['account'], r['history_index'], r['current_status'], 'Current overlap' if r['overlaps_current'] else 'Historical',
                     'Yes' if r['nt_recovered'] else 'Not recovered' if r['nt_assessed'] else 'Not assessed',
                     r['lm_recovery']) for r in risk['history']]
    data = []
    flag_labels = {'enabled_current_recovered': 'Enabled: current password known',
                   'disabled_current_recovered': 'Disabled: current password known',
                   'unknown_status_current_recovered': 'Unknown status: current password known',
                   'privileged_current_recovered': 'Privileged password known',
                   'service_account_current_recovered': 'Service password known',
                   'krbtgt_credential_exposure': 'krbtgt credential exposure',
                   'lm_material_present': 'LM material present',
                   'known_empty_current_password': 'Current empty password',
                   'shared_current_credential': 'Shared current credential',
                   'enabled_disabled_reuse': 'Enabled / disabled reuse',
                   'history_to_current_reuse': 'Historical / current reuse'}
    for a in risk['accounts']:
        roles = ', '.join(name for name, key in [('Privileged', 'privileged'), ('Service account', 'service_account')] if a[key] is True) or 'None confirmed'
        data.append({'account': a['account'], 'status': a['status'], 'kind': a['kind']+(' (history only)' if not a['has_current'] else ''),
                     'recovery': a['recovery_basis'], 'lm': a['lm_recovery'], 'roles': roles,
                     'flags': ', '.join(flag_labels.get(flag, flag) for flag in a['risk_flags']) or 'None', 'age': a['password_age_days'],
                     'asset': a['asset'], 'recovered': a['current_nt_recovered']})
    downloads = '<a href="accounts.csv" download>Accounts CSV</a><a href="password_history.csv" download>History CSV</a><a href="credential_reuse.csv" download>Reuse CSV</a><a href="account_risk.json" download>Account JSON</a>'
    if seeds_exported:
        downloads += '<a href="candidate_seeds.txt" download>Candidate seeds (sensitive)</a>'
    warning = ''
    if metrics['invalid_nt_recovery_claims'] or metrics['undecodable_recovery_records']:
        warning = f'<p class="note">Recovery checks: {metrics["invalid_nt_recovery_claims"]:,} NT hash/password mismatches excluded; {metrics["undecodable_recovery_records"]:,} records could not be decoded for NT verification. Check the input encoding.</p>'
    if seeds_exported and metrics['seed_records_excluded_newlines']:
        warning += f'<p class="note">Candidate export omitted {metrics["seed_records_excluded_newlines"]:,} entries containing line breaks.</p>'
    return (f'<section class="account-overview" aria-labelledby="account-risk-heading"><h2 id="account-risk-heading">Account exposure</h2>'
            f'<p class="note">Inventory snapshot: {esc(risk["snapshot_time"] or "not supplied")}. Rates use current accounts with an NT hash, grouped by status. Roles require directory context.</p>'
            f'<nav class="downloads" aria-label="Account report downloads">{downloads}</nav><dl class="metrics account-metrics">{blocks}</dl>{warning}'
            f'<div class="grid account-grid">{picture}<section class="card"><h2>Status and recovery rates</h2>{status_table}</section></div>'
            '<section class="card wide"><h2>Account explorer</h2><div class="controls" id="account-controls" hidden>'
            '<div class="field search-field"><label for="account-search">Search accounts, roles, or risk flags</label><input id="account-search" type="search" aria-controls="account-rows" autocomplete="off"></div>'
            '<div class="field"><label for="account-status-filter">Status</label><select id="account-status-filter"><option value="">All statuses</option><option>Enabled</option><option>Disabled</option><option>Unknown</option></select></div>'
            '<label><input id="account-known" type="checkbox"> Current password known</label></div>'
            '<div class="table-wrapper" tabindex="0" role="region" aria-labelledby="account-explorer-caption"><table class="responsive-table">'
            '<caption id="account-explorer-caption">Account recovery and reuse · 50 rows per page</caption><thead><tr>'
            + ''.join(f'<th scope="col">{esc(label)}</th>' for label in ('Account', 'Status', 'Kind', 'Current NT recovery', 'LM evidence', 'Confirmed roles', 'Risk flags', 'Password age (days)', 'Asset'))
            + '</tr></thead><tbody id="account-rows"></tbody></table></div>'
            '<div class="pagination" id="account-pagination" hidden><p id="account-page-status" role="status" aria-atomic="true"></p>'
            '<div class="page-actions"><button id="account-prev" aria-controls="account-rows">Previous</button><button id="account-next" aria-controls="account-rows">Next</button></div></div>'
            '<noscript><p>Open Accounts CSV for account details, or enable JavaScript for search and pagination.</p></noscript></section>'
            '<section class="card wide"><h2>Credential reuse relationships</h2><p class="note">Exact NT hash relationships, not password similarity. One credential can affect several accounts.</p>'
            + table('reuse-caption', 'Current and historical credential reuse', ('Group', 'Current accounts', 'History accounts', 'Enabled / disabled bridge', 'Password known'), reuse_rows)
            + '</section><section class="card wide"><h2>Password history</h2>'
            f'<p class="note">{metrics["current_history_overlaps"]:,} history entries overlap their own current NT hash and are excluded from historical recovery totals. Indices are not dates. History-only accounts: {metrics["history_only_accounts"]:,}.</p>'
            + table('history-caption', 'Historical records and current overlaps', ('Account', 'History index', 'Current status', 'Classification', 'NT password known', 'LM evidence'), history_rows)
            + '</section><p class="note">LM halves and matching LM potfile keys do not establish the case-sensitive current NT password. Account identities are sensitive; keep this report private.</p>'
            f'<template id="account-data">{esc(json.dumps(data, ensure_ascii=True, separators=(",", ":")))}</template></section>')
