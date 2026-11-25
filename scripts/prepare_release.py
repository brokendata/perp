"""Build a local, allowlisted release archive without Git or network access."""
import hashlib
import json
import re
import io
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
FILES = (
    '.gitignore', 'README.md', 'CHANGELOG.md', 'WORDLISTS.md',
    'perp.py', 'potfile_parser.py', 'hash_types.py', 'dashboard_renderer.py', 'excel_export.py',
    'account_inventory.py', 'account_dashboard.py', 'docs/account-inventory.md', 'scripts/build_account_sample.py',
    'attackforge_export.py', 'requirements-excel.txt', 'scripts/prepare_release.py',
    'web/logo.txt', 'web/dashboard.html', 'web/dashboard.css',
    'web/dashboard.js', 'web/charts.js', 'web/accounts.js',
    'tests/test_perp.py', 'tests/test_potfile_parser.py', 'tests/test_hash_types.py',
    'tests/test_excel_export.py', 'tests/test_dashboard_charts.py',
    'tests/test_attackforge_export.py', 'tests/check_dashboard.cjs',
    'tests/check_charts.cjs', 'tests/test_account_inventory.py', 'tests/check_accounts.cjs',
    'skills/perp-attackforge/SKILL.md',
    'skills/perp-attackforge/agents/openai.yaml',
    'skills/perp-attackforge/references/connections.md',
    'skills/perp-attackforge/references/bundle-and-context.md',
    'skills/perp-attackforge/scripts/bundle.py',
    'sample/README.md', 'sample/password_report.html', 'sample/password_report.xlsx',
    'sample/passwords.csv', 'sample/masks.csv', 'sample/summary.json',
    'sample/HashcatMasks.hcmask', 'sample/HashcatMasks.txt',
    'sample/attackforge/bundle.json', 'sample/attackforge/review.txt',
    'sample/attackforge/evidence/summary.svg',
    'docs/screenshots/dashboard-light.png', 'docs/screenshots/dashboard-dark.png',
    'docs/screenshots/account-risk-light.png', 'docs/screenshots/account-risk-dark.png',
    'sample/account-risk/README.md', 'sample/account-risk/password_report.html',
    'sample/account-risk/password_report.xlsx', 'sample/account-risk/summary.json',
    'sample/account-risk/passwords.csv', 'sample/account-risk/masks.csv',
    'sample/account-risk/HashcatMasks.hcmask', 'sample/account-risk/HashcatMasks.txt',
    'sample/account-risk/accounts.csv', 'sample/account-risk/account_risk.json',
    'sample/account-risk/password_history.csv', 'sample/account-risk/credential_reuse.csv',
    'sample/account-risk/attackforge/bundle.json', 'sample/account-risk/attackforge/review.txt',
    'sample/account-risk/attackforge/evidence/summary.svg',
)


def main():
    import sys
    sys.path.insert(0, str(ROOT))
    from perp import VERSION

    contents = {}
    # This catches common accidental inclusions, not every possible secret.
    checks = (
        r'(?i)[A-Z]:[\\/]Users[\\/]',
        r'/(?:Users|home)/[A-Za-z0-9_.-]+/',
        r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
        r'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|AKIA[A-Z0-9]{16})\b',
    )
    for name in FILES:
        path = ROOT / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f'Missing or symlinked release file: {name}')
        data = path.read_bytes()
        if path.suffix == '.png':
            if not data.startswith(b'\x89PNG\r\n\x1a\n'):
                raise ValueError(f'Invalid screenshot PNG: {name}')
            texts = []  # Screenshots also require visual review.
        elif path.suffix == '.xlsx':
            with ZipFile(io.BytesIO(data)) as workbook:
                texts = [workbook.read(item).decode('utf-8') for item in workbook.namelist()
                         if item.endswith(('.xml', '.rels'))]
        else:
            texts = [data.decode('utf-8')]
        if any(re.search(pattern, text) for text in texts for pattern in checks):
            raise ValueError(f'Potential personal path or credential in {name}; review required')
        contents[name] = data

    output = ROOT / 'dist'
    output.mkdir(exist_ok=True)
    archive_path = output / f'perp-{VERSION}.zip'
    with ZipFile(archive_path, 'w', compression=ZIP_DEFLATED) as archive:
        for name, data in sorted(contents.items()):
            info = ZipInfo(f'perp-{VERSION}/{name}', date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
    with ZipFile(archive_path) as archive:
        assert archive.testzip() is None
        assert len(archive.namelist()) == len(FILES)
        for name, data in contents.items():
            assert archive.read(f'perp-{VERSION}/{name}') == data

    manifest = {
        'version': VERSION,
        'archive': archive_path.name,
        'archive_sha256': hashlib.sha256(archive_path.read_bytes()).hexdigest(),
        'files': [
            {'path': name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
            for name, data in sorted(contents.items())
        ],
    }
    (output / f'perp-{VERSION}-manifest.json').write_text(
        json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    print(f'Prepared {archive_path.name}: {len(FILES)} allowlisted files; no upload performed.')


if __name__ == '__main__':
    main()
