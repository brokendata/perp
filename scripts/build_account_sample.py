"""Build the explicitly synthetic v1.1 account demonstration; never reads audit data."""
import argparse
from pathlib import Path
import shutil
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import perp
from account_inventory import EMPTY_LM, nt_hash, load_inventory, load_directory_context, inventory_type_map, correlate


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT/'dist/account-demo', help='New demonstration directory (must not exist)')
    args = parser.parse_args()
    if args.output.exists():
        parser.error('Output already exists; choose a new directory')
    with tempfile.TemporaryDirectory() as temporary:
        temp = Path(temporary)
        def row(name, rid, password, status='', lm=EMPTY_LM):
            return f'EXAMPLE.TEST\\{name}:{rid}:{lm}:{nt_hash(password)}:::'+(' (status='+status+')' if status else '')+'\n'
        lm = 'a1'*8+'b2'*8
        text = row('lab-admin', 500, b'DemoAdmin1!', 'Enabled')
        text += row('app-service', 1001, b'DemoShared2!', 'Enabled')
        text += row('retired-user', 1002, b'DemoShared2!', 'Disabled', lm)
        text += row('current-user', 1003, b'DemoNew3!', 'Enabled')
        text += row('unclassified', 1004, b'DemoUnknown4!')
        text += row('empty-disabled', 1005, b'', 'Disabled')
        text += row('DCX$', 1006, b'DemoMachine5!', 'Enabled')
        text += row('lab-admin_history0', 500, b'DemoAdmin1!')
        text += row('retired-user_history0', 1002, b'DemoNew3!')
        text += row('retired-user_history1', 1002, b'DemoOld6!')
        text += row('DCX$_history0', 1006, b'DemoMachineOld7!')
        inventory_path = temp/'accounts.ntds'
        inventory_path.write_text(text, encoding='utf-8')
        directory = temp/'directory.csv'
        directory.write_text('domain,rid,privileged,service_account,asset,owner,pwd_last_set,password_never_expires,account_type\n'
                             'EXAMPLE.TEST,500,true,false,example-directory,Example IAM team,2026-09-01T00:00:00+00:00,false,user\n'
                             'EXAMPLE.TEST,1001,false,true,example-app,Example app team,2026-08-01T00:00:00+00:00,true,service\n'
                             'EXAMPLE.TEST,1002,false,false,example-directory,Example IAM team,,,user\n'
                             'EXAMPLE.TEST,1003,false,false,example-directory,Example IAM team,,,user\n'
                             'EXAMPLE.TEST,1006,false,false,example-directory,Example IAM team,,,computer\n', encoding='utf-8')
        pot = temp/'recovery.potfile'
        pot.write_text(''.join(nt_hash(password)+':'+password.decode()+'\n' for password in
                               (b'DemoAdmin1!', b'DemoShared2!', b'DemoNew3!', b'DemoOld6!'))+lm[:16]+':DEMOHAL\n', encoding='utf-8')
        inventory = load_inventory([inventory_path])
        load_directory_context(inventory, directory)
        recoveries = []
        rows, summary = perp.collect([pot], 'hashcat', 'utf-8', b':', None, recovery_records=recoveries,
                                     inventory_types=inventory_type_map(inventory))
        risk, _ = correlate(inventory, recoveries, snapshot_time='2026-11-25T12:00:00+00:00')
        for row in rows:
            row['source'] = 'synthetic/recovery.potfile'
        summary['sources'][0]['path'] = 'synthetic/recovery.potfile'
        summary['created'] = '2026-11-25T12:00:00+00:00'
        for source in risk['sources']:
            source['path'] = 'synthetic/'+('directory.csv' if source['format'] == 'directory-csv' else 'accounts.ntds')
        for account in risk['accounts']:
            for evidence in account['recovery_evidence']:
                if 'source' in evidence:
                    evidence['source'] = 'synthetic/recovery.potfile'
        result = perp.write_results(rows, summary, temp/'results', excel=True, attackforge=True, account_risk=risk)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(result, args.output)
    print(f'Synthetic account demonstration: {args.output}')


if __name__ == '__main__':
    main()
