# Synthetic account demonstration · v1.1

Open [password_report.html](password_report.html) locally, or download the
[Excel workbook](password_report.xlsx). All accounts, credentials, roles, owners,
and assets are invented for demonstration; no assessment inputs were used.

The example includes seven current accounts, Enabled/Disabled/Unknown status,
an enabled/disabled shared credential, history-to-current reuse, one history
overlap, partial LM-key evidence, and an empty-password account. Roles and dates
are explicitly supplied synthetic metadata. It is not a live domain assessment.

- [Accounts CSV](accounts.csv) and [account analysis JSON](account_risk.json).
- [History CSV](password_history.csv) and [reuse CSV](credential_reuse.csv).
- [AttackForge review bundle](attackforge/bundle.json), with no credentials or uploads.
- Standard password-pattern exports accompany the account report.

Rebuild to a **new** directory with the optional Excel dependency installed:

```bash
python3 ./scripts/build_account_sample.py --output ./dist/new-account-demo
```

The builder generates its fixtures in a temporary directory, uses neutral source
labels, and does not read or overwrite real inventories. No candidate-seed file
is included in this demonstration. See [the account workflow](../../docs/account-inventory.md)
for your own inputs.
