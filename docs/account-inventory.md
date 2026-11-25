# Account inventory reporting

perp 1.1 correlates a current/history account inventory with recovered passwords
offline. It does not connect to a domain controller, attempt logins, extract a
binary database, or launch cracking tools.

## Files to provide

| Input | Purpose |
| --- | --- |
| Complete NTDS/secretsdump **text** export | Current account hashes, status, and optional history; supplies the account denominator. |
| Hashcat/John potfiles | Recovered hash/password records. |
| Hashcat `--show --username` output | Alternative recovery input with a declared `username:hash:password` layout. |
| Plaintext recovered-password/candidate list | Candidates verified against inventory NT hashes; not assumed to belong to accounts. |
| Directory CSV | Optional confirmed roles, status, ownership, and timestamps. |

Use one coherent inventory snapshot. Binary `NTDS.dit` needs separate extraction
with an appropriate tool and key material; it is not a text input for perp.
Keep account inventories and recovery files outside the project or in ignored
`inputs/`. Never commit actual assessment inputs to the public sample folders.

## Inventory format

```text
DOMAIN\account:RID:LM_HASH:NT_HASH::: (status=Enabled)
DOMAIN\account_history0:RID:LM_HASH:NT_HASH:::
HOST$_history1:RID:LM_HASH:NT_HASH:::
```

- LM and NT fields are 32 hexadecimal characters, or empty when unavailable.
  Missing NT material is excluded from recovery-rate denominators.
- Status is optional: `Enabled`, `Disabled`, `Unknown`, or `N/A`. Missing/N/A
  status remains Unknown. History-line status does not establish current status.
- `_historyN` is the exporter's reserved history suffix. Indices are positions,
  not timestamps. Genuine account names with that suffix need normalization to
  an unambiguous inventory before import.
- Domain/RID identifies an account. Unqualified names are scoped per input file;
  `--inventory-domain DOMAIN` supplies a shared domain for those names. Qualified
  domains are preserved. Cross-file unqualified records are not silently merged.
- Exact duplicate credential records collapse while retaining their source
  references. Conflicting names, hashes, or statuses fail rather than mixing
  snapshots. Empty lines and `#` comments are accepted; extraction log messages
  must be removed. A terminal presentation backslash after a complete record is
  accepted; backslashes in account identities remain meaningful.
- Inventory and directory files use UTF-8; `--encoding` applies to recovery inputs
  and password decoding for NT verification.

## Example workflow

Start with inventory-only visibility:

```bash
python3 ./perp.py --inventory /path/to/accounts.ntds --inventory-domain EXAMPLE.TEST --output-root ./reports
```

Add potfiles and directory context:

```bash
python3 ./perp.py /path/to/hashcat.potfile --format hashcat --inventory /path/to/accounts.ntds --directory-context /path/to/directory.csv --snapshot-time 2026-11-25T12:00:00+00:00 --excel --attackforge --output-root ./reports
```

`--inventory` is repeatable for complementary files from the same snapshot.
Use the virtual environment's interpreter if Excel's dependency is installed
there. See the main README for platform installation instructions.

For a default hash-plus-password export from `--show --username`:

```bash
python3 ./perp.py /path/to/show.txt --format hashcat-show --inventory /path/to/accounts.ntds
```

This dialect expects exactly a username prefix, a hash representation, and a
password. Hashcat's default `$HEX[]` encoding preserves passwords containing the
separator or unusual bytes. Do not combine it with `--password-field`, a custom
outfile column arrangement, disabled auto-hex, or trailing metadata. Usernames
are contextual labels; they never override hash/password verification.

## Directory CSV

Required columns: `domain,rid`. Optional columns:

```csv
domain,rid,account,status,privileged,service_account,asset,owner,pwd_last_set,password_never_expires,account_expires,last_logon
EXAMPLE.TEST,1001,app-service,Enabled,false,true,example-app,Example owner,2026-10-01T00:00:00+00:00,true,,
```

Boolean values are `true`, `false`, or blank (unknown). Timestamps must be ISO 8601
with a timezone. Names such as `admin`/`svc`, SPNs, or `adminCount` are not treated
as proof of privilege or service ownership. Supply roles confirmed by the
assessment. The RID-500 account is labeled built-in Administrator for context,
but its `privileged` flag still requires explicit confirmation.

An additional `account_type` column accepts `user`, `computer`, `gmsa`, `msa`,
`service`, or `unknown` for confirmed directory classification. A `$` suffix
alone is not proof of a computer account; managed service accounts and even user
accounts can use it. Without directory context it is labeled unconfirmed.
See [Microsoft's account-name guidance](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/compatibility-user-accounts-end-dollar-sign).

Directory status can fill missing status, but cannot silently replace conflicting
inventory status. Unknown or ambiguous domain/RID joins and duplicate mappings
fail. Password age is calculated only when both password-last-set and
`--snapshot-time` are supplied. No last-logon value is assumed authoritative for
dormancy; that interpretation remains with the assessment.

## How correlation works

Recovery records are decoded into password bytes. Decodable candidates are
converted to Unicode and checked against inventory NT hashes using offline MD4
verification. This supports shared passwords and passwords recovered from other
hash families without joining unlike hash representations. A claimed NT recovery
whose password does not verify is excluded and counted as a mismatch. Undecodable
records are counted separately so an encoding issue is visible.
The dependency-free verifier is tested against [RFC 1320](https://www.rfc-editor.org/info/rfc1320/) vectors and NT-password test cases.

An NT hash matching the standard empty-password hash is marked **known empty**,
even without a potfile. That is distinct from a supplied recovery result.

Non-placeholder LM material is tracked separately. LM potfile keys can match a
complete hash or its halves. The empty LM placeholder is not evidence of stored
LM. These key matches are labeled **unverified LM**: perp does not independently
compute DES/LM or restore case, and LM matches never establish current NT recovery.

History entries matching their own current NT hash are overlaps, not evidence of
a previous password change, and are excluded from historical recovery totals.
Other historical entries can identify history-to-current reuse across accounts.
No dates or password-evolution patterns are invented from history positions.

Rates use **current accounts with an NT hash** within Enabled, Disabled, and
Unknown groups. Historical entries, history-only accounts, LM halves, and
duplicate recovery records do not inflate those denominators. Shared-current,
enabled/disabled, and historical/current reuse groups are based on identical NT
hashes; similarity is not presented as confirmed reuse.
Rates include computer/managed accounts; use the Kind column and account search
to inspect those separately. A history row's status is the account's current
snapshot status, not its status when that historical credential was used.

## Outputs

The HTML dashboard adds account recovery charts, rates, account filters, reuse
relationships, and history tables. Excel adds Account risk, Accounts, History,
and Reuse sheets. Both support inventory-only runs.

| File | Contents |
| --- | --- |
| `account_risk.json` | All account findings, denominators, provenance, history and reuse relationships; no raw hashes or passwords. |
| `accounts.csv` | Account status, current NT recovery, LM evidence, confirmed roles, metadata and risk flags. |
| `password_history.csv` | History positions, recovery, and own-current overlaps. |
| `credential_reuse.csv` | Group membership using account IDs from Accounts CSV. |

The normal password report still contains recovery input values. Account names,
roles, paths, and inventories are also sensitive. Keep assessment outputs private.

## Candidate exports and further recovery rounds

```bash
python3 ./perp.py /path/to/recovery.potfile --inventory /path/to/accounts.ntds --export-seeds
```

`candidate_seeds.txt` is produced **only** with `--export-seeds`. It deduplicates
password bytes that verified against an inventory NT hash, plus values from
matching LM potfile keys (which can be uppercase/partial components). It is a
local seed list for tools such as PRINCE, not a claim that every seed is a current
password. Entries containing line breaks are omitted and counted in the report.
No permutations are generated and no recovery tool is launched.

Import the resulting new potfile against the same coherent inventory to produce
a new report. To compare snapshots, run each snapshot separately; mixing changed
current hashes is rejected. Raw input hashes are never copied into account
reports, and seed exports are never added to AttackForge bundles.

## AttackForge

`--attackforge` consumes the account analysis automatically. It can prepare
review-required drafts for enabled current-password exposure, enabled/disabled
reuse, history/current reuse, LM storage, confirmed privileged/service accounts,
and krbtgt exposure. Missing assets and unknown status produce review checks.
History-only or disabled credentials are not promoted to enabled current-password
findings. Account state is a snapshot, not proof of successful authentication.

The bundle omits credentials and local paths. Screenshots require privacy review,
and the consultant's authenticated connection and publication instruction remain
necessary. No inventory or bundle command uploads data.
