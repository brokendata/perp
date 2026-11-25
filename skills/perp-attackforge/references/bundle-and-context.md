# Bundle and account context

`bundle.json` uses `perp.attackforge.bundle.v1`, a portable review format. An agent
maps it to its consultant's live AttackForge schema. It is not advertised as a
drop-in native JSON import. The companion `review.txt` summarizes proposed
findings and unresolved context, and `evidence/summary.svg` contains aggregate
counts only. Additional PNG/JPEG/WebP images are copied into `evidence/` with
generic names and SHA-256 metadata; every supplied image needs content review.
Supplied screenshots are initially unassigned; the consultant must associate
each image with the findings it actually supports. Source IDs follow the source
order in the original `summary.json`, preserving local traceability without
shipping local file paths.

## Account CSV

Columns:

```csv
source,line,account,asset,hash_type,privileged,service_account,lm_storage_confirmed,recovery_confirmed
```

- `source`: exact path of an input listed in `summary.json`, or a path relative to
  this CSV. It must join to a recovered record in `passwords.csv`.
- `line`: original input line number, not CSV row number.
- `account`: confirmed account identity from an authorized account/hash inventory.
- `asset`: confirmed affected asset name to map to the target project.
- `hash_type`: supplied evidence such as `LM`, `NTLM`, or `Kerberos`; never inferred
  from digest length or password content. `LANMAN` and `3000` normalize to `LM`.
- Boolean fields accept `true`, `false`, or blank (unknown).
- `privileged` and `service_account`: confirmed roles; name hints alone are not
  confirmation. Multiple accounts may map to the same recovered hash record.
- `lm_storage_confirmed`: confirmation that an active, non-placeholder LM hash
  is stored. A declared LM format alone doesn't prove this. The familiar empty
  LM placeholder, a 32-character digest, and wordlist strings are insufficient.
- `recovery_confirmed`: for a plaintext source, confirm that this record really
  is a recovered audit credential rather than an example/dictionary entry.
  Potfile sources are treated as recovery records; the engagement still needs
  consultant review. No authentication replay or account changes are performed.

Exact duplicate account mappings, unknown source/line joins, malformed booleans,
and missing account/asset values fail preparation. The tool never silently
matches an ambiguous basename or guesses account names from password text.

## Findings

### Account-aware perp 1.1 results

When `summary.json` includes `perp.account-risk.v1` analysis, the standalone helper
also prepares drafts for enabled current-password exposure, current reuse across
enabled/disabled accounts, historical/current reuse affecting enabled accounts,
and krbtgt exposure. It consumes only safe account fields and inventory source
aliases/digests; it does not copy raw inventory hashes, passwords, local paths,
or seed lists into the bundle. Current status is a supplied snapshot, not live
authentication evidence. Source role flags must be explicitly confirmed.

LM storage can be established by non-placeholder LM material in a typed current
inventory record. It does not require an NT password recovery. Partial LM key
matches do not establish the current case-sensitive NT password. History records
overlapping their own current hash are excluded from historical reuse analysis.

Privileged/service-password drafts from inventory analysis require a known
current NT password, Enabled status, and the corresponding confirmed role.
Unknown-status recoveries and missing in-scope asset mappings become review checks.
No disabled/history-only record is promoted to an enabled credential finding.
krbtgt exposure has separate domain-response guidance; do not recommend enabling
that account because its disabled flag is present.

### Legacy explicit context CSV

- **Active LAN Manager password hash storage** requires `hash_type=LM`,
  `lm_storage_confirmed=true`, and a recovered audit record. Recommend enabling
  the applicable NoLMHash policy, coordinating password changes, and verifying
  that stored LM material has been removed. Validate compatibility first.
- **Recoverable privileged-account passwords** requires a recovered record and
  `privileged=true`. Recommend controlled rotation, reuse review, appropriate
  MFA, and separation of privileged credentials.
- **Recoverable service-account passwords** requires a recovered record and
  `service_account=true`. Recommend coordinated rotation across consuming
  services/tasks, managed service accounts/identities where supported, and
  least privilege. Don't prescribe an uncoordinated reset that breaks services.

The helper provides severity suggestions, never a CVSS score or a final rating.
All findings remain consultant-review drafts. Names containing admin/svc/service
produce review hints only when roles are unknown. Plaintext wordlists and aggregate
statistics alone produce no account-specific vulnerabilities. The bundle counts
input recovery records, not unique users or an account crack rate.

The context contains no password column. Password values, password-derived
fingerprints, hash strings, source local paths, and top-password labels are
omitted from exported JSON and generated graphics. Account names remain sensitive;
supplied images may still show secrets. Review them before publication.

LM remediation reference:
[Microsoft NoLMHash policy](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-do-not-store-lan-manager-hash-value-on-next-password-change).
