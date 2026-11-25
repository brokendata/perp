# Changelog

## 1.1

- Account-inventory mode for NTDS/secretsdump text exports, including enabled,
  disabled, and unknown status, current records, and password history.
- Offline NT-password verification with separate recovery rates, current/history
  overlap handling, shared credentials, and disabled/history-to-enabled reuse.
- LM placeholder and partial/full key-match reporting without treating LM halves
  as recovered case-sensitive NT passwords.
- Optional directory context for confirmed roles, ownership, status, and password
  age; domain/RID scoping and conflicting-snapshot checks.
- Account charts, searchable/paginated tables, CSV/JSON exports, and Excel sheets,
  including inventory-only reports.
- Hashcat username-aware show input and explicit deduplicated candidate-seed
  exports for further recovery rounds.
- Account-aware AttackForge review drafts and a synthetic demonstration dashboard.

## 1.0

- Python reporting across Kali/Linux, macOS, and Windows, with flexible file,
  wildcard, and recursive directory inputs.
- A single offline HTML dashboard with colorful interactive donut charts,
  searchable records, and System, Light, and Dark themes.
- Character-set profiles, password-length distributions, frequent patterns,
  and ordered byte-level Hashcat masks.
- Hash/credential-type charts and count tables in HTML and Excel, with an
  extensible format registry, searchable type labels, and explicit declarations
  for ambiguous or custom formats.
- Optional Excel workbooks with native charts and filterable records and masks.
- Format-aware Hashcat and John potfile parsing, including structured Kerberos
  and NetNTLM records, plus literal plaintext input.
- Timestamped result folders with CSV/JSON exports and input provenance.
- AttackForge review bundles with remediation drafts, evidence attachments, and
  a portable skill for a consultant's authenticated MCP/API connection.
- A public-wordlist sample with interactive HTML, Excel output, and light/dark
  chart screenshots.
