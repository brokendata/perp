# Public wordlist demonstration

This v1.0 report uses a restored 10,000-entry excerpt of the public RockYou
dictionary. It is not an engagement report, identified accounts, or an account
crack-rate measurement. The full wordlist and archive are not included; see
[External wordlists](../WORDLISTS.md).

There are 10,000 distinct records, one empty entry, and 150 distinct masks.
Dictionary strings remain visible in HTML, CSV, and XLSX to demonstrate real
output. No account mappings, customer identifiers, original machine paths, or
raw hashes are included. `public-wordlist/rockyou-excerpt.txt` is a neutral source
label, not a bundled input. The date is normalized to midnight UTC; statistics
and the input digest retain the restored report's provenance.

- [Interactive HTML dashboard](password_report.html): download the sample folder
  and open locally; GitHub's viewer does not execute the dashboard.
- [Excel workbook](password_report.xlsx): native charts and filterable tables.
- [Detailed CSV](passwords.csv), [mask frequencies](masks.csv), and
  [summary JSON](summary.json).
- [Runnable masks](HashcatMasks.hcmask); `HashcatMasks.txt` is the compatibility copy.
- [AttackForge bundle](attackforge/bundle.json): no findings because dictionary
  entries do not establish account vulnerabilities. Its SVG is an aggregate
  graphic, not a screenshot.

The [README screenshots](../docs/screenshots/) are browser captures of this report.
Hover/focus donut legends, hide/restore categories, search records, and switch
System/Light/Dark in the HTML to explore the interactive output.

Generate your own report from an independently obtained plaintext input:

```bash
python3 ./perp.py /path/to/rockyou-excerpt.txt --format plaintext --encoding latin-1 --excel --attackforge --output-root ./reports
```

`--excel` needs the optional dependency described in the main README. Use the
virtual environment's interpreter if installed there. `passwords.csv` contains
metadata columns and is not a plaintext input list. Keep real audit outputs out
of this folder; only the reviewed files are allowlisted for release.
