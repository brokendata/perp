# Password Excel(lent) Reporting Python

perp **1.0** is an offline dashboard for recovered passwords from
Hashcat, John the Ripper, and plaintext lists.

Python 3.10+ runs the tool on Windows, Linux, and macOS. HTML, CSV, JSON, and mask
exports have **no third-party runtime dependencies**. Optional native Excel export
uses XlsxWriter; Microsoft Excel is not required to generate files.

## Sample dashboard

The [sample folder](sample/README.md) contains a reviewed v1.0 report from a
10,000-entry public RockYou excerpt: 10,000 unique records and 150 masks. It
demonstrates dictionary patterns, not an account crack rate or customer findings.
Original machine paths have been replaced with a neutral source label.

Download the project and open [sample/password_report.html](sample/password_report.html)
locally for interactive charts, record search, and theme switching. GitHub previews
the HTML source rather than running it. You can also download the
[Excel workbook](sample/password_report.xlsx) or inspect the
[summary JSON](sample/summary.json). The full wordlist is not bundled.

Light theme, showing length/profile donuts and overlapping character-set counts:

![Light dashboard with password length and character-set charts](docs/screenshots/dashboard-light.png)

Dark theme of the same sample:

![Dark dashboard with password length and character-set charts](docs/screenshots/dashboard-dark.png)

## Install dependencies

Run the commands from the project directory after downloading or cloning perp.

### Kali Linux

On **Kali Linux, prefer `apt` over system-wide `pip`**. Kali marks its system
Python as externally managed (PEP 668), so global and `--user` pip installs can
fail with `externally-managed-environment`. Use the distribution packages:

```bash
sudo apt update
sudo apt install python3
# Optional: only needed for --excel
sudo apt install python3-xlsxwriter

python3 ./perp.py /path/to/rockyou.txt --encoding latin-1 --excel --output-root ./reports
```

The normal HTML/CSV/JSON/mask exports and local AttackForge bundle need only
Python 3.10+; there is no pip install step for them. `apt` installs Python and
the optional library, while perp runs directly from this project directory.
See [Kali's Python package guidance](https://www.kali.org/docs/general-use/python3-external-packages/)
and the [Kali XlsxWriter package repository](https://http.kali.org/kali/pool/main/x/xlsxwriter/).

If you need the PyPI versions from `requirements-excel.txt`, use an isolated
virtual environment instead of modifying Kali's system Python:

```bash
sudo apt install python3-venv
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-excel.txt
.venv/bin/python ./perp.py /path/to/rockyou.txt --encoding latin-1 --excel
```

Do not use `sudo pip`, `pip install --user`, or `--break-system-packages` to
bypass Kali's protection. A default virtual environment does not see packages
installed by `apt`; use `python3` for the apt-installed library, or install the
requirements inside the virtual environment as shown above.

### macOS

Use Python 3.10+; check an existing installation with `python3 --version`.
If needed, install Python with [Homebrew](https://brew.sh/) (follow its setup
instructions, including the shell PATH step), then run:

```bash
brew install python
python3 --version

# Standard reports: no additional packages needed
python3 ./perp.py /path/to/rockyou.txt --encoding latin-1 --output-root ./reports
```

For optional Excel export, install XlsxWriter in a virtual environment.
[Homebrew's Python is also externally managed](https://docs.brew.sh/Language-Runtimes-and-Packages#python),
so use the environment's pip rather than installing into Homebrew's Python:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-excel.txt
.venv/bin/python ./perp.py /path/to/rockyou.txt --encoding latin-1 --excel --output-root ./reports
```

These commands work from Terminal with the default zsh shell; no activation is
required. Use `.venv/bin/python` in place of `python3` in the usage and verification
examples when using this environment. To view a report, open the generated HTML
in Finder or run `open "./reports/results-YOUR-RUN/password_report.html"`, replacing
`results-YOUR-RUN` with the folder printed by perp. The RockYou example must be
prepared separately as described below; it is not supplied by macOS or Homebrew.

### Windows

An optional Excel dependency can likewise be installed in a virtual environment:

```text
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-excel.txt
.\.venv\Scripts\python.exe .\perp.py C:\path\to\rockyou.txt --encoding latin-1 --excel
```

## Run

The usage examples refer to a separately downloaded RockYou file. See
[External wordlists](WORDLISTS.md) for the upstream download reference and input
size guidance. The reviewed sample outputs are included separately; no input
wordlist or compressed archive is bundled.

Examples below use `python3` on Kali/Linux/macOS. On Windows, use `python`
instead. For a virtual environment, use its Python executable as shown above.

```bash
# One file (plaintext by default for .txt)
python3 ./perp.py /path/to/rockyou.txt --encoding latin-1 --output-root ./reports

# Multiple files, with automatic format detection per file
python3 ./perp.py ./hashcat.potfile ./john.pot

# Directory or quoted wildcard; recurse into subdirectories if desired
python3 ./perp.py ./inputs --recursive --output-root ./reports
python3 ./perp.py "./inputs/*.pot*" --output-root ./reports

# Optional Excel workbook alongside the standalone HTML report
# Install XlsxWriter using the platform instructions above first.
python3 ./perp.py /path/to/rockyou.txt --encoding latin-1 --excel --output-root ./reports
```

`--output-root` defaults to the current directory. Each invocation
creates its own `results-YYYYMMDD-HHMMSS-microseconds` directory using local time.
Existing results and input files are never overwritten. Open `password_report.html`
directly in a browser; no web server or internet connection is needed.
Use the Theme selector in the report header to choose System, Light, or Dark.
System follows live changes in your OS preference. Manual choices are remembered
when browser local storage is available; selecting System removes the override.
Printing always uses light colors. Charts have labeled data tables, and record
tables stack into labeled cards when their container is narrow. Keyboard users
can skip straight to the record explorer and focus scrollable tables.

The HTML remains a single offline file. Keep `dashboard_renderer.py` and the
`web/` source assets alongside the scripts when copying or installing perp; these
are embedded during generation, so generated reports do not need those files.
Search is debounced, filtering/sorting is cached between page changes, and only
50 records are rendered at once. The full dataset is still embedded in the HTML.

Colorful SVG donut charts show password lengths, frequent passwords, masks, and
character combinations. Hover/tap a slice or focus a legend button to inspect
counts and percentages; activate legend buttons to hide/show categories, and
use Show all categories to reset. Each donut shows the six leading categories
plus Other categories, including records beyond the top-password summary.
Hiding changes only that chart, with shares recalculated over visible categories.
Character-set presence stays a bar chart because its groups overlap. Expand
View chart data for the original counts and shares. SVG, chart code, styles, and
data are embedded; no chart library, CDN, or network access is required.

The Character-set profiles donut counts one profile per recovered record:
`upper`, `lower`, `upperlower` (both letter cases only), `alphanum` (letters of
either case plus digits), `alphanumspecial` (letters, digits, symbols/spaces),
`alphaspecial`, `numeric`, `numspecial`, `special`, or `empty`. Records with any
non-ASCII/control bytes use `non-ASCII/control`. These categories are mutually
exclusive and sum to the total record count. The detailed CSV includes
`charset_profile`, and Summary JSON includes `character_set_profiles`.

## Input formats

- `auto`: `.pot` and `.potfile` are potfiles; everything else is plaintext.
- `--format plaintext`: one literal password per line, including blank lines,
  spaces, colons, and literal `$HEX[...]` text. An empty file has no records.
- `--format potfile` (also selected by `auto` for potfile extensions) uses a
  conservative boundary parser: known Kerberos TGS/AS-REP and NetNTLMv1/v2 layouts
  are recognized as complete hashes, including internal colons. Unknown layouts
  with multiple separators fail rather than guessing. Simple records with only
  one separator can be split unambiguously; this does not validate the algorithm.
- `--format hashcat` is for **canonical Hashcat potfiles**. It follows Hashcat's
  final-separator rule and decodes `$HEX[]` passwords. Hashcat encodes passwords
  containing the separator, so internal hash fields stay out of the password.
  This mode supports hash representations beyond the built-in recognizers but
  trusts the input to be a genuine Hashcat potfile, not a custom `--show` export.
- `--format john` uses the conservative parser; unsupported John formats need an
  explicit layout. Empty potfile lines are ignored; `hash:` is an empty password.
- Hashcat `$HEX[...]` passwords are decoded to original bytes in potfile mode.
  Invalid hex and malformed potfile lines fail with file and line context.
- For hashes/salts containing separators, explicitly set `--password-field N`:
  `hash:salt:password` needs `--password-field 2`. All text after that separator
  belongs to the password. This is a deliberate override, never the default.
  Nonstandard exports with trailing metadata need normalization into a documented
  layout first. Never assume the first or last field of an arbitrary export is a
  password. Split incompatible layouts into separate runs or normalize them.
- Set `--separator '|'` for another delimiter. `--encoding cp1252` can change text
  display for a non-UTF-8 list; use an ASCII-compatible encoding. UTF-16/32 input
  must first be converted to UTF-8. The original password bytes drive masks.
- Directory scans select `.txt`, `.pot`, and `.potfile`; `--recursive` includes
  subdirectories and skips previous `results-*` directories and known output text
  files. Explicit files/wildcards accept any extension. Overlapping paths resolve
  to one file; identical records in different files still count independently.

## Results

| File | Contents |
| --- | --- |
| `password_report.html` | Responsive dashboard, length/character/pattern charts, top passwords and masks, searchable and paginated records, source inventory |
| `password_report.xlsx` (with `--excel`) | Summary with native doughnut/column charts and source inventory; filterable Passwords and Masks tables with frozen headers |
| `passwords.csv` | Every recovered record, case-sensitive counts, character and byte lengths, ordered mask, source path and line |
| `masks.csv` | All masks and frequencies, including an empty mask for empty passwords |
| `HashcatMasks.hcmask` | Unique, nonempty runnable masks ordered by observed frequency |
| `HashcatMasks.txt` | Same masks, retaining the legacy filename |
| `summary.json` | Full aggregate distributions, top 20 passwords, input SHA-256 digests, version, and timestamp |

Mask positions follow **bytes in their original order**: `Ab9!z` becomes
`?u?l?d?s?l`. ASCII uppercase/lowercase/digit/symbol classes are separate.
Non-ASCII and control bytes use `?b` per byte: UTF-8 `é` becomes `?b?b`. These broad
byte masks cover the input but can have very large search spaces. Empty passwords
remain in reports but have no runnable mask. Masks summarize observed shapes;
they are not password strength scores or guarantees of successful recovery.

The HTML uses embedded data, CSS charts, and local JavaScript; it loads no external
scripts, fonts, or analytics. Search and sorting operate locally, 50 records per
page. Passwords are HTML-escaped and inserted as text. Invalid text/control bytes
are displayed as `$HEX[...]`. Formula-like CSV text gets an apostrophe prefix for
safer opening in Excel. JSON and the HTML retain unprefixed display values.

Counts describe recovered input records, not total accounts or a crack rate.
Repeated records are retained; unique password counts compare original bytes
case-sensitively. Length charts use bytes; the detailed CSV also includes character
length when decodable. Character classes use ASCII byte ranges. The engine keeps
records in memory and embeds them in HTML, so very large potfiles may need to be
split. Reports contain recovered passwords and source paths.

## Excel export

Use `--excel` after installing `python3-xlsxwriter` with `apt` on Kali, or
`requirements-excel.txt` inside a virtual environment. Run perp with the same
Python interpreter used for the dependency. The workbook is linked
from the generated HTML and saved in the same timestamped folder. It contains
the same detailed records and profile/mask counts, with native Excel charts and
filterable tables. Passwords remain literal strings, including leading zeros,
URLs, and text starting with `=`. Profiles and lengths include cached percentage
formulas. PivotTables are not generated.

Excel has a 1,048,576-row sheet limit (including the header) and a 32,767-character
cell limit. If either limit is exceeded, `--excel` fails before creating results
rather than truncating records; split the input or generate HTML/CSV/JSON instead.
HTML-only runs do not load XlsxWriter. Run the Python entry point, `perp.py`.

## AttackForge export and portable skill

Use `--attackforge` to add a local review bundle under `attackforge/` in the
timestamped result folder. It makes **no API calls or uploads**:

```bash
python3 ./perp.py ./audit.potfile --format hashcat --attackforge --account-context ./accounts.csv --evidence ./screenshots/redacted.png
```

`--account-context` and repeatable `--evidence` are optional. The bundle contains
`bundle.json`, `review.txt`, an aggregate SVG graphic, and supplied PNG/JPEG/WebP
images with SHA-256 digests. The SVG is generated evidence, **not a screenshot**.
Images still need review for sensitive content and association with findings.
Passwords, password-derived fingerprints, raw hashes, local source paths, and
top-password labels are omitted from the JSON/graphic. The usual HTML/XLSX/CSV
outputs still contain password data and are not included in this bundle.

Account-specific recommendations require a CSV linking original `source` paths
and `line` numbers to confirmed accounts, assets, roles, and hash-type evidence.
See the CSV columns and requirements in the
[context contract](skills/perp-attackforge/references/bundle-and-context.md).
LM storage needs explicit confirmation of active non-placeholder storage.
`admin`/`svc` name hints trigger review, not a confirmed privilege finding.
Plaintext dictionaries do not establish recovered account credentials.

The portable skill source is [skills/perp-attackforge](skills/perp-attackforge/SKILL.md),
and the distributable is `dist/perp-attackforge-skill.zip`. It includes a standalone
Python helper, so a consultant can prepare a bundle from existing perp results:

```bash
python3 ./skills/perp-attackforge/scripts/bundle.py prepare ./reports/results-RUN --account-context ./accounts.csv
python3 ./skills/perp-attackforge/scripts/bundle.py verify ./reports/results-RUN/attackforge
```

Extract the skill folder into the consultant's skill directory, then invoke
`$perp-attackforge` with the result folder and intended AttackForge project. It
prefers their connected official MCP integration and can use an authorized API
connection when appropriate. It discovers that tenant's actual schemas, maps
in-scope assets and severity, checks existing finding markers, attaches reviewed
evidence, and reads back confirmed IDs. It does not ship credentials or configure
the consultant's authentication. Missing connection permissions stop that step.

The JSON is a **portable review bundle**, not an assumed native AttackForge import
format. Publication requires a specified project and the consultant's instruction
to publish the reviewed findings. Severity suggestions require review; no CVSS
score is invented. Live MCP/API publication is not tested without a connection.

## Password extraction correctness

Parser revision 2 replaces the unsafe first-colon default. Generated summaries
record the parser revision, format, separator, and any explicit field override.
Regenerate old potfile-derived reports and wordlists; their password statistics
may contain pieces of hashes or salts. Plaintext RockYou reports are unaffected.
Usernames, domains, SPNs, ports, salts, and ticket data remain in the hash record;
only the extracted password bytes drive password counts and masks. Actual
passwords that happen to equal usernames remain valid password candidates.

Reference behavior: [Hashcat potfile reader/writer](https://github.com/hashcat/hashcat/blob/v6.2.6/src/potfile.c),
[Kerberos TGS parser](https://github.com/hashcat/hashcat/blob/master/src/modules/module_13100.c),
and [example formats](https://hashcat.net/wiki/doku.php?id=example_hashes).

## Verify

```bash
python3 -m unittest discover -s tests -v
python3 ./perp.py --version
```

Tests use synthetic passwords, including mixed case, colons, whitespace, empty
passwords, non-ASCII/binary bytes, malformed records, overlapping inputs, HTML
injection strings, CSV formulas, timestamp isolation, Python CLI behavior, and
optional Excel literal-cell handling, native charts, cached ratios, and limits.

## Release contents

The release includes Python source, embedded dashboard assets, tests with synthetic
fixtures, documentation, the portable AttackForge skill source, and the reviewed
public-dictionary outputs under `sample/` with chart screenshots. Legacy code has
been removed. Wordlists are obtained separately; real audit reports, audit inputs,
credentials, and local environments are excluded. Generate a review archive and
SHA-256 manifest with:

```bash
python3 ./scripts/prepare_release.py
```

Artifacts are written under the ignored `dist/` directory. Review the archive and
manifest before publishing; this command does not initialize Git or upload files.
