#!/usr/bin/env python3
"""Password Excel(lent) Reporting Python: offline password analysis (perp 1.1)."""
from __future__ import annotations

import argparse
import csv
import glob
import hashlib
import html
import json
import re
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from potfile_parser import PARSER_REVISION, parse_record
from hash_types import PLAINTEXT, identify_hash_type, normalize_hint

VERSION = "1.1"
PRODUCT_NAME = "Password Excel(lent) Reporting Python"
INPUT_EXTENSIONS = {".txt", ".pot", ".potfile"}
OUTPUT_NAMES = {"hashcatmasks.txt", "passwords.csv", "masks.csv", "summary.json", "accounts.csv", "password_history.csv", "credential_reuse.csv", "candidate_seeds.txt"}
PASSWORD_FIELDS = ('password', 'length', 'byte_length', 'upper', 'lower', 'digit', 'special',
                   'other_byte', 'mask', 'pattern', 'charset_profile', 'source', 'line', 'hash_type', 'hash_type_basis')


def discover(paths: list[str], recursive: bool = False) -> list[Path]:
    """Explicit files accept any extension; directory scans select password text files."""
    found: dict[str, Path] = {}
    for pattern in paths:
        matches = [Path(pattern)] if Path(pattern).exists() else [Path(p) for p in glob.glob(pattern, recursive=recursive)]
        if not matches:
            raise ValueError(f"Input did not match a file or directory: {pattern}")
        for match in matches:
            candidates = sorted(match.rglob("*") if recursive else match.glob("*")) if match.is_dir() else [match]
            for path in candidates:
                if not path.is_file():
                    continue
                if match.is_dir() and (path.suffix.lower() not in INPUT_EXTENSIONS or
                                       path.name.lower() in OUTPUT_NAMES or
                                       any(p.lower().startswith("results-") for p in path.relative_to(match).parts[:-1])):
                    continue
                resolved = path.resolve()
                found[str(resolved)] = resolved
    if not found:
        raise ValueError("No input files found (.txt, .pot, .potfile in directories).")
    return sorted(found.values())


def records(path: Path, input_format: str, encoding: str, separator: bytes, field: int | None,
            *, with_hash_type=False, hash_type='auto', with_hash=False, inventory_types=None):
    fmt = input_format
    if fmt == "auto":
        fmt = "potfile" if path.suffix.lower() in {".pot", ".potfile"} else "plaintext"
    # Binary lines prevent newline conversion and preserve spaces and arbitrary potfile bytes.
    with path.open("rb") as stream:
        for number, line in enumerate(stream, 1):
            if line.endswith(b"\n"):
                line = line[:-1].removesuffix(b"\r")
            if number == 1:
                line = line.removeprefix(b"\xef\xbb\xbf")
            hashed = None
            if fmt in {"potfile", "hashcat", "john", "hashcat-show"}:
                if not line:
                    continue
                try:
                    if fmt == 'hashcat-show':
                        if field is not None:
                            raise ValueError('hashcat-show uses username:hash:password; do not combine with --password-field')
                        username, boundary, line = line.partition(separator)
                        if not boundary or not username or any(c < 32 for c in username):
                            raise ValueError('Expected username:hash:password from --show --username')
                    dialect = 'hashcat' if fmt == 'hashcat-show' else fmt if fmt in {'hashcat', 'john'} else 'auto'
                    hashed, raw = parse_record(line, separator, field, dialect)
                    type_name, type_basis = identify_hash_type(hashed, hash_type)
                    if type_basis == 'unknown' and inventory_types:
                        inferred = inventory_types.get(hashed.decode('ascii', errors='replace').lower())
                        if inferred:
                            type_name, type_basis = inferred, 'inventory'
                except ValueError as error:
                    raise ValueError(f"{path.name}:{number}: {error}") from error
            else:
                # Plaintext is literal, including $HEX[] strings and empty passwords.
                raw = line
                type_name, type_basis = PLAINTEXT, 'plaintext'
            detail = (number, raw, fmt, type_name, type_basis)
            yield detail+(hashed,) if with_hash else detail if with_hash_type else (number, raw, fmt)


def character_set_profile(row: dict) -> str:
    """Assign one ASCII profile per record, independent of character order."""
    if row["other_byte"]:
        return "non-ASCII/control"
    letters = bool(row["upper"] or row["lower"])
    if letters and row["digit"]:
        return "alphanumspecial" if row["special"] else "alphanum"
    if letters and row["special"]:
        return "alphaspecial"
    if letters:
        return "upperlower" if row["upper"] and row["lower"] else "upper" if row["upper"] else "lower"
    if row["digit"]:
        return "numspecial" if row["special"] else "numeric"
    return "special" if row["special"] else "empty"


def analyze(raw: bytes, encoding: str) -> dict:
    try:
        password = raw.decode(encoding)
        # Controls are represented as HEX so report/CSV/XML remain legible.
        display = password if not any(ord(c) < 32 or 127 <= ord(c) < 160 for c in password) else f"$HEX[{raw.hex()}]"
        length = len(password)
    except UnicodeDecodeError:
        password, display, length = "", f"$HEX[{raw.hex()}]", None
    counts = Counter()
    tokens = []
    for byte in raw:
        kind = "Upper" if 65 <= byte <= 90 else "Lower" if 97 <= byte <= 122 else "Digit" if 48 <= byte <= 57 else "Special" if 32 <= byte <= 126 else "OtherByte"
        counts[kind] += 1
        tokens.append({"Upper": "?u", "Lower": "?l", "Digit": "?d", "Special": "?s", "OtherByte": "?b"}[kind])
    row = {"password": display, "length": length, "byte_length": len(raw),
            "upper": counts["Upper"], "lower": counts["Lower"], "digit": counts["Digit"],
            "special": counts["Special"], "other_byte": counts["OtherByte"],
            "mask": "".join(tokens), "pattern": "+".join(k for k in ("Upper", "Lower", "Digit", "Special", "OtherByte") if counts[k]) or "Empty"}
    row["charset_profile"] = character_set_profile(row)
    return row


def ranked(counter: Counter) -> list[dict]:
    return [{"label": str(k), "count": v} for k, v in sorted(counter.items(), key=lambda p: (-p[1], str(p[0])))]


def collect(files: list[Path], fmt: str, encoding: str, separator: bytes, field: int, hash_type='auto',
            *, recovery_records=None, inventory_types=None, allow_empty=False):
    hash_type = normalize_hint(hash_type)
    rows, sources = [], []
    frequencies, masks, lengths, patterns, types, profiles = (Counter() for _ in range(6))
    hash_types, type_bases = Counter(), Counter()
    for path in files:
        count = 0
        # Digest identifies the exact input without copying the potfile into the output.
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        actual_format = ("potfile" if path.suffix.lower() in {".pot", ".potfile"} else "plaintext") if fmt == "auto" else fmt
        for number, raw, actual_format, type_name, type_basis, hashed in records(
                path, fmt, encoding, separator, field, with_hash=True, hash_type=hash_type, inventory_types=inventory_types):
            row = analyze(raw, encoding)
            row.update(source=str(path), line=number)
            row.update(hash_type=type_name, hash_type_basis=type_basis)
            rows.append(row)
            if recovery_records is not None:
                recovery_records.append({'hash': hashed, 'password': raw, 'hash_type': type_name,
                                         'source': str(path), 'line': number, 'format': actual_format})
            frequencies[raw] += 1
            masks[row["mask"]] += 1
            lengths[row["byte_length"]] += 1
            patterns[row["pattern"]] += 1
            profiles[row["charset_profile"]] += 1
            hash_types[type_name] += 1
            type_bases[type_basis] += 1
            for key in ("upper", "lower", "digit", "special", "other_byte"):
                types[key] += int(row[key] > 0)
            count += 1
        sources.append({"path": str(path), "format": actual_format, "records": count, "sha256": digest.hexdigest()})
    if not rows and not allow_empty:
        raise ValueError("The selected inputs contain no password records.")
    total = len(rows)
    summary = {"version": VERSION, "product_name": PRODUCT_NAME, "parser_revision": PARSER_REVISION,
               "password_field": field, "input_format": fmt, "separator_hex": separator.hex(),
               "created": datetime.now().astimezone().isoformat(),
               "total": total, "unique": len(frequencies), "duplicate_records": total - len(frequencies),
               "empty_passwords": frequencies[b""], "sources": sources,
               "lengths": [{"label": str(k), "count": v} for k, v in sorted(lengths.items())],
               "masks": ranked(masks), "patterns": ranked(patterns), "character_types": ranked(types),
               "character_set_profiles": ranked(profiles),
               "hash_types": ranked(hash_types), "hash_type_bases": ranked(type_bases),
               "hash_type_hint": hash_type,
               "top_passwords": [{"label": analyze(k, encoding)["password"], "count": v}
                                 for k, v in sorted(frequencies.items(), key=lambda p: (-p[1], p[0]))[:20]]}
    return rows, summary


def escape(value) -> str:
    return html.escape(str(value), quote=True)


def dashboard(rows, summary):
    # Analysis can be imported independently of the report renderer and assets.
    from dashboard_renderer import dashboard as render_dashboard
    return render_dashboard(rows, summary)


def chart(title, items, total, limit=15):
    from dashboard_renderer import chart as render_chart
    return render_chart(title, items, total, limit)


def csv_value(value):
    if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def write_csv(path: Path, rows: list[dict], fields: list[str]):
    with path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows({k: csv_value(row[k]) for k in fields} for row in rows)


def write_results(rows, summary, output_root: Path, excel=False, attackforge=False, account_context=None, evidence=(),
                  account_risk=None, candidate_seeds=None) -> Path:
    if account_risk is not None:
        summary['account_risk'] = account_risk
    summary['candidate_seeds_exported'] = candidate_seeds is not None
    if excel:
        from excel_export import validate_export
        validate_export(rows, summary)
    summary['excel_export'] = bool(excel)
    output_root.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("results-%Y%m%d-%H%M%S")
    counter = 1
    while True:
        result = output_root / (stamp if counter == 1 else f"{stamp}-{counter}")
        try:
            result.mkdir()  # Atomic reservation, including concurrent runs.
            break
        except FileExistsError:
            counter += 1
    try:
        if excel:
            from excel_export import write_excel
            write_excel(result / 'password_report.xlsx', rows, summary)
        (result / "password_report.html").write_text(dashboard(rows, summary), encoding="utf-8")
        (result / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
        write_csv(result / "passwords.csv", rows, list(rows[0]) if rows else PASSWORD_FIELDS)
        write_csv(result / "masks.csv", summary["masks"], ["label", "count"])
        masks = [item["label"] for item in summary["masks"] if item["label"]]
        content = "\n".join(masks) + ("\n" if masks else "")
        (result / "HashcatMasks.hcmask").write_text(content, encoding="ascii")
        (result / "HashcatMasks.txt").write_text(content, encoding="ascii")
        if account_risk is not None:
            from account_inventory import account_csv_rows
            (result/'account_risk.json').write_text(json.dumps(account_risk, indent=2)+'\n', encoding='utf-8')
            accounts = account_csv_rows(account_risk)
            write_csv(result/'accounts.csv', accounts, list(accounts[0]))
            histories = account_risk['history']
            write_csv(result/'password_history.csv', histories,
                      ('account_id', 'account', 'current_status', 'history_index', 'overlaps_current', 'nt_assessed', 'nt_recovered', 'lm_recovery'))
            write_csv(result/'credential_reuse.csv', [{key: '; '.join(value) if isinstance(value, list) else value for key, value in group.items()}
                                                    for group in account_risk['reuse_groups']],
                      ('id', 'current_accounts', 'historical_accounts', 'enabled_current_accounts', 'disabled_current_accounts', 'password_known'))
        if candidate_seeds is not None:
            (result/'candidate_seeds.txt').write_bytes(b'\n'.join(candidate_seeds)+(b'\n' if candidate_seeds else b''))
        if attackforge:
            from attackforge_export import write_attackforge_bundle
            write_attackforge_bundle(result, account_context, evidence)
    except Exception:
        (result / "INCOMPLETE.txt").write_text("Report generation failed; outputs in this directory may be incomplete.\n", encoding="utf-8")
        raise
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="*", help="Recovery files, directories, or quoted wildcards; optional with --inventory")
    parser.add_argument("--version", action="version", version=f"perp {VERSION}")
    parser.add_argument("-r", "--recursive", action="store_true", help="Recurse into input directories")
    parser.add_argument("-o", "--output-root", type=Path, default=Path.cwd(), help="Parent of a new results-timestamp folder")
    parser.add_argument("--format", choices=["auto", "plaintext", "potfile", "hashcat", "john", "hashcat-show"], default="auto")
    parser.add_argument('--inventory', action='append', type=Path, default=[], help='NTDS/secretsdump text inventory; repeatable (not binary NTDS.dit)')
    parser.add_argument('--inventory-domain', help='Domain scope for unqualified inventory names; otherwise scoped per file')
    parser.add_argument('--directory-context', type=Path, help='Directory CSV joined by domain,RID with confirmed roles/status/age/ownership')
    parser.add_argument('--snapshot-time', help='Inventory snapshot ISO 8601 timestamp with timezone')
    parser.add_argument('--export-seeds', action='store_true', help='Explicitly export local candidate seeds from verified NT matches and matching LM potfile keys; requires --inventory')
    parser.add_argument("--hash-type", default="auto", help="Type label for otherwise unidentified potfile hashes (e.g. NTLM, LM, MD5, or a custom name); never overrides recognized signatures or plaintext")
    parser.add_argument("--encoding", default="utf-8", help="Password display encoding (default UTF-8); masks always use original bytes")
    parser.add_argument("--separator", default=":", help="Potfile field separator (default colon)")
    parser.add_argument("--password-field", type=int, help="Explicit layout override: number of separators before password; default uses format-aware boundaries")
    parser.add_argument("--excel", action="store_true", help="Also export password_report.xlsx (requires XlsxWriter)")
    parser.add_argument("--attackforge", action="store_true", help="Prepare a local AttackForge review bundle; no upload")
    parser.add_argument("--account-context", type=Path, help="CSV linking original source/line to confirmed account/asset/role context (with --attackforge)")
    parser.add_argument("--evidence", action="append", default=[], type=Path, help="Screenshot/image to include for consultant review (repeatable, with --attackforge)")
    args = parser.parse_args(argv)
    try:
        if not args.inputs and not args.inventory:
            raise ValueError('Supply recovery inputs or --inventory')
        if not args.inventory and (args.inventory_domain or args.directory_context or args.snapshot_time or args.export_seeds):
            raise ValueError('Inventory options and --export-seeds require --inventory')
        if (args.account_context or args.evidence) and not args.attackforge:
            raise ValueError('--account-context and --evidence require --attackforge')
        if args.excel:
            from excel_export import require_xlsxwriter
            require_xlsxwriter()
        if not args.separator or "\n" in args.separator or "\r" in args.separator:
            raise ValueError("Separator must be nonempty and cannot contain a newline.")
        if args.password_field is not None and args.password_field < 1:
            raise ValueError("Password field must be at least 1.")
        if args.format == 'hashcat-show' and args.password_field is not None:
            raise ValueError('hashcat-show cannot be combined with --password-field')
        if "A\n".encode(args.encoding) != b"A\n":
            raise ValueError("Input encoding must be ASCII-compatible; convert UTF-16/32 files to UTF-8 first.")
        fmt = args.format
        inventory, type_map, recoveries = None, None, []
        if args.inventory:
            from account_inventory import load_inventory, load_directory_context, inventory_type_map, correlate
            inventory = load_inventory(args.inventory, args.inventory_domain)
            load_directory_context(inventory, args.directory_context)
            type_map = inventory_type_map(inventory)
        files = discover(args.inputs, args.recursive) if args.inputs else []
        if inventory and any(Path(source['path']) in files for source in inventory['sources']):
            raise ValueError('Inventory/context files must not also be supplied as recovery inputs')
        rows, summary = collect(files, fmt, args.encoding, args.separator.encode("utf-8"), args.password_field, args.hash_type,
                                recovery_records=recoveries if inventory else None, inventory_types=type_map, allow_empty=bool(inventory))
        risk, seeds = correlate(inventory, recoveries, args.encoding, args.snapshot_time) if inventory else (None, None)
        result = write_results(rows, summary, args.output_root, excel=args.excel, attackforge=args.attackforge,
                               account_context=args.account_context, evidence=args.evidence, account_risk=risk,
                               candidate_seeds=seeds if args.export_seeds else None)
    except (ValueError, OSError, LookupError, csv.Error) as error:
        print(f"perp: {error}", file=sys.stderr)
        return 1
    print(f"{PRODUCT_NAME} (perp {VERSION}): {summary['total']:,} records, {summary['unique']:,} unique passwords")
    print(f"Report: {result / 'password_report.html'}")
    if risk is not None:
        print(f"Account inventory: {risk['metrics']['current_accounts']:,} current accounts; {risk['metrics']['current_accounts_recovered']:,} current NT passwords known")
    if args.export_seeds:
        print(f"Candidate seeds: {len(seeds):,}; {risk['metrics']['seed_records_excluded_newlines']:,} entries with line breaks omitted")
    if args.excel:
        print(f"Excel: {result / 'password_report.xlsx'}")
    if args.attackforge:
        print(f"AttackForge review bundle (not uploaded): {result / 'attackforge/bundle.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
