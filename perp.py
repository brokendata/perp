#!/usr/bin/env python3
"""Password Excel(lent) Reporting Python: offline password analysis (perp 1.0)."""
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

VERSION = "1.0"
PRODUCT_NAME = "Password Excel(lent) Reporting Python"
INPUT_EXTENSIONS = {".txt", ".pot", ".potfile"}
OUTPUT_NAMES = {"hashcatmasks.txt", "passwords.csv", "masks.csv", "summary.json"}


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


def records(path: Path, input_format: str, encoding: str, separator: bytes, field: int | None):
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
            if fmt in {"potfile", "hashcat", "john"}:
                if not line:
                    continue
                try:
                    _, raw = parse_record(line, separator, field, fmt if fmt in {"hashcat", "john"} else "auto")
                except ValueError as error:
                    raise ValueError(f"{path.name}:{number}: {error}") from error
            else:
                # Plaintext is literal, including $HEX[] strings and empty passwords.
                raw = line
            yield number, raw, fmt


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


def collect(files: list[Path], fmt: str, encoding: str, separator: bytes, field: int):
    rows, sources = [], []
    frequencies, masks, lengths, patterns, types, profiles = (Counter() for _ in range(6))
    for path in files:
        count = 0
        # Digest identifies the exact input without copying the potfile into the output.
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        actual_format = ("potfile" if path.suffix.lower() in {".pot", ".potfile"} else "plaintext") if fmt == "auto" else fmt
        for number, raw, actual_format in records(path, fmt, encoding, separator, field):
            row = analyze(raw, encoding)
            row.update(source=str(path), line=number)
            rows.append(row)
            frequencies[raw] += 1
            masks[row["mask"]] += 1
            lengths[row["byte_length"]] += 1
            patterns[row["pattern"]] += 1
            profiles[row["charset_profile"]] += 1
            for key in ("upper", "lower", "digit", "special", "other_byte"):
                types[key] += int(row[key] > 0)
            count += 1
        sources.append({"path": str(path), "format": actual_format, "records": count, "sha256": digest.hexdigest()})
    if not rows:
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


def write_results(rows, summary, output_root: Path, excel=False, attackforge=False, account_context=None, evidence=()) -> Path:
    if excel:
        from excel_export import validate_export
        validate_export(rows, summary)
    summary['excel_export'] = bool(excel)
    output_root.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("results-%Y%m%d-%H%M%S-%f")
    result = output_root / stamp
    result.mkdir()  # Exclusive creation: never overwrite an existing run.
    try:
        if excel:
            from excel_export import write_excel
            write_excel(result / 'password_report.xlsx', rows, summary)
        (result / "password_report.html").write_text(dashboard(rows, summary), encoding="utf-8")
        (result / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
        write_csv(result / "passwords.csv", rows, list(rows[0]))
        write_csv(result / "masks.csv", summary["masks"], ["label", "count"])
        masks = [item["label"] for item in summary["masks"] if item["label"]]
        content = "\n".join(masks) + ("\n" if masks else "")
        (result / "HashcatMasks.hcmask").write_text(content, encoding="ascii")
        (result / "HashcatMasks.txt").write_text(content, encoding="ascii")
        if attackforge:
            from attackforge_export import write_attackforge_bundle
            write_attackforge_bundle(result, account_context, evidence)
    except Exception:
        (result / "INCOMPLETE.txt").write_text("Report generation failed; outputs in this directory may be incomplete.\n", encoding="utf-8")
        raise
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", help="Files, directories, or quoted wildcard patterns")
    parser.add_argument("--version", action="version", version=f"perp {VERSION}")
    parser.add_argument("-r", "--recursive", action="store_true", help="Recurse into input directories")
    parser.add_argument("-o", "--output-root", type=Path, default=Path.cwd(), help="Parent of a new results-timestamp folder")
    parser.add_argument("--format", choices=["auto", "plaintext", "potfile", "hashcat", "john"], default="auto")
    parser.add_argument("--encoding", default="utf-8", help="Password display encoding (default UTF-8); masks always use original bytes")
    parser.add_argument("--separator", default=":", help="Potfile field separator (default colon)")
    parser.add_argument("--password-field", type=int, help="Explicit layout override: number of separators before password; default uses format-aware boundaries")
    parser.add_argument("--excel", action="store_true", help="Also export password_report.xlsx (requires XlsxWriter)")
    parser.add_argument("--attackforge", action="store_true", help="Prepare a local AttackForge review bundle; no upload")
    parser.add_argument("--account-context", type=Path, help="CSV linking original source/line to confirmed account/asset/role context (with --attackforge)")
    parser.add_argument("--evidence", action="append", default=[], type=Path, help="Screenshot/image to include for consultant review (repeatable, with --attackforge)")
    args = parser.parse_args(argv)
    try:
        if (args.account_context or args.evidence) and not args.attackforge:
            raise ValueError('--account-context and --evidence require --attackforge')
        if args.excel:
            from excel_export import require_xlsxwriter
            require_xlsxwriter()
        if not args.separator or "\n" in args.separator or "\r" in args.separator:
            raise ValueError("Separator must be nonempty and cannot contain a newline.")
        if args.password_field is not None and args.password_field < 1:
            raise ValueError("Password field must be at least 1.")
        if "A\n".encode(args.encoding) != b"A\n":
            raise ValueError("Input encoding must be ASCII-compatible; convert UTF-16/32 files to UTF-8 first.")
        fmt = args.format
        files = discover(args.inputs, args.recursive)
        rows, summary = collect(files, fmt, args.encoding, args.separator.encode("utf-8"), args.password_field)
        result = write_results(rows, summary, args.output_root, excel=args.excel, attackforge=args.attackforge,
                               account_context=args.account_context, evidence=args.evidence)
    except (ValueError, OSError, LookupError) as error:
        print(f"perp: {error}", file=sys.stderr)
        return 1
    print(f"{PRODUCT_NAME} (perp {VERSION}): {summary['total']:,} records, {summary['unique']:,} unique passwords")
    print(f"Report: {result / 'password_report.html'}")
    if args.excel:
        print(f"Excel: {result / 'password_report.xlsx'}")
    if args.attackforge:
        print(f"AttackForge review bundle (not uploaded): {result / 'attackforge/bundle.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
