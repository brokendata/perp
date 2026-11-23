"""Render the offline HTML dashboard; source assets are embedded in the result."""
import html
import json
import re
from pathlib import Path

ASSETS = Path(__file__).resolve().with_name("web")
PIE_COLORS = ("#8b5cf6", "#06b6d4", "#f59e0b", "#ec4899", "#22c55e", "#f97316", "#64748b")


def escape(value):
    return html.escape(str(value), quote=True)


def pie_items(items, total, limit=6):
    """A composition includes its full denominator, even when only top items exist."""
    leading = sorted((dict(item) for item in items if item["count"] > 0), key=lambda item: (-item["count"], str(item["label"])))[:limit]
    remainder = total - sum(item["count"] for item in leading)
    if remainder > 0:
        leading.append({"label": "Other categories", "count": remainder})
    return leading


def donut(title, items, total):
    groups = pie_items(items, total)
    circles, legend, offset = [], [], 0.0
    for index, item in enumerate(groups):
        share = item["count"] / total * 100
        color = PIE_COLORS[index]
        circles.append(
            f'<circle class="donut-slice" data-slice="{index}" cx="120" cy="120" r="86" fill="none" '
            f'stroke="{color}" stroke-width="32" pathLength="100" stroke-dasharray="{share:.8f} {100-share:.8f}" '
            f'stroke-dashoffset="{-offset:.8f}" transform="rotate(-90 120 120)">'
            f'<title>{escape(item["label"] or "(empty)")}: {item["count"]:,} records ({share:.1f}%)</title></circle>'
        )
        legend.append(
            f'<button type="button" class="legend-item" data-legend="{index}" aria-pressed="true">'
            f'<span class="swatch" style="--slice-color:{color}" aria-hidden="true"></span>'
            f'<span class="legend-label">{escape(item["label"] or "(empty)")}</span>'
            f'<span class="legend-value">{item["count"]:,} · <span data-share="{index}">{share:.1f}%</span></span></button>'
        )
        offset += share
    return (
        f'<figure class="donut-chart" data-items="{escape(json.dumps(groups, ensure_ascii=True))}">'
        '<div class="donut-layout"><svg class="donut-svg" viewBox="0 0 240 240" role="img" '
        f'aria-label="{escape(title)}. Category counts are in the legend and data table.">'
        '<circle class="donut-track" cx="120" cy="120" r="86" fill="none" stroke-width="32"/>'
        + "".join(circles)
        + f'<text class="donut-total" x="120" y="118" text-anchor="middle">{total:,}</text>'
        '<text class="donut-unit" x="120" y="140" text-anchor="middle">records shown</text></svg>'
        '<div class="donut-legend" role="group" aria-label="Visible chart categories">' + "".join(legend) + '</div></div>'
        '<figcaption class="donut-detail">Hover a slice or focus a legend item for details.</figcaption>'
        '<div class="donut-actions"><button type="button" class="chart-reset" hidden>Show all categories</button></div>'
        '<p class="note">Toggle legend items to hide/show categories. Shares use visible categories; this changes only this chart.</p>'
        '<noscript><p class="note">The chart is static without JavaScript. Its data table is available below.</p></noscript></figure>'
    )


def chart(title, items, total, limit=15, pie=False, description=None):
    maximum = max(1, max((item["count"] for item in items), default=0))
    bars = "".join(
        f'<tr><th scope="row"><span class="chart-label">{escape(item["label"] or "(empty)")}</span>'
        f'<span class="track" aria-hidden="true"><span class="fill" style="width:{item["count"] / maximum * 100:.2f}%"></span></span></th>'
        f'<td class="count"><strong>{item["count"]:,}</strong></td><td class="count">{item["count"] / total:.1%}</td></tr>'
        for item in items[:limit]
    )
    table = (
        f'<div class="chart-scroll" tabindex="0" role="region" aria-label="{escape(title)} data">'
        '<table class="chart-table"><caption>Counts and share of all recovered records</caption>'
        '<thead><tr><th scope="col">Group</th><th scope="col" class="count">Records</th><th scope="col" class="count">Share</th></tr></thead>'
        f'<tbody>{bars}</tbody></table></div><p class="note">Showing {min(limit, len(items))} of {len(items)} groups. Table shares always use all records.</p>'
    )
    content = donut(title, items, total) + '<details class="chart-data"><summary>View chart data</summary>' + table + '</details>' if pie else table
    note = f'<p class="note">{escape(description)}</p>' if description else ""
    return f'<section class="card"><h2>{escape(title)}</h2>{note}{content}</section>'


def dashboard(rows, summary):
    total = summary["total"]
    metrics = "".join(
        f'<div class="metric"><dt>{title}</dt><dd>{value:,}</dd></div>'
        for title, value in [("Recovered records", total), ("Unique passwords", summary["unique"]),
                             ("Repeated records", summary["duplicate_records"]), ("Distinct masks", len(summary["masks"]))]
    )
    charts = chart("Password lengths · bytes", summary["lengths"], total, 30, pie=True)
    if "character_set_profiles" in summary:
        charts += chart("Character-set profiles", summary["character_set_profiles"], total, pie=True,
                        description="One profile per record: upperlower = both letter cases only; alphanum = letters (either case) + digits; alphanumspecial = letters + digits + symbols/spaces. Non-ASCII/control bytes are grouped separately. Expand chart data for every profile and count.")
    charts += chart("Character sets present · overlapping", summary["character_types"], total)
    charts += chart("Most frequent passwords", summary["top_passwords"], total, 10, pie=True)
    charts += chart("Most frequent masks", summary["masks"], total, 10, pie=True)
    charts += chart("Character combinations", summary["patterns"], total, pie=True)
    sources = "".join(
        f'<tr><th scope="row">{escape(source["path"])}</th><td data-label="Format">{escape(source["format"])}</td>'
        f'<td data-label="Records">{source["records"]:,}</td></tr>' for source in summary["sources"]
    )
    values = {
        "TITLE": escape(f'Password Excel(lent) Reporting Python · {summary["created"]}'),
        "PRODUCT_NAME": "Password Excel(lent) Reporting Python",
        "LOGO": escape((ASSETS / "logo.txt").read_text(encoding="ascii").rstrip()),
        "EXCEL_LINK": '<a href="password_report.xlsx" download>Excel workbook (.xlsx)</a>' if summary.get('excel_export') else '',
        "VERSION": escape(summary["version"]), "CREATED": escape(summary["created"]),
        "SOURCE_COUNT": str(len(summary["sources"])), "METRICS": metrics, "CHARTS": charts,
        "SOURCES": sources, "EMPTY_COUNT": f'{summary["empty_passwords"]:,}',
        "CSS": (ASSETS / "dashboard.css").read_text(encoding="utf-8"),
        "JS": (ASSETS / "dashboard.js").read_text(encoding="utf-8"),
        "CHART_JS": (ASSETS / "charts.js").read_text(encoding="utf-8"),
        # Inert template data, escaped before entering HTML. One substitution pass
        # ensures placeholder-looking passwords can never be expanded as markup.
        "ROWS": escape(json.dumps(rows, ensure_ascii=True, separators=(",", ":"))),
    }
    template = (ASSETS / "dashboard.html").read_text(encoding="utf-8")
    return re.sub(r"@@([A-Z_]+)@@", lambda match: values[match[1]], template)
