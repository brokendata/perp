"""Optional Python-native XLSX export for perp; no Excel installation required."""
from pathlib import Path
import math

MAX_ROWS = 1048576
MAX_TEXT = 32767
PALETTE = ['#8b5cf6', '#06b6d4', '#f59e0b', '#ec4899', '#22c55e', '#f97316', '#64748b', '#14b8a6', '#a3e635', '#ef4444', '#3b82f6']


def require_xlsxwriter():
    try:
        import xlsxwriter
    except ImportError as error:
        raise ValueError('Excel export requires XlsxWriter. Run: python -m pip install -r requirements-excel.txt') from error
    return xlsxwriter


def validate_export(rows, summary):
    require_xlsxwriter()
    for name, data in [('Passwords', rows), ('Masks', summary['masks'])]:
        if len(data) >= MAX_ROWS:
            raise ValueError(f'{name} exceeds Excel\'s {MAX_ROWS-1:,} data-row limit; split the input or omit --excel.')
        for row in data:
            if any(isinstance(value, str) and len(value) > MAX_TEXT for value in row.values()):
                raise ValueError(f'{name} contains text longer than Excel\'s {MAX_TEXT:,}-character cell limit; omit --excel to preserve it in HTML/JSON/CSV.')
    risk = summary.get('account_risk')
    if risk:
        from account_inventory import account_csv_rows
        for name, data in [('Accounts', account_csv_rows(risk)), ('History', risk['history']), ('Reuse', risk['reuse_groups'])]:
            if len(data) >= MAX_ROWS:
                raise ValueError(f'{name} exceeds Excel row limits; omit --excel')
            for row in data:
                if any(len(str(value)) > MAX_TEXT for value in row.values()):
                    raise ValueError(f'{name} exceeds Excel character cell limit; omit --excel')


def write_account_sheets(book, risk):
    from account_inventory import account_csv_rows
    header = book.add_format({'bold': True, 'bg_color': '#087966', 'font_color': '#ffffff', 'text_wrap': True})
    literal = book.add_format({'num_format': '@', 'text_wrap': True, 'valign': 'top'})
    percent = book.add_format({'num_format': '0.0%'})
    summary = book.add_worksheet('Account risk')
    summary.activate()
    summary.hide_gridlines(2)
    summary.set_column('A:A', 26)
    summary.set_column('B:F', 18)
    summary.merge_range('A1:F1', 'Account exposure · current NT passwords', header)
    summary.merge_range('A2:F2', 'Snapshot: '+(risk['snapshot_time'] or 'not supplied'))
    summary.write_row(3, 0, ['Status', 'Accounts', 'NT assessed', 'Passwords known', 'Not assessed', 'Recovery rate'], header)
    for index, row in enumerate(risk['by_status'], 4):
        summary.write_row(index, 0, [row['status'], row['accounts'], row['assessed'], row['recovered'], row['not_assessed']])
        if row['recovery_rate'] is not None:
            summary.write_formula(index, 5, f'=D{index+1}/C{index+1}', percent, row['recovery_rate'])
        else:
            summary.write_string(index, 5, 'Not assessed', literal)
    chart = book.add_chart({'type': 'column', 'subtype': 'stacked'})
    for column, name, colour in [(3, 'Current password known', '#ef4444'), (4, 'Not assessed', '#64748b')]:
        chart.add_series({'name': name, 'categories': ['Account risk', 4, 0, 6, 0],
                          'values': ['Account risk', 4, column, 6, column], 'fill': {'color': colour}})
    # Assessed but not recovered is a separate series with an explicit input column.
    summary.write(3, 6, 'Not recovered', header)
    summary.set_column('G:G', 18)
    for index, row in enumerate(risk['by_status'], 4):
        summary.write_number(index, 6, row['not_recovered'])
    chart.add_series({'name': 'Not recovered', 'categories': ['Account risk', 4, 0, 6, 0],
                      'values': ['Account risk', 4, 6, 6, 6], 'fill': {'color': '#f59e0b'}})
    chart.set_title({'name': 'Current account recovery by status'})
    chart.set_y_axis({'name': 'Accounts', 'min': 0, 'num_format': '0'})
    chart.set_size({'width': 690, 'height': 350})
    summary.insert_chart('A10', chart)
    summary.merge_range('A29:G31', 'Known passwords are verified offline or identified by the empty NT hash. Status is supplied inventory data, not a live login result. History/current overlaps are excluded from historical recovery totals. LM matches do not establish a current NT password.', literal)
    for index, (name, value) in enumerate(risk['metrics'].items(), 33):
        summary.write_string(index, 0, name.replace('_', ' ').title(), literal)
        summary.write_number(index, 1, value)
    summary.freeze_panes(4, 1)
    history = [{key: value for key, value in row.items() if key != 'record_refs'} for row in risk['history']]
    reuse = [{key: '; '.join(value) if isinstance(value, list) else value for key, value in row.items()} for row in risk['reuse_groups']]
    for name, rows in [('Accounts', account_csv_rows(risk)), ('History', history), ('Reuse', reuse)]:
        sheet = book.add_worksheet(name)
        sheet.hide_gridlines(2)
        if not rows:
            sheet.write_string(0, 0, 'No '+name.lower()+' records', header)
            continue
        fields = list(rows[0])
        sheet.add_table(0, 0, len(rows), len(fields)-1, {'name': name+'Inventory', 'style': 'Table Style Medium 2',
                        'columns': [{'header': field.replace('_', ' ').title()} for field in fields]})
        for row_index, row in enumerate(rows, 1):
            for column, field in enumerate(fields):
                value = row[field]
                if value is None:
                    continue
                if isinstance(value, bool):
                    sheet.write_boolean(row_index, column, value)
                elif isinstance(value, (int, float)):
                    sheet.write_number(row_index, column, value)
                else:
                    sheet.write_string(row_index, column, str(value), literal)
        sheet.set_column(0, len(fields)-1, 23)
        sheet.set_row(0, 32)
        sheet.freeze_panes(1, 1)


def write_excel(path: Path, rows, summary):
    xlsxwriter = require_xlsxwriter()
    temporary = path.with_name('.' + path.name + '.tmp')
    if not rows and summary.get('account_risk'):
        with xlsxwriter.Workbook(temporary, {'strings_to_formulas': False, 'strings_to_urls': False}) as book:
            book.set_properties({'title': summary['product_name'], 'author': 'perp'})
            write_account_sheets(book, summary['account_risk'])
        temporary.replace(path)
        return
    with xlsxwriter.Workbook(temporary, {'strings_to_formulas': False, 'strings_to_urls': False, 'strings_to_numbers': False}) as book:
        book.set_properties({'title': summary['product_name'], 'author': 'perp', 'comments': 'Local recovered-password analysis'})
        header = book.add_format({'bold': True, 'bg_color': '#087966', 'font_color': '#ffffff', 'text_wrap': True, 'valign': 'vcenter'})
        title = book.add_format({'bold': True, 'font_size': 18, 'font_color': '#172638', 'text_wrap': True, 'valign': 'vcenter'})
        muted = book.add_format({'font_color': '#52657b', 'text_wrap': True, 'valign': 'top'})
        integer = book.add_format({'num_format': '#,##0', 'valign': 'top'})
        percent = book.add_format({'num_format': '0.00%'})
        literal = book.add_format({'num_format': '@', 'valign': 'top', 'align': 'left', 'text_wrap': True})
        wrap = book.add_format({'text_wrap': True, 'valign': 'top'})
        logo_format = book.add_format({'font_name': 'Consolas', 'font_size': 10, 'font_color': '#087966', 'text_wrap': True, 'valign': 'vcenter'})
        overview = book.add_worksheet('Summary')
        overview.hide_gridlines(2)
        overview.set_column('A:A', 36)
        overview.set_column('B:C', 18)
        overview.set_column('D:D', 3)
        overview.set_column('E:L', 11)
        logo = Path(__file__).resolve().with_name('web').joinpath('logo.txt').read_text(encoding='ascii').rstrip()
        overview.merge_range('A1:C7', logo, logo_format)
        overview.merge_range('A8:D10', summary['product_name'], title)
        overview.set_row(7, 25)
        overview.set_row(8, 25)
        overview.merge_range('A11:D11', f"perp {summary['version']} / parser {summary['parser_revision']}", muted)
        metrics = [('Recovered records', summary['total']), ('Unique passwords', summary['unique']),
                   ('Repeated records', summary['duplicate_records']), ('Empty passwords', summary['empty_passwords'])]
        for index, (label, value) in enumerate(metrics, 12):
            overview.write_string(index, 0, label)
            overview.write_number(index, 1, value, integer)
        overview.merge_range('A18:D18', 'Created: ' + summary['created'], muted)
        overview.merge_range('A20:D21', 'Counts include repeated recovered records. Profiles are exclusive; character-set presence can overlap.', muted)

        profiles = summary['character_set_profiles']
        profile_start = 23
        overview.write_row(profile_start-1, 0, ['Character-set profile', 'Records', 'Share'], header)
        for index, item in enumerate(profiles, profile_start):
            overview.write_string(index, 0, item['label'], literal)
            overview.write_number(index, 1, item['count'], integer)
            overview.write_formula(index, 2, f'=B{index+1}/$B$13', percent, item['count']/summary['total'])
        pie = book.add_chart({'type': 'doughnut'})
        pie.add_series({'name': 'Character-set profiles', 'categories': ['Summary', profile_start, 0, profile_start+len(profiles)-1, 0],
                        'values': ['Summary', profile_start, 1, profile_start+len(profiles)-1, 1],
                        'points': [{'fill': {'color': PALETTE[i % len(PALETTE)]}} for i in range(len(profiles))]})
        pie.set_title({'name': 'Character-set profiles'})
        pie.set_hole_size(58)
        pie.set_legend({'position': 'right', 'font': {'size': 9}})
        pie.set_size({'width': 570, 'height': 320})
        overview.insert_chart('E2', pie)

        lengths = summary['lengths']
        length_start = max(40, profile_start+len(profiles)+4)
        overview.write_row(length_start-1, 0, ['Length (bytes)', 'Records', 'Share'], header)
        for index, item in enumerate(lengths, length_start):
            overview.write_number(index, 0, int(item['label']), integer)
            overview.write_number(index, 1, item['count'], integer)
            overview.write_formula(index, 2, f'=B{index+1}/$B$13', percent, item['count']/summary['total'])
        bars = book.add_chart({'type': 'column'})
        bars.add_series({'name': 'Recovered records', 'categories': ['Summary', length_start, 0, length_start+len(lengths)-1, 0],
                         'values': ['Summary', length_start, 1, length_start+len(lengths)-1, 1], 'fill': {'color': '#087966'}})
        bars.set_title({'name': 'Password lengths'})
        bars.set_x_axis({'name': 'Length (bytes)'})
        bars.set_y_axis({'name': 'Records', 'min': 0, 'major_gridlines': {'visible': False}})
        bars.set_legend({'none': True})
        bars.set_size({'width': 570, 'height': 320})
        overview.insert_chart('E23', bars)

        source_start = max(46, length_start+len(lengths)+4)
        hash_types = summary.get('hash_types', [])
        if hash_types:
            type_start = max(64, length_start+len(lengths)+4)
            overview.write_row(type_start-1, 0, ['Hash / credential type', 'Records', 'Share'], header)
            for index, item in enumerate(hash_types, type_start):
                overview.write_string(index, 0, item['label'], literal)
                overview.write_number(index, 1, item['count'], integer)
                overview.write_formula(index, 2, f'=B{index+1}/$B$13', percent, item['count']/summary['total'])
            hash_pie = book.add_chart({'type': 'doughnut'})
            hash_pie.add_series({'name': 'Hash / credential types',
                                 'categories': ['Summary', type_start, 0, type_start+len(hash_types)-1, 0],
                                 'values': ['Summary', type_start, 1, type_start+len(hash_types)-1, 1],
                                 'points': [{'fill': {'color': PALETTE[i % len(PALETTE)]}} for i in range(len(hash_types))]})
            hash_pie.set_title({'name': 'Hash / credential types'})
            hash_pie.set_hole_size(58)
            hash_pie.set_legend({'position': 'right', 'font': {'size': 9}})
            hash_pie.set_size({'width': 570, 'height': 320})
            overview.insert_chart('E44', hash_pie)
            source_start = max(66, type_start+len(hash_types)+4)
            overview.merge_range(source_start-2, 0, source_start-2, 11,
                                 'Types are recognized signatures or user-declared labels, not verification. Unknown digests are not guessed. Counts include LM halves; plaintext has no hash.', muted)
            overview.set_row(source_start-2, 30)
        overview.write_row(source_start, 0, ['Input file', 'Format', 'Records'], header)
        overview.merge_range(source_start, 3, source_start, 11, 'Input SHA-256', header)
        for index, source in enumerate(summary['sources'], source_start+1):
            overview.write_string(index, 0, source['path'], wrap)
            overview.write_string(index, 1, source['format'], literal)
            overview.write_number(index, 2, source['records'], integer)
            overview.merge_range(index, 3, index, 11, source['sha256'], wrap)
            overview.set_row(index, min(400, max(30, math.ceil(len(source['path'])/34)*15)))
        overview.set_landscape()
        overview.fit_to_pages(1, 0)
        overview.print_area(0, 0, source_start+len(summary['sources']), 11)

        for sheet_name, data in [('Passwords', rows), ('Masks', summary['masks'])]:
            sheet = book.add_worksheet(sheet_name)
            sheet.hide_gridlines(2)
            fields = list(data[0])
            sheet.add_table(0, 0, len(data), len(fields)-1, {'name': sheet_name+'Data', 'style': 'Table Style Medium 2',
                            'columns': [{'header': 'Hashcat Mask' if sheet_name == 'Masks' and field == 'label' else field.replace('_', ' ').title()} for field in fields]})
            for row_index, row in enumerate(data, 1):
                wrapped_lines = 1
                for col_index, field in enumerate(fields):
                    value = row[field]
                    if isinstance(value, str):
                        sheet.write_string(row_index, col_index, value, literal)
                        width = 46 if field in {'password', 'mask', 'source', 'label'} else 27 if field in {'pattern', 'charset_profile'} else 14
                        wrapped_lines = max(wrapped_lines, math.ceil(len(value)/width))
                    elif value is not None:
                        sheet.write_number(row_index, col_index, value, integer)
                sheet.set_row(row_index, min(409, 15 * wrapped_lines))
            for col_index, field in enumerate(fields):
                width = 46 if field in {'password', 'mask', 'source', 'label'} else 27 if field in {'pattern', 'charset_profile'} else 14
                sheet.set_column(col_index, col_index, width)
            sheet.freeze_panes(1, 1)
            sheet.set_row(0, 32)
            sheet.set_landscape()
            sheet.fit_to_pages(1, 0)
        if summary.get('account_risk'):
            write_account_sheets(book, summary['account_risk'])
    temporary.replace(path)
