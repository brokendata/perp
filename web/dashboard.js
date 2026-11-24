// Theme colors are CSS-driven; JavaScript only manages the explicit preference.
const schemeMeta = document.querySelector('meta[name="color-scheme"]');
const themeControl = document.getElementById('theme');
document.getElementById('theme-container').hidden = false;
const systemOption = document.getElementById('system-theme');
const systemScheme = window.matchMedia?.('(prefers-color-scheme: dark)');
function syncThemeControl() {
  themeControl.value = ['light', 'dark'].includes(schemeMeta.content) ? schemeMeta.content : 'system';
  systemOption.textContent = `System (${systemScheme?.matches ? 'dark' : 'light'})`;
}
themeControl.addEventListener('change', () => {
  const value = themeControl.value;
  schemeMeta.content = value === 'system' ? 'light dark' : value;
  try {
    if (value === 'system') localStorage.removeItem('perp-theme');
    else localStorage.setItem('perp-theme', value);
  } catch { /* Theme still works when storage is blocked for a local file. */ }
});
systemScheme?.addEventListener('change', syncThemeControl);
window.addEventListener('storage', event => {
  if (event.key !== 'perp-theme' && event.key !== null) return;
  schemeMeta.content = ['light', 'dark'].includes(event.newValue) ? event.newValue : 'light dark';
  syncThemeControl();
});
syncThemeControl();

const rows = JSON.parse(document.getElementById('data').content.textContent);
const search = document.getElementById('search');
const sort = document.getElementById('sort');
const body = document.getElementById('records');
const previous = document.getElementById('prev');
const next = document.getElementById('next');
const status = document.getElementById('status');
document.getElementById('explorer-controls').hidden = false;
document.getElementById('pagination').hidden = false;
let page = 0;
const pageSize = 50;
let selected = rows;
let searchTimer;

// Filtering and sorting are cached between page changes, not repeated per page.
function applyFilters() {
  const query = search.value.toLowerCase();
  selected = query ? rows.filter(row => [row.password, row.mask, row.source, row.hash_type || ''].some(value => value.toLowerCase().includes(query))) : rows;
  if (sort.value !== 'source') selected = [...selected].sort((a, b) => sort.value === 'short' ? a.byte_length - b.byte_length : b.byte_length - a.byte_length);
  page = 0;
  render();
}
function render() {
  const pages = Math.max(1, Math.ceil(selected.length / pageSize));
  page = Math.max(0, Math.min(page, pages - 1));
  const fragment = document.createDocumentFragment();
  for (const row of selected.slice(page * pageSize, (page + 1) * pageSize)) {
    const tr = document.createElement('tr');
    const type = row.hash_type || 'Unknown / ambiguous';
    const values = [row.password || '(empty)', row.byte_length, row.mask || '(empty)', type + (row.hash_type_basis === 'declared' ? ' (declared)' : ''), row.source + ' : ' + row.line];
    const labels = ['Password', 'Bytes', 'Mask', 'Hash / credential type', 'Source : line'];
    values.forEach((value, index) => {
      const cell = document.createElement(index === 0 ? 'th' : 'td');
      if (index === 0) cell.scope = 'row';
      cell.dataset.label = labels[index];
      cell.textContent = value; // Passwords are data, never HTML.
      tr.append(cell);
    });
    fragment.append(tr);
  }
  body.replaceChildren(fragment);
  const first = selected.length ? page * pageSize + 1 : 0;
  const last = Math.min((page + 1) * pageSize, selected.length);
  status.textContent = `${first.toLocaleString()}–${last.toLocaleString()} of ${selected.length.toLocaleString()} matches · page ${page + 1} / ${pages}`;
  previous.setAttribute('aria-disabled', String(page === 0));
  next.setAttribute('aria-disabled', String(page >= pages - 1));
  document.getElementById('empty').hidden = selected.length !== 0;
}
search.addEventListener('input', () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(applyFilters, 160);
});
sort.addEventListener('change', () => { clearTimeout(searchTimer); applyFilters(); });
previous.addEventListener('click', () => {
  if (previous.getAttribute('aria-disabled') === 'true') return;
  page--; render();
});
next.addEventListener('click', () => {
  if (next.getAttribute('aria-disabled') === 'true') return;
  page++; render();
});
render();
