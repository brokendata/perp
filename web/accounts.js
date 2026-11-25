// Account data is inert JSON; all visible strings are inserted as text.
(() => {
  const payload = document.getElementById('account-data');
  if (!payload) return;
  const accounts = JSON.parse(payload.content.textContent);
  const byId = id => document.getElementById(id);
  const search = byId('account-search'), status = byId('account-status-filter'), known = byId('account-known');
  const body = byId('account-rows'), previous = byId('account-prev'), next = byId('account-next');
  const pageStatus = byId('account-page-status');
  const labels = ['Account', 'Status', 'Kind', 'Current NT recovery', 'LM evidence', 'Confirmed roles', 'Risk flags', 'Password age (days)', 'Asset'];
  let page = 0, selected = accounts, timer;
  function render() {
    const pages = Math.max(1, Math.ceil(selected.length / 50));
    page = Math.max(0, Math.min(page, pages - 1));
    const fragment = document.createDocumentFragment();
    for (const a of selected.slice(page * 50, (page + 1) * 50)) {
      const tr = document.createElement('tr');
      [a.account, a.status, a.kind, a.recovery, a.lm, a.roles, a.flags, a.age ?? 'Unknown', a.asset || 'Unspecified'].forEach((value, index) => {
        const cell = document.createElement(index === 0 ? 'th' : 'td');
        if (index === 0) cell.scope = 'row';
        cell.dataset.label = labels[index];
        cell.textContent = value;
        tr.append(cell);
      });
      fragment.append(tr);
    }
    body.replaceChildren(fragment);
    pageStatus.textContent = `${selected.length ? page * 50 + 1 : 0}–${Math.min((page + 1) * 50, selected.length)} of ${selected.length.toLocaleString()} accounts · page ${page + 1} / ${pages}`;
    previous.setAttribute('aria-disabled', String(page === 0));
    next.setAttribute('aria-disabled', String(page >= pages - 1));
  }
  function filter() {
    const query = search.value.toLowerCase();
    selected = accounts.filter(a => (!status.value || a.status === status.value) && (!known.checked || a.recovered) &&
      (!query || [a.account, a.kind, a.roles, a.flags, a.asset, a.recovery].some(value => value.toLowerCase().includes(query))));
    page = 0; render();
  }
  search.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(filter, 160); });
  for (const control of [status, known]) control.addEventListener('change', () => { clearTimeout(timer); filter(); });
  previous.addEventListener('click', () => { if (previous.getAttribute('aria-disabled') !== 'true') { page--; render(); } });
  next.addEventListener('click', () => { if (next.getAttribute('aria-disabled') !== 'true') { page++; render(); } });
  byId('account-controls').hidden = false;
  byId('account-pagination').hidden = false;
  render();
})();
