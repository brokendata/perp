// Inline SVG charts: no CDN, canvas dependency, fetch, or external assets.
(() => {
  function mountDonut(figure) {
    const items = JSON.parse(figure.dataset.items);
    const unit = figure.dataset.unit || 'records';
    const visible = items.map(() => true);
    const slices = [...figure.querySelectorAll('[data-slice]')];
    const legends = [...figure.querySelectorAll('[data-legend]')];
    const shares = [...figure.querySelectorAll('[data-share]')];
    const totalLabel = figure.querySelector('.donut-total');
    const detail = figure.querySelector('.donut-detail');
    const reset = figure.querySelector('.chart-reset');
    function total() { return items.reduce((sum, item, i) => sum + (visible[i] ? item.count : 0), 0); }
    function inspect(index) {
      const item = items[index];
      const denominator = total();
      const percent = visible[index] && denominator ? item.count / denominator * 100 : 0;
      detail.textContent = `${item.label || '(empty)'} · ${item.count.toLocaleString()} ${unit} · ${visible[index] ? percent.toFixed(1) + '% of visible categories' : 'hidden'}`;
      slices.forEach((slice, i) => slice.classList.toggle('is-active', i === index && visible[i]));
    }
    function update() {
      const denominator = total();
      let offset = 0;
      items.forEach((item, index) => {
        const percent = visible[index] && denominator ? item.count / denominator * 100 : 0;
        const slice = slices[index];
        slice.style.display = percent ? '' : 'none';
        slice.setAttribute('stroke-dasharray', `${percent} ${100 - percent}`);
        slice.setAttribute('stroke-dashoffset', String(-offset));
        slice.classList.remove('is-active');
        slice.querySelector('title').textContent = `${item.label || '(empty)'}: ${item.count.toLocaleString()} ${unit} (${percent.toFixed(1)}% of visible categories)`;
        legends[index].setAttribute('aria-pressed', String(visible[index]));
        shares[index].textContent = visible[index] ? percent.toFixed(1) + '%' : 'hidden';
        offset += percent;
      });
      totalLabel.textContent = denominator.toLocaleString();
      reset.hidden = visible.every(Boolean);
      detail.textContent = denominator ? `${denominator.toLocaleString()} ${unit} in visible categories. Hover a slice or focus a legend item.` : 'No visible categories. Use the legend or Show all categories to restore the chart.';
    }
    legends.forEach((legend, index) => {
      legend.addEventListener('focus', () => inspect(index));
      legend.addEventListener('pointerenter', () => inspect(index));
      legend.addEventListener('click', () => { visible[index] = !visible[index]; update(); inspect(index); });
    });
    slices.forEach((slice, index) => {
      slice.addEventListener('pointerenter', () => inspect(index));
      slice.addEventListener('click', () => inspect(index));
    });
    reset.addEventListener('click', () => {
      visible.fill(true); update();
      // The reset button becomes hidden; return focus to a visible native control.
      legends[0]?.focus();
    });
    update();
    reset.hidden = true;
  }
  document.querySelectorAll('.donut-chart').forEach(mountDonut);
  // Native details supplies a click/keyboard fallback without scripts or polyfills.
  const help = document.getElementById?.('mask-key');
  if (help) {
    const trigger = help.querySelector('summary');
    let pinned = false, hovering = false, focused = false, suppressed = false;
    function close() { help.open = false; pinned = false; suppressed = true; }
    function preview() { if (!suppressed) help.open = true; }
    help.addEventListener('pointerenter', event => {
      if (event.pointerType === 'touch') return;
      hovering = true; suppressed = false; preview();
    });
    help.addEventListener('pointerleave', () => {
      hovering = false;
      if (!focused && !pinned) help.open = false;
    });
    help.addEventListener('focusin', () => { focused = true; suppressed = false; preview(); });
    help.addEventListener('focusout', event => {
      if (help.contains(event.relatedTarget)) return;
      focused = false;
      if (!hovering) { help.open = false; pinned = false; }
    });
    trigger.addEventListener('click', event => {
      event.preventDefault();
      if (pinned) close();
      else { pinned = true; suppressed = false; help.open = true; }
    });
    document.addEventListener('keydown', event => {
      if (event.key === 'Escape' && help.open) close();
    });
    document.addEventListener('pointerdown', event => {
      if (!help.contains(event.target)) { help.open = false; pinned = false; }
    });
  }
})();
