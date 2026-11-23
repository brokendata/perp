// Inline SVG charts: no CDN, canvas dependency, fetch, or external assets.
(() => {
  function mountDonut(figure) {
    const items = JSON.parse(figure.dataset.items);
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
      detail.textContent = `${item.label || '(empty)'} · ${item.count.toLocaleString()} records · ${visible[index] ? percent.toFixed(1) + '% of visible categories' : 'hidden'}`;
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
        slice.querySelector('title').textContent = `${item.label || '(empty)'}: ${item.count.toLocaleString()} records (${percent.toFixed(1)}% of visible categories)`;
        legends[index].setAttribute('aria-pressed', String(visible[index]));
        shares[index].textContent = visible[index] ? percent.toFixed(1) + '%' : 'hidden';
        offset += percent;
      });
      totalLabel.textContent = denominator.toLocaleString();
      reset.hidden = visible.every(Boolean);
      detail.textContent = denominator ? `${denominator.toLocaleString()} records in visible categories. Hover a slice or focus a legend item.` : 'No visible categories. Use the legend or Show all categories to restore the chart.';
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
})();
