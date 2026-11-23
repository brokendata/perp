const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const script = fs.readFileSync(process.argv[2], 'utf8');
function node() {
  const classes = new Set();
  return {textContent:'', hidden:false, style:{}, attributes:{}, handlers:{}, focused:false,
    classList:{toggle:(key,on) => on ? classes.add(key) : classes.delete(key), remove:key => classes.delete(key)},
    setAttribute(key,value) {this.attributes[key] = value;},
    addEventListener(key,handler) {this.handlers[key] = handler;},
    focus() {this.focused=true;this.handlers.focus?.();}};
}
function fixture(items) {
  const slices = items.map(() => {const slice=node();slice.title=node();slice.querySelector=() => slice.title;return slice;});
  const legends=items.map(node), shares=items.map(node);
  const total=node(), detail=node(), reset=node();
  const figure={dataset:{items:JSON.stringify(items)},
    querySelectorAll:selector => ({'[data-slice]':slices,'[data-legend]':legends,'[data-share]':shares})[selector],
    querySelector:selector => ({'.donut-total':total,'.donut-detail':detail,'.chart-reset':reset})[selector]};
  return {figure,slices,legends,shares,total,detail,reset};
}
const a=fixture([{label:'</script><img onerror=alert(1)>',count:30},{label:'B',count:70}]);
const b=fixture([{label:'Only category',count:1}]);
const empty=fixture([]);
vm.runInNewContext(script,{document:{querySelectorAll:() => [a.figure,b.figure,empty.figure]}});
assert.equal(a.total.textContent,'100');
assert.equal(a.slices[0].attributes['stroke-dasharray'],'30 70');
assert.equal(a.slices[1].attributes['stroke-dashoffset'],'-30');
a.legends[0].handlers.focus();
assert.match(a.detail.textContent,/<\/script><img/); // Literal text, never markup.
assert.match(a.detail.textContent,/30.0%/);
a.legends[0].handlers.click();
assert.equal(a.total.textContent,'70');
assert.equal(a.legends[0].attributes['aria-pressed'],'false');
assert.equal(a.slices[0].style.display,'none');
assert.equal(a.shares[1].textContent,'100.0%');
assert.equal(a.reset.hidden,false);
a.legends[1].handlers.click();
assert.equal(a.total.textContent,'0');
assert.equal(a.slices[1].style.display,'none');
a.reset.handlers.click();
assert.equal(a.total.textContent,'100');
assert.equal(a.reset.hidden,true);
assert.equal(a.legends[0].focused,true);
a.slices[1].handlers.pointerenter(); assert.match(a.detail.textContent,/B · 70 records/);
assert.equal(b.slices[0].attributes['stroke-dasharray'],'100 0');
assert.equal(empty.total.textContent,'0'); assert.match(empty.detail.textContent,/No visible categories/);
console.log('Donut percentages, hidden/all-hidden states, reset focus, hover, keyboard focus, single-category and empty states passed.');
