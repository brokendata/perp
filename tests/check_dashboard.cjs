// Exercise the emitted JavaScript offline. These checks do not replace browser QA.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const report = fs.readFileSync(process.argv[2], 'utf8');
const encoded = report.match(/<template id="data">([\s\S]*?)<\/template>/)[1];
const decoded = encoded.replace(/&quot;|&#x27;|&lt;|&gt;|&amp;/g, x => ({
  '&quot;':'"', '&#x27;':"'", '&lt;':'<', '&gt;':'>', '&amp;':'&'
})[x]);
function element(fragment = false) {
  return {value:'', textContent:'', children:[], handlers:{}, attributes:{}, dataset:{}, hidden:false, fragment,
    append(node) { this.children.push(node); },
    replaceChildren(node) { this.children = node?.fragment ? [...node.children] : node ? [node] : []; },
    setAttribute(key, value) { this.attributes[key] = value; },
    getAttribute(key) { return this.attributes[key] ?? null; },
    addEventListener(event, action) { this.handlers[event] = action; }};
}
const names = ['data','search','sort','records','status','prev','next','theme','system-theme','empty','theme-container','explorer-controls','pagination'];
const ids = Object.fromEntries(names.map(id => [id, element()]));
ids.data.content = {textContent:decoded}; ids.sort.value = 'source';
const meta = {content:'light dark'};
const document = {getElementById:id => ids[id], querySelector:() => meta, querySelectorAll:() => [],
  createElement:() => element(), createDocumentFragment:() => element(true)};
const scripts = [...report.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(match => match[1]);
const storage = new Map();
const localStorage = {getItem:key => storage.get(key), setItem:(key,value) => storage.set(key,value), removeItem:key => storage.delete(key)};
const media = {matches:false, addEventListener:(event,callback) => { media.onchange = callback; }};
const windowHandlers = {};
const window = {matchMedia:() => media, addEventListener:(event,callback) => {windowHandlers[event] = callback;}};
const timers = new Map(); let timerId = 0;
const setTimeout = action => {timers.set(++timerId, action); return timerId;};
const clearTimeout = id => timers.delete(id);
function flushTimers() {for (const [id, action] of timers) {timers.delete(id); action();}}
const context = vm.createContext({document,localStorage,window,setTimeout,clearTimeout});
for (const script of scripts) vm.runInContext(script,context);
// System is reversible, and pinned choices survive OS changes.
assert.equal(meta.content,'light dark'); assert.equal(ids.theme.value,'system');
ids.theme.value = 'dark'; ids.theme.handlers.change();
assert.equal(meta.content,'dark'); assert.equal(storage.get('perp-theme'),'dark');
media.matches = true; media.onchange();
assert.equal(meta.content,'dark'); assert.equal(storage.get('perp-theme'),'dark');
assert.equal(ids['system-theme'].textContent,'System (dark)');
ids.theme.value = 'system'; ids.theme.handlers.change();
assert.equal(meta.content,'light dark'); assert.equal(storage.has('perp-theme'),false);
windowHandlers.storage({key:'perp-theme',newValue:'light'});
assert.equal(meta.content,'light'); assert.equal(ids.theme.value,'light');
localStorage.setItem('perp-theme','dark'); vm.runInContext(scripts[0],context);
assert.equal(meta.content,'dark');
localStorage.getItem = () => {throw new Error('Storage disabled');};
localStorage.setItem = () => {throw new Error('Storage disabled');};
localStorage.removeItem = () => {throw new Error('Storage disabled');};
meta.content = 'light dark'; vm.runInContext(scripts[0],context);
ids.theme.value = 'light'; ids.theme.handlers.change(); assert.equal(meta.content,'light');
// Pagination retains focusable controls and guards unavailable actions.
assert.equal(ids.records.children.length,50);
assert.equal(ids.prev.getAttribute('aria-disabled'),'true');
ids.prev.handlers.click(); assert.match(ids.status.textContent,/page 1 /);
ids.next.handlers.click(); assert.match(ids.status.textContent,/page 2 /);
assert.equal(ids.records.children[0].children[0].scope,'row');
assert.equal(ids.records.children[0].children[1].dataset.label,'Bytes');
assert.equal(ids.records.children[0].children[3].dataset.label,'Hash / credential type');
ids.search.value = 'Plaintext (no hash)'; ids.search.handlers.input(); flushTimers();
assert.match(ids.status.textContent,/122 matches/);
ids.search.value = 'discard this query'; ids.search.handlers.input();
ids.search.value = '</template><script>'; ids.search.handlers.input();
assert.equal(timers.size,1); flushTimers();
assert.equal(ids.records.children.length,1);
assert.equal(ids.records.children[0].children[0].textContent,'</template><script>alert(1)</script>');
ids.search.value = 'no matches at all'; ids.search.handlers.input(); flushTimers();
assert.equal(ids.records.children.length,0); assert.equal(ids.empty.hidden,false);
assert.equal(ids.next.getAttribute('aria-disabled'),'true');
ids.next.handlers.click(); assert.match(ids.status.textContent,/page 1 /);
ids.search.value = ''; ids.search.handlers.input(); flushTimers(); assert.equal(ids.empty.hidden,true);
ids.sort.value = 'short'; ids.sort.handlers.change();
assert.equal(ids.records.children[0].children[1].textContent,1);
ids.sort.value = 'long'; ids.sort.handlers.change();
assert.equal(ids.records.children[0].children[1].textContent,36);
console.log('Theme persistence, OS changes, storage fallback, debounce, pagination, filtering, sorting, and literal text insertion passed.');
