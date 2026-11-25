// Exercise account pagination, filters, and safe text insertion without a browser.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
function element(fragment = false) {
  return {value:'', checked:false, hidden:true, children:[], dataset:{}, attributes:{}, handlers:{}, fragment,
    append(child) {this.children.push(child);},
    replaceChildren(child) {this.children = child?.fragment ? [...child.children] : [];},
    setAttribute(key,value) {this.attributes[key] = value;}, getAttribute(key) {return this.attributes[key];},
    addEventListener(key,callback) {this.handlers[key] = callback;}};
}
const names = ['account-data','account-search','account-status-filter','account-known','account-rows','account-prev','account-next','account-page-status','account-controls','account-pagination'];
const ids = Object.fromEntries(names.map(name => [name,element()]));
const data = Array.from({length:123}, (_,i) => ({account:i === 0 ? '<img src=x onerror=alert(1)>' : `example\\user${i}`,status:i%2 ? 'Disabled':'Enabled',kind:'account',recovery:i%3 ? 'not recovered':'verified NT password',lm:'Not stored',roles:i === 0 ? 'Privileged':'Unconfirmed',flags:'shared_current_credential',age:5,asset:'example-host',recovered:i%3 === 0}));
ids['account-data'].content = {textContent:JSON.stringify(data)};
const document = {getElementById:id=>ids[id],createElement:()=>element(),createDocumentFragment:()=>element(true)};
const timers = new Map();let nextTimer=0;
vm.runInNewContext(fs.readFileSync(process.argv[2],'utf8'),{document,
  setTimeout:callback=>{timers.set(++nextTimer,callback);return nextTimer;},clearTimeout:id=>timers.delete(id)});
function flush() {for (const [id,callback] of timers) {timers.delete(id);callback();}}
assert.equal(ids['account-rows'].children.length,50);
assert.equal(ids['account-rows'].children[0].children[0].textContent,'<img src=x onerror=alert(1)>');
assert.equal(ids['account-rows'].children[0].children[0].scope,'row');
assert.equal(ids['account-rows'].children[0].children[1].dataset.label,'Status');
assert.equal(ids['account-prev'].getAttribute('aria-disabled'),'true');
ids['account-prev'].handlers.click();assert.match(ids['account-page-status'].textContent,/page 1/);
ids['account-next'].handlers.click();assert.match(ids['account-page-status'].textContent,/page 2/);
ids['account-status-filter'].value='Enabled';ids['account-status-filter'].handlers.change();
assert.match(ids['account-page-status'].textContent,/62 accounts/);
ids['account-known'].checked=true;ids['account-known'].handlers.change();
assert.match(ids['account-page-status'].textContent,/21 accounts/);
ids['account-search'].value='discard';ids['account-search'].handlers.input();
ids['account-search'].value='Privileged';ids['account-search'].handlers.input();
assert.equal(timers.size,1);flush();
assert.match(ids['account-page-status'].textContent,/1 accounts/);
ids['account-search'].value='no match';ids['account-search'].handlers.input();flush();
assert.equal(ids['account-rows'].children.length,0);
assert.equal(ids['account-next'].getAttribute('aria-disabled'),'true');
assert.match(ids['account-page-status'].textContent,/0–0 of 0/);
console.log('Account filters, pagination, debounce, and text insertion passed.');
