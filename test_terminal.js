// jsdom end-to-end test for the live terminal scan log.
const fs = require('fs');
const { JSDOM, VirtualConsole } = require('C:/Users/yasir ahmed/AppData/Local/Temp/osint-jsdom/node_modules/jsdom');
const errors = [];
const vc = new VirtualConsole();
vc.on('jsdomError', e => errors.push('jsdomError: ' + (e.detail || e.message)));
vc.on('error', (...a) => errors.push('console.error: ' + a.join(' ')));

const html = fs.readFileSync('index.html', 'utf8')
  .replace(/<script src="https?:[^"]+"><\/script>/g, '')
  .replace('<script src="advanced.js"></script>', '');
const js = fs.readFileSync('advanced.js', 'utf8');
const dom = new JSDOM(html, {
  runScripts: 'dangerously', url: 'http://127.0.0.1:8899/index.html', virtualConsole: vc,
  beforeParse(win) {
    win.Element.prototype.scrollIntoView = function () {};
    win.scrollTo = function () {};
    win.fetch = async () => ({ ok: true, status: 200, json: async () => ({}), text: async () => '' });
    win.L = { map: () => ({ setView(){}, removeLayer(){}, invalidateSize(){}, addTo(){return this;} }),
              tileLayer: () => ({ addTo(){} }), marker: () => ({ addTo(){return this;}, bindPopup(){return this;}, openPopup(){return this;} }),
              layerGroup: () => ({ addTo(){return this;} }), circle: () => ({ addTo(){return this;}, bindPopup(){return this;} }),
              circleMarker: () => ({ addTo(){return this;}, bindPopup(){return this;} }) };
    win.exifr = { parse: async () => ({}) };
  }
});
const w = dom.window, d = w.document;
w.eval(js);

(async () => {
  d.getElementById('aiInput').value = '8.8.8.8';
  w.runAllInOne();
  await new Promise(r => setTimeout(r, 3000));
  const body = d.getElementById('aiTermBody').textContent;
  const lines = [...d.querySelectorAll('#aiTermBody .tline')].map(x => x.textContent);
  const checks = {
    'terminal has lines': lines.length > 5,
    'scan command logged': body.includes('advanced-osint-scan --target'),
    'module start logged': body.includes('run --module'),
    'live/network lines logged': body.includes('→ GET') || body.includes('▌'),
    'module completion logged': body.includes('OK ') || body.includes('NO DATA '),
    'scan complete logged': body.includes('SCAN COMPLETE'),
    'progress statuses updated': [...d.querySelectorAll('.pi-status')].some(x => x.textContent.includes('done') || x.textContent.includes('n/a')),
    'GUI summary cards rendered': d.querySelectorAll('#aiSummary .sum-card').length === 3,
    'GUI module cards rendered': d.querySelectorAll('#aiSections .mod-card').length > 0,
    'no JS errors': errors.length === 0,
  };
  // Rich data → verify tiles / badges / link chips
  w.renderGuiReport([
    { name:'Email Analysis', html:'<span class="k">Email:</span> test@gmail.com\n<span class="k">Gravatar:</span> FOUND ✓\n<span class="k">Disposable?:</span> no\n<a href="https://epieos.com" target="_blank">Epieos deep-check ↗</a>' },
    { name:'DNS Security Grade', html:'<span class="k">Security Grade:</span> A (95/100)\n<span class="k">SPF:</span> yes' }
  ], 2, 2, '📧 Email Address', '1.2');
  checks['data tiles rendered'] = d.querySelectorAll('#aiSections .kv-item').length >= 5;
  checks['status badges rendered'] = d.querySelectorAll('#aiSections .mpill.ok').length === 2;
  checks['link chips rendered'] = d.querySelectorAll('#aiSections .mod-links a').length >= 1;
  checks['colored values rendered'] = d.querySelectorAll('#aiSections .kv-value.good').length >= 1;
  console.log('\n--- terminal sample (first 12 lines) ---');
  console.log(lines.slice(0, 12).join('\n'));
  console.log('\n--- results ---');
  for (const [k, v] of Object.entries(checks)) console.log(`  ${v ? 'PASS' : 'FAIL'}  ${k}`);
  if (errors.length) console.log('ERRORS:', errors.join('\n'));
  process.exit(Object.values(checks).every(Boolean) ? 0 : 1);
})();
