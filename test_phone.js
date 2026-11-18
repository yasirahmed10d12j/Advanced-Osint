// jsdom test: phone country-code parsing (+91 bug).
const fs = require('fs');
const { JSDOM, VirtualConsole } = require('C:/Users/yasir ahmed/AppData/Local/Temp/osint-jsdom/node_modules/jsdom');
const errors = [];
const vc = new VirtualConsole();
vc.on('jsdomError', e => errors.push(e.detail || e.message));
const html = fs.readFileSync('index.html', 'utf8')
  .replace(/<script src="https?:[^"]+"><\/script>/g, '')
  .replace('<script src="advanced.js"></script>', '');
const js = fs.readFileSync('advanced.js', 'utf8');
const dom = new JSDOM(html, {
  runScripts: 'dangerously', url: 'http://127.0.0.1:8899/', virtualConsole: vc,
  beforeParse(win) {
    win.Element.prototype.scrollIntoView = function(){};
    win.fetch = async () => ({ ok: false, status: 404, json: async () => ({}), text: async () => '' });
  }
});
const w = dom.window, d = w.document;
w.eval(js);

(async () => {
  d.getElementById('phoneInput').value = '+918889600828';
  w.analyzePhone();
  const out = d.getElementById('phoneResult').textContent;
  const mod = (await w.modPhone('+918889600828')).replace(/<[^>]+>/g,'').replace(/\s+/g,' ');
  const checks = {
    'country code +91 (not +918)': out.includes('Country Code: +91') && !out.includes('Country Code: +918'),
    'national number = 8889600828': out.includes('National Number: 8889600828'),
    'country = India': out.includes('Country (likely): India'),
    'validity shown': out.includes('valid Indian mobile'),
    'all-in-one module fixed': mod.includes('Country Code: +91') && mod.includes('National Number: 8889600828'),
    'no JS errors': errors.length === 0,
  };
  d.getElementById('phoneInput').value = '+441234567890';
  w.analyzePhone();
  const uk = d.getElementById('phoneResult').textContent;
  checks['UK +44 parsed'] = uk.includes('Country Code: +44') && uk.includes('National Number: 1234567890');

  console.log('--- India output ---\n' + out.split('\n').slice(0, 6).join('\n'));
  console.log('\n--- results ---');
  for (const [k, v] of Object.entries(checks)) console.log(`  ${v ? 'PASS' : 'FAIL'}  ${k}`);
  process.exit(Object.values(checks).every(Boolean) ? 0 : 1);
})();
