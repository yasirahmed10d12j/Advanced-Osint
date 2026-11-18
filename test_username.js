// jsdom test: username auto-check audit output (why no auto-match).
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
    win.fetch = async (input) => {
      let url = typeof input === 'string' ? input : input.url;
      if (url.includes('/proxy?')) url = decodeURIComponent(new URL(url, 'http://127.0.0.1:8899').searchParams.get('url'));
      const code = url.includes('gitlab.com') ? 200 : url.includes('pypi.org') ? 200
        : url.includes('reddit.com') || url.includes('npmjs.com') ? 403 : 404;
      const data = url.includes('gitlab.com') ? [] : null;
      return { ok: code >= 200 && code < 300, status: code,
               json: async () => data, text: async () => '<html>generic page</html>' };
    };
  }
});
dom.window.eval(js);

(async () => {
  const out = await dom.window.modUsername('molviyasir823');
  const checks = {
    'no auto-match message': out.includes('Koi auto-match nahi mila'),
    'audit section present': out.includes('kaunsi APIs check hui'),
    'GitHub checked': out.includes('GitHub: not found'),
    'Reddit blocked shown': out.includes('Reddit: blocked (403)'),
    'Dev.to added': out.includes('Dev.to: not found'),
    'Codewars added': out.includes('Codewars: not found'),
    'explains manual-only platforms': out.includes('automated check allowed nahi hai'),
    'manual links present': (out.match(/target="_blank"/g) || []).length >= 20,
    'no JS errors': errors.length === 0,
  };
  console.log('--- sample output (first 16 lines) ---');
  console.log(out.split('\n').slice(0, 16).join('\n'));
  console.log('\n--- results ---');
  for (const [k, v] of Object.entries(checks)) console.log(`  ${v ? 'PASS' : 'FAIL'}  ${k}`);
  process.exit(Object.values(checks).every(Boolean) ? 0 : 1);
})();
