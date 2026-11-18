// Headless logic test for advanced.js (stubs browser globals)
const fs = require('fs'), vm = require('vm');
let src = fs.readFileSync('advanced.js', 'utf8');
src = src.split('/* ---------- wire up ---------- */')[0];
const ctx = {
  console,
  smartText: async () => null,
  esc: s => String(s ?? ''),
  kv: (k, v) => k + ': ' + v + '\n',
  $: () => ({ value: '', innerHTML: '', addEventListener() {} }),
  document: { querySelectorAll: () => [] },
  localStorage: { getItem: () => null, setItem: () => {} },
  enterKey: () => {},
  URL, Math, Date, JSON, Blob: class {}, FileReader: class {},
};
vm.createContext(ctx);
vm.runInContext(src, ctx);

(async () => {
  let pass = 0, fail = 0;
  const check = (name, cond) => { cond ? pass++ : fail++; console.log(`  ${cond ? 'PASS' : 'FAIL'}  ${name}`); };

  const evil = await ctx.urlThreatCore('https://paypa1-secure-login.xyz/verify');
  check('typosquat paypa1 detected', evil.score >= 35 && evil.findings.some(f => /Typosquatting/.test(f.txt)));
  check('suspicious TLD detected', evil.findings.some(f => /TLD/.test(f.txt)));
  check('verdict = HIGH RISK', /HIGH RISK/.test(evil.verdict));

  const homograph = await ctx.urlThreatCore('https://аpple.com'); // Cyrillic 'а'
  check('homograph/punycode detected', homograph.findings.some(f => /Homograph/.test(f.txt)));

  const iphost = await ctx.urlThreatCore('http://192.168.1.1/admin');
  check('IP-literal host detected', iphost.findings.some(f => /IP address/.test(f.txt)));

  const at = await ctx.urlThreatCore('https://google.com@evil.com/login');
  check('@ trick detected', at.findings.some(f => /"@"/.test(f.txt)));

  const safe = await ctx.urlThreatCore('https://google.com');
  check('legit google.com not flagged', safe.score === 0, `score=${safe.score}`);

  check('levenshtein paypa1/paypal = 1', ctx.levenshtein('paypa1', 'paypal') === 1);
  check('shannon helper works', ctx.shannon('aaaa') === 0);
  check('case file helpers defined', typeof ctx.saveCase === 'function' && typeof ctx.recordHistory === 'function');
  check('Tor + DNS grade helpers defined', typeof ctx.torCore === 'function' && typeof ctx.secGradeCore === 'function');

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
