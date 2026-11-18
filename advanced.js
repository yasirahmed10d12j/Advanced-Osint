/* ============================================================
   ADVANCED OSINT — ADVANCED MODULES
   URL Threat Analyzer · Tor Exit Check · DNS Security Grade · Case Files
   All client-side; uses helpers ($, kv, esc, show, err, spin, smartText)
   defined in index.html.
============================================================ */

/* ---------- 1. URL THREAT ANALYZER (phishing heuristics) ---------- */
const PHISH_BRANDS = ['paypal','google','microsoft','apple','amazon','netflix','instagram','facebook','linkedin','twitter','bankofamerica','wellsfargo','chase','icici','hdfc','sbi','axisbank','upi','phonepe','paytm','flipkart','whatsapp','github','dropbox'];
const BAD_TLDS = ['tk','ml','ga','cf','gq','xyz','top','click','loan','work','party','review','country','stream','download','racing','bid','mom','cyou','sbs','icu','pw','su'];
const SHORTENERS = ['bit.ly','tinyurl.com','goo.gl','t.co','is.gd','ow.ly','buff.ly','rebrand.ly','cutt.ly','s.id','tiny.cc','rb.gy'];

function levenshtein(a,b){
  const m=a.length,n=b.length,d=Array.from({length:m+1},(_,i)=>[i].concat(Array(n).fill(0)));
  for(let j=0;j<=n;j++)d[0][j]=j;
  for(let i=1;i<=m;i++)for(let j=1;j<=n;j++)
    d[i][j]=Math.min(d[i-1][j]+1,d[i][j-1]+1,d[i-1][j-1]+(a[i-1]===b[j-1]?0:1));
  return d[m][n];
}
function shannon(s){
  const f={}; for(const c of s)f[c]=(f[c]||0)+1;
  return -Object.values(f).reduce((a,n)=>{const p=n/s.length;return a+p*Math.log2(p)},0);
}
const confusables = s => s.toLowerCase().replace(/0/g,'o').replace(/1/g,'l').replace(/3/g,'e')
  .replace(/5/g,'s').replace(/8/g,'b').replace(/rn/g,'m').replace(/vv/g,'w').replace(/-/g,'');

async function urlThreatCore(raw){
  let url=String(raw||'').trim();
  if(!/^https?:\/\//i.test(url)) url='https://'+url;
  let u;
  try{ u=new URL(url); }catch(e){ return {error:'Invalid URL — check karein'}; }
  const host=u.hostname.toLowerCase().replace(/^www\./,'');
  const parts=host.split('.'), tld=parts[parts.length-1];
  const findings=[]; let score=0;
  const f=(sev,txt,w)=>{ findings.push({sev,txt}); score+=w; };

  if(/[\u0080-\uFFFF]/.test(host)||host.includes('xn--'))
    f('high','Homograph / punycode domain — Unicode chars se brand impersonation',30);
  const norm=confusables(host);
  for(const b of PHISH_BRANDS){
    const label=host.split('.')[0];
    if(host===b||host.endsWith('.'+b)||label===b) continue;   // legit brand domain
    if(levenshtein(norm,b)<=2 || (norm.includes(b)&&norm.length>b.length)){
      f('high','Typosquatting: "'+host+'" brand "'+b+'" se mel kha raha hai',35); break;
    }
  }
  if(BAD_TLDS.includes(tld)) f('high','Suspicious/cheap TLD .'+tld+' — phishing me common',20);
  if(u.username||u.password||raw.includes('@')) f('high','URL me "@" trick — asli host chhupa ho sakta hai',30);
  if(/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) f('high','Host IP address hai (domain nahi)',25);
  if((host.match(/-/g)||[]).length>=3) f('med','Bahut hyphens ('+(host.match(/-/g)||[]).length+')',12);
  if(host.length>40) f('med','Bahut lamba hostname ('+host.length+' chars)',10);
  if(shannon(norm)>3.7) f('med','High hostname entropy ('+shannon(norm).toFixed(2)+') — random-looking domain',10);
  if(SHORTENERS.some(s=>host===s||host.endsWith('.'+s))) f('med','URL shortener — final destination alag ho sakta hai',10);
  if(u.protocol==='http:') f('low','HTTP (HTTPS nahi)',5);
  if(url.length>120) f('low','Bahut lambi URL ('+url.length+' chars)',5);

  let pageNote='';
  try{
    const text=await smartText(url);
    if(text){
      const title=(text.match(/<title[^>]*>([^<]*)<\/title>/i)||[])[1]||'';
      const login=/<input[^>]+type=["']password["']/i.test(text);
      const urgent=/verify your account|account suspended|confirm your (?:identity|password)|urgent action/i.test(text);
      if(login) f('med','Page me password input field hai',10);
      if(urgent) f('high','"Verify account / suspended / urgent" social-engineering text mila',20);
      const tb=PHISH_BRANDS.find(b=>title.toLowerCase().includes(b));
      if(tb&&!host.includes(tb)) f('high','Brand mismatch — title "'+tb+'" par host alag: '+host,25);
      pageNote='\n'+kv('Page Title',esc(title.trim()).slice(0,120))+kv('Login form',login?'YES ⚠':'no')+kv('Urgency text',urgent?'YES ⚠':'no');
    }
  }catch(e){}

  score=Math.min(100,score);
  let verdict,cls;
  if(score>=60){verdict='🔴 HIGH RISK — PHISHING LIKELY';cls='v-high';}
  else if(score>=30){verdict='🟡 SUSPICIOUS — CAREFUL';cls='v-mid';}
  else{verdict='🟢 LOOKS SAFE';cls='v-safe';}
  const out=kv('URL',esc(url))+kv('Host',host)+kv('TLD','.'+tld)+kv('Entropy',shannon(norm).toFixed(2))+
    kv('Risk Score',score+'/100')+pageNote+
    (findings.length?'\n\nFINDINGS:\n':'\n\nKoi red flag nahi mila.')+
    findings.map(x=>'• ['+x.sev.toUpperCase()+'] '+x.txt).join('\n')+
    '\n\nDeep scan:\n<a href="https://urlscan.io/search/#'+encodeURIComponent(url)+'" target="_blank">urlscan.io ↗</a> | '+
    '<a href="https://transparencyreport.google.com/safe-browsing/search?url='+encodeURIComponent(url)+'" target="_blank">Safe Browsing ↗</a>';
  return {url,host,score,verdict,cls,findings,out};
}
async function analyzeURL(){
  const raw=$('urlInput').value.trim();
  if(!raw){ err('urlResult','URL enter karein'); return; }
  spin('urlResult'); $('urlVerdict').innerHTML='';
  const r=await urlThreatCore(raw);
  if(r.error){ err('urlResult',r.error); return; }
  $('urlVerdict').innerHTML='<span class="verdict '+r.cls+'">'+r.verdict+' · '+r.score+'/100</span>'+
    '<div class="scorebar"><i style="width:'+r.score+'%"></i></div>';
  show('urlResult',r.out);
}
async function modUrlThreat(d){
  const r=await urlThreatCore(d);
  return r.error?('✗ '+r.error):kv('Verdict',r.verdict)+kv('Score',r.score+'/100')+'\n'+
    r.findings.map(x=>'• ['+x.sev+'] '+x.txt).join('\n');
}

/* ---------- 2. TOR EXIT NODE CHECK ---------- */
async function torCore(ip){
  let target=ip;
  if(!target){ try{ target=(await (await fetch('https://ipwho.is/')).json()).ip; }catch(e){} }
  if(!target) return {error:'IP unavailable'};
  const list=await smartText('https://check.torproject.org/torbulkexitlist');
  if(!list) return {error:'Tor list fetch nahi hua'};
  const hit=list.split(/\r?\n/).map(s=>s.trim()).includes(target.trim());
  return {target,hit,count:list.split(/\r?\n/).filter(Boolean).length};
}
async function checkTor(){
  spin('torResult');
  const r=await torCore($('torInput').value.trim());
  if(r.error){ err('torResult',r.error+' — <a href="https://check.torproject.org/" target="_blank">Manual check ↗</a>'); return; }
  show('torResult',kv('IP',r.target)+kv('Tor network size',r.count+' nodes')+
    kv('Tor Exit Node',r.hit?'YES ⚠ — Tor se traffic':'NO ✓')+
    '\n\nReputation:\n<a href="https://www.abuseipdb.com/check/'+r.target+'" target="_blank">AbuseIPDB ↗</a> | '+
    '<a href="https://greynoise.io/community/" target="_blank">GreyNoise ↗</a> | '+
    '<a href="https://www.shodan.io/host/'+r.target+'" target="_blank">Shodan ↗</a> | '+
    '<a href="https://bgp.he.net/ip/'+r.target+'" target="_blank">BGP.HE ↗</a>');
}
async function modTor(ip){
  const r=await torCore(ip);
  return r.error?('✗ '+r.error):kv('IP',r.target)+kv('Tor Exit Node',r.hit?'YES ⚠':'NO ✓');
}

/* ---------- 3. DNS SECURITY GRADE ---------- */
async function secGradeCore(d){
  d=String(d||'').trim().toLowerCase().replace(/^https?:\/\//,'').split('/')[0];
  const q=async(name,type)=>{ try{ const r=await fetch('https://dns.google/resolve?name='+encodeURIComponent(name)+'&type='+type); return await r.json(); }catch(e){ return {}; } };
  const [txt,dmarc,caa,dnskey,wild]=await Promise.all([
    q(d,'TXT'), q('_dmarc.'+d,'TXT'), q(d,'CAA'), q(d,'DNSKEY'),
    q('osintprobe-'+Math.random().toString(36).slice(2,8)+'.'+d,'A')
  ]);
  const txts=(txt.Answer||[]).map(a=>String(a.data));
  const dm=(dmarc.Answer||[]).map(a=>String(a.data));
  const spf=txts.find(x=>x.includes('v=spf1'));
  const spfWeak=spf&&/\+all|~all/.test(spf);
  const dmarcRec=dm.find(x=>x.includes('v=DMARC1'));
  const dmarcPolicy=(dmarcRec&&dmarcRec.match(/p=(\w+)/)||[])[1];
  let dkim=null;
  for(const sel of ['google','default','k1','s1','dkim','selector1','mail']){
    const r=await q(sel+'._domainkey.'+d,'TXT');
    if((r.Answer||[]).map(a=>String(a.data)).find(x=>x.includes('v=DKIM1'))){ dkim=sel; break; }
  }
  const caaRec=caa.Answer||[];
  const dnssec=(dnskey.Answer||[]).some(a=>a.type===48);
  const wildcard=(wild.Answer||[]).length>0;
  let score=100; const notes=[];
  if(!spf){score-=20;notes.push(['high','SPF missing — email spoofing allowed']);}
  else if(spfWeak){score-=12;notes.push(['med','SPF uses softfail/+all — weak policy']);}
  else notes.push(['low','SPF present ✓']);
  if(!dmarcRec){score-=25;notes.push(['high','DMARC missing — domain impersonation possible']);}
  else if(dmarcPolicy==='none'){score-=10;notes.push(['med','DMARC p=none (monitor only)']);}
  else notes.push(['low','DMARC p='+dmarcPolicy+' ✓']);
  if(!dkim){score-=15;notes.push(['med','DKIM not found on common selectors']);}
  else notes.push(['low','DKIM selector: '+dkim+' ✓']);
  if(!caaRec.length){score-=10;notes.push(['med','CAA missing — any CA can issue certs']);}
  else notes.push(['low','CAA present ✓']);
  if(!dnssec){score-=10;notes.push(['med','DNSSEC not published']);}
  else notes.push(['low','DNSSEC DNSKEY present ✓']);
  if(wildcard){score-=10;notes.push(['med','Wildcard DNS (*) enabled']);}
  score=Math.max(0,score);
  const grade=score>=90?'A':score>=80?'B':score>=70?'C':score>=60?'D':'F';
  return {d,score,grade,spf,dmarcPolicy,dkim,caa:caaRec.length,dnssec,wildcard,notes};
}
async function dnsSecurityGrade(){
  const d=$('secInput').value.trim();
  if(!d){ err('secResult','Domain enter karein'); return; }
  spin('secResult');
  const r=await secGradeCore(d);
  const cls=r.score>=80?'v-safe':r.score>=60?'v-mid':'v-high';
  show('secResult','<span class="verdict '+cls+'">Grade '+r.grade+' · '+r.score+'/100</span>'+
    kv('Domain',r.d)+kv('SPF',r.spf||'none')+kv('DMARC policy',r.dmarcPolicy||'none')+
    kv('DKIM selector',r.dkim||'none')+kv('CAA records',r.caa||'none')+
    kv('DNSSEC',r.dnssec?'YES ✓':'no')+kv('Wildcard DNS',r.wildcard?'YES ⚠':'no')+
    '\n\nFINDINGS:\n'+r.notes.map(x=>'• ['+x[0].toUpperCase()+'] '+x[1]).join('\n'));
}
async function modSecGrade(d){
  const r=await secGradeCore(d);
  return kv('Security Grade',r.grade+' ('+r.score+'/100)')+kv('SPF',r.spf?'yes':'NO')+
    kv('DMARC',r.dmarcPolicy||'NONE')+kv('DNSSEC',r.dnssec?'yes':'no')+'\n'+
    r.notes.filter(x=>x[0]!=='low').map(x=>'• '+x[1]).join('\n');
}

/* ---------- 4. CASE FILES (localStorage) ---------- */
const CASE_KEY='osint_cases', HIST_KEY='osint_history';
const readJSON=(k,def)=>{ try{ return JSON.parse(localStorage.getItem(k))||def; }catch(e){ return def; } };
const writeJSON=(k,v)=>localStorage.setItem(k,JSON.stringify(v));
function renderCases(){
  const cases=readJSON(CASE_KEY,[]), q=($('caseSearch')?.value||'').toLowerCase();
  $('caseCount').textContent=cases.length;
  const shown=cases.map((c,i)=>({c,i})).filter(x=>!q||(x.c.target+' '+(x.c.tag||'')+' '+(x.c.notes||'')).toLowerCase().includes(q));
  $('caseList').innerHTML=shown.length?shown.map(({c,i})=>
    '<div class="case"><div class="cbody"><div class="ctarget">'+esc(c.target)+
    (c.tag?'<span class="tag">'+esc(c.tag)+'</span>':'')+'</div>'+
    (c.notes?'<div class="cnote">'+esc(c.notes)+'</div>':'')+
    '<div class="cmeta">'+new Date(c.time).toLocaleString()+'</div></div>'+
    '<div class="cbtns"><button onclick="loadCase('+i+')">Open</button><button onclick="deleteCase('+i+')">✕</button></div></div>'
  ).join(''):'<div class="empty">Abhi koi case saved nahi. Upar target + notes daal ke save karo.</div>';
}
function saveCase(){
  let target=$('caseTarget').value.trim();
  if(!target) target=$('aiInput').value.trim();
  if(!target){ err('caseMsg','Target enter karein'); return; }
  const cases=readJSON(CASE_KEY,[]);
  cases.unshift({target,notes:$('caseNotes').value.trim(),tag:$('caseTag').value.trim(),time:Date.now()});
  writeJSON(CASE_KEY,cases.slice(0,200));
  $('caseTarget').value=''; $('caseNotes').value=''; $('caseTag').value='';
  show('caseMsg','✓ Case saved (sirf browser me).'); renderCases();
}
function deleteCase(i){ const c=readJSON(CASE_KEY,[]); c.splice(i,1); writeJSON(CASE_KEY,c); renderCases(); }
function loadCase(i){
  const c=readJSON(CASE_KEY,[])[i]; if(!c)return;
  $('aiInput').value=c.target;
  document.querySelector('#nav button[data-tab="ip"]').click();
  window.scrollTo({top:0,behavior:'smooth'});
}
function exportCases(){
  const blob=new Blob([JSON.stringify(readJSON(CASE_KEY,[]),null,2)],{type:'application/json'});
  const a=document.createElement('a'); a.href=URL.createObjectURL(blob);
  a.download='osint-cases-'+Date.now()+'.json'; a.click();
}
function importCases(e){
  const file=e.target.files[0]; if(!file)return;
  const rd=new FileReader();
  rd.onload=()=>{ try{ const arr=JSON.parse(rd.result); if(!Array.isArray(arr))throw 0;
    writeJSON(CASE_KEY,[...arr,...readJSON(CASE_KEY,[])].slice(0,200)); renderCases();
    show('caseMsg','✓ '+arr.length+' cases imported.');
  }catch(x){ err('caseMsg','Invalid JSON file'); } };
  rd.readAsText(file);
}
function recordHistory(target,label,ok,total){
  const h=readJSON(HIST_KEY,[]);
  h.unshift({target,label,ok,total,time:Date.now()});
  writeJSON(HIST_KEY,h.slice(0,50)); renderHistory();
}
function renderHistory(){
  const h=readJSON(HIST_KEY,[]);
  $('historyList').innerHTML=h.length?h.map(x=>
    '<div class="case"><div class="cbody"><div class="ctarget">'+esc(x.target)+'</div>'+
    '<div class="cmeta">'+esc(x.label||'scan')+' · '+x.ok+'/'+x.total+' modules · '+new Date(x.time).toLocaleString()+'</div></div>'+
    '<div class="cbtns"><button onclick="rescanHistory('+JSON.stringify(x.target)+')">Re-scan</button></div></div>'
  ).join(''):'<div class="empty">Abhi koi scan history nahi.</div>';
}
function rescanHistory(t){ $('aiInput').value=t; window.scrollTo({top:0,behavior:'smooth'}); }
function clearHistory(){ writeJSON(HIST_KEY,[]); renderHistory(); }

/* ---------- wire up ---------- */
/* Edge/Chrome me direct cross-origin fetch CORS se block hota hai —
   jab bhi local server se serve ho rahe ho, sab API calls /proxy se bhejo. */
if (/^https?:/.test(location.protocol)) {
  const nativeFetch = window.fetch.bind(window);
  window.fetch = function (input, init) {
    const url = typeof input === 'string' ? input : (input && input.url) || '';
    const short = url.replace(/^https?:\/\//,'').slice(0,95);
    const t0 = performance.now();
    if (typeof termLog === 'function') termLog('  → GET '+short, 'dim');
    let p;
    if (/^https?:\/\//i.test(url) && !url.startsWith(location.origin) && !url.includes('/proxy?')) {
      p = nativeFetch('/proxy?url=' + encodeURIComponent(url), init);
    } else {
      p = nativeFetch(input, init);
    }
    return p.then(r => {
      if (typeof termLog === 'function') termLog('    ← '+r.status+' '+(Math.round(performance.now()-t0))+'ms', 'info');
      return r;
    }).catch(e => {
      if (typeof termLog === 'function') termLog('    ✗ ERR '+short+' — '+e.message, 'err');
      throw e;
    });
  };
}
enterKey('urlInput',analyzeURL);
enterKey('torInput',checkTor);
enterKey('secInput',dnsSecurityGrade);
$('caseSearch')?.addEventListener('input',renderCases);
document.querySelectorAll('#threatSamples .chip').forEach(c=>c.onclick=()=>{ $('urlInput').value=c.textContent; analyzeURL(); });
renderCases(); renderHistory();
