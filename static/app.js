// ── State ───────────────────────────────────────────────────────────────
const socket = io();
let allRows = [];
let paused = false;
let selectedIdx = null;
let sortCol = 'time', sortDir = -1;
let counts = { total:0, clean:0, sus:0, mal:0 };
let sessionStart = Date.now();
let alertTimeout = null;
let currentDetail = null;

// Українські пояснення полів (tooltip)
const FIELD_TIPS = {
  entropy:     "Ентропія Шеннона H(X) — міра випадковості символів у домені. Високе значення (>4.2) характерне для доменів, згенерованих алгоритмами ботнетів (DGA)",
  age:         "Вік сертифіката в днях від моменту видачі. Самопідписані сертифікати віком менше 3 днів часто вказують на свіжорозгорнуту фішингову інфраструктуру",
  self_signed: "Чи підписаний сертифікат сам собою (без довіреного центру сертифікації). Самопідписані сертифікати на публічних сайтах — потенційна аномалія",
  puny:        "Punycode (IDN Homograph) — виявлення префікса xn--, що вказує на спробу підробити відомий домен візуально схожими символами інших алфавітів",
  source:      "Джерело події: перехоплено з трафіку, ручна перевірка за URL, або аналіз завантаженого .pem файлу",
  requested:   "Домен або URL, який ввів користувач (або ім'я завантаженого файлу)",
  cn:          "Common Name — реальне ім'я в полі Subject сертифіката",
  mismatch:    "Невідповідність імені хоста: запитаний домен не збігається з CN сертифіката — можлива ознака підстановки",
  method:      "Метод, яким система винесла вердикт: ML-сигнатура, ентропія, Punycode, вік або комплексна евристика",
  serial:      "Серійний номер сертифіката (унікальний ідентифікатор від видавця)",
  sig_algo:    "Алгоритм криптографічного підпису сертифіката",
  issuer:      "Issuer DN — повне ім'я центру, що видав сертифікат",
};
function tip(key){
  const t = FIELD_TIPS[key];
  if(!t) return '';
  // екрануємо лапки для атрибута
  const safe = t.replace(/"/g,'&quot;');
  return `<span class="info-i" data-tip="${safe}">i</span>`;
}

function pad(n){return String(n).padStart(2,'0');}
function fmtDuration(ms){let s=Math.floor(ms/1000);return `${pad(Math.floor(s/3600))}:${pad(Math.floor(s%3600/60))}:${pad(s%60)}`;}
function tick(){
  const now=new Date();
  document.getElementById('clock').textContent=`${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
  const dur=fmtDuration(Date.now()-sessionStart);
  document.getElementById('session-timer').textContent=`SESSION: ${dur}`;
  document.getElementById('s-uptime').textContent=dur;
}
setInterval(tick,1000); tick();

function updateStats(){
  document.getElementById('s-total').textContent=counts.total;
  document.getElementById('s-clean').textContent=counts.clean;
  document.getElementById('s-sus').textContent=counts.sus;
  document.getElementById('s-mal').textContent=counts.mal;
  const rate=counts.total?Math.round((counts.mal+counts.sus)/counts.total*100):0;
  document.getElementById('s-rate').textContent=rate+'%';
}

function entropyColor(h){if(h>4.2)return 'var(--red)';if(h>3.5)return 'var(--yellow)';return 'var(--green)';}

function methodTag(verdict){
  if(!verdict)return '';
  const v=verdict.toUpperCase();
  if(v.includes('STRUCTURAL')||v.includes('PATTERN')||v.includes('BOTNET')||v.includes('PHISHING TEMPLATE'))return '<span class="method-tag mt-ml">ML</span>';
  if(v.includes('ENTROPY')||v.includes('DGA'))return '<span class="method-tag mt-ent">ENTROPY</span>';
  if(v.includes('HOMOGRAPH')||v.includes('PUNYCODE'))return '<span class="method-tag mt-pun">PUNYCODE</span>';
  if(v.includes('SHORT-LIVED')||v.includes('AGE'))return '<span class="method-tag mt-age">CERT AGE</span>';
  return '<span class="method-tag mt-sig">HEURISTIC</span>';
}
function methodName(verdict){
  if(!verdict)return 'Heuristic';
  const v=verdict.toUpperCase();
  if(v.includes('STRUCTURAL')||v.includes('PATTERN')||v.includes('BOTNET')||v.includes('PHISHING TEMPLATE'))return 'ML / Signature analysis';
  if(v.includes('ENTROPY')||v.includes('DGA'))return 'Entropy analysis (DGA)';
  if(v.includes('HOMOGRAPH')||v.includes('PUNYCODE'))return 'Punycode / IDN Homograph';
  if(v.includes('SHORT-LIVED')||v.includes('AGE'))return 'Certificate age analysis';
  return 'Composite heuristic';
}

function srcTag(source){
  if(source==='traffic')return '<span class="src-tag src-traffic">TRAFFIC</span>';
  if(source==='url')return '<span class="src-tag src-url">DOMAIN</span>';
  if(source==='file')return '<span class="src-tag src-file">FILE</span>';
  return '<span class="src-tag src-file">—</span>';
}
function srcName(source){
  if(source==='traffic')return 'Captured from traffic (Sniffer)';
  if(source==='url')return 'Manual lookup by domain/URL';
  if(source==='file')return 'Uploaded .PEM file';
  return '—';
}

function badgeClass(verdict){
  const v=(verdict||'').toUpperCase();
  if(v.includes('CRITICAL')||v.includes('BLACKLISTED'))return 'badge-critical';
  if(v.includes('MALICIOUS'))return 'badge-malicious';
  if(v.includes('SUSPICIOUS'))return 'badge-suspicious';
  return 'badge-safe';
}
function rowClass(verdict){
  const v=(verdict||'').toUpperCase();
  if(v.includes('MALICIOUS')||v.includes('CRITICAL'))return 'row-mal';
  if(v.includes('SUSPICIOUS'))return 'row-sus';
  return '';
}
function nowStr(){const n=new Date();return `${pad(n.getHours())}:${pad(n.getMinutes())}:${pad(n.getSeconds())}`;}

function ingest(data){
  if(!data._time) data._time=data.time||nowStr();
  if(!data._ts)   data._ts=(data.ts?data.ts*1000:Date.now());
  allRows.unshift(data);
  counts.total++;
  const v=(data.verdict||'').toUpperCase();
  if(v.includes('MALICIOUS')||v.includes('CRITICAL'))counts.mal++;
  else if(v.includes('SUSPICIOUS'))counts.sus++;
  else counts.clean++;
  updateStats();
  if(v.includes('CRITICAL')||v.includes('MALICIOUS'))
    showAlert(`⚠ THREAT DETECTED: ${data.domain} — ${data.detail||data.verdict}`);
  if(allRows.length>1000)allRows=allRows.slice(0,1000);
  if(!paused)renderTable();
}

socket.on('connect',()=>setSnifferStatus(true));
socket.on('disconnect',()=>setSnifferStatus(false));
socket.on('new_result',d=>ingest(d));

function setSnifferStatus(on){
  document.getElementById('sniffer-dot').className='dot '+(on?'green':'red');
  document.getElementById('sniffer-label').textContent=on?'Sniffer Active':'Disconnected';
}

async function loadHistory(){
  try{
    const r=await fetch('/history');
    if(!r.ok)return;
    const hist=await r.json();
    hist.forEach(d=>{
      d._time=d.time||nowStr();
      d._ts=(d.ts?d.ts*1000:Date.now());
      allRows.unshift(d);
      counts.total++;
      const v=(d.verdict||'').toUpperCase();
      if(v.includes('MALICIOUS')||v.includes('CRITICAL'))counts.mal++;
      else if(v.includes('SUSPICIOUS'))counts.sus++;
      else counts.clean++;
    });
    updateStats();
    renderTable();
  }catch(e){}
}
loadHistory();

function renderTable(){
  const q=document.getElementById('search-input').value.toLowerCase();
  const fVerdict=document.getElementById('filter-verdict').value;
  const fSource=document.getElementById('filter-source').value;
  let rows=allRows.filter(d=>{
    const v=(d.verdict||'').toUpperCase();
    if(fVerdict!=='ALL'){
      if(fVerdict==='SAFE'&&!v.includes('CLEAN')&&!v.includes('SAFE'))return false;
      if(fVerdict==='SUSPICIOUS'&&!v.includes('SUSPICIOUS'))return false;
      if(fVerdict==='MALICIOUS'&&!v.includes('MALICIOUS')&&!v.includes('CRITICAL'))return false;
    }
    if(fSource!=='ALL'&&d.source!==fSource)return false;
    if(q){
      const haystack=`${d.domain} ${d.ip} ${d.verdict} ${d.detail} ${d.requested||''}`.toLowerCase();
      if(!haystack.includes(q))return false;
    }
    return true;
  });
  rows.sort((a,b)=>{
    let av=a[sortCol]??a._ts??'';
    let bv=b[sortCol]??b._ts??'';
    if(sortCol==='time'){av=a._ts;bv=b._ts;}
    if(typeof av==='string')av=av.toLowerCase();
    if(typeof bv==='string')bv=bv.toLowerCase();
    return av<bv?sortDir:av>bv?-sortDir:0;
  });
  document.getElementById('row-count').textContent=rows.length+' records';
  if(rows.length===0){
    document.getElementById('empty-state').style.display='flex';
    document.getElementById('main-table').style.display='none';
    return;
  }
  document.getElementById('empty-state').style.display='none';
  document.getElementById('main-table').style.display='';
  const body=document.getElementById('feed-body');
  body.innerHTML='';
  rows.forEach((d,i)=>{
    const h=parseFloat(d.entropy)||0;
    const barPct=Math.min(100,(h/6)*100).toFixed(1);
    const barCol=entropyColor(h);
    const punyCell=d.puny==='Yes'?`<span class="puny-warn">⚠ YES</span>`:`<span class="puny-ok">—</span>`;
    const rc=rowClass(d.verdict);
    const bc=badgeClass(d.detail||d.verdict);
    const mt=methodTag(d.detail||d.verdict);
    const verdLabel=d.verdict||'CLEAN';
    const tr=document.createElement('tr');
    tr.className=rc+(i===selectedIdx?' selected':'');
    tr.innerHTML=`
      <td class="td-time">${d._time||''}</td>
      <td>${srcTag(d.source)}</td>
      <td class="td-domain" title="${d.detail||''}">${d.domain||'—'}</td>
      <td class="td-ip">${d.ip||'—'}</td>
      <td class="td-num"><div class="entropy-wrap">${h.toFixed(2)}<div class="e-bar"><div class="e-fill" style="width:${barPct}%;background:${barCol}"></div></div></div></td>
      <td class="td-num">${d.age!=null?d.age+'d':'—'}</td>
      <td class="td-num">${punyCell}</td>
      <td>${mt}</td>
      <td><span class="badge ${bc}">${verdLabel}</span></td>
    `;
    tr.addEventListener('click',()=>showDetail(d,i));
    body.appendChild(tr);
  });
}

function sortBy(col){
  if(sortCol===col)sortDir*=-1;else{sortCol=col;sortDir=-1;}
  document.querySelectorAll('thead th').forEach(th=>{
    th.classList.remove('sort-asc','sort-desc');
    if(th.dataset.col===col)th.classList.add(sortDir===-1?'sort-desc':'sort-asc');
  });
  renderTable();
}

document.getElementById('search-input').addEventListener('input',renderTable);
document.getElementById('filter-verdict').addEventListener('change',renderTable);
document.getElementById('filter-source').addEventListener('change',renderTable);

function togglePause(){
  paused=!paused;
  const btn=document.getElementById('btn-pause');
  btn.textContent=paused?'▶ Resume':'⏸ Pause';
  btn.classList.toggle('active',paused);
  if(!paused)renderTable();
}

function clearAll(){
  if(!confirm('Clear all records from the table? (server history is preserved)'))return;
  allRows=[];counts={total:0,clean:0,sus:0,mal:0};selectedIdx=null;
  updateStats();renderTable();showDetailEmpty();
}

function showAlert(msg){
  const b=document.getElementById('alert-banner');
  b.textContent=msg;b.style.display='block';
  clearTimeout(alertTimeout);
  alertTimeout=setTimeout(()=>{b.style.display='none';},5000);
}

function showDetailEmpty(){
  document.getElementById('dp-expand').style.display='none';
  document.getElementById('dp-body').innerHTML=`
    <div class="dp-empty">
      <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.4"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
      <span>Select a row<br>to view details</span>
    </div>`;
}

function showDetail(d,idx){
  selectedIdx=idx;
  currentDetail=d;
  renderTable();
  document.getElementById('dp-expand').style.display='inline';
  const v=(d.verdict||'').toUpperCase();
  let vc='v-safe';
  if(v.includes('MALICIOUS')||v.includes('CRITICAL'))vc='v-mal';
  else if(v.includes('SUSPICIOUS'))vc='v-sus';
  const h=parseFloat(d.entropy)||0;
  const hPct=Math.min(100,(h/6)*100).toFixed(1);
  const hCol=entropyColor(h);
  const age=d.age!=null?d.age:'—';
  const ageSafe=age!=='—'&&parseInt(age)>=3;

  let reqRow='';
  if(d.source==='url'||d.source==='file'){
    const reqLabel=d.source==='url'?'Requested domain':'File name';
    reqRow=`<div class="dp-row"><span class="dp-key">${reqLabel} ${tip('requested')}</span><span class="dp-val">${d.requested||'—'}</span></div>`;
  }
  let mismatchRow='';
  if(d.mismatch){
    mismatchRow=`<div class="mismatch-warn">⚠ Requested domain does not match certificate CN (hostname mismatch) ${tip('mismatch')}</div>`;
  }

  document.getElementById('dp-body').innerHTML=`
    <div class="dp-verdict ${vc}">
      <div class="v-label">${d.verdict||'CLEAN'}</div>
      <div class="v-detail">${d.detail||'No anomalies detected'}</div>
    </div>
    <div class="dp-section">
      <div class="dp-section-title">Source & Identity</div>
      <div class="dp-row"><span class="dp-key">Source ${tip('source')}</span><span class="dp-val">${srcName(d.source)}</span></div>
      ${reqRow}
      <div class="dp-row"><span class="dp-key">Certificate CN ${tip('cn')}</span><span class="dp-val" title="${d.domain}">${d.domain||'—'}</span></div>
      <div class="dp-row"><span class="dp-key">IP Address</span><span class="dp-val">${d.ip||'—'}</span></div>
      <div class="dp-row"><span class="dp-key">Time</span><span class="dp-val">${d._time||'—'}</span></div>
      ${mismatchRow}
    </div>
    <div class="dp-section">
      <div class="dp-section-title">Analysis Metrics</div>
      <div class="gauge-wrap">
        <div class="gauge-label"><span style="color:var(--text-lo);display:flex;align-items:center;gap:4px">Shannon Entropy H(X) ${tip('entropy')}</span><span style="color:${hCol};font-weight:700;font-family:var(--mono);white-space:nowrap">${h.toFixed(4)} bits</span></div>
        <div class="gauge-bar"><div class="gauge-fill" style="width:${hPct}%;background:${hCol}"></div></div>
        <div style="font-size:11px;color:var(--text-lo);margin-top:4px">${h>4.2?'⚠ Above 4.2 threshold — DGA candidate':'✓ Within normal range (threshold: 4.2 bits)'}</div>
      </div>
      <div class="dp-row"><span class="dp-key">Certificate Age ${tip('age')}</span><span class="dp-val" style="color:${ageSafe?'var(--green)':'var(--red)'}">${age}${age!=='—'?' days':''} ${!ageSafe&&age!=='—'?'⚠':'✓'}</span></div>
      <div class="dp-row"><span class="dp-key">Self-signed ${tip('self_signed')}</span><span class="dp-val" style="color:${d.self_signed==='Yes'?'var(--yellow)':'var(--green)'}">${d.self_signed==='Yes'?'⚠ Yes':'✓ No (CA)'}</span></div>
      <div class="dp-row"><span class="dp-key">Punycode (IDN) ${tip('puny')}</span><span class="dp-val" style="color:${d.puny==='Yes'?'var(--red)':'var(--green)'}">${d.puny==='Yes'?'⚠ DETECTED':'✓ None'}</span></div>
    </div>
    <div class="dp-section">
      <div class="dp-section-title">Detection Method</div>
      <div style="padding:6px 0;display:flex;align-items:center;gap:6px;flex-wrap:wrap;">${methodTag(d.detail||d.verdict)} <span style="font-size:11.5px;color:var(--text-mid)">${methodName(d.detail||d.verdict)}</span> ${tip('method')}</div>
    </div>
  `;
}

// ── EVENT MODAL ──────────────────────────────────────────────────────────
function openModal(){
  if(!currentDetail)return;
  const d=currentDetail;
  document.getElementById('modal-title').textContent=d.domain||'Event Details';
  document.getElementById('modal-sub').textContent=`${srcName(d.source)} · ${d._time||''}`;
  const rows=[
    ['Verdict',d.verdict],
    ['Detail',d.detail],
    ['Source',srcName(d.source)],
    ['Requested domain/file',d.requested||'—'],
    ['Certificate CN',d.domain],
    ['IP Address',d.ip],
    ['Time',d._time],
    ['Shannon Entropy',(parseFloat(d.entropy)||0).toFixed(4)+' bits'],
    ['Certificate Age',(d.age!=null?d.age+' days':'—')],
    ['Self-signed',d.self_signed||'—'],
    ['Punycode (IDN)',d.puny||'—'],
    ['Hostname mismatch',d.mismatch?'⚠ Yes':'No'],
    ['Serial number',d.serial||'—'],
    ['Signature algorithm',d.sig_algo||'—'],
    ['Issuer DN',d.issuer_dn||'—'],
    ['Detection method',methodName(d.detail||d.verdict)],
  ];
  document.getElementById('pane-formatted').innerHTML=
    '<div class="kv-grid">'+rows.map(([k,v])=>`<div class="kv-k">${k}</div><div class="kv-v">${(v??'—')}</div>`).join('')+'</div>';
  const clean={};
  ['time','ts','source','requested','domain','ip','entropy','age','puny','self_signed','mismatch','serial','sig_algo','issuer_dn','verdict','detail'].forEach(k=>{if(d[k]!==undefined)clean[k]=d[k];});
  document.getElementById('json-view').innerHTML=syntaxJson(JSON.stringify(clean,null,2));
  switchTab('formatted');
  document.getElementById('modal').classList.add('open');
}
function closeModal(){document.getElementById('modal').classList.remove('open');}
function switchTab(pane){
  document.querySelectorAll('.modal-tab').forEach(t=>t.classList.toggle('active',t.dataset.pane===pane));
  document.querySelectorAll('.modal-pane').forEach(p=>p.classList.remove('active'));
  document.getElementById('pane-'+pane).classList.add('active');
}
function syntaxJson(json){
  json=json.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g,m=>{
    let cls='jn';
    if(/^"/.test(m)){cls=/:$/.test(m)?'jk':'js';}
    else if(/true|false|null/.test(m)){cls='jb';}
    return `<span class="${cls}">${m}</span>`;
  });
}
function copyJson(){
  if(!currentDetail)return;
  const clean={};
  ['time','ts','source','requested','domain','ip','entropy','age','puny','self_signed','mismatch','serial','sig_algo','issuer_dn','verdict','detail'].forEach(k=>{if(currentDetail[k]!==undefined)clean[k]=currentDetail[k];});
  navigator.clipboard.writeText(JSON.stringify(clean,null,2));
}

// ── INFO MODAL ───────────────────────────────────────────────────────────
function openInfo(){document.getElementById('info-modal').classList.add('open');}
function closeInfo(){document.getElementById('info-modal').classList.remove('open');}

document.addEventListener('keydown',e=>{if(e.key==='Escape'){closeModal();closeInfo();}});

// ── Input zones ────────────────────────────────────────────────────────────
function recalcBodyHeight(){
  const toolbar=document.querySelector('.toolbar').offsetHeight;
  const urlZ=document.getElementById('url-zone');
  const upZ=document.getElementById('upload-zone');
  const extra=(urlZ.classList.contains('open')?urlZ.offsetHeight:0)+(upZ.classList.contains('open')?upZ.offsetHeight:0);
  document.querySelector('.body-wrap').style.height=`calc(100vh - 50px - ${toolbar}px - ${extra}px)`;
}
function toggleUrl(){
  const z=document.getElementById('url-zone');
  z.classList.toggle('open');
  document.getElementById('btn-url').classList.toggle('active',z.classList.contains('open'));
  recalcBodyHeight();
  if(z.classList.contains('open'))document.getElementById('url-input').focus();
}
function toggleUpload(){
  const z=document.getElementById('upload-zone');
  z.classList.toggle('open');
  document.getElementById('btn-upload').classList.toggle('active',z.classList.contains('open'));
  recalcBodyHeight();
}

async function analyzeUrl(){
  const input=document.getElementById('url-input');
  const out=document.getElementById('url-results');
  const btn=document.getElementById('url-submit');
  const mode=document.getElementById('url-mode').value;
  let target=input.value.trim();
  if(!target){out.textContent='⚠ Enter a domain or URL';return;}
  target=target.replace(/^https?:\/\//i,'').replace(/\/.*$/,'').trim();
  if(!target){out.textContent='⚠ Invalid URL';return;}
  btn.disabled=true;
  out.textContent=`⏳ Fetching certificate from ${target}...`;
  try{
    const r=await fetch('/analyze_url',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target,mode})});
    const data=await r.json();
    if(r.ok){out.innerHTML=`✓ ${target} → <strong>${data.verdict||'analysis complete'}</strong>`;input.value='';}
    else{out.textContent=`✗ ${data.error||'could not fetch certificate'}`;}
  }catch(e){out.textContent=`✗ Connection error: ${e.message}`;}
  btn.disabled=false;
}

function handleDrop(e){e.preventDefault();document.getElementById('pem-drop').classList.remove('drag');handleFiles(Array.from(e.dataTransfer.files));}
function handleFileSelect(e){handleFiles(Array.from(e.target.files));}
async function handleFiles(files){
  const pems=files.filter(f=>f.name.endsWith('.pem')||f.name.endsWith('.crt')||f.name.endsWith('.cer'));
  if(!pems.length){document.getElementById('upload-results').textContent='⚠ Not a .pem file';return;}
  const mode=document.getElementById('pem-mode').value;
  document.getElementById('upload-results').textContent=`Sending ${pems.length} file(s)...`;
  let ok=0,fail=0;
  for(const f of pems){
    const form=new FormData();form.append('pem',f);form.append('mode',mode);
    try{const r=await fetch('/analyze_pem',{method:'POST',body:form});if(r.ok)ok++;else fail++;}catch(e){fail++;}
  }
  document.getElementById('upload-results').textContent=`✓ ${ok} analyzed${fail?' | ✗ '+fail+' errors':''}`;
  document.getElementById('pem-file').value='';
}

function exportCSV(){
  if(!allRows.length){alert('No data to export');return;}
  const hdr='Time,Source,Requested,Domain(CN),IP,Entropy,Age(days),Punycode,SelfSigned,Verdict,Detail\n';
  const srcMap={traffic:'Traffic',url:'Domain/URL',file:'PEM file'};
  const rows=allRows.map(d=>`"${d._time}","${srcMap[d.source]||d.source||''}","${d.requested||''}","${d.domain}","${d.ip}","${d.entropy}","${d.age}","${d.puny}","${d.self_signed||''}","${d.verdict}","${d.detail||''}"`).join('\n');
  const blob=new Blob(['\uFEFF'+hdr+rows],{type:'text/csv;charset=utf-8;'});
  const url=URL.createObjectURL(blob);
  const a=document.createElement('a');a.href=url;
  a.download=`ids_report_${new Date().toISOString().slice(0,19).replace(/:/g,'-')}.csv`;
  a.click();URL.revokeObjectURL(url);
}


// ── Global tooltip ──────
(function(){
  const tipEl = document.createElement('div');
  tipEl.id = 'global-tip';
  document.body.appendChild(tipEl);

  function show(target){
    const text = target.getAttribute('data-tip');
    if(!text) return;
    tipEl.textContent = text;
    tipEl.classList.add('show');
    const r = target.getBoundingClientRect();
    let tw = tipEl.offsetWidth, th = tipEl.offsetHeight;
    let left = r.left + r.width/2 - tw/2;
    let top  = r.top - th - 8;
    const pad = 8;
    if(left < pad) left = pad;
    if(left + tw > window.innerWidth - pad) left = window.innerWidth - tw - pad;
    if(top < pad) top = r.bottom + 8;
    tipEl.style.left = left + 'px';
    tipEl.style.top  = top + 'px';
  }
  function hide(){ tipEl.classList.remove('show'); }

  document.addEventListener('mouseover', e=>{
    const ic = e.target.closest('.info-i');
    if(ic) show(ic);
  });
  document.addEventListener('mouseout', e=>{
    const ic = e.target.closest('.info-i');
    if(ic) hide();
  });
  window.addEventListener('scroll', hide, true);
  window.addEventListener('resize', hide);
})();
