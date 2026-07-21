// AUTO-GENERATED from dashboard/index.html — do not edit by hand.
// Regenerate: node scripts/build-dashboard.mjs
export const DASHBOARD_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>StormForge — Authorized Recon Console</title>
<style>
  :root { color-scheme: light dark; --bg:#0f1117; --panel:#171a23; --line:#262b38; --fg:#e6e9ef; --mut:#8b93a7; --acc:#5b8cff; --crit:#ff5470; --high:#ff8f3f; --med:#ffd23f; --low:#4fd1c5; --info:#6b7280; }
  * { box-sizing:border-box; }
  body { margin:0; font:14px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif; background:var(--bg); color:var(--fg); }
  header { padding:18px 24px; border-bottom:1px solid var(--line); display:flex; align-items:center; gap:12px; }
  header h1 { font-size:18px; margin:0; letter-spacing:.3px; }
  .badge { font-size:11px; color:var(--mut); border:1px solid var(--line); padding:2px 8px; border-radius:999px; }
  main { max-width:1100px; margin:0 auto; padding:24px; display:grid; gap:20px; grid-template-columns:1fr; }
  .panel { background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:18px; }
  .panel h2 { margin:0 0 12px; font-size:14px; text-transform:uppercase; letter-spacing:.6px; color:var(--mut); }
  label { display:block; font-size:12px; color:var(--mut); margin:10px 0 4px; }
  input, textarea, select { width:100%; background:#0c0e14; border:1px solid var(--line); color:var(--fg); border-radius:8px; padding:9px 10px; font:inherit; }
  textarea { min-height:70px; resize:vertical; font-family:ui-monospace,monospace; }
  .row { display:grid; grid-template-columns:1fr 1fr; gap:12px; }
  .check { display:flex; align-items:center; gap:8px; margin:8px 0; }
  .check input { width:auto; }
  button { background:var(--acc); color:white; border:0; border-radius:8px; padding:11px 18px; font:inherit; font-weight:600; cursor:pointer; }
  button:disabled { opacity:.5; cursor:not-allowed; }
  button.secondary { background:transparent; border:1px solid var(--line); color:var(--fg); }
  .warn { background:#2a1a1f; border:1px solid var(--crit); color:#ffb3c0; padding:10px 12px; border-radius:8px; font-size:12px; margin-top:12px; }
  .progress { height:8px; background:#0c0e14; border-radius:999px; overflow:hidden; margin:10px 0; }
  .progress > div { height:100%; width:0; background:var(--acc); transition:width .3s; }
  .stat-row { display:flex; gap:10px; flex-wrap:wrap; }
  .stat { flex:1; min-width:90px; text-align:center; background:#0c0e14; border:1px solid var(--line); border-radius:8px; padding:10px; }
  .stat b { display:block; font-size:22px; }
  .s-critical b { color:var(--crit);} .s-high b{color:var(--high);} .s-medium b{color:var(--med);} .s-low b{color:var(--low);} .s-info b{color:var(--info);}
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th, td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
  th { color:var(--mut); font-weight:600; font-size:11px; text-transform:uppercase; }
  .pill { font-size:11px; padding:2px 8px; border-radius:999px; font-weight:600; }
  .pill.critical{background:var(--crit);color:#fff;} .pill.high{background:var(--high);color:#1a1a1a;} .pill.medium{background:var(--med);color:#1a1a1a;} .pill.low{background:var(--low);color:#1a1a1a;} .pill.info{background:var(--info);color:#fff;}
  .muted { color:var(--mut); font-size:12px; }
  .review { color:var(--med); font-size:11px; }
  pre { background:#0c0e14; border:1px solid var(--line); border-radius:8px; padding:12px; overflow:auto; font-size:12px; }
  a { color:var(--acc); }
</style>
</head>
<body>
<header>
  <h1>⚡ StormForge</h1>
  <span class="badge">Authorized Recon Console</span>
  <span class="badge" id="mode">non-destructive</span>
</header>
<main>
  <section class="panel">
    <h2>1 · Scope &amp; Target</h2>
    <div class="row">
      <div><label>Program name</label><input id="program" placeholder="acme-h1" value="demo-program" /></div>
      <div><label>Platform</label>
        <select id="platform">
          <option value="hackerone">HackerOne</option>
          <option value="bugcrowd">Bugcrowd</option>
          <option value="immunefi">Immunefi</option>
          <option value="intigriti">Intigriti</option>
          <option value="generic" selected>Generic</option>
        </select>
      </div>
    </div>
    <label>In-scope hosts (one per line — supports <code>*.example.com</code>)</label>
    <textarea id="inScope" placeholder="*.example.com&#10;api.example.com"></textarea>
    <label>Out-of-scope hosts (optional)</label>
    <textarea id="outOfScope" placeholder="blog.example.com"></textarea>
    <label>Seed targets to probe (must be in scope)</label>
    <textarea id="targets" placeholder="https://api.example.com&#10;www.example.com"></textarea>
    <div class="check">
      <input type="checkbox" id="authorized" />
      <label for="authorized" style="margin:0;color:var(--fg)">
        I confirm I am authorized to test these assets under the program's rules of engagement.
      </label>
    </div>
    <div class="warn">
      StormForge only performs passive, non-destructive checks (safe GET/HEAD requests). It never exploits,
      exfiltrates, or targets anything outside the scope you define above. You are responsible for staying within program rules.
    </div>
    <div style="margin-top:14px; display:flex; gap:10px;">
      <button id="launch">Launch Recon</button>
      <button class="secondary" id="loadReport">View Report Draft</button>
    </div>
  </section>

  <section class="panel">
    <h2>2 · Progress</h2>
    <div class="muted" id="status">Idle.</div>
    <div class="progress"><div id="bar"></div></div>
    <div class="stat-row" id="stats"></div>
  </section>

  <section class="panel">
    <h2>3 · Findings</h2>
    <div id="findings"><p class="muted">No findings yet. Launch a scan.</p></div>
  </section>

  <section class="panel">
    <h2>4 · Bounty Packs</h2>
    <p class="muted">Submit-ready high/critical drafts (CVSS-ranked). Never auto-submitted.</p>
    <button type="button" id="loadBounty" class="secondary">Load Bounty Packs</button>
    <div id="bounty"><p class="muted">Click load after a scan with confirmed findings.</p></div>
  </section>

  <section class="panel">
    <h2>Report Draft</h2>
    <pre id="report" class="muted">Run a scan, then click “View Report Draft”.</pre>
  </section>
</main>

<script>
const $ = (id) => document.getElementById(id);
const lines = (v) => v.split('\\n').map(s => s.trim()).filter(Boolean);
let pollTimer = null;

function buildRequest() {
  return {
    scope: {
      program: $('program').value.trim() || 'unnamed',
      platform: $('platform').value,
      inScope: lines($('inScope').value),
      outOfScope: lines($('outOfScope').value),
      authorized: $('authorized').checked,
    },
    targets: lines($('targets').value),
  };
}

async function launch() {
  const body = buildRequest();
  if (!body.scope.authorized) { alert('You must confirm authorization first.'); return; }
  if (body.scope.inScope.length === 0) { alert('Add at least one in-scope host.'); return; }
  if (body.targets.length === 0) { alert('Add at least one seed target.'); return; }

  $('launch').disabled = true;
  $('status').textContent = 'Starting…';
  try {
    const res = await fetch('/api/scan', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify(body) });
    const data = await res.json();
    if (!res.ok) { $('status').textContent = 'Error: ' + (data.error || res.status) + (data.refused ? ' — ' + JSON.stringify(data.refused) : ''); $('launch').disabled=false; return; }
    poll(data.scanId);
  } catch (e) { $('status').textContent = 'Error: ' + e.message; $('launch').disabled = false; }
}

function poll(scanId) {
  clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    try {
      const res = await fetch('/api/scan/' + scanId + '/status');
      const s = await res.json();
      const pct = s.total ? Math.round((s.probed / s.total) * 100) : 0;
      $('bar').style.width = pct + '%';
      $('status').textContent = \`[\${s.status}] \${s.phase} — probed \${s.probed}/\${s.total}, \${s.findings} findings\`;
      if (s.status === 'done') { clearInterval(pollTimer); $('launch').disabled = false; renderReport(s.report); }
      if (s.status === 'error') { clearInterval(pollTimer); $('launch').disabled = false; $('status').textContent = 'Error: ' + s.error; }
    } catch (e) { /* transient */ }
  }, 1000);
}

function renderReport(report) {
  const sev = report.summary;
  $('stats').innerHTML = ['critical','high','medium','low','info'].map(k =>
    \`<div class="stat s-\${k}"><b>\${sev[k]||0}</b>\${k}</div>\`).join('');

  if (!report.findings.length) { $('findings').innerHTML = '<p class="muted">No findings.</p>'; return; }
  const rows = report.findings
    .sort((a,b) => rank(b.severity)-rank(a.severity))
    .map(f => \`<tr>
      <td><span class="pill \${f.severity}">\${f.severity}</span></td>
      <td><b>\${esc(f.title)}</b><br><span class="muted">\${esc(f.target)}</span>
        \${f.submitReady ? '<br><span class="pill high">submit-ready</span>' : ''}
        \${f.needsManualReview ? '<br><span class="review">⚠ verify manually</span>':''}
        \${f.confidence!=null ? '<br><span class="muted">conf ' + Math.round(f.confidence*100) + '% · ' + esc(f.evidenceGrade||'') + '</span>' : ''}
      </td>
      <td>\${esc(f.cwe||'')}</td>
    </tr>\`).join('');
  $('findings').innerHTML = \`<table><thead><tr><th>Sev</th><th>Finding</th><th>CWE</th></tr></thead><tbody>\${rows}</tbody></table>\`;
  if (sDraftHint(report)) loadBounty();
}

function sDraftHint(report) {
  return (report.findings||[]).some(f => f.severity==='critical'||f.severity==='high');
}

async function loadBounty() {
  const program = $('program').value.trim();
  const platform = $('platform').value === 'immunefi' ? 'immunefi' : 'hackerone';
  const res = await fetch('/api/bounty/' + encodeURIComponent(program) + '?platform=' + platform);
  if (!res.ok) {
    const e = await res.json().catch(()=>({}));
    $('bounty').innerHTML = '<p class="muted">' + esc(e.error || ('No packs ('+res.status+')')) + '</p>';
    return;
  }
  const data = await res.json();
  if (!data.packets || !data.packets.length) {
    $('bounty').innerHTML = '<p class="muted">No submit-ready packs yet (candidates need confirmation).</p>';
    return;
  }
  $('bounty').innerHTML = data.packets.map((p,i) => \`
    <div class="panel" style="margin:0.5rem 0;padding:0.75rem">
      <b>\${i+1}. \${esc(p.submissionTitle)}</b>
      <div class="muted">CVSS \${p.cvssScore} · \${esc(p.cvssVector)} · \${esc(p.platform)}</div>
      <button type="button" class="secondary" data-copy="\${i}">Copy markdown</button>
      <pre class="muted" id="bounty-md-\${i}" style="max-height:160px;overflow:auto">\${esc(p.markdown.slice(0,1200))}</pre>
    </div>\`).join('');
  $('bounty').querySelectorAll('[data-copy]').forEach(btn => {
    btn.addEventListener('click', () => {
      const i = btn.getAttribute('data-copy');
      const text = data.packets[i].markdown;
      navigator.clipboard.writeText(text).then(() => { btn.textContent = 'Copied'; });
    });
  });
}

async function loadReport() {
  const program = $('program').value.trim();
  const res = await fetch('/api/report/' + encodeURIComponent(program));
  if (!res.ok) { const e = await res.json().catch(()=>({})); $('report').textContent = e.error || ('No report ('+res.status+')'); return; }
  $('report').textContent = await res.text();
}

const rank = (s) => ({info:0,low:1,medium:2,high:3,critical:4})[s] ?? 0;
const esc = (s) => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
$('launch').addEventListener('click', launch);
$('loadReport')?.addEventListener('click', loadReport);
$('loadBounty')?.addEventListener('click', loadBounty);
</script>
</body>
</html>`;
