/** Mobile-first chat UI for StormForge orchestration (Grok companion). */

export const MOBILE_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"/>
<meta name="theme-color" content="#0c1210"/>
<title>StormForge · Mobile</title>
<style>
  :root {
    --bg0: #0c1210;
    --bg1: #141c18;
    --ink: #e8f0ea;
    --muted: #8aa092;
    --line: #243028;
    --accent: #6fbf8a;
    --accent-dim: #3d7a52;
    --danger: #d4786a;
    --font-display: "Iowan Old Style", "Palatino Linotype", Palatino, "Book Antiqua", Georgia, serif;
    --font-body: "IBM Plex Sans", "Segoe UI", sans-serif;
    --font-mono: "IBM Plex Mono", ui-monospace, monospace;
  }
  * { box-sizing: border-box; }
  html, body {
    margin: 0; height: 100%;
    background:
      radial-gradient(1200px 600px at 10% -10%, #1a3328 0%, transparent 55%),
      radial-gradient(900px 500px at 110% 10%, #1c2830 0%, transparent 50%),
      var(--bg0);
    color: var(--ink);
    font-family: var(--font-body);
  }
  body {
    display: grid;
    grid-template-rows: auto 1fr auto;
    min-height: 100dvh;
    max-width: 720px;
    margin: 0 auto;
  }
  header {
    padding: 1.1rem 1.15rem 0.75rem;
    border-bottom: 1px solid var(--line);
  }
  header h1 {
    margin: 0;
    font-family: var(--font-display);
    font-weight: 600;
    font-size: clamp(1.55rem, 5vw, 2rem);
    letter-spacing: -0.02em;
    line-height: 1.1;
  }
  header p {
    margin: 0.35rem 0 0;
    color: var(--muted);
    font-size: 0.88rem;
    line-height: 1.35;
  }
  #log {
    overflow-y: auto;
    padding: 1rem 1.15rem 1.25rem;
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }
  .msg {
    max-width: 92%;
    padding: 0.7rem 0.85rem;
    border-radius: 4px 14px 14px 14px;
    white-space: pre-wrap;
    word-break: break-word;
    font-size: 0.92rem;
    line-height: 1.45;
    animation: rise 0.28s ease-out;
  }
  .msg.user {
    align-self: flex-end;
    background: var(--accent-dim);
    color: #f2fff6;
    border-radius: 14px 4px 14px 14px;
  }
  .msg.bot {
    align-self: flex-start;
    background: var(--bg1);
    border: 1px solid var(--line);
    font-family: var(--font-mono);
    font-size: 0.82rem;
  }
  .msg.err { border-color: var(--danger); color: #f0c4bc; }
  @keyframes rise {
    from { opacity: 0; transform: translateY(8px); }
    to { opacity: 1; transform: none; }
  }
  footer {
    border-top: 1px solid var(--line);
    padding: 0.75rem 1rem calc(0.85rem + env(safe-area-inset-bottom));
    background: color-mix(in srgb, var(--bg0) 88%, transparent);
    backdrop-filter: blur(8px);
  }
  .secret-row {
    display: flex;
    gap: 0.5rem;
    margin-bottom: 0.55rem;
  }
  .secret-row input {
    flex: 1;
    font-family: var(--font-mono);
    font-size: 0.78rem;
  }
  .composer {
    display: flex;
    gap: 0.5rem;
    align-items: flex-end;
  }
  textarea, input {
    width: 100%;
    background: var(--bg1);
    border: 1px solid var(--line);
    color: var(--ink);
    border-radius: 10px;
    padding: 0.7rem 0.8rem;
    outline: none;
  }
  textarea:focus, input:focus { border-color: var(--accent-dim); }
  textarea {
    min-height: 2.8rem;
    max-height: 8rem;
    resize: vertical;
    font-family: var(--font-body);
    font-size: 0.95rem;
  }
  button {
    appearance: none;
    border: 0;
    background: var(--accent);
    color: #0a140e;
    font-weight: 650;
    font-family: var(--font-body);
    border-radius: 10px;
    padding: 0.75rem 1rem;
    cursor: pointer;
  }
  button:disabled { opacity: 0.5; cursor: wait; }
  .hints {
    display: flex;
    flex-wrap: wrap;
    gap: 0.4rem;
    margin-top: 0.55rem;
  }
  .hints button {
    background: transparent;
    color: var(--muted);
    border: 1px solid var(--line);
    font-weight: 500;
    font-size: 0.72rem;
    padding: 0.35rem 0.55rem;
  }
</style>
</head>
<body>
  <header>
    <h1>StormForge</h1>
    <p>Mobile orchestrator for Grok — authorized recon only. Paste the same commands you would send from the Grok app.</p>
  </header>
  <main id="log" aria-live="polite"></main>
  <footer>
    <div class="secret-row">
      <input id="secret" type="password" placeholder="x-executor-secret" autocomplete="off" spellcheck="false"/>
    </div>
    <div class="composer">
      <textarea id="msg" rows="2" placeholder="scan https://api.example *.example authorized program=lab"></textarea>
      <button id="send" type="button">Send</button>
    </div>
    <div class="hints">
      <button type="button" data-hint="help">help</button>
      <button type="button" data-hint="audit">audit</button>
      <button type="button" data-hint="plan https://httpbin.org authorized program=httpbin-lab inScope=httpbin.org">plan httpbin</button>
    </div>
  </footer>
<script>
(function () {
  const log = document.getElementById('log');
  const msg = document.getElementById('msg');
  const secret = document.getElementById('secret');
  const send = document.getElementById('send');
  const KEY = 'stormforge.mobile.secret';

  try { secret.value = localStorage.getItem(KEY) || ''; } catch (_) {}
  secret.addEventListener('change', () => {
    try { localStorage.setItem(KEY, secret.value); } catch (_) {}
  });

  function bubble(text, kind) {
    const el = document.createElement('div');
    el.className = 'msg ' + kind;
    el.textContent = text;
    log.appendChild(el);
    log.scrollTop = log.scrollHeight;
  }

  bubble('Commands need the word "authorized" for plan/scan/dispatch.\\nType help for the cheat-sheet.', 'bot');

  async function run() {
    const text = (msg.value || '').trim();
    if (!text) return;
    bubble(text, 'user');
    msg.value = '';
    send.disabled = true;
    try {
      const headers = { 'content-type': 'application/json' };
      if (secret.value) headers['x-executor-secret'] = secret.value;
      const res = await fetch('/api/orchestrate', {
        method: 'POST',
        headers,
        body: JSON.stringify({ message: text }),
      });
      const data = await res.json().catch(() => ({ text: res.statusText }));
      const out = data.text || data.error || JSON.stringify(data, null, 2);
      bubble(out, res.ok ? 'bot' : 'bot err');
    } catch (e) {
      bubble(String(e && e.message ? e.message : e), 'bot err');
    } finally {
      send.disabled = false;
      msg.focus();
    }
  }

  send.addEventListener('click', run);
  msg.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); run(); }
  });
  document.querySelectorAll('[data-hint]').forEach((btn) => {
    btn.addEventListener('click', () => {
      msg.value = btn.getAttribute('data-hint') || '';
      msg.focus();
    });
  });
})();
</script>
</body>
</html>`;
