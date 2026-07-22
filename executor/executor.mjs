#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// StormForge Executor — Remote Tool Runner (production-oriented)
//
// Polls C2 for pending tasks, runs offensive tools with timeouts + retries,
// emits structured JSON logs, parses findings with stable FNV IDs matching
// the Worker, and reports results back.
//
// AUTHORIZED TARGETS ONLY. C2 validates scope; this executor double-checks.
// Required: STORMFORGE_C2_URL, EXECUTOR_SECRET (unless ALLOW_INSECURE_EXECUTOR=true)
// ─────────────────────────────────────────────────────────────────────────────

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { pathToFileURL } from 'node:url';

const execFileAsync = promisify(execFile);

const C2_URL = (process.env.STORMFORGE_C2_URL || 'http://localhost:8787').replace(/\/$/, '');
const EXECUTOR_SECRET = process.env.EXECUTOR_SECRET || '';
const ALLOW_INSECURE = process.env.ALLOW_INSECURE_EXECUTOR === 'true';
const POLL_INTERVAL_MS = parseInt(process.env.POLL_INTERVAL || '5000', 10);
const MAX_CONCURRENT = parseInt(process.env.MAX_CONCURRENT || '3', 10);
const MAX_RETRIES = parseInt(process.env.C2_RETRIES || '3', 10);
const DEFAULT_TIMEOUT_SEC = parseInt(process.env.DEFAULT_TIMEOUT_SEC || '300', 10);

let running = 0;
/** Tasks received from poll but deferred due to concurrency — retry next loop. */
const deferred = [];

// ─── Structured logging ──────────────────────────────────────────────────────

function log(level, event, fields = {}) {
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    level,
    event,
    ...fields,
  });
  if (level === 'error') console.error(line);
  else console.log(line);
}

// ─── Stable finding IDs (must match Worker FNV + canonicalize) ───────────────

function canonicalizeTarget(target) {
  const raw = String(target || '').trim();
  if (!raw) return '';
  try {
    const withScheme = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
    const u = new URL(withScheme);
    const host = u.hostname.toLowerCase();
    const port = u.port && u.port !== '80' && u.port !== '443' ? `:${u.port}` : '';
    let path = u.pathname || '/';
    if (path.length > 1 && path.endsWith('/')) path = path.slice(0, -1);
    const params = [...u.searchParams.entries()].sort(([a], [b]) => a.localeCompare(b));
    const qs = params.length
      ? `?${params.map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&')}`
      : '';
    return `${host}${port}${path}${qs}`;
  } catch {
    return raw.toLowerCase().replace(/\/+$/, '');
  }
}

function fnv1a(input) {
  let hash = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    hash ^= input.charCodeAt(i);
    hash = (hash + ((hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24))) >>> 0;
  }
  return hash.toString(16).padStart(8, '0');
}

function makeFindingId(checkId, target, evidence) {
  const canonTarget = canonicalizeTarget(target) || target;
  const canonEvidence = String(evidence || '').trim().replace(/\s+/g, ' ').slice(0, 200);
  return `${checkId}-${fnv1a(`${checkId}|${canonTarget}|${canonEvidence}`)}`;
}

function hashTokenList(items) {
  return [...new Set(items.map((s) => s.trim().toLowerCase()).filter(Boolean))]
    .sort()
    .slice(0, 50)
    .join('|')
    .slice(0, 180);
}

// ─── Scope (mirrors Worker evaluateScope) ────────────────────────────────────

function hostMatches(host, pattern) {
  const p = pattern.trim().toLowerCase();
  if (p === host) return true;
  if (p.startsWith('*.')) {
    const suffix = p.slice(1);
    return host.endsWith(suffix) && host.length > suffix.length;
  }
  return false;
}

function isInScope(target, scope) {
  if (!scope || !scope.authorized) return false;
  let host;
  try {
    const raw = target.includes('://') ? target : `https://${target}`;
    host = new URL(raw).hostname.toLowerCase();
  } catch {
    return false;
  }
  for (const oos of scope.outOfScope || []) {
    if (hostMatches(host, oos)) return false;
  }
  for (const pattern of scope.inScope || []) {
    if (hostMatches(host, pattern)) return true;
  }
  return false;
}

// ─── Tool definitions ────────────────────────────────────────────────────────

const TOOLS = {
  nmap: {
    bin: 'nmap',
    buildArgs: (task) => {
      const flags = (task.args.flags || '-sV -sC --top-ports 1000 -T4 --open').split(/\s+/).filter(Boolean);
      return [...flags, task.target];
    },
    parseFindings: parseNmapOutput,
  },
  nuclei: {
    bin: 'nuclei',
    buildArgs: (task) => {
      const args = ['-u', task.target, '-silent', '-jsonl'];
      if (task.args.templates) {
        // Support comma-separated tags as -tags when not a path
        const t = task.args.templates;
        if (t.includes('/') || t.endsWith('.yaml') || t.endsWith('.yml')) args.push('-t', t);
        else args.push('-tags', t);
      }
      if (task.args.flags) args.push(...task.args.flags.split(/\s+/).filter(Boolean));
      return args;
    },
    parseFindings: parseNucleiOutput,
  },
  httpx: {
    bin: 'httpx',
    buildArgs: (task) => {
      const flags = (task.args.flags || '-silent -status-code -title -tech-detect').split(/\s+/).filter(Boolean);
      return ['-u', task.target, ...flags, '-json'];
    },
    parseFindings: parseHttpxOutput,
  },
  subfinder: {
    bin: 'subfinder',
    buildArgs: (task) => {
      const flags = (task.args.flags || '-silent').split(/\s+/).filter(Boolean);
      return ['-d', task.target, ...flags];
    },
    parseFindings: parseSubfinderOutput,
  },
  katana: {
    bin: 'katana',
    buildArgs: (task) => {
      const flags = (task.args.flags || '-silent -d 2 -jc -kf').split(/\s+/).filter(Boolean);
      return ['-u', task.target, ...flags];
    },
    parseFindings: parseKatanaOutput,
  },
  ffuf: {
    bin: 'ffuf',
    buildArgs: (task) => {
      const wordlist = task.args.wordlist || '/usr/share/wordlists/dirb/common.txt';
      const flags = (task.args.flags || '-mc 200,301,302,403 -t 20 -ac').split(/\s+/).filter(Boolean);
      return ['-u', task.target, '-w', wordlist, ...flags, '-o', '/dev/stdout', '-of', 'json'];
    },
    parseFindings: parseFfufOutput,
  },
  sqlmap: {
    bin: 'sqlmap',
    buildArgs: (task) => {
      const flags = (task.args.flags || '--batch --level=1 --risk=1 --random-agent').split(/\s+/).filter(Boolean);
      // Hard refuse destructive flags even if planner slips
      const blocked = flags.some((f) =>
        /--dump|--os-shell|--sql-shell|--file-write|--priv-esc/i.test(f),
      );
      if (blocked) throw new Error('REFUSED: destructive sqlmap flags are not allowed');
      return ['-u', task.target, ...flags, '--output-dir=/tmp/sqlmap-out'];
    },
    parseFindings: parseSqlmapOutput,
  },
  gobuster: {
    bin: 'gobuster',
    buildArgs: (task) => {
      const mode = task.args.mode || 'dir';
      const wordlist = task.args.wordlist || '/usr/share/wordlists/dirb/common.txt';
      const flags = (task.args.flags || '-q --no-error -t 20').split(/\s+/).filter(Boolean);
      return [mode, '-u', task.target, '-w', wordlist, ...flags];
    },
    parseFindings: parseGobusterOutput,
  },
};

// ─── HTTP with retries ───────────────────────────────────────────────────────

async function fetchWithRetry(url, options = {}, label = 'http') {
  let lastErr;
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      const res = await fetch(url, options);
      if (res.status >= 500 || res.status === 429) {
        throw new Error(`C2 ${res.status}`);
      }
      return res;
    } catch (err) {
      lastErr = err;
      const backoff = Math.min(8000, 400 * 2 ** (attempt - 1));
      log('warn', 'retry', { label, attempt, backoffMs: backoff, error: err.message });
      await sleep(backoff);
    }
  }
  throw lastErr;
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function authHeaders() {
  const headers = { 'content-type': 'application/json', accept: 'application/json' };
  if (EXECUTOR_SECRET) headers['x-executor-secret'] = EXECUTOR_SECRET;
  return headers;
}

// ─── Execution ───────────────────────────────────────────────────────────────

async function executeTask(task) {
  const toolDef = TOOLS[task.tool];
  const timeoutSec = task.timeoutSec || DEFAULT_TIMEOUT_SEC;

  if (!toolDef) {
    return resultShell(1, '', `Unknown tool: ${task.tool}`, [], 0, false, '');
  }

  if (!isInScope(task.target, task.scope)) {
    log('error', 'scope_refused', { tool: task.tool, target: task.target, taskId: task.id });
    return resultShell(1, '', `REFUSED: target ${task.target} is out of scope or not authorized`, [], 0, false, '');
  }

  let args;
  try {
    args = toolDef.buildArgs(task);
  } catch (err) {
    return resultShell(1, '', err.message, [], 0, false, '');
  }

  const command = `${toolDef.bin} ${args.join(' ')}`;
  const start = Date.now();
  log('info', 'exec_start', { taskId: task.id, tool: task.tool, target: task.target, command, timeoutSec });

  try {
    const { stdout, stderr } = await execFileAsync(toolDef.bin, args, {
      timeout: timeoutSec * 1000,
      maxBuffer: 10 * 1024 * 1024,
      env: { ...process.env, HOME: process.env.HOME || '/root' },
    });

    const durationMs = Date.now() - start;
    const findings = (toolDef.parseFindings(stdout, task) || []).map(tagExecutor);

    log('info', 'exec_done', {
      taskId: task.id,
      tool: task.tool,
      target: task.target,
      findings: findings.length,
      durationMs,
      exitCode: 0,
      stdoutPreview: String(stdout).slice(0, 400),
      stderrPreview: String(stderr).slice(0, 200),
    });

    return {
      exitCode: 0,
      stdout: String(stdout).slice(0, 50000),
      stderr: String(stderr).slice(0, 5000),
      findings,
      durationMs,
      completedAt: new Date().toISOString(),
      timedOut: false,
      command,
    };
  } catch (err) {
    const durationMs = Date.now() - start;
    const timedOut = !!(err.killed || err.signal === 'SIGTERM' || /ETIMEDOUT|timed out/i.test(err.message || ''));
    const stdout = err.stdout || '';
    const findings = (toolDef.parseFindings(stdout, task) || []).map(tagExecutor);

    log('error', 'exec_error', {
      taskId: task.id,
      tool: task.tool,
      target: task.target,
      timedOut,
      durationMs,
      error: err.message,
      stdoutPreview: String(stdout).slice(0, 400),
      stderrPreview: String(err.stderr || '').slice(0, 400),
      command,
    });

    return {
      exitCode: timedOut ? 124 : err.code || 1,
      stdout: String(stdout).slice(0, 50000),
      stderr: String(err.stderr || err.message || '').slice(0, 5000),
      findings,
      durationMs,
      completedAt: new Date().toISOString(),
      timedOut,
      command,
    };
  }
}

function tagExecutor(f) {
  return {
    ...f,
    source: 'executor',
    evidenceGrade: f.evidenceGrade || (f.severity === 'info' ? 'heuristic' : 'tool-confirmed'),
  };
}

function resultShell(exitCode, stdout, stderr, findings, durationMs, timedOut, command) {
  return {
    exitCode,
    stdout,
    stderr,
    findings,
    durationMs,
    completedAt: new Date().toISOString(),
    timedOut,
    command,
  };
}

// ─── Parsers (noise-reduced) ─────────────────────────────────────────────────

const DANGEROUS_SERVICES = ['mysql', 'postgres', 'redis', 'mongodb', 'memcached', 'elasticsearch', 'ftp', 'smb', 'rdp'];

function parseNmapOutput(stdout, task) {
  const findings = [];
  const portRegex = /^(\d+)\/(\w+)\s+open\s+(.+)$/gm;
  let match;
  while ((match = portRegex.exec(stdout)) !== null) {
    const [, port, proto, service] = match;
    const lower = service.toLowerCase();
    const dangerous = DANGEROUS_SERVICES.some((s) => lower.includes(s));
    // Skip boring open ports — only keep dangerous / unusual
    if (!dangerous && !/http|ssl|tls|ssh/i.test(lower)) continue;
    if (!dangerous && /ssh|http/i.test(lower)) continue; // common web/ssh = noise

    findings.push({
      id: makeFindingId('nmap-open-port', task.target, `${port}/${proto}`),
      checkId: 'nmap-open-port',
      title: dangerous
        ? `[HIGH] Exposed service ${port}/${proto}: ${service.trim()}`
        : `Open port ${port}/${proto}: ${service.trim()}`,
      severity: dangerous ? 'high' : 'info',
      target: task.target,
      description: `Port ${port}/${proto} is open running ${service.trim()}`,
      evidence: match[0],
      reproduction: [`nmap -sV -p ${port} ${task.target}`],
      remediation: dangerous
        ? 'This service should NOT be publicly accessible. Restrict with firewall rules.'
        : 'Review if this service should be publicly exposed.',
      references: [],
      needsManualReview: dangerous,
      discoveredAt: new Date().toISOString(),
    });
  }
  return findings;
}

function parseNucleiOutput(stdout, task) {
  const findings = [];
  for (const line of stdout.split('\n')) {
    if (!line.trim()) continue;
    try {
      const item = JSON.parse(line);
      const severity = (item.info?.severity || 'info').toLowerCase();
      let sev = ['info', 'low', 'medium', 'high', 'critical'].includes(severity) ? severity : 'info';
      if (sev === 'info') {
        // Most info templates are recon noise, but exposure/token/config/secret
        // templates are genuine bounty leads — keep those, promoted to low.
        const tid = String(item['template-id'] || '').toLowerCase();
        const tags = (Array.isArray(item.info?.tags) ? item.info.tags.join(',') : item.info?.tags || '')
          .toString()
          .toLowerCase();
        const highSignalInfo =
          /expos|token|secret|cred|backup|config|\.git|\.env|disclos|leak|listing|swagger|graphql|api-?docs|\bidor\b/.test(
            `${tid} ${tags}`,
          );
        if (!highSignalInfo) continue;
        sev = 'low';
      }
      const matchedAt = item['matched-at'] || item.matched || item.host || task.target;
      const matcher = item['matcher-name'] || item['matcher_name'] || '';
      const extracted = Array.isArray(item['extracted-results'])
        ? item['extracted-results'].slice(0, 5).join(', ')
        : '';
      const evidenceParts = [
        matchedAt && `matched-at: ${matchedAt}`,
        matcher && `matcher: ${matcher}`,
        extracted && `extracted: ${extracted}`,
        item['curl-command'] && `curl: ${item['curl-command']}`,
        item['template-id'] && `template: ${item['template-id']}`,
      ].filter(Boolean);
      findings.push({
        id: makeFindingId('nuclei', matchedAt, item['template-id'] || matcher || ''),
        checkId: `nuclei-${item['template-id'] || 'unknown'}`,
        title: item.info?.name || item['template-id'] || 'Nuclei finding',
        severity: sev,
        target: matchedAt,
        description: item.info?.description || `Nuclei template ${item['template-id']} matched`,
        evidence: evidenceParts.join('\n') || line.slice(0, 500),
        reproduction: item['curl-command']
          ? [item['curl-command']]
          : [`nuclei -u ${task.target} -t ${item['template-id'] || ''}`],
        remediation: item.info?.remediation || 'See references for remediation guidance.',
        cwe: item.info?.classification?.['cwe-id']?.[0] || undefined,
        references: item.info?.reference || [],
        needsManualReview: sev === 'low' || sev === 'medium',
        evidenceGrade: 'tool-confirmed',
        confidence: sev === 'critical' || sev === 'high' ? 0.9 : 0.75,
        submitReady: sev === 'critical' || sev === 'high',
        source: 'executor',
        discoveredAt: new Date().toISOString(),
      });
    } catch {
      /* skip */
    }
  }
  return findings;
}

function parseHttpxOutput(stdout, task) {
  const findings = [];
  for (const line of stdout.split('\n')) {
    if (!line.trim()) continue;
    try {
      const item = JSON.parse(line);
      // Keep a single compact tech fingerprint (recon), not one-per-line spam in store —
      // C2 quality filter may drop info; still useful for planner follow-ups.
      if (item.tech && item.tech.length > 0) {
        const techKey = hashTokenList(item.tech);
        findings.push({
          id: makeFindingId('httpx-tech-detect', item.url || task.target, techKey),
          checkId: 'httpx-tech-detect',
          title: `Tech detected: ${item.tech.join(', ')}`,
          severity: 'info',
          target: item.url || task.target,
          description: `Technologies: ${item.tech.join(', ')}. Status: ${item['status-code']}. Title: ${item.title || 'N/A'}`,
          evidence: item.tech.join(','),
          reproduction: [`httpx -u ${item.url || task.target} -tech-detect -json`],
          remediation: 'Review detected technologies for known vulnerabilities.',
          references: [],
          needsManualReview: false,
          evidenceGrade: 'heuristic',
          discoveredAt: new Date().toISOString(),
        });
      }
    } catch {
      /* skip */
    }
  }
  return findings;
}

function parseSubfinderOutput(stdout, task) {
  const subdomains = stdout
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean);
  if (!subdomains.length) return [];
  const key = hashTokenList(subdomains);
  return [
    {
      id: makeFindingId('subfinder-enumeration', task.target, key),
      checkId: 'subfinder-enumeration',
      title: `${subdomains.length} subdomains discovered for ${task.target}`,
      severity: 'info',
      target: task.target,
      description: `Subdomain enumeration found ${subdomains.length} hosts:\n${subdomains.slice(0, 50).join('\n')}${subdomains.length > 50 ? '\n... (truncated)' : ''}`,
      evidence: subdomains.slice(0, 30).join(', '),
      reproduction: [`subfinder -d ${task.target} -silent`],
      remediation: 'Review subdomains for unauthorized services or takeover opportunities.',
      references: [],
      needsManualReview: true,
      evidenceGrade: 'heuristic',
      discoveredAt: new Date().toISOString(),
    },
  ];
}

function parseKatanaOutput(stdout, task) {
  const urls = stdout
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean);
  if (!urls.length) return [];

  const interesting = urls.filter(
    (u) =>
      u.includes('?') ||
      u.includes('/api/') ||
      u.includes('/admin') ||
      u.includes('/graphql') ||
      u.includes('.json') ||
      u.includes('/debug') ||
      u.includes('/swagger') ||
      u.includes('/openapi'),
  );
  if (!interesting.length) return [];

  const findings = [];
  const key = hashTokenList(interesting);
  findings.push({
    id: makeFindingId('katana-endpoint-discovery', task.target, key),
    checkId: 'katana-endpoint-discovery',
    title: `${interesting.length} interesting endpoints on ${task.target}`,
    severity: 'low',
    target: task.target,
    description: `Crawling found ${urls.length} URLs, ${interesting.length} interesting:\n${interesting.slice(0, 30).join('\n')}`,
    evidence: interesting.slice(0, 40).join('\n'),
    reproduction: [`katana -u ${task.target} -d 2 -jc`],
    remediation: 'Review endpoints for authz issues and injection surfaces.',
    references: [],
    needsManualReview: true,
    evidenceGrade: 'heuristic',
    discoveredAt: new Date().toISOString(),
  });

  // Per-URL findings for param endpoints (planner fan-out); hard cap.
  for (const u of interesting.filter((x) => /[?&]\w+=/.test(x)).slice(0, 12)) {
    findings.push({
      id: makeFindingId('katana-param-url', u, 'param'),
      checkId: 'katana-param-url',
      title: `Parameterized URL discovered: ${u.slice(0, 120)}`,
      severity: 'info',
      target: u,
      description: 'Katana discovered a URL with query parameters — candidate for sqlmap/XSS testing.',
      evidence: u,
      reproduction: [`curl -sI '${u}'`],
      remediation: 'Validate all user-controlled parameters server-side.',
      references: [],
      needsManualReview: true,
      evidenceGrade: 'heuristic',
      discoveredAt: new Date().toISOString(),
    });
  }

  return findings;
}

function parseFfufOutput(stdout, task) {
  const findings = [];
  try {
    const data = JSON.parse(stdout);
    for (const r of data.results || []) {
      if (![200, 301, 302, 403].includes(r.status)) continue;
      // Skip tiny/generic index noise
      const fuzz = r.input?.FUZZ || r.url || '';
      if (!fuzz || fuzz === '/') continue;
      findings.push({
        id: makeFindingId('ffuf-directory', task.target, String(fuzz)),
        checkId: 'ffuf-directory',
        title: `Hidden path: ${fuzz} (${r.status})`,
        severity: r.status === 200 ? 'medium' : 'low',
        target: r.url || task.target,
        description: `Discovered ${r.url} — Status ${r.status}, Size ${r.length}`,
        evidence: `URL: ${r.url}\nStatus: ${r.status}\nSize: ${r.length}`,
        reproduction: [`curl -s -o /dev/null -w "%{http_code}" '${r.url}'`],
        remediation: 'Review path accessibility; remove or protect if unintended.',
        references: [],
        needsManualReview: true,
        evidenceGrade: 'tool-confirmed',
        discoveredAt: new Date().toISOString(),
      });
    }
  } catch {
    for (const line of stdout.split('\n')) {
      const match = line.match(/(\S+)\s+\[Status:\s*(\d+)/);
      if (match) {
        findings.push({
          id: makeFindingId('ffuf-directory', task.target, match[1]),
          checkId: 'ffuf-directory',
          title: `Path found: ${match[1]} (${match[2]})`,
          severity: 'low',
          target: task.target,
          description: line.trim(),
          evidence: line.trim(),
          reproduction: [`curl -s '${task.target}'`],
          remediation: 'Review path accessibility.',
          references: [],
          needsManualReview: true,
          discoveredAt: new Date().toISOString(),
        });
      }
    }
  }
  return findings;
}

function parseSqlmapOutput(stdout, task) {
  const findings = [];
  if (!/is vulnerable|injectable/i.test(stdout)) return findings;

  const paramMatch = stdout.match(/Parameter:\s*([^\s(]+)\s*\(([^)]+)\)\s*is\s+vulnerable/i);
  const dbmsMatch = stdout.match(/back-end DBMS:\s*([^\n]+)/i);
  const techniqueMatch = stdout.match(/Type:\s*([^\n]+)/i);
  const param = paramMatch?.[1] || 'unknown';
  const place = paramMatch?.[2] || '';
  const dbms = dbmsMatch?.[1]?.trim() || '';
  const technique = techniqueMatch?.[1]?.trim() || '';

  const evidenceStart = Math.max(0, stdout.search(/vulnerable|injectable/i));
  findings.push({
    id: makeFindingId('sqlmap-injection', task.target, param),
    checkId: 'sqlmap-injection',
    title: paramMatch
      ? `SQL Injection in ${param}${place ? ` (${place})` : ''} on ${task.target}`
      : `SQL Injection confirmed on ${task.target}`,
    severity: 'critical',
    target: task.target,
    description: [
      'sqlmap confirmed SQL injection (detection mode).',
      dbms ? `DBMS: ${dbms}.` : '',
      technique ? `Technique: ${technique}.` : '',
    ]
      .filter(Boolean)
      .join(' '),
    evidence: stdout.slice(evidenceStart, evidenceStart + 600),
    reproduction: [
      `sqlmap -u "${task.target}" --batch --level=1 --risk=1`,
      param !== 'unknown' ? `Focus parameter: ${param}` : '',
    ].filter(Boolean),
    remediation: 'Use parameterized queries / prepared statements; never concatenate user input into SQL.',
    cwe: 'CWE-89',
    references: ['https://owasp.org/www-community/attacks/SQL_Injection'],
    needsManualReview: true,
    evidenceGrade: 'tool-confirmed',
    confidence: 0.92,
    submitReady: false,
    source: 'executor',
    discoveredAt: new Date().toISOString(),
  });
  return findings;
}

function parseGobusterOutput(stdout, task) {
  const findings = [];
  for (const line of stdout.split('\n')) {
    const match = line.match(/^\/(\S+)\s+\(Status:\s*(\d+)\)/);
    if (!match) continue;
    const [, path, status] = match;
    findings.push({
      id: makeFindingId('gobuster-directory', task.target, path),
      checkId: 'gobuster-directory',
      title: `Directory found: /${path} (${status})`,
      severity: status === '200' ? 'medium' : 'low',
      target: `${task.target.replace(/\/$/, '')}/${path}`,
      description: `Gobuster discovered /${path} with status ${status}`,
      evidence: line.trim(),
      reproduction: [`curl -s -o /dev/null -w "%{http_code}" ${task.target}/${path}`],
      remediation: 'Review directory accessibility.',
      references: [],
      needsManualReview: true,
      discoveredAt: new Date().toISOString(),
    });
  }
  return findings;
}

// ─── Poll loop ───────────────────────────────────────────────────────────────

async function reportComplete(task, result) {
  const res = await fetchWithRetry(
    `${C2_URL}/api/tasks/complete`,
    {
      method: 'POST',
      headers: authHeaders(),
      body: JSON.stringify({ taskId: task.id, result }),
    },
    'complete',
  );
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`complete ${res.status}: ${text.slice(0, 200)}`);
  }
  log('info', 'report_ok', { taskId: task.id, findings: result.findings.length, timedOut: !!result.timedOut });
}

async function runOne(task) {
  running++;
  try {
    const result = await executeTask(task);
    await reportComplete(task, result);
  } catch (err) {
    log('error', 'task_fatal', { taskId: task.id, error: err.message });
  } finally {
    running--;
  }
}

async function pollForTasks() {
  try {
    // Drain deferred first
    while (deferred.length && running < MAX_CONCURRENT) {
      const task = deferred.shift();
      runOne(task);
    }

    const res = await fetchWithRetry(`${C2_URL}/api/tasks/poll`, { headers: authHeaders() }, 'poll');
    if (res.status === 401) {
      log('error', 'auth_failed', {
        hint: 'Set EXECUTOR_SECRET to match Worker, or ALLOW_INSECURE_EXECUTOR=true on both for local only',
      });
      return;
    }
    if (!res.ok) {
      log('error', 'poll_http', { status: res.status, body: (await res.text()).slice(0, 200) });
      return;
    }

    const body = await res.json();
    const tasks = body.tasks || [];
    if (!tasks.length) return;

    log('info', 'poll_got', { count: tasks.length, running, deferred: deferred.length });

    for (const task of tasks) {
      if (running >= MAX_CONCURRENT) {
        deferred.push(task);
        log('warn', 'throttle_defer', { taskId: task.id, tool: task.tool });
        continue;
      }
      runOne(task);
    }
  } catch (err) {
    log('error', 'poll_error', { error: err.message });
  }
}

// ─── Main ────────────────────────────────────────────────────────────────────

function banner() {
  log('info', 'executor_start', {
    c2: C2_URL,
    pollIntervalMs: POLL_INTERVAL_MS,
    maxConcurrent: MAX_CONCURRENT,
    secretConfigured: Boolean(EXECUTOR_SECRET),
    allowInsecure: ALLOW_INSECURE,
  });
}

async function main() {
  if (!EXECUTOR_SECRET && !ALLOW_INSECURE) {
    console.error(
      JSON.stringify({
        ts: new Date().toISOString(),
        level: 'error',
        event: 'config_error',
        error: 'EXECUTOR_SECRET is required (or set ALLOW_INSECURE_EXECUTOR=true for local dev only)',
      }),
    );
    process.exit(1);
  }

  banner();

  const toolNames = Object.keys(TOOLS);
  const checks = await Promise.all(
    toolNames.map(async (name) => {
      try {
        await execFileAsync('which', [TOOLS[name].bin]);
        log('info', 'tool_ok', { tool: name, bin: TOOLS[name].bin });
        return true;
      } catch {
        log('warn', 'tool_missing', { tool: name, bin: TOOLS[name].bin });
        return false;
      }
    }),
  );

  const available = checks.filter(Boolean).length;
  log('info', 'tools_summary', { available, total: toolNames.length });
  if (available === 0) {
    log('error', 'no_tools', { hint: 'See executor/INSTALL.md' });
    process.exit(1);
  }

  // Minimum useful set for this session's charter
  for (const required of ['nuclei', 'httpx', 'subfinder', 'katana', 'ffuf', 'sqlmap']) {
    if (!checks[toolNames.indexOf(required)]) {
      log('warn', 'recommended_missing', { tool: required });
    }
  }

  setInterval(pollForTasks, POLL_INTERVAL_MS);
  pollForTasks();
}

// Exported for unit-style smoke tests via node --experimental-vm-modules if needed
export {
  canonicalizeTarget,
  makeFindingId,
  isInScope,
  hashTokenList,
  parseHttpxOutput,
  parseSubfinderOutput,
  parseNucleiOutput,
  parseKatanaOutput,
  parseSqlmapOutput,
};

if (import.meta.url === pathToFileURL(process.argv[1] || '').href) {
  main();
}
