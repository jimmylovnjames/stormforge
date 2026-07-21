#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// StormForge Executor — Remote Tool Runner
//
// This script runs on a VPS/Docker container with offensive tools installed.
// It polls the C2 Worker for pending tasks, executes them via child_process,
// parses output into findings, and reports results back.
//
// AUTHORIZED TARGETS ONLY. The C2 validates scope before dispatching, and
// this executor double-checks before executing.
// ─────────────────────────────────────────────────────────────────────────────

import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash } from 'node:crypto';

const execFileAsync = promisify(execFile);

// ─── Configuration ───────────────────────────────────────────────────────────

const C2_URL = process.env.STORMFORGE_C2_URL || 'http://localhost:8787';
const EXECUTOR_SECRET = process.env.EXECUTOR_SECRET || '';
const POLL_INTERVAL_MS = parseInt(process.env.POLL_INTERVAL || '5000', 10);
const MAX_CONCURRENT = parseInt(process.env.MAX_CONCURRENT || '3', 10);

let running = 0;

// ─── Tool Definitions ────────────────────────────────────────────────────────

const TOOLS = {
  nmap: {
    bin: 'nmap',
    buildArgs: (task) => {
      const flags = (task.args.flags || '-sV -sC --top-ports 1000 -T4 --open').split(' ');
      return [...flags, task.target];
    },
    parseFindings: parseNmapOutput,
  },
  nuclei: {
    bin: 'nuclei',
    buildArgs: (task) => {
      const args = ['-u', task.target, '-silent', '-jsonl'];
      if (task.args.templates) args.push('-t', task.args.templates);
      if (task.args.flags) args.push(...task.args.flags.split(' '));
      return args;
    },
    parseFindings: parseNucleiOutput,
  },
  httpx: {
    bin: 'httpx',
    buildArgs: (task) => {
      const flags = (task.args.flags || '-silent -status-code -title -tech-detect').split(' ');
      return ['-u', task.target, ...flags, '-json'];
    },
    parseFindings: parseHttpxOutput,
  },
  subfinder: {
    bin: 'subfinder',
    buildArgs: (task) => {
      const flags = (task.args.flags || '-silent -all').split(' ');
      return ['-d', task.target, ...flags];
    },
    parseFindings: parseSubfinderOutput,
  },
  katana: {
    bin: 'katana',
    buildArgs: (task) => {
      const flags = (task.args.flags || '-silent -d 3 -jc -kf').split(' ');
      return ['-u', task.target, ...flags];
    },
    parseFindings: parseKatanaOutput,
  },
  ffuf: {
    bin: 'ffuf',
    buildArgs: (task) => {
      const wordlist = task.args.wordlist || '/usr/share/wordlists/dirb/common.txt';
      const flags = (task.args.flags || '-mc 200,301,302,403 -t 20 -ac').split(' ');
      return ['-u', task.target, '-w', wordlist, ...flags, '-o', '/dev/stdout', '-of', 'json'];
    },
    parseFindings: parseFfufOutput,
  },
  sqlmap: {
    bin: 'sqlmap',
    buildArgs: (task) => {
      // sqlmap is dangerous — we run it in detection-only mode (--level 1 --risk 1 --batch)
      const flags = (task.args.flags || '--batch --level=1 --risk=1 --random-agent').split(' ');
      return ['-u', task.target, ...flags, '--output-dir=/tmp/sqlmap-out'];
    },
    parseFindings: parseSqlmapOutput,
  },
  gobuster: {
    bin: 'gobuster',
    buildArgs: (task) => {
      const mode = task.args.mode || 'dir';
      const wordlist = task.args.wordlist || '/usr/share/wordlists/dirb/common.txt';
      const flags = (task.args.flags || '-q --no-error -t 20').split(' ');
      return [mode, '-u', task.target, '-w', wordlist, ...flags];
    },
    parseFindings: parseGobusterOutput,
  },
};

// ─── Scope Validation (double-check on executor side) ────────────────────────

function isInScope(target, scope) {
  if (!scope.authorized) return false;
  let host;
  try {
    const raw = target.includes('://') ? target : `https://${target}`;
    host = new URL(raw).hostname.toLowerCase();
  } catch {
    return false;
  }
  for (const oos of (scope.outOfScope || [])) {
    const p = oos.toLowerCase();
    if (p === host) return false;
    if (p.startsWith('*.') && host.endsWith(p.slice(1))) return false;
  }
  for (const pattern of (scope.inScope || [])) {
    const p = pattern.toLowerCase();
    if (p === host) return true;
    if (p.startsWith('*.') && host.endsWith(p.slice(1)) && host.length > p.length - 1) return true;
  }
  return false;
}

// ─── Execution Engine ────────────────────────────────────────────────────────

async function executeTask(task) {
  const toolDef = TOOLS[task.tool];
  if (!toolDef) {
    return { exitCode: 1, stdout: '', stderr: `Unknown tool: ${task.tool}`, findings: [], durationMs: 0, completedAt: new Date().toISOString() };
  }

  // Double-check scope
  if (!isInScope(task.target, task.scope)) {
    return { exitCode: 1, stdout: '', stderr: `REFUSED: target ${task.target} is out of scope`, findings: [], durationMs: 0, completedAt: new Date().toISOString() };
  }

  const args = toolDef.buildArgs(task);
  const start = Date.now();

  console.log(`[EXEC] ${task.tool} ${args.join(' ')}`);

  try {
    const { stdout, stderr } = await execFileAsync(toolDef.bin, args, {
      timeout: task.timeoutSec * 1000,
      maxBuffer: 10 * 1024 * 1024, // 10MB
      env: { ...process.env, HOME: '/root' },
    });

    const durationMs = Date.now() - start;
    const findings = toolDef.parseFindings(stdout, task);

    console.log(`[DONE] ${task.tool} on ${task.target} — ${findings.length} findings in ${durationMs}ms`);

    return {
      exitCode: 0,
      stdout: stdout.slice(0, 50000), // Cap at 50KB for KV storage
      stderr: stderr.slice(0, 5000),
      findings,
      durationMs,
      completedAt: new Date().toISOString(),
    };
  } catch (err) {
    const durationMs = Date.now() - start;
    const isTimeout = err.killed || err.signal === 'SIGTERM';

    console.error(`[ERROR] ${task.tool} on ${task.target}: ${err.message}`);

    return {
      exitCode: err.code || 1,
      stdout: (err.stdout || '').slice(0, 50000),
      stderr: (err.stderr || err.message || '').slice(0, 5000),
      findings: toolDef.parseFindings(err.stdout || '', task), // Partial output may have findings
      durationMs,
      completedAt: new Date().toISOString(),
    };
  }
}

// ─── Output Parsers ──────────────────────────────────────────────────────────

function makeFindingId(checkId, target, evidence) {
  return createHash('sha256').update(`${checkId}:${target}:${evidence}`).digest('hex').slice(0, 16);
}

function parseNmapOutput(stdout, task) {
  const findings = [];
  // Match open ports with service info
  const portRegex = /^(\d+)\/(\w+)\s+open\s+(.+)$/gm;
  let match;
  while ((match = portRegex.exec(stdout)) !== null) {
    const [, port, proto, service] = match;
    findings.push({
      id: makeFindingId('nmap-open-port', task.target, `${port}/${proto}`),
      checkId: 'nmap-open-port',
      title: `Open port ${port}/${proto}: ${service.trim()}`,
      severity: 'info',
      target: task.target,
      description: `Port ${port}/${proto} is open running ${service.trim()}`,
      evidence: match[0],
      reproduction: [`nmap -sV -p ${port} ${task.target}`],
      remediation: 'Review if this service should be publicly exposed. Close unnecessary ports.',
      references: [],
      needsManualReview: false,
      discoveredAt: new Date().toISOString(),
    });
  }

  // Detect potentially dangerous services
  const dangerousServices = ['mysql', 'postgres', 'redis', 'mongodb', 'memcached', 'elasticsearch', 'ftp'];
  for (const f of findings) {
    const lower = f.description.toLowerCase();
    if (dangerousServices.some(s => lower.includes(s))) {
      f.severity = 'high';
      f.title = `[HIGH] Exposed database/service: ${f.title}`;
      f.remediation = 'This service should NOT be publicly accessible. Restrict with firewall rules.';
      f.needsManualReview = true;
    }
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
      findings.push({
        id: makeFindingId('nuclei', item.host || task.target, item['template-id'] || ''),
        checkId: `nuclei-${item['template-id'] || 'unknown'}`,
        title: item.info?.name || item['template-id'] || 'Nuclei finding',
        severity: ['info', 'low', 'medium', 'high', 'critical'].includes(severity) ? severity : 'info',
        target: item.host || item.matched || task.target,
        description: item.info?.description || `Nuclei template ${item['template-id']} matched`,
        evidence: item.matched || item['curl-command'] || line.slice(0, 500),
        reproduction: item['curl-command'] ? [item['curl-command']] : [`nuclei -u ${task.target} -t ${item['template-id']}`],
        remediation: item.info?.remediation || 'See references for remediation guidance.',
        cwe: item.info?.classification?.['cwe-id']?.[0] || undefined,
        references: item.info?.reference || [],
        needsManualReview: severity === 'info' || severity === 'low',
        discoveredAt: new Date().toISOString(),
      });
    } catch {
      // Not JSON — skip
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
      // Flag interesting tech or status codes
      if (item.tech && item.tech.length > 0) {
        findings.push({
          id: makeFindingId('httpx-tech', item.url || task.target, item.tech.join(',')),
          checkId: 'httpx-tech-detect',
          title: `Tech detected: ${item.tech.join(', ')}`,
          severity: 'info',
          target: item.url || task.target,
          description: `Technologies detected: ${item.tech.join(', ')}. Status: ${item['status-code']}. Title: ${item.title || 'N/A'}`,
          evidence: JSON.stringify(item, null, 2).slice(0, 1000),
          reproduction: [`httpx -u ${item.url || task.target} -tech-detect`],
          remediation: 'Review detected technologies for known vulnerabilities.',
          references: [],
          needsManualReview: false,
          discoveredAt: new Date().toISOString(),
        });
      }
    } catch {
      // Not JSON
    }
  }
  return findings;
}

function parseSubfinderOutput(stdout, task) {
  const subdomains = stdout.split('\n').filter(l => l.trim());
  if (subdomains.length === 0) return [];
  return [{
    id: makeFindingId('subfinder-enum', task.target, `${subdomains.length}-subs`),
    checkId: 'subfinder-enumeration',
    title: `${subdomains.length} subdomains discovered for ${task.target}`,
    severity: 'info',
    target: task.target,
    description: `Subdomain enumeration found ${subdomains.length} hosts:\n${subdomains.slice(0, 50).join('\n')}${subdomains.length > 50 ? '\n... (truncated)' : ''}`,
    evidence: subdomains.slice(0, 20).join(', '),
    reproduction: [`subfinder -d ${task.target} -silent`],
    remediation: 'Review all subdomains for unauthorized services or takeover opportunities.',
    references: [],
    needsManualReview: true,
    discoveredAt: new Date().toISOString(),
  }];
}

function parseKatanaOutput(stdout, task) {
  const urls = stdout.split('\n').filter(l => l.trim());
  if (urls.length === 0) return [];

  const findings = [];
  // Flag interesting endpoints (params, API paths, admin)
  const interesting = urls.filter(u =>
    u.includes('?') || u.includes('/api/') || u.includes('/admin') ||
    u.includes('/graphql') || u.includes('.json') || u.includes('/debug')
  );

  if (interesting.length > 0) {
    findings.push({
      id: makeFindingId('katana-interesting', task.target, `${interesting.length}-endpoints`),
      checkId: 'katana-endpoint-discovery',
      title: `${interesting.length} interesting endpoints discovered on ${task.target}`,
      severity: 'low',
      target: task.target,
      description: `Crawling found ${urls.length} total URLs, ${interesting.length} with parameters/API paths:\n${interesting.slice(0, 30).join('\n')}`,
      evidence: interesting.slice(0, 10).join('\n'),
      reproduction: [`katana -u ${task.target} -d 3 -jc`],
      remediation: 'Review discovered endpoints for authorization issues, parameter injection, and information disclosure.',
      references: [],
      needsManualReview: true,
      discoveredAt: new Date().toISOString(),
    });
  }

  return findings;
}

function parseFfufOutput(stdout, task) {
  const findings = [];
  try {
    const data = JSON.parse(stdout);
    const results = data.results || [];
    for (const r of results) {
      if (r.status === 200 || r.status === 301 || r.status === 403) {
        findings.push({
          id: makeFindingId('ffuf-dir', task.target, r.input?.FUZZ || r.url),
          checkId: 'ffuf-directory',
          title: `Hidden path found: ${r.input?.FUZZ || r.url} (${r.status})`,
          severity: r.status === 403 ? 'low' : 'medium',
          target: r.url || task.target,
          description: `Directory/file discovered: ${r.url} — Status: ${r.status}, Size: ${r.length} bytes`,
          evidence: `URL: ${r.url}\nStatus: ${r.status}\nSize: ${r.length}\nWords: ${r.words}`,
          reproduction: [`curl -s -o /dev/null -w "%{http_code}" ${r.url}`],
          remediation: 'Review if this path should be publicly accessible. Restrict or remove if unnecessary.',
          references: [],
          needsManualReview: true,
          discoveredAt: new Date().toISOString(),
        });
      }
    }
  } catch {
    // Non-JSON output — parse line by line
    for (const line of stdout.split('\n')) {
      const match = line.match(/(\S+)\s+\[Status:\s*(\d+)/);
      if (match) {
        findings.push({
          id: makeFindingId('ffuf-dir', task.target, match[1]),
          checkId: 'ffuf-directory',
          title: `Path found: ${match[1]} (${match[2]})`,
          severity: 'low',
          target: task.target,
          description: line.trim(),
          evidence: line.trim(),
          reproduction: [`curl -s ${task.target}/${match[1]}`],
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
  // Look for confirmed injection
  if (stdout.includes('is vulnerable') || stdout.includes('injectable')) {
    findings.push({
      id: makeFindingId('sqlmap-sqli', task.target, 'confirmed'),
      checkId: 'sqlmap-injection',
      title: `[CRITICAL] SQL Injection confirmed on ${task.target}`,
      severity: 'critical',
      target: task.target,
      description: 'sqlmap confirmed SQL injection vulnerability.',
      evidence: stdout.slice(stdout.indexOf('is vulnerable'), stdout.indexOf('is vulnerable') + 500),
      reproduction: [`sqlmap -u "${task.target}" --batch --level=1`],
      remediation: 'Use parameterized queries / prepared statements. Never concatenate user input into SQL.',
      cwe: 'CWE-89',
      references: ['https://owasp.org/www-community/attacks/SQL_Injection'],
      needsManualReview: false,
      confidence: 0.95,
      evidenceGrade: 'tool-confirmed',
      submitReady: true,
      source: 'sqlmap',
      discoveredAt: new Date().toISOString(),
    });
  }
  // Look for parameter identification
  const paramMatch = stdout.match(/Parameter:\s+(.+?)(?:\s+\(|$)/gm);
  if (paramMatch && !findings.length) {
    findings.push({
      id: makeFindingId('sqlmap-param', task.target, paramMatch[0]),
      checkId: 'sqlmap-parameter',
      title: `Potential SQLi parameter identified: ${paramMatch[0]}`,
      severity: 'medium',
      target: task.target,
      description: `sqlmap identified potentially injectable parameters: ${paramMatch.join(', ')}`,
      evidence: paramMatch.join('\n'),
      reproduction: [`sqlmap -u "${task.target}" --batch`],
      remediation: 'Investigate and apply parameterized queries.',
      cwe: 'CWE-89',
      references: ['https://owasp.org/www-community/attacks/SQL_Injection'],
      needsManualReview: true,
      discoveredAt: new Date().toISOString(),
    });
  }
  return findings;
}

function parseGobusterOutput(stdout, task) {
  const findings = [];
  for (const line of stdout.split('\n')) {
    const match = line.match(/^\/(\S+)\s+\(Status:\s*(\d+)\)/);
    if (match) {
      const [, path, status] = match;
      findings.push({
        id: makeFindingId('gobuster-dir', task.target, path),
        checkId: 'gobuster-directory',
        title: `Directory found: /${path} (${status})`,
        severity: status === '200' ? 'medium' : 'low',
        target: `${task.target}/${path}`,
        description: `Gobuster discovered /${path} with status ${status}`,
        evidence: line.trim(),
        reproduction: [`curl -s -o /dev/null -w "%{http_code}" ${task.target}/${path}`],
        remediation: 'Review if this directory should be publicly accessible.',
        references: [],
        needsManualReview: true,
        discoveredAt: new Date().toISOString(),
      });
    }
  }
  return findings;
}

// ─── Poll Loop ───────────────────────────────────────────────────────────────

async function pollForTasks() {
  try {
    const headers = { 'content-type': 'application/json' };
    if (EXECUTOR_SECRET) headers['x-executor-secret'] = EXECUTOR_SECRET;

    const res = await fetch(`${C2_URL}/api/tasks/poll`, { headers });
    if (!res.ok) {
      console.error(`[POLL] C2 returned ${res.status}: ${await res.text()}`);
      return;
    }

    const { tasks } = await res.json();
    if (!tasks || tasks.length === 0) return;

    console.log(`[POLL] Got ${tasks.length} task(s)`);

    for (const task of tasks) {
      if (running >= MAX_CONCURRENT) {
        console.log(`[THROTTLE] At max concurrency (${MAX_CONCURRENT}), re-queuing...`);
        break;
      }
      running++;
      executeTask(task).then(async (result) => {
        // Report back to C2
        try {
          const completeRes = await fetch(`${C2_URL}/api/tasks/complete`, {
            method: 'POST',
            headers,
            body: JSON.stringify({ taskId: task.id, result }),
          });
          if (!completeRes.ok) {
            console.error(`[REPORT] Failed to report task ${task.id}: ${completeRes.status}`);
          } else {
            console.log(`[REPORT] Task ${task.id} reported — ${result.findings.length} findings`);
          }
        } catch (err) {
          console.error(`[REPORT] Network error reporting task ${task.id}: ${err.message}`);
        }
        running--;
      }).catch((err) => {
        console.error(`[FATAL] Task ${task.id} crashed: ${err.message}`);
        running--;
      });
    }
  } catch (err) {
    console.error(`[POLL] Error: ${err.message}`);
  }
}

// ─── Main ────────────────────────────────────────────────────────────────────

console.log(`
╔═══════════════════════════════════════════════════════════════╗
║  StormForge Executor v1.0                                     ║
║  C2: ${C2_URL.padEnd(54)}║
║  Poll interval: ${String(POLL_INTERVAL_MS).padEnd(44)}ms ║
║  Max concurrent: ${String(MAX_CONCURRENT).padEnd(43)}║
║  AUTHORIZED TARGETS ONLY                                      ║
╚═══════════════════════════════════════════════════════════════╝
`);

// Verify tools are available
const toolChecks = Object.entries(TOOLS).map(async ([name, def]) => {
  try {
    await execFileAsync('which', [def.bin]);
    console.log(`  ✓ ${name} (${def.bin})`);
    return true;
  } catch {
    console.warn(`  ✗ ${name} (${def.bin}) — NOT INSTALLED`);
    return false;
  }
});

Promise.all(toolChecks).then((results) => {
  const available = results.filter(Boolean).length;
  console.log(`\n  ${available}/${Object.keys(TOOLS).length} tools available.\n`);
  if (available === 0) {
    console.error('  No tools installed. Install at least one tool to proceed.');
    console.error('  See: executor/INSTALL.md');
    process.exit(1);
  }
  console.log('  Starting poll loop...\n');
  setInterval(pollForTasks, POLL_INTERVAL_MS);
  pollForTasks(); // First poll immediately
});
