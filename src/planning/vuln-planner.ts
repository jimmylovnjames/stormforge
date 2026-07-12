// Vulnerability-focused attack surface planner.
//
// This module takes authorized targets and generates a prioritized list of
// ToolTasks for the remote executor. It uses an LLM when available, otherwise
// falls back to a deterministic heuristic that covers the OWASP Top 10 and
// common bug-bounty patterns.
//
// IMPORTANT: This planner only generates tasks for AUTHORIZED, IN-SCOPE targets.
// It does not execute anything — execution is the executor's job.

import type { Env, Scope, ToolName } from '../types.js';

export interface PlannedTask {
  tool: ToolName;
  target: string;
  args: Record<string, string>;
  timeoutSec: number;
  rationale: string;
}

export interface AttackPlan {
  tasks: PlannedTask[];
  rationale: string;
  source: 'llm' | 'heuristic';
}

const VULN_PLANNER_SYSTEM = `You are an expert bug-bounty attack surface planner for AUTHORIZED penetration testing.
Given a list of in-scope targets and scope definition, generate a prioritized list of tool execution tasks.

Available tools: nmap, nuclei, httpx, subfinder, katana, ffuf, sqlmap, gobuster

For each task, specify:
- tool: one of the available tools
- target: the specific host/URL to test (MUST be in the provided scope)
- args: tool-specific arguments as key-value pairs
- timeoutSec: max execution time (60-600)
- rationale: why this task matters

Prioritize by likelihood of finding real vulns:
1. Subdomain enumeration (subfinder) — expand attack surface
2. HTTP probing (httpx) — identify live services and tech stack
3. Port scanning (nmap) — find non-standard services
4. Web crawling (katana) — discover endpoints and parameters
5. Directory bruteforce (gobuster/ffuf) — find hidden paths
6. Nuclei templates — known CVEs and misconfigs
7. SQL injection (sqlmap) — only on endpoints with parameters

NEVER suggest testing targets outside the provided scope.
Respond as JSON: {"tasks": [...], "rationale": "..."}`;

export async function planAttackSurface(
  targets: string[],
  scope: Scope,
  env: Env,
): Promise<AttackPlan> {
  if (env.LLM_PLANNER_ENDPOINT && env.LLM_PLANNER_API_KEY) {
    try {
      return await llmPlan(targets, scope, env);
    } catch {
      // Fall through to heuristic
    }
  }
  return heuristicAttackPlan(targets, scope);
}

async function llmPlan(targets: string[], scope: Scope, env: Env): Promise<AttackPlan> {
  const res = await fetch(env.LLM_PLANNER_ENDPOINT, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${env.LLM_PLANNER_API_KEY}`,
    },
    body: JSON.stringify({
      model: env.LLM_PLANNER_MODEL || 'gpt-4o-mini',
      messages: [
        { role: 'system', content: VULN_PLANNER_SYSTEM },
        {
          role: 'user',
          content: JSON.stringify({
            targets,
            scope: { program: scope.program, inScope: scope.inScope, outOfScope: scope.outOfScope },
          }),
        },
      ],
      response_format: { type: 'json_object' },
      temperature: 0.3,
    }),
    signal: AbortSignal.timeout(20_000),
  });

  if (!res.ok) throw new Error(`LLM returned ${res.status}`);

  const data = (await res.json()) as { choices?: { message?: { content?: string } }[] };
  const content = data.choices?.[0]?.message?.content ?? '{}';
  const parsed = JSON.parse(content) as { tasks?: PlannedTask[]; rationale?: string };

  if (!parsed.tasks?.length) throw new Error('No tasks from LLM');

  // Validate all targets are in scope
  const validTasks = parsed.tasks.filter((t) => isTargetInScope(t.target, scope));

  return {
    tasks: validTasks.slice(0, 20),
    rationale: parsed.rationale || 'LLM-generated attack plan',
    source: 'llm',
  };
}

/** Deterministic attack plan covering standard recon → exploit methodology. */
function heuristicAttackPlan(targets: string[], scope: Scope): AttackPlan {
  const tasks: PlannedTask[] = [];

  // Extract base domains for subdomain enum
  const domains = extractDomains(targets, scope);

  // Phase 1: Subdomain enumeration on each wildcard domain
  for (const domain of domains) {
    tasks.push({
      tool: 'subfinder',
      target: domain,
      args: { flags: '-silent -all' },
      timeoutSec: 120,
      rationale: `Enumerate subdomains of ${domain} to expand attack surface`,
    });
  }

  // Phase 2: HTTP probing on all targets
  for (const target of targets) {
    tasks.push({
      tool: 'httpx',
      target,
      args: { flags: '-silent -status-code -title -tech-detect -follow-redirects' },
      timeoutSec: 60,
      rationale: `Probe ${target} for live HTTP services and tech fingerprinting`,
    });
  }

  // Phase 3: Port scan (top 1000 + common web ports)
  for (const target of targets) {
    const host = extractHost(target);
    tasks.push({
      tool: 'nmap',
      target: host,
      args: { flags: '-sV -sC --top-ports 1000 -T4 --open' },
      timeoutSec: 300,
      rationale: `Service detection on ${host} — find non-standard ports and versions`,
    });
  }

  // Phase 4: Web crawling for endpoint discovery
  for (const target of targets) {
    tasks.push({
      tool: 'katana',
      target,
      args: { flags: '-silent -d 3 -jc -kf -ef css,png,jpg,gif,svg,woff,ttf' },
      timeoutSec: 180,
      rationale: `Crawl ${target} for endpoints, JS files, and parameters`,
    });
  }

  // Phase 5: Directory bruteforce
  for (const target of targets) {
    tasks.push({
      tool: 'gobuster',
      target,
      args: {
        mode: 'dir',
        flags: '-q --no-error -t 20',
        wordlist: '/usr/share/wordlists/dirb/common.txt',
      },
      timeoutSec: 300,
      rationale: `Bruteforce directories on ${target} for hidden admin panels, backups, configs`,
    });
  }

  // Phase 6: Nuclei vulnerability scanning
  for (const target of targets) {
    tasks.push({
      tool: 'nuclei',
      target,
      args: {
        flags: '-severity critical,high,medium -silent -c 25',
        templates: 'cves,vulnerabilities,misconfiguration,exposed-panels,takeovers',
      },
      timeoutSec: 600,
      rationale: `Run Nuclei templates against ${target} for known CVEs, misconfigs, and takeovers`,
    });
  }

  // Phase 7: Fuzzing for hidden parameters (ffuf)
  for (const target of targets) {
    tasks.push({
      tool: 'ffuf',
      target: `${normalizeUrl(target)}/FUZZ`,
      args: {
        flags: '-mc 200,301,302,403 -t 20 -ac',
        wordlist: '/usr/share/wordlists/dirb/common.txt',
      },
      timeoutSec: 180,
      rationale: `Fuzz ${target} for hidden endpoints that may expose vulns`,
    });
  }

  return {
    tasks,
    rationale: 'Heuristic attack plan: recon → enumerate → scan → fuzz. Covers OWASP Top 10 surface.',
    source: 'heuristic',
  };
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function extractDomains(targets: string[], scope: Scope): string[] {
  const domains = new Set<string>();
  // Use wildcard scope entries as subdomain enum targets
  for (const pattern of scope.inScope) {
    if (pattern.startsWith('*.')) {
      domains.add(pattern.slice(2));
    }
  }
  // Also extract domains from explicit targets
  for (const t of targets) {
    const host = extractHost(t);
    // Get the registrable domain (simple: last two parts)
    const parts = host.split('.');
    if (parts.length >= 2) {
      domains.add(parts.slice(-2).join('.'));
    }
  }
  return [...domains];
}

function extractHost(target: string): string {
  try {
    const raw = target.includes('://') ? target : `https://${target}`;
    return new URL(raw).hostname;
  } catch {
    return target;
  }
}

function normalizeUrl(target: string): string {
  if (target.startsWith('http://') || target.startsWith('https://')) return target;
  return `https://${target}`;
}

function isTargetInScope(target: string, scope: Scope): boolean {
  const host = extractHost(target);
  for (const oos of scope.outOfScope) {
    if (host === oos.toLowerCase() || (oos.startsWith('*.') && host.endsWith(oos.slice(1)))) {
      return false;
    }
  }
  for (const pattern of scope.inScope) {
    const p = pattern.toLowerCase();
    if (p === host) return true;
    if (p.startsWith('*.') && host.endsWith(p.slice(1)) && host.length > p.length - 1) return true;
  }
  return false;
}
