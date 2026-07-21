// Vulnerability-focused attack surface planner.
//
// Generates prioritized ToolTasks for the remote executor. Uses an LLM when
// available; otherwise a deterministic heuristic. Never executes tools itself.
// AUTHORIZED + IN-SCOPE targets only (shared scope-guard).

import type { Env, Finding, Scope, ToolName } from '../types.js';
import { evaluateScope } from '../scope/scope-guard.js';

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
  source: 'llm' | 'heuristic' | 'evolved';
}

const ALLOWED_TOOLS: ReadonlySet<ToolName> = new Set([
  'nmap',
  'nuclei',
  'httpx',
  'subfinder',
  'katana',
  'ffuf',
  'sqlmap',
  'gobuster',
]);

const VULN_PLANNER_SYSTEM = `You plan AUTHORIZED bug-bounty executor tasks. High signal only.

Tools: nmap, nuclei, httpx, subfinder, katana, ffuf, sqlmap, gobuster.

Rules:
- Only in-scope targets from the user payload.
- Prefer: subfinder → httpx → katana → nuclei (tech-tagged) → ffuf/gobuster → sqlmap only on URLs with query params.
- nuclei args.templates: comma tags like cves,misconfiguration,exposures,wordpress,graphql — never invent hosts.
- Max 12 tasks. No destructive sqlmap flags (--dump, --os-shell).
- JSON only: {"tasks":[{"tool","target","args","timeoutSec","rationale"}],"rationale":"..."}`;

/** Product → nuclei template tags (tight pack). */
const TECH_NUCLEI: Record<string, string> = {
  wordpress: 'wordpress,wp-plugin,cves',
  php: 'php,cves,vulnerabilities',
  nginx: 'nginx,misconfiguration,cves',
  apache: 'apache,misconfiguration,cves',
  express: 'nodejs,misconfiguration,exposures',
  graphql: 'graphql,exposures',
  swagger: 'swagger,exposures,misconfiguration',
  django: 'django,cves,misconfiguration',
  spring: 'springboot,cves,misconfiguration',
};

export async function planAttackSurface(
  targets: string[],
  scope: Scope,
  env: Env,
  opts?: { findings?: Finding[] },
): Promise<AttackPlan> {
  if (!scope.authorized) {
    return { tasks: [], rationale: 'REFUSED: scope.authorized is false', source: 'heuristic' };
  }

  const inScopeTargets = targets.filter((t) => evaluateScope(t, scope).allowed);
  if (!inScopeTargets.length) {
    return { tasks: [], rationale: 'REFUSED: no in-scope targets', source: 'heuristic' };
  }

  // Finding-driven follow-ups first when we have prior results.
  if (opts?.findings?.length) {
    const evolved = planFromFindings(opts.findings, scope);
    if (evolved.tasks.length) return evolved;
  }

  if (env.LLM_PLANNER_ENDPOINT && env.LLM_PLANNER_API_KEY) {
    try {
      return await llmPlan(inScopeTargets, scope, env, opts?.findings);
    } catch {
      // Fall through
    }
  }
  return heuristicAttackPlan(inScopeTargets, scope);
}

async function llmPlan(
  targets: string[],
  scope: Scope,
  env: Env,
  findings?: Finding[],
): Promise<AttackPlan> {
  const model = env.LLM_PLANNER_MODEL || 'grok-4';
  const isGrok = env.LLM_PLANNER_ENDPOINT.includes('x.ai') || model.toLowerCase().includes('grok');

  const surface = summarizeForPlanner(targets, findings);
  const res = await fetch(env.LLM_PLANNER_ENDPOINT, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${env.LLM_PLANNER_API_KEY}`,
    },
    body: JSON.stringify({
      model,
      messages: [
        { role: 'system', content: VULN_PLANNER_SYSTEM },
        {
          role: 'user',
          content: JSON.stringify({
            targets,
            scope: {
              program: scope.program,
              inScope: scope.inScope,
              outOfScope: scope.outOfScope,
              authorized: true,
            },
            surface,
          }),
        },
      ],
      temperature: 0.2,
      max_tokens: 1200,
      ...(isGrok ? {} : { response_format: { type: 'json_object' } }),
    }),
    signal: AbortSignal.timeout(20_000),
  });

  if (!res.ok) throw new Error(`LLM returned ${res.status}`);

  const data = (await res.json()) as { choices?: { message?: { content?: string } }[] };
  const content = data.choices?.[0]?.message?.content ?? '{}';
  const parsed = safeJson(content) as { tasks?: PlannedTask[]; rationale?: string };

  if (!parsed.tasks?.length) throw new Error('No tasks from LLM');

  const validTasks = sanitizeTasks(parsed.tasks, scope).slice(0, 12);
  if (!validTasks.length) throw new Error('No in-scope LLM tasks');

  return {
    tasks: validTasks,
    rationale: parsed.rationale || 'LLM-generated attack plan',
    source: 'llm',
  };
}

/** Deterministic attack plan covering standard recon → scan methodology. */
export function heuristicAttackPlan(targets: string[], scope: Scope): AttackPlan {
  const tasks: PlannedTask[] = [];
  const domains = extractDomains(targets, scope);

  for (const domain of domains) {
    tasks.push({
      tool: 'subfinder',
      target: domain,
      args: { flags: '-silent' },
      timeoutSec: 120,
      rationale: `Enumerate subdomains of ${domain}`,
    });
  }

  for (const target of targets) {
    tasks.push({
      tool: 'httpx',
      target,
      args: { flags: '-silent -status-code -title -tech-detect -follow-redirects' },
      timeoutSec: 60,
      rationale: `Probe ${target} for live HTTP + tech`,
    });
  }

  for (const target of targets) {
    tasks.push({
      tool: 'katana',
      target,
      args: { flags: '-silent -d 2 -jc -kf -ef css,png,jpg,gif,svg,woff,ttf' },
      timeoutSec: 180,
      rationale: `Crawl ${target} for endpoints/params`,
    });
  }

  for (const target of targets) {
    tasks.push({
      tool: 'nuclei',
      target,
      args: {
        flags: '-severity critical,high,medium -silent -c 25',
        templates: 'cves,vulnerabilities,misconfiguration,exposures',
      },
      timeoutSec: 420,
      rationale: `Nuclei known-issue pack on ${target}`,
    });
  }

  for (const target of targets) {
    tasks.push({
      tool: 'ffuf',
      target: `${normalizeUrl(target)}/FUZZ`,
      args: {
        flags: '-mc 200,301,302,403 -t 20 -ac',
        wordlist: '/usr/share/wordlists/dirb/common.txt',
      },
      timeoutSec: 180,
      rationale: `Fuzz hidden paths on ${target}`,
    });
  }

  // sqlmap only when seed already has query params
  for (const target of targets) {
    if (!/[?&]\w+=/.test(target)) continue;
    tasks.push({
      tool: 'sqlmap',
      target,
      args: { flags: '--batch --level=1 --risk=1 --random-agent --technique=BEUST' },
      timeoutSec: 300,
      rationale: `SQLi detection-only on parameterized URL ${target}`,
    });
  }

  return {
    tasks: sanitizeTasks(tasks, scope),
    rationale: 'Heuristic: subfinder → httpx → katana → nuclei → ffuf (+ sqlmap if params).',
    source: 'heuristic',
  };
}

/**
 * Turn prior findings into the next high-leverage executor tasks
 * (tech-tagged nuclei, katana on APIs, sqlmap on params).
 */
export function planFromFindings(findings: Finding[], scope: Scope): AttackPlan {
  const tasks: PlannedTask[] = [];
  const seen = new Set<string>();

  const push = (t: PlannedTask) => {
    if (!evaluateScope(t.target, scope).allowed) return;
    const key = `${t.tool}|${t.target}|${t.args.templates ?? ''}`;
    if (seen.has(key)) return;
    seen.add(key);
    tasks.push(t);
  };

  const ordered = [...findings].sort(
    (a, b) => (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0),
  );

  for (const f of ordered) {
    if (tasks.length >= 12) break;
    const target = f.target;
    if (!target) continue;

    if (/httpx-tech|version-cve|fingerprint/i.test(f.checkId)) {
      const templates = nucleiTemplatesFromText(`${f.title}\n${f.evidence}`);
      push({
        tool: 'nuclei',
        target,
        args: {
          flags: '-severity critical,high,medium -silent -c 25',
          templates,
        },
        timeoutSec: 420,
        rationale: `Tech-tagged nuclei after ${f.checkId}`,
      });
    }

    if (/graphql|api-schema|swagger|openapi|katana/i.test(f.checkId)) {
      push({
        tool: 'katana',
        target,
        args: { flags: '-silent -d 2 -jc' },
        timeoutSec: 120,
        rationale: `Crawl API surface from ${f.checkId}`,
      });
      push({
        tool: 'nuclei',
        target,
        args: {
          flags: '-severity critical,high,medium -silent -c 20',
          templates: 'exposures,misconfiguration,graphql,swagger',
        },
        timeoutSec: 360,
        rationale: `Nuclei exposures on schema/API surface`,
      });
    }

    if (/[?&]\w+=/.test(target) || /sql|injection|xss|ssrf/i.test(f.checkId + f.title)) {
      if (/[?&]\w+=/.test(target)) {
        push({
          tool: 'sqlmap',
          target,
          args: { flags: '--batch --level=2 --risk=1 --random-agent' },
          timeoutSec: 360,
          rationale: `sqlmap follow-up from ${f.checkId}`,
        });
      }
    }

    if (/secret|exposed|bucket|git|env/i.test(f.checkId + f.title)) {
      const origin = originOf(target);
      if (origin) {
        push({
          tool: 'ffuf',
          target: `${origin}/FUZZ`,
          args: {
            flags: '-mc 200,301,302,403 -t 20 -ac',
            wordlist: '/usr/share/wordlists/dirb/common.txt',
          },
          timeoutSec: 180,
          rationale: `Fuzz near disclosure from ${f.checkId}`,
        });
      }
    }
  }

  return {
    tasks: sanitizeTasks(tasks, scope).slice(0, 12),
    rationale: `Evolved plan from ${findings.length} finding(s)`,
    source: 'evolved',
  };
}

export function nucleiTemplatesFromText(text: string): string {
  const lower = text.toLowerCase();
  const tags = new Set<string>(['cves', 'vulnerabilities', 'misconfiguration']);
  for (const [product, pack] of Object.entries(TECH_NUCLEI)) {
    if (lower.includes(product)) {
      for (const t of pack.split(',')) tags.add(t);
    }
  }
  return [...tags].slice(0, 8).join(',');
}

export function sanitizeTasks(tasks: PlannedTask[], scope: Scope): PlannedTask[] {
  const out: PlannedTask[] = [];
  for (const t of tasks) {
    if (!ALLOWED_TOOLS.has(t.tool)) continue;
    if (!t.target || typeof t.target !== 'string') continue;
    if (!evaluateScope(t.target, scope).allowed) continue;
    if (t.tool === 'sqlmap') {
      // Refuse destructive flags
      const flags = (t.args.flags || '').toLowerCase();
      if (/--dump|--os-shell|--sql-shell|--file-write|--priv-esc/.test(flags)) continue;
      if (!/[?&]\w+=/.test(t.target) && !flags.includes('-p ')) {
        // Prefer parameterized URLs only
        continue;
      }
    }
    out.push({
      tool: t.tool,
      target: t.target,
      args: t.args || {},
      timeoutSec: clampTimeout(t.timeoutSec),
      rationale: t.rationale || `${t.tool} on ${t.target}`,
    });
  }
  return out;
}

const SEVERITY_RANK: Record<string, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

function summarizeForPlanner(targets: string[], findings?: Finding[]) {
  const top = (findings || [])
    .slice(0, 15)
    .map((f) => ({ checkId: f.checkId, severity: f.severity, target: f.target, title: f.title }));
  return { targetCount: targets.length, findings: top };
}

function extractDomains(targets: string[], scope: Scope): string[] {
  const domains = new Set<string>();
  for (const pattern of scope.inScope) {
    if (pattern.startsWith('*.')) domains.add(pattern.slice(2));
  }
  for (const t of targets) {
    const host = extractHost(t);
    const parts = host.split('.');
    if (parts.length >= 2) domains.add(parts.slice(-2).join('.'));
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

function originOf(target: string): string | null {
  try {
    const raw = target.includes('://') ? target : `https://${target}`;
    return new URL(raw).origin;
  } catch {
    return null;
  }
}

function clampTimeout(n: number | undefined): number {
  if (!n || !Number.isFinite(n)) return 300;
  return Math.max(30, Math.min(600, Math.floor(n)));
}

function safeJson(text: string): unknown {
  try {
    // Strip markdown fences if Grok wraps JSON
    const cleaned = text.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/i, '');
    return JSON.parse(cleaned);
  } catch {
    return {};
  }
}
