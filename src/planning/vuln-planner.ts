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
import { nucleiArgsForTech, productsFromFindingText } from './tech-templates.js';
import { parseSubdomains, rankSubdomains } from '../recon/subdomain-intel.js';

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

  // Phase 8: sqlmap on parameterized seed URLs
  for (const target of targets) {
    if (!/[?&]\w+=/.test(target)) continue;
    tasks.push({
      tool: 'sqlmap',
      target: normalizeUrl(target),
      args: { flags: '--batch --level=1 --risk=1 --random-agent --technique=BEUST' },
      timeoutSec: 300,
      rationale: `SQL injection detection on parameterized URL ${target}`,
    });
  }

  return {
    tasks,
    rationale:
      'Autonomous heuristic plan: recon → enumerate → scan → fuzz → sqlmap on params. Covers OWASP Top 10 surface.',
    source: 'heuristic',
  };
}

/**
 * Finding-driven follow-up planner — the autonomy core.
 * Maps passive/executor findings into the next wave of scoped tool tasks
 * (sqlmap on param URLs, nuclei on high findings, httpx on new hosts, etc.).
 */
export function planFollowUpTasks(
  findings: Array<{
    checkId: string;
    severity: string;
    target: string;
    title: string;
    evidence?: string;
  }>,
  scope: Scope,
  opts: { scanId?: string; maxTasks?: number } = {},
): AttackPlan {
  const tasks: PlannedTask[] = [];
  const seen = new Set<string>();
  const maxTasks = opts.maxTasks ?? 15;

  const push = (t: PlannedTask) => {
    const key = `${t.tool}|${t.target}|${JSON.stringify(t.args)}`;
    if (seen.has(key)) return;
    if (!isTargetInScope(t.target, scope) && t.tool !== 'subfinder') return;
    // subfinder targets are bare domains
    if (t.tool === 'subfinder' && !isDomainAllowed(t.target, scope)) return;
    seen.add(key);
    tasks.push(t);
  };

  const ordered = [...findings].sort((a, b) => {
    const rank = (s: string) =>
      ({ info: 0, low: 1, medium: 2, high: 3, critical: 4 } as Record<string, number>)[s] ?? 0;
    return rank(b.severity) - rank(a.severity);
  });

  for (const f of ordered) {
    if (tasks.length >= maxTasks) break;
    const target = f.target;
    if (!target) continue;

    // Parameterized URLs → sqlmap
    if (/[?&]\w+=/.test(target) || /injection|xss|ssrf|sql|command/i.test(f.checkId + f.title)) {
      if (/[?&]\w+=/.test(target)) {
        push({
          tool: 'sqlmap',
          target,
          args: { flags: '--batch --level=2 --risk=1 --random-agent' },
          timeoutSec: 360,
          rationale: `Follow-up SQLi probe from finding ${f.checkId}: ${f.title}`,
        });
      }
    }

    // High/critical web findings → focused nuclei (tech-tagged when possible)
    if (f.severity === 'critical' || f.severity === 'high') {
      const products = productsFromFindingText(f.title, f.evidence, f.checkId);
      const tech = nucleiArgsForTech(products);
      push({
        tool: 'nuclei',
        target,
        args: {
          flags: tech.flags,
          templates: tech.templates,
        },
        timeoutSec: 420,
        rationale: `Nuclei deep-scan after ${f.severity} finding (${f.checkId})`,
      });
    }

    // httpx tech detect → product-tagged nuclei
    if (/httpx-tech|version-cve|fingerprint/i.test(f.checkId)) {
      const products = productsFromFindingText(f.title, f.evidence);
      if (products.length) {
        const tech = nucleiArgsForTech(products);
        push({
          tool: 'nuclei',
          target,
          args: {
            flags: tech.flags,
            templates: tech.templates,
          },
          timeoutSec: 420,
          rationale: `Tech-tagged nuclei for ${products.slice(0, 4).join(', ')}`,
        });
      }
    }

    // GraphQL / schema → katana + nuclei
    if (/graphql|api-schema|swagger|openapi|robots-disclosure|sourcemap/i.test(f.checkId)) {
      push({
        tool: 'katana',
        target,
        args: { flags: '-silent -d 2 -jc' },
        timeoutSec: 120,
        rationale: `Crawl API/GraphQL surface from ${f.checkId}`,
      });
    }

    // JSONP → nuclei exposures around the same origin
    if (/jsonp-callback/i.test(f.checkId)) {
      push({
        tool: 'nuclei',
        target,
        args: {
          flags: '-severity critical,high,medium -silent -c 20',
          templates: 'exposures,misconfiguration,vulnerabilities',
        },
        timeoutSec: 300,
        rationale: `Nuclei after confirmed JSONP on ${target}`,
      });
    }

    // Secrets / exposed files / buckets → gobuster nearby
    if (/secret|exposed-files|git|env|cloud-bucket/i.test(f.checkId + f.title)) {
      const base = originOf(target);
      if (base) {
        push({
          tool: 'gobuster',
          target: base,
          args: {
            mode: 'dir',
            flags: '-q --no-error -t 15',
            wordlist: '/usr/share/wordlists/dirb/common.txt',
          },
          timeoutSec: 240,
          rationale: `Dirbust after secret/exposure finding on ${base}`,
        });
      }
    }

    // SQLi / CRLF / PP / HPP → prefer sqlmap + nuclei
    if (/sql-injection|crlf-header|prototype-pollution|http-parameter-pollution/i.test(f.checkId)) {
      if (/[?&]\w+=/.test(target)) {
        push({
          tool: 'sqlmap',
          target,
          args: { flags: '--batch --level=3 --risk=1 --random-agent' },
          timeoutSec: 420,
          rationale: `Deepen injection finding ${f.checkId} with sqlmap`,
        });
      }
    }

    // Weak JWT / OAuth → nuclei exposures + crawl auth surface
    if (/weak-jwt|oauth/i.test(f.checkId)) {
      push({
        tool: 'nuclei',
        target,
        args: {
          flags: '-severity critical,high,medium -silent -c 20',
          templates: 'exposures,token-spray,misconfiguration',
        },
        timeoutSec: 360,
        rationale: `Nuclei exposures after ${f.checkId}`,
      });
      push({
        tool: 'katana',
        target,
        args: { flags: '-silent -d 2 -jc' },
        timeoutSec: 120,
        rationale: `Crawl auth surface after ${f.checkId}`,
      });
    }

    // Cache deception / poisoning / host-header → nuclei misconfiguration
    if (/cache-deception|cache-poisoning|host-header/i.test(f.checkId)) {
      push({
        tool: 'nuclei',
        target,
        args: {
          flags: '-silent -c 20',
          templates: 'misconfiguration,vulnerabilities',
        },
        timeoutSec: 360,
        rationale: `Nuclei misconfiguration after ${f.checkId}`,
      });
    }

    // Auth differential / horizontal IDOR → ffuf neighbor IDs + httpx
    if (/auth-differential|auth-access/i.test(f.checkId)) {
      const base = originOf(target);
      if (base) {
        push({
          tool: 'ffuf',
          target: target.includes('/users/')
            ? target.replace(/\/users\/\d+/, '/users/FUZZ')
            : `${base}/api/v1/users/FUZZ`,
          args: {
            flags: '-mc 200 -t 10 -s',
            wordlist: '1,2,3,4,5,10,100',
          },
          timeoutSec: 180,
          rationale: `Neighbor ID fuzz after ${f.checkId}`,
        });
      }
      push({
        tool: 'httpx',
        target,
        args: { flags: '-silent -status-code -title -tech-detect' },
        timeoutSec: 60,
        rationale: `Re-fingerprint auth surface after ${f.checkId}`,
      });
    }

    // Subdomain enum / takeover → ranked httpx + takeover nuclei
    if (/subdomain-takeover|subfinder|recon-subfinder/i.test(f.checkId)) {
      const hostTarget = extractHost(f.target);
      const parts = hostTarget.split('.');
      const apex = parts.length >= 2 ? parts.slice(-2).join('.') : hostTarget;
      const hosts = rankSubdomains(
        parseSubdomains(`${f.target}\n${f.evidence ?? ''}`, apex),
        6,
      );
      for (const host of hosts) {
        if (tasks.length >= maxTasks) break;
        if (!isDomainAllowed(host, scope)) continue;
        push({
          tool: 'httpx',
          target: `https://${host}`,
          args: { flags: '-silent -status-code -title -tech-detect' },
          timeoutSec: 60,
          rationale: `Ranked subdomain probe (${host}) from ${f.checkId}`,
        });
        push({
          tool: 'nuclei',
          target: `https://${host}`,
          args: {
            flags: '-silent -c 20',
            templates: 'http/takeovers,takeovers',
          },
          timeoutSec: 240,
          rationale: `Takeover templates for ranked host ${host}`,
        });
      }
      // Also keep a takeover pass on the original target when it is a URL/host.
      if (/^https?:\/\//i.test(target) || target.includes('.')) {
        push({
          tool: 'nuclei',
          target: target.includes('://') ? target : `https://${target}`,
          args: {
            flags: '-silent -c 20',
            templates: 'http/takeovers,takeovers',
          },
          timeoutSec: 300,
          rationale: `Nuclei takeover templates after ${f.checkId}`,
        });
      }
    }

    // New hostnames in evidence → httpx (skip if already handled by subdomain ranking)
    if (!/subfinder|recon-subfinder/i.test(f.checkId)) {
      const hosts = extractHostsFromText(`${f.target}\n${f.evidence ?? ''}`);
      for (const host of hosts) {
        if (tasks.length >= maxTasks) break;
        push({
          tool: 'httpx',
          target: `https://${host}`,
          args: { flags: '-silent -status-code -title -tech-detect' },
          timeoutSec: 60,
          rationale: `Probe host discovered via finding ${f.checkId}`,
        });
      }
    }
  }

  return {
    tasks: tasks.slice(0, maxTasks),
    rationale: `Autonomous follow-up wave from ${findings.length} finding(s) → ${Math.min(tasks.length, maxTasks)} tasks`,
    source: 'heuristic',
  };
}

function isDomainAllowed(domain: string, scope: Scope): boolean {
  const d = domain.toLowerCase();
  for (const oos of scope.outOfScope) {
    if (d === oos.toLowerCase() || (oos.startsWith('*.') && d.endsWith(oos.slice(1)))) return false;
  }
  for (const pattern of scope.inScope) {
    const p = pattern.toLowerCase();
    if (p === d) return true;
    if (p.startsWith('*.') && (d === p.slice(2) || d.endsWith(p.slice(1)))) return true;
    if (!p.startsWith('*.') && d.endsWith(`.${p}`)) return true;
  }
  return false;
}

function originOf(target: string): string | null {
  try {
    const u = new URL(target.includes('://') ? target : `https://${target}`);
    return u.origin;
  } catch {
    return null;
  }
}

function extractHostsFromText(text: string): string[] {
  const out = new Set<string>();
  const re = /\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)\b/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const h = m[1].toLowerCase();
    if (h.includes('.') && !h.endsWith('.example') && !h.endsWith('.local')) out.add(h);
  }
  return [...out].slice(0, 10);
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
