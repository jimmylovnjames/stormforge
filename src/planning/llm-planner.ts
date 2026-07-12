// LLM Planner — upgraded for real vulnerability hunting.
//
// This module serves two roles:
// 1. Path prioritization for the passive scanner (existing)
// 2. Advisory input to the vuln-planner for active tool dispatch
//
// It NEVER generates exploits or executes anything. It suggests what to look at.

import type { Env, Finding, ProbeResult } from '../types.js';

export interface PlannerSuggestion {
  suggestedPaths: string[];
  rationale: string;
  source: 'llm' | 'heuristic';
}

const SYSTEM_PROMPT = `You are an expert bug-bounty recon planner for AUTHORIZED testing.
Given technology fingerprints, response patterns, and paths already probed, suggest:
1. Additional paths likely to expose vulnerabilities (IDOR, auth bypass, info disclosure)
2. Paths with parameters that may be injectable (SQLi, XSS, SSRF)
3. API endpoints that may lack proper authorization
4. Debug/admin paths specific to the detected tech stack

Focus on HIGH-IMPACT patterns:
- /api/v1/users/1 → /api/v1/users/2 (IDOR)
- /admin, /debug, /internal, /graphql (auth bypass)
- Endpoints returning JSON with user data (data exposure)
- File upload endpoints, password reset flows
- GraphQL introspection, Swagger/OpenAPI docs
- .env, .git, backup files (info disclosure)

Respond as JSON: {"paths": string[], "rationale": string, "vulnHints": string[]}
vulnHints should describe what vuln class each path group targets.`;

export async function planNextPaths(
  probes: ProbeResult[],
  env: Env,
): Promise<PlannerSuggestion> {
  const context = summarizeRecon(probes);

  if (!env.LLM_PLANNER_ENDPOINT || !env.LLM_PLANNER_API_KEY) {
    return heuristicPlan(context);
  }

  try {
    const res = await fetch(env.LLM_PLANNER_ENDPOINT, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${env.LLM_PLANNER_API_KEY}`,
      },
      body: JSON.stringify({
        model: env.LLM_PLANNER_MODEL || 'gpt-4o-mini',
        messages: [
          { role: 'system', content: SYSTEM_PROMPT },
          { role: 'user', content: JSON.stringify(context) },
        ],
        response_format: { type: 'json_object' },
        temperature: 0.3,
      }),
      signal: AbortSignal.timeout(15_000),
    });

    if (!res.ok) return heuristicPlan(context);

    const data = (await res.json()) as { choices?: { message?: { content?: string } }[] };
    const content = data.choices?.[0]?.message?.content ?? '{}';
    const parsed = JSON.parse(content) as { paths?: string[]; rationale?: string };
    const paths = (parsed.paths ?? []).filter((p: string) => typeof p === 'string' && p.startsWith('/')).slice(0, 40);

    if (paths.length === 0) return heuristicPlan(context);
    return { suggestedPaths: paths, rationale: parsed.rationale ?? 'LLM suggestion', source: 'llm' };
  } catch {
    return heuristicPlan(context);
  }
}

interface ReconContext {
  products: string[];
  seenPaths: string[];
  statuses: Record<string, number>;
  interestingHeaders: string[];
  paramEndpoints: string[];
}

function summarizeRecon(probes: ProbeResult[]): ReconContext {
  const products = new Set<string>();
  const seenPaths: string[] = [];
  const statuses: Record<string, number> = {};
  const interestingHeaders: string[] = [];
  const paramEndpoints: string[] = [];

  for (const p of probes) {
    const server = p.headers['server'];
    const powered = p.headers['x-powered-by'];
    if (server) products.add(server);
    if (powered) products.add(powered);

    // Track interesting response headers
    if (p.headers['x-debug-token']) interestingHeaders.push('x-debug-token');
    if (p.headers['x-request-id']) interestingHeaders.push('x-request-id');

    try {
      const url = new URL(p.url);
      seenPaths.push(url.pathname);
      if (url.search) paramEndpoints.push(url.pathname + url.search);
    } catch { /* ignore */ }

    statuses[String(p.status)] = (statuses[String(p.status)] ?? 0) + 1;
  }

  return { products: [...products], seenPaths, statuses, interestingHeaders: [...new Set(interestingHeaders)], paramEndpoints };
}

/** Deterministic fallback: aggressive vuln-focused path suggestions. */
function heuristicPlan(context: ReconContext): PlannerSuggestion {
  const seen = new Set(context.seenPaths);
  const candidates: string[] = [];
  const blob = context.products.join(' ').toLowerCase();

  // IDOR / Auth bypass patterns
  candidates.push(
    '/api/v1/users/1', '/api/v1/users/me', '/api/v2/users/1',
    '/api/admin', '/api/internal', '/admin/dashboard',
    '/api/v1/admin/users', '/internal/metrics',
  );

  // Info disclosure
  candidates.push(
    '/.git/config', '/.git/HEAD', '/.env', '/.env.production',
    '/debug', '/debug/vars', '/debug/pprof',
    '/server-info', '/server-status', '/_debug',
    '/trace', '/health', '/healthcheck',
    '/swagger.json', '/openapi.json', '/api-docs',
    '/graphql', '/graphql/playground', '/.well-known/openid-configuration',
  );

  // Stack-specific
  if (blob.includes('php') || blob.includes('apache')) {
    candidates.push('/phpinfo.php', '/wp-login.php', '/wp-json/wp/v2/users',
      '/wp-config.php.bak', '/xmlrpc.php', '/wp-admin/install.php');
  }
  if (blob.includes('nginx')) {
    candidates.push('/nginx_status', '/.nginx.conf');
  }
  if (blob.includes('express') || blob.includes('node') || blob.includes('next')) {
    candidates.push('/api-docs', '/graphql', '/_next/data', '/api/auth/session');
  }
  if (blob.includes('spring') || blob.includes('java') || blob.includes('tomcat')) {
    candidates.push('/actuator', '/actuator/env', '/actuator/heapdump',
      '/actuator/mappings', '/jolokia', '/console');
  }
  if (blob.includes('django') || blob.includes('python')) {
    candidates.push('/admin/', '/__debug__/', '/api/schema/', '/static/admin/');
  }
  if (blob.includes('rails') || blob.includes('ruby')) {
    candidates.push('/rails/info', '/rails/mailers', '/sidekiq');
  }
  if (blob.includes('laravel')) {
    candidates.push('/_ignition/health-check', '/telescope', '/horizon');
  }

  // Cloud misconfig
  candidates.push(
    '/.aws/credentials', '/.docker/config.json',
    '/metadata', '/latest/meta-data/',
  );

  const suggested = candidates.filter((c) => !seen.has(c));
  return {
    suggestedPaths: [...new Set(suggested)],
    rationale: 'Aggressive heuristic plan targeting IDOR, auth bypass, info disclosure, and stack-specific vulns.',
    source: 'heuristic',
  };
}

export function summarizeFindings(findings: Finding[]): string {
  const bySeverity = findings.reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] ?? 0) + 1;
    return acc;
  }, {});
  const parts = Object.entries(bySeverity)
    .sort()
    .map(([sev, n]) => `${n} ${sev}`);
  return `StormForge surfaced ${findings.length} finding(s): ${parts.join(', ')}. ${
    findings.some((f) => f.needsManualReview) ? 'Some require manual verification before submission.' : ''
  }`.trim();
}
