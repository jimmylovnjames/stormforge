// Passive path planner for Worker recon (Grok/xAI-friendly).
// Suggests high-impact GET paths from probe context + tactic memory.

import type { Env, Finding, ProbeResult } from '../types.js';

export interface PlannerSuggestion {
  suggestedPaths: string[];
  rationale: string;
  source: 'llm' | 'heuristic' | 'evolved';
  tacticsUsed?: string[];
}

const SYSTEM_PROMPT = `Senior bug-bounty path planner. Suggest ONLY high-impact paths for GET recon.

Focus: IDOR, auth bypass, disclosure, GraphQL/OpenAPI, debug, injection params.
Rules: impact over noise; evolve from priorTactics; paths must start with /.
JSON only: {"paths":string[],"rationale":string,"vulnClasses":string[],"evolvedTactics":string[]}`;

export async function planNextPaths(
  probes: ProbeResult[],
  env: Env,
  program?: string,
): Promise<PlannerSuggestion> {
  const context = summarizeRecon(probes);
  const priorTactics = program ? await loadTactics(env, program) : [];

  const endpoint = env.LLM_PLANNER_ENDPOINT;
  const apiKey = env.LLM_PLANNER_API_KEY;
  const model = env.LLM_PLANNER_MODEL || 'grok-4';

  if (endpoint && apiKey) {
    try {
      const isGrok = endpoint.includes('x.ai') || model.toLowerCase().includes('grok');

      const res = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${apiKey}`,
        },
        body: JSON.stringify({
          model,
          messages: [
            { role: 'system', content: SYSTEM_PROMPT },
            {
              role: 'user',
              content: JSON.stringify({
                products: context.products.slice(0, 12),
                statuses: context.statuses,
                samplePaths: context.seenPaths.slice(0, 25),
                paramEndpoints: context.paramEndpoints.slice(0, 15),
                priorTactics: priorTactics.slice(0, 30),
              }),
            },
          ],
          temperature: 0.2,
          max_tokens: 800,
          ...(isGrok ? {} : { response_format: { type: 'json_object' } }),
        }),
        signal: AbortSignal.timeout(18_000),
      });

      if (res.ok) {
        const data = (await res.json()) as { choices?: { message?: { content?: string } }[] };
        const rawContent = data.choices?.[0]?.message?.content ?? '{}';
        const parsed = safeJson(rawContent) as {
          paths?: string[];
          rationale?: string;
          evolvedTactics?: string[];
        };

        const paths = (parsed.paths ?? [])
          .filter((p): p is string => typeof p === 'string' && p.startsWith('/'))
          .slice(0, 35);

        if (paths.length > 0 && program && Array.isArray(parsed.evolvedTactics)) {
          await saveTactics(env, program, parsed.evolvedTactics.filter((t) => typeof t === 'string' && t.startsWith('/')));
        }

        if (paths.length > 0) {
          return {
            suggestedPaths: paths,
            rationale: parsed.rationale || 'LLM suggestion',
            source: 'llm',
            tacticsUsed: parsed.evolvedTactics,
          };
        }
      }
    } catch {
      // fall through
    }
  }

  return heuristicPlan(context, priorTactics);
}

export function heuristicPlan(
  context: {
    products?: string[];
    seenPaths?: string[];
    statuses?: Record<string, number>;
    paramEndpoints?: string[];
  },
  priorTactics: string[] = [],
): PlannerSuggestion {
  const seen = new Set(context.seenPaths ?? []);
  const candidates = [...priorTactics];

  candidates.push(
    '/api/v1/users/1',
    '/api/v2/users/me',
    '/api/admin/users',
    '/internal',
    '/debug',
    '/graphql',
    '/.env',
    '/.git/config',
    '/actuator/env',
    '/swagger.json',
    '/openapi.json',
    '/_ignition/health-check',
  );

  for (const pe of context.paramEndpoints ?? []) {
    const pathOnly = pe.split('?')[0];
    if (pathOnly?.startsWith('/')) candidates.push(pathOnly);
  }

  const statuses = context.statuses ?? {};
  if ((statuses['401'] ?? 0) + (statuses['403'] ?? 0) > 0) {
    candidates.push('/admin', '/api/v1/me', '/api/v1/users', '/dashboard');
  }

  const blob = (context.products || []).join(' ').toLowerCase();
  if (blob.includes('php')) candidates.push('/wp-json/wp/v2/users', '/phpinfo.php');
  if (blob.includes('node') || blob.includes('express') || blob.includes('next')) {
    candidates.push('/api/auth/session', '/_next/data');
  }
  if (blob.includes('spring') || blob.includes('java')) candidates.push('/actuator', '/jolokia');
  if (blob.includes('django')) candidates.push('/admin/', '/__debug__/');
  if (blob.includes('graphql') || (context.seenPaths ?? []).some((p) => /graphql/i.test(p))) {
    candidates.push('/graphql', '/api/graphql', '/graphiql');
  }

  const suggested = [...new Set(candidates)]
    .filter((c) => c.startsWith('/') && !seen.has(c))
    .slice(0, 30);

  return {
    suggestedPaths: suggested,
    rationale: priorTactics.length
      ? `Heuristic seeded with ${priorTactics.length} prior working tactics.`
      : 'High-signal heuristic for IDOR, disclosure, bypass patterns.',
    source: priorTactics.length ? 'evolved' : 'heuristic',
    tacticsUsed: priorTactics,
  };
}

export function summarizeFindings(findings: Finding[]): string {
  const bySeverity = findings.reduce((acc: Record<string, number>, f) => {
    acc[f.severity] = (acc[f.severity] ?? 0) + 1;
    return acc;
  }, {});
  const parts = Object.entries(bySeverity)
    .sort()
    .map(([sev, n]) => `${n} ${sev}`);
  const needsReview = findings.some((f) => f.needsManualReview);
  return `StormForge found ${findings.length} issue(s): ${parts.join(', ')}.${needsReview ? ' Some need manual verification.' : ''}`.trim();
}

function summarizeRecon(probes: ProbeResult[]) {
  const products = new Set<string>();
  const seenPaths: string[] = [];
  const statuses: Record<string, number> = {};
  const interestingHeaders: string[] = [];
  const paramEndpoints: string[] = [];

  for (const p of probes) {
    const server = p.headers['server'] || p.headers['x-powered-by'];
    if (server) products.add(server);
    if (p.headers['x-debug-token'] || p.headers['x-request-id']) {
      interestingHeaders.push('debug-header');
    }
    try {
      const url = new URL(p.url);
      seenPaths.push(url.pathname);
      if (url.search) paramEndpoints.push(url.pathname + url.search);
    } catch {
      /* ignore */
    }
    statuses[String(p.status)] = (statuses[String(p.status)] ?? 0) + 1;
  }

  return {
    products: [...products],
    seenPaths,
    statuses,
    interestingHeaders: [...new Set(interestingHeaders)],
    paramEndpoints,
  };
}

async function loadTactics(env: Env, program: string): Promise<string[]> {
  if (!env.STORMFORGE_KV) return [];
  const raw = await env.STORMFORGE_KV.get(`tactics:${program}`, 'json');
  return Array.isArray(raw) ? raw : [];
}

async function saveTactics(env: Env, program: string, newTactics: string[]): Promise<void> {
  if (!env.STORMFORGE_KV || !newTactics?.length) return;
  const key = `tactics:${program}`;
  const existing = await loadTactics(env, program);
  const merged = [...new Set([...existing, ...newTactics])].slice(0, 200);
  await env.STORMFORGE_KV.put(key, JSON.stringify(merged), { expirationTtl: 7776000 });
}

function safeJson(text: string): unknown {
  try {
    const cleaned = text.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/i, '');
    return JSON.parse(cleaned);
  } catch {
    return {};
  }
}
