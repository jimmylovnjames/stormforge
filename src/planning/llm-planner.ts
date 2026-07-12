// Optional, advisory LLM planner.
//
// SCOPE OF THIS MODULE: it only *prioritizes* which in-scope paths are most
// worth probing given the recon seen so far, and summarizes findings for the
// report. It NEVER generates exploits, payloads, or executes anything. If no
// endpoint is configured it degrades to a deterministic heuristic.

import type { Env, Finding, ProbeResult } from '../types.js';

export interface PlannerSuggestion {
  /** Extra in-scope paths worth probing, ranked most-promising first. */
  suggestedPaths: string[];
  rationale: string;
  source: 'llm' | 'heuristic';
}

const SYSTEM_PROMPT = `You are a recon prioritization assistant for AUTHORIZED bug-bounty testing.
Given technology fingerprints and paths already seen, suggest additional common,
publicly-known paths (config files, docs, admin panels) that are worth a single
non-destructive GET. Only suggest paths. Never suggest exploits, payloads, or
destructive actions. Respond as JSON: {"paths": string[], "rationale": string}.`;

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
        // High reasoning only matters for planning; execution never uses the LLM.
        messages: [
          { role: 'system', content: SYSTEM_PROMPT },
          { role: 'user', content: JSON.stringify(context) },
        ],
        response_format: { type: 'json_object' },
        temperature: 0.2,
      }),
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) return heuristicPlan(context);
    const data = (await res.json()) as { choices?: { message?: { content?: string } }[] };
    const content = data.choices?.[0]?.message?.content ?? '{}';
    const parsed = JSON.parse(content) as { paths?: string[]; rationale?: string };
    const paths = (parsed.paths ?? []).filter((p) => typeof p === 'string' && p.startsWith('/')).slice(0, 25);
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
}

function summarizeRecon(probes: ProbeResult[]): ReconContext {
  const products = new Set<string>();
  const seenPaths: string[] = [];
  const statuses: Record<string, number> = {};
  for (const p of probes) {
    const server = p.headers['server'];
    const powered = p.headers['x-powered-by'];
    if (server) products.add(server);
    if (powered) products.add(powered);
    try {
      seenPaths.push(new URL(p.url).pathname);
    } catch {
      /* ignore */
    }
    statuses[String(p.status)] = (statuses[String(p.status)] ?? 0) + 1;
  }
  return { products: [...products], seenPaths, statuses };
}

/** Deterministic fallback: suggest stack-specific paths not yet probed. */
function heuristicPlan(context: ReconContext): PlannerSuggestion {
  const seen = new Set(context.seenPaths);
  const candidates: string[] = [];
  const blob = context.products.join(' ').toLowerCase();

  if (blob.includes('php')) candidates.push('/phpinfo.php', '/wp-login.php', '/wp-json');
  if (blob.includes('nginx')) candidates.push('/nginx_status');
  if (blob.includes('express') || blob.includes('node')) candidates.push('/api-docs', '/graphql');
  if (blob.includes('spring') || blob.includes('java')) candidates.push('/actuator', '/actuator/env');
  // Always-useful low-cost probes.
  candidates.push('/.well-known/security.txt', '/robots.txt', '/openapi.json');

  const suggested = candidates.filter((c) => !seen.has(c));
  return {
    suggestedPaths: [...new Set(suggested)],
    rationale: 'Heuristic plan based on fingerprinted stack (no LLM configured).',
    source: 'heuristic',
  };
}

/** Optional: use the LLM to write a prose summary for the disclosure header. */
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
