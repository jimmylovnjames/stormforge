// src/planning/llm-planner.ts
// Optimized for Cloudflare Workers + KV + Grok/xAI.
// Drop-in replacement. Same exports. Defensive parsing. No invented APIs.

import type { Env, Finding, ProbeResult } from '../types.js';

export interface PlannerSuggestion {
  suggestedPaths: string[];
  rationale: string;
  source: 'llm' | 'heuristic' | 'evolved';
  tacticsUsed?: string[];
}

const SYSTEM_PROMPT = `You are a senior bug bounty planner.
Given recon data and previously successful tactics for this program, suggest only high-impact paths likely to find real vulnerabilities (IDOR, auth bypass, info disclosure, injection, misconfig).

Rules:
- Impact over noise.
- Evolve from prior tactics when available.
- Every path targets a clear vuln class.
- Output clean JSON only.

Respond exactly: {"paths": string[], "rationale": string, "vulnClasses": string[], "evolvedTactics": string[]}`;

export async function planNextPaths(
  probes: ProbeResult[],
  env: Env,
  program?: string
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
            { role: 'user', content: JSON.stringify({ context, priorTactics }) },
          ],
          temperature: 0.2,
          max_tokens: 800,
          ...(isGrok ? {} : { response_format: { type: 'json_object' } }),
        }),
        signal: AbortSignal.timeout(18000),
      });

      if (!res.ok) {
        return heuristicPlan(context, priorTactics);
      }

      const data = await res.json() as any;
      const rawContent = data.choices?.[0]?.message?.content ?? '{}';
      const parsed = safeJson(rawContent);

      const paths = (parsed.paths ?? [])
        .filter((p: unknown) => typeof p === 'string' && (p as string).startsWith('/'))
        .slice(0, 35);

      if (paths.length > 0 && program && Array.isArray(parsed.evolvedTactics)) {
        await saveTactics(env, program, parsed.evolvedTactics);
      }

      if (paths.length > 0) {
        return {
          suggestedPaths: paths,
          rationale: parsed.rationale || 'LLM suggestion',
          source: isGrok ? 'llm' : 'llm',
          tacticsUsed: parsed.evolvedTactics,
        };
      }
    } catch {
      // fall through to heuristic
    }
  }

  return heuristicPlan(context, priorTactics);
}

function safeJson(text: string): any {
  try {
    return JSON.parse(text);
  } catch {
    return {};
  }
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
    } catch {}
    statuses[String(p.status)] = (statuses[String(p.status)] ?? 0) + 1;
  }

  return { products: [...products], seenPaths, statuses, interestingHeaders: [...new Set(interestingHeaders)], paramEndpoints };
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

function heuristicPlan(context: any, priorTactics: string[] = []): PlannerSuggestion {
  const seen = new Set(context.seenPaths);
  const candidates = [...priorTactics];

  candidates.push(
    '/api/v1/users/1', '/api/v2/users/me', '/api/admin/users',
    '/internal', '/debug', '/graphql', '/.env', '/.git/config',
    '/actuator/env', '/swagger.json', '/_ignition/health-check'
  );

  const blob = (context.products || []).join(' ').toLowerCase();
  if (blob.includes('php')) candidates.push('/wp-json/wp/v2/users', '/phpinfo.php');
  if (blob.includes('node') || blob.includes('express') || blob.includes('next')) {
    candidates.push('/api/auth/session', '/_next/data');
  }
  if (blob.includes('spring') || blob.includes('java')) candidates.push('/actuator', '/jolokia');
  if (blob.includes('django')) candidates.push('/admin/', '/__debug__/');

  const suggested = [...new Set(candidates)].filter(c => !seen.has(c)).slice(0, 30);

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
  const parts = Object.entries(bySeverity).sort().map(([sev, n]) => `${n} ${sev}`);
  const needsReview = findings.some(f => f.needsManualReview);
  return `StormForge found ${findings.length} issue(s): ${parts.join(', ')}.${needsReview ? ' Some need manual verification.' : ''}`.trim();
}

/**
 * Finding-driven path suggestions for a second passive scan pass.
 * Turns check hits into the next high-signal paths to probe.
 */
export function planPathsFromFindings(findings: Finding[]): PlannerSuggestion {
  const paths: string[] = [];
  for (const f of findings) {
    switch (f.checkId) {
      case 'graphql-introspection':
      case 'api-schema-exposure':
        paths.push('/graphql', '/api/graphql', '/graphiql', '/v1/graphql', '/swagger.json', '/openapi.json');
        break;
      case 'auth-access-control':
      case 'weak-jwt':
        paths.push('/api/v1/users/1', '/api/v1/users/2', '/api/v1/me', '/admin/users', '/api/v1/accounts/1', '/admin', '/dashboard');
        break;
      case 'secret-exposure':
      case 'exposed-files':
        paths.push('/.env', '/.env.backup', '/config.json', '/.aws/credentials', '/backup.sql', '/.git/config');
        break;
      case 'xss-injection':
      case 'command-injection':
      case 'ssrf-open-redirect':
      case 'sql-injection-error':
      case 'crlf-header-injection':
      case 'prototype-pollution':
        try {
          const u = new URL(f.target);
          if (u.pathname && u.pathname !== '/') paths.push(u.pathname);
        } catch {
          /* ignore */
        }
        paths.push('/search', '/redirect', '/proxy', '/ping', '/exec', '/api/users', '/api/v1/users');
        break;
      case 'path-traversal':
        paths.push('/download', '/file', '/static', '/api/file', '/view', '/include', '/page');
        break;
      case 'host-header-injection':
        paths.push('/', '/login', '/reset-password', '/account', '/forgot-password');
        break;
      case 'cloud-bucket-exposure':
        paths.push('/assets/', '/static/', '/uploads/', '/media/', '/files/', '/backup/', '/data/');
        break;
      case 'rate-limit-missing':
        paths.push('/login', '/api/v1/login', '/oauth/token', '/otp');
        break;
      default:
        break;
    }
  }
  const suggested = [...new Set(paths)].filter((p) => p.startsWith('/')).slice(0, 30);
  return {
    suggestedPaths: suggested,
    rationale: `Second-pass paths derived from ${findings.length} finding(s) across ${new Set(findings.map((f) => f.checkId)).size} check class(es)`,
    source: 'evolved',
  };
}

