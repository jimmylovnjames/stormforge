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
  const merged = mergeTactics(existing, newTactics, 200);
  await env.STORMFORGE_KV.put(key, JSON.stringify(merged), { expirationTtl: 7776000 });
}

/** Persist path tactics that actually produced high-signal findings. */
export async function recordWinningTactics(
  env: Env,
  program: string,
  findings: Finding[],
): Promise<string[]> {
  const won = extractWinningTactics(findings);
  if (!won.length) return [];
  await saveTactics(env, program, won);
  return won;
}

/** Pathnames from submit-ready / high-severity findings worth remembering. */
export function extractWinningTactics(findings: Finding[]): string[] {
  const out: string[] = [];
  for (const f of findings) {
    if (f.severity !== 'critical' && f.severity !== 'high') continue;
    if (f.checkId.startsWith('recon-') || f.checkId === 'security-headers') continue;
    if (!(f.submitReady || f.needsManualReview === false || f.severity === 'critical' || f.severity === 'high')) {
      continue;
    }
    try {
      const path = new URL(f.target.includes('://') ? f.target : `https://${f.target}`).pathname;
      if (path && path !== '/' && path.length < 120) out.push(path);
    } catch {
      /* skip */
    }
  }
  return [...new Set(out)].slice(0, 40);
}

export function mergeTactics(existing: string[], incoming: string[], cap = 200): string[] {
  return [...new Set([...existing, ...incoming].filter((p) => typeof p === 'string' && p.startsWith('/')))].slice(
    0,
    cap,
  );
}

/** Derive sibling paths from parameterized endpoints discovered in recon. */
export function pathsFromParamEndpoints(paramEndpoints: string[]): string[] {
  const out: string[] = [];
  for (const pe of paramEndpoints) {
    try {
      const u = new URL(pe, 'https://example.invalid');
      const path = u.pathname;
      if (!path || path === '/') continue;
      out.push(path);
      // Sibling guesses: /search → /api/search
      if (!path.startsWith('/api/')) out.push(`/api${path}`);
      if (path.startsWith('/api/') && !path.includes('/v1/')) {
        out.push(path.replace(/^\/api\//, '/api/v1/'));
      }
    } catch {
      const pathOnly = pe.split('?')[0] ?? '';
      if (pathOnly.startsWith('/')) out.push(pathOnly);
    }
  }
  return [...new Set(out)].slice(0, 20);
}

export function heuristicPlan(
  context: {
    products?: string[];
    seenPaths?: string[];
    statuses?: Record<string, number>;
    interestingHeaders?: string[];
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
    '/_ignition/health-check',
  );

  candidates.push(...pathsFromParamEndpoints(context.paramEndpoints ?? []));

  const statuses = context.statuses ?? {};
  if ((statuses['401'] ?? 0) + (statuses['403'] ?? 0) > 0) {
    candidates.push(
      '/admin',
      '/admin/users',
      '/api/v1/me',
      '/api/v1/users',
      '/api/v1/admin',
      '/dashboard',
      '/manage',
      '/internal/admin',
    );
  }

  const blob = (context.products || []).join(' ').toLowerCase();
  if (blob.includes('php')) candidates.push('/wp-json/wp/v2/users', '/phpinfo.php');
  if (blob.includes('node') || blob.includes('express') || blob.includes('next')) {
    candidates.push('/api/auth/session', '/_next/data');
  }
  if (blob.includes('spring') || blob.includes('java')) candidates.push('/actuator', '/jolokia');
  if (blob.includes('django')) candidates.push('/admin/', '/__debug__/');
  if (
    blob.includes('graphql') ||
    (context.seenPaths ?? []).some((p) => /graphql|swagger|openapi/i.test(p))
  ) {
    candidates.push('/graphql', '/api/graphql', '/openapi.json', '/swagger.json');
  }

  const suggested = [...new Set(candidates)].filter((c) => c.startsWith('/') && !seen.has(c)).slice(0, 30);

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
    // Concrete paths embedded in evidence (e.g. harvested OpenAPI).
    for (const p of pathsFromEvidence(f.evidence)) paths.push(p);

    switch (f.checkId) {
      case 'graphql-introspection':
      case 'api-schema-exposure':
        paths.push('/graphql', '/api/graphql', '/graphiql', '/v1/graphql', '/swagger.json', '/openapi.json');
        break;
      case 'auth-access-control':
      case 'auth-differential':
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
      case 'ssrf-blind-canary':
      case 'sql-injection-error':
      case 'crlf-header-injection':
      case 'prototype-pollution':
      case 'http-parameter-pollution':
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
      case 'cache-deception':
      case 'cache-poisoning':
        paths.push('/', '/login', '/reset-password', '/account', '/forgot-password', '/me', '/profile', '/api/v1/me');
        break;
      case 'subdomain-takeover':
        paths.push('/');
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
  const suggested = [...new Set(paths)].filter((p) => p.startsWith('/')).slice(0, 40);
  return {
    suggestedPaths: suggested,
    rationale: `Second-pass paths derived from ${findings.length} finding(s) across ${new Set(findings.map((f) => f.checkId)).size} check class(es)`,
    source: 'evolved',
  };
}

/** Parse `/path` tokens from evidence lines like `paths: /a, /b`. */
function pathsFromEvidence(evidence: string | undefined): string[] {
  if (!evidence) return [];
  const out: string[] = [];
  const m = evidence.match(/paths:\s*([^\n]+)/i);
  if (m) {
    for (const part of m[1]!.split(/[,\s]+/)) {
      const p = part.trim();
      if (p.startsWith('/') && p.length < 120) out.push(p.replace(/\{[^}]+\}/g, '1'));
    }
  }
  return out;
}

