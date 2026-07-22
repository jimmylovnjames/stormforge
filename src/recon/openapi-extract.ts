// OpenAPI / Swagger path extraction → IDOR-shaped follow-up URLs.
// Pure / sync. GET-only materialization — never invents write methods.

import type { ProbeResult, Scope } from '../types.js';
import { evaluateScope } from '../scope/scope-guard.js';
import { parseBodySignals } from './body-parse.js';

export interface SchemaRoute {
  /** Path template as declared in the spec (e.g. `/users/{id}`). */
  path: string;
  /** Lower-cased HTTP methods present under the path (best-effort). */
  methods: string[];
  /** True when the path looks like an object-level / IDOR candidate. */
  idorish: boolean;
}

/** Path templates that look like object-level access / BOLA bait. */
const IDORISH =
  /\{[^}]*(?:id|uuid|guid|user|account|order|customer|org|tenant|profile)[^}]*\}/i;

const SAMPLE_IDS = ['1', '2', 'me'];

/**
 * Extract path templates from an OpenAPI/Swagger JSON (or light YAML) body.
 * Best-effort regex parser — enough for follow-up fan-out, not a full OAS load.
 */
export function extractOpenApiRoutes(body: string): SchemaRoute[] {
  if (!body) return [];
  const routes: SchemaRoute[] = [];
  const seen = new Set<string>();

  // JSON: "\/users\/{id}": { "get": … }
  const jsonRe = /"(\/[A-Za-z0-9_{}\-/.]+)"\s*:\s*\{([^}]{0,800})/g;
  let m: RegExpExecArray | null;
  while ((m = jsonRe.exec(body)) !== null) {
    const path = m[1]!;
    if (seen.has(path)) continue;
    seen.add(path);
    const chunk = m[2] ?? '';
    const methods = ['get', 'post', 'put', 'patch', 'delete', 'head', 'options'].filter((verb) =>
      new RegExp(`"${verb}"\\s*:`, 'i').test(chunk),
    );
    routes.push({ path, methods, idorish: IDORISH.test(path) });
  }

  // YAML: /users/{id}:  (only when JSON didn't already yield paths)
  if (routes.length === 0) {
    const yamlRe = /^(\/[A-Za-z0-9_{}\-/.]+):\s*$/gm;
    while ((m = yamlRe.exec(body)) !== null) {
      const path = m[1]!;
      if (seen.has(path)) continue;
      seen.add(path);
      routes.push({ path, methods: [], idorish: IDORISH.test(path) });
    }
  }

  return routes;
}

/** Prefer GET-capable IDOR-ish routes; fall back to any IDOR-ish. */
export function idorishRoutes(routes: SchemaRoute[]): SchemaRoute[] {
  const withGet = routes.filter((r) => r.idorish && (r.methods.length === 0 || r.methods.includes('get')));
  return withGet.length ? withGet : routes.filter((r) => r.idorish);
}

/**
 * Turn `/users/{id}` into concrete GET URLs under `origin`, substituting sample
 * IDs. Bounded and deterministic.
 */
export function materializeIdorUrls(origin: string, routes: SchemaRoute[], cap = 20): string[] {
  let base: URL;
  try {
    base = new URL(origin.includes('://') ? origin : `https://${origin}`);
  } catch {
    return [];
  }
  const out: string[] = [];
  const seen = new Set<string>();
  for (const route of idorishRoutes(routes)) {
    for (const sample of SAMPLE_IDS) {
      if (out.length >= cap) return out;
      const concrete = route.path.replace(/\{[^}]+\}/g, sample);
      try {
        const u = new URL(concrete, base);
        u.hash = '';
        // Drop leftover unresolved templates.
        if (/\{/.test(u.pathname)) continue;
        const href = u.toString();
        if (seen.has(href)) continue;
        seen.add(href);
        out.push(href);
      } catch {
        /* skip */
      }
    }
  }
  return out;
}

/**
 * From probes that already exposed an OpenAPI/Swagger body, build in-scope
 * GET follow-up URLs targeting IDOR-shaped operations.
 */
export function buildSchemaIdorFollowUps(probes: ProbeResult[], scope: Scope, cap = 20): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const p of probes) {
    if (out.length >= cap) break;
    if (p.error || !p.body) continue;
    const signals = p.signals ?? parseBodySignals(p.body, p.headers, p.status);
    if (!signals.openApiVersion || signals.openApiPathCount <= 0) continue;
    let origin: string;
    try {
      origin = new URL(p.finalUrl ?? p.url).origin;
    } catch {
      continue;
    }
    const routes = extractOpenApiRoutes(p.body);
    for (const url of materializeIdorUrls(origin, routes, cap - out.length)) {
      if (seen.has(url)) continue;
      if (!evaluateScope(url, scope).allowed) continue;
      // Skip URLs we already probed.
      if (probes.some((x) => x.url === url || x.finalUrl === url)) continue;
      seen.add(url);
      out.push(url);
      if (out.length >= cap) break;
    }
  }
  return out;
}

/** Human-readable candidate list for finding evidence / planner parsing. */
export function formatIdorCandidates(urls: string[], limit = 12): string {
  return urls
    .slice(0, limit)
    .map((u) => `  - ${u}`)
    .join('\n');
}
