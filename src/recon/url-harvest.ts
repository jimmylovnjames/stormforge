// Harvest API paths / URLs from HTML and JavaScript bodies (GET-safe intelligence).

import type { ProbeResult } from '../types.js';
import { extractOpenApiPaths } from './body-parse.js';

const MAX_HARVEST = 40;

/** Resolve href/src-like URLs from HTML relative to a base page URL. */
export function extractUrlsFromHtml(body: string, baseUrl: string): string[] {
  if (!body) return [];
  const out = new Set<string>();
  let base: URL;
  try {
    base = new URL(baseUrl);
  } catch {
    return [];
  }

  const attrRe = /(?:href|src|action)\s*=\s*["']([^"']+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = attrRe.exec(body)) !== null) {
    const raw = m[1]!.trim();
    if (!raw || raw.startsWith('#') || raw.startsWith('mailto:') || raw.startsWith('javascript:')) {
      continue;
    }
    try {
      const abs = new URL(raw, base);
      if (abs.protocol !== 'http:' && abs.protocol !== 'https:') continue;
      // Prefer same-origin; still keep other https for scope filtering later.
      out.add(abs.toString());
    } catch {
      /* skip */
    }
    if (out.size >= MAX_HARVEST) break;
  }
  return [...out];
}

/** Extract API-looking path strings from JS source. */
export function extractApiPathsFromJs(body: string): string[] {
  if (!body) return [];
  const out = new Set<string>();
  const re =
    /["'`](\/(?:api|graphql|v\d+|admin|auth|oauth|rest|gateway)\/[A-Za-z0-9_/{}.\-]+)["'`]/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(body)) !== null) {
    out.add(normalizePath(m[1]!));
    if (out.size >= MAX_HARVEST) break;
  }
  // Also catch plain "/graphql" and "/api/..."
  const simple = /["'`](\/(?:graphql|api(?:\/[A-Za-z0-9_/{}.\-]+)?))["'`]/g;
  while ((m = simple.exec(body)) !== null) {
    out.add(normalizePath(m[1]!));
    if (out.size >= MAX_HARVEST) break;
  }
  return [...out];
}

/**
 * Harvest concrete paths from a probe body (OpenAPI > JS > HTML pathnames).
 * Returns pathnames starting with `/` for use with buildProbeUrls / extraPaths.
 */
export function harvestPathsFromProbe(probe: ProbeResult): string[] {
  const out = new Set<string>();
  const body = probe.body ?? '';
  const ct = (probe.headers['content-type'] ?? '').toLowerCase();

  if (
    probe.signals?.openApiVersion ||
    /"openapi"\s*:|"swagger"\s*:|^openapi:/m.test(body)
  ) {
    for (const p of extractOpenApiPaths(body)) out.add(p);
  }

  if (ct.includes('javascript') || /\b(fetch|axios|XMLHttpRequest)\b/.test(body)) {
    for (const p of extractApiPathsFromJs(body)) out.add(p);
  }

  if (ct.includes('html') || /^\s*</.test(body)) {
    for (const u of extractUrlsFromHtml(body, probe.finalUrl ?? probe.url)) {
      try {
        const path = new URL(u).pathname;
        if (path && path !== '/') out.add(path);
      } catch {
        /* skip */
      }
    }
  }

  return [...out].filter((p) => p.startsWith('/')).slice(0, MAX_HARVEST);
}

function normalizePath(p: string): string {
  // Strip template placeholders for probing seeds: /orders/{id} → /orders/1
  return p.replace(/\{[^}]+\}/g, '1').replace(/\/+/g, '/');
}
