// Unkeyed-header web cache poisoning helpers (GET-safe, two-step confirm).

import { hasCacheableResponse } from './cache-deception-probes.js';

export const CACHE_POISON_CANARY_PREFIX = 'sfcp-';

/** Headers commonly unkeyed by CDNs / reverse proxies. */
export const CACHE_POISON_HEADERS = [
  'x-forwarded-host',
  'x-original-url',
  'x-rewrite-url',
  'x-forwarded-server',
  'x-host',
] as const;

export interface CachePoisonVariant {
  url: string;
  poisonHeaders: Record<string, string>;
  canary: string;
  kind: (typeof CACHE_POISON_HEADERS)[number];
}

export function newCachePoisonCanary(): string {
  return `${CACHE_POISON_CANARY_PREFIX}${crypto.randomUUID().replace(/-/g, '').slice(0, 12)}`;
}

export function urlCarriesCachePoisonCanary(value: string): boolean {
  return typeof value === 'string' && value.includes(CACHE_POISON_CANARY_PREFIX);
}

export function buildCachePoisonVariants(baseUrl: string, max = 3): CachePoisonVariant[] {
  const out: CachePoisonVariant[] = [];
  try {
    const u = new URL(baseUrl);
    u.search = '';
    // Prefer site root / short paths for cache key sharing.
    if (u.pathname.length > 1 && u.pathname.split('/').length > 3) {
      u.pathname = '/';
    }
    for (const kind of CACHE_POISON_HEADERS.slice(0, max)) {
      const canary = newCachePoisonCanary();
      const poisonHeaders: Record<string, string> = {};
      if (kind === 'x-forwarded-host' || kind === 'x-forwarded-server' || kind === 'x-host') {
        poisonHeaders[kind] = canary;
      } else {
        // Path-style unkeyed headers.
        poisonHeaders[kind] = `/${canary}`;
      }
      out.push({ url: u.toString(), poisonHeaders, canary, kind });
    }
  } catch {
    return [];
  }
  return out;
}

export function shouldProbeCachePoison(probe: {
  url: string;
  status: number;
  headers: Record<string, string>;
  body: string;
  error?: string;
}): boolean {
  if (probe.error || probe.status === 0) return false;
  if (probe.status < 200 || probe.status >= 400) return false;
  if (!hasCacheableResponse(probe.headers)) return false;
  try {
    const path = new URL(probe.url).pathname;
    // Prefer roots and short HTML/API entrypoints.
    if (path === '/' || path === '/index' || path === '/home' || path === '/app') return true;
    if (path.split('/').filter(Boolean).length <= 1) return true;
  } catch {
    return false;
  }
  const ct = (probe.headers['content-type'] ?? '').toLowerCase();
  return ct.includes('html') || ct.includes('json');
}

/** True when a clean (unpoisoned) response body/headers reflect a known canary. */
export function cleanResponseContainsCanary(
  body: string,
  headers: Record<string, string>,
  canary: string,
): boolean {
  if (!canary || !urlCarriesCachePoisonCanary(canary)) return false;
  if (body.includes(canary)) return true;
  for (const v of Object.values(headers)) {
    if (v.includes(canary)) return true;
  }
  return false;
}
