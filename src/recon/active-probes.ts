// Active-probe planning + canary analysis (RoE-GATED, detection-only).
//
// SAFETY MODEL — read before extending:
//  - OFF by default. Only runs when ACTIVE_TESTING=true (or SCAN_MODE contains
//    "active") AND the scope is authorized. The operator opts in per deploy.
//  - GET-only, scope-checked (host must be in-scope), rate-limited via the
//    shared HttpClient. Never mutates remote state.
//  - Canaries point at a non-resolving RFC-2606 `.example` host, so a reflected
//    redirect/URL is unambiguous evidence yet leads nowhere.
//  - Host-header probes carry a cache-buster query param so a shared cache is
//    NEVER poisoned for real users — we only observe reflection of our header.

import type { Env, Scope } from '../types.js';

/** Header the scanner stamps on an active probe so checks can identify it. */
export const ACTIVE_MARKER_HEADER = 'x-stormforge-active';
/** Header carrying the injected canary (host or URL) for the check to confirm. */
export const ACTIVE_CANARY_HEADER = 'x-stormforge-canary';
/** Header carrying the injected parameter name (open-redirect). */
export const ACTIVE_PARAM_HEADER = 'x-stormforge-param';

/** Non-resolving canary host (RFC 2606). A redirect/URL to it is proof-only. */
export const CANARY_HOST = 'stormforge-oob.example';
export const CANARY_REDIRECT_URL = `https://${CANARY_HOST}/sf-redir`;

/** Common open-redirect parameter names (safe, GET query only). */
export const REDIRECT_PARAMS = [
  'redirect',
  'redirect_uri',
  'redirect_url',
  'url',
  'next',
  'return',
  'returnTo',
  'return_url',
  'dest',
  'destination',
  'continue',
  'target',
];

/** Headers used to detect host-header injection / cache-poisoning surface. */
export const HOST_HEADER_NAMES = ['x-forwarded-host', 'x-forwarded-scheme', 'x-forwarded-proto'];

export interface OpenRedirectProbe {
  url: string;
  param: string;
  canary: string;
}

export interface HostHeaderProbe {
  url: string;
  headers: Record<string, string>;
  canary: string;
}

/** RoE gate: active testing requires an explicit opt-in AND an authorized scope. */
export function activeTestingEnabled(env: Env, scope: Scope): boolean {
  if (!scope?.authorized) return false;
  const flag = (env.ACTIVE_TESTING ?? '').toLowerCase();
  const mode = (env.SCAN_MODE ?? '').toLowerCase();
  return flag === 'true' || flag === '1' || mode.includes('active');
}

/**
 * Build open-redirect probes: for each base URL, inject the canary into a small
 * set of redirect params. Bounded by `cap` total probes. Base URL host stays
 * in-scope (only the query value is off-site).
 */
export function buildOpenRedirectProbes(baseUrls: string[], cap = 12): OpenRedirectProbe[] {
  const out: OpenRedirectProbe[] = [];
  const seen = new Set<string>();
  const paramsPerUrl = Math.max(1, Math.ceil(cap / Math.max(1, baseUrls.length)));
  for (const base of baseUrls) {
    let added = 0;
    for (const param of REDIRECT_PARAMS) {
      if (out.length >= cap || added >= paramsPerUrl) break;
      const url = withParam(base, param, CANARY_REDIRECT_URL);
      if (!url || seen.has(`${url}`)) continue;
      seen.add(url);
      out.push({ url, param, canary: CANARY_REDIRECT_URL });
      added++;
    }
    if (out.length >= cap) break;
  }
  return out;
}

/** Build host-header reflection probes (cache-busted so no real cache is keyed). */
export function buildHostHeaderProbes(baseUrls: string[], cap = 8): HostHeaderProbe[] {
  const out: HostHeaderProbe[] = [];
  const seen = new Set<string>();
  for (const base of baseUrls) {
    if (out.length >= cap) break;
    const url = withParam(base, 'sf_cb', cacheBuster());
    if (!url || seen.has(url)) continue;
    seen.add(url);
    out.push({
      url,
      canary: CANARY_HOST,
      headers: {
        'x-forwarded-host': CANARY_HOST,
        'x-forwarded-scheme': 'https',
        'x-forwarded-proto': 'https',
      },
    });
  }
  return out;
}

/** Hostname a Location header ultimately points at (absolute / protocol-relative). */
export function redirectHostOf(location: string): string | null {
  let s = location.trim().replace(/\\/g, '/');
  if (/^https?:\/\//i.test(s)) {
    try {
      return new URL(s).hostname.toLowerCase();
    } catch {
      return null;
    }
  }
  // protocol-relative //host, or leading-slash variants ///host
  const m = /^\/*\/\/([^/?#]+)/.exec(s);
  if (m && m[1]) return m[1].toLowerCase();
  return null; // relative path → not an off-site redirect
}

/** True when a Location redirects to the canary host (open redirect confirmed). */
export function isCanaryRedirect(location: string, canaryHost = CANARY_HOST): boolean {
  const host = redirectHostOf(location);
  if (!host) return false;
  return host === canaryHost || host.endsWith(`.${canaryHost}`);
}

/** True when the canary host appears as an absolute URL / link target in a body. */
export function bodyReflectsCanary(body: string, canaryHost = CANARY_HOST): boolean {
  if (!body) return false;
  const esc = canaryHost.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`(?:https?:)?//${esc}\\b`, 'i').test(body);
}

function withParam(base: string, key: string, value: string): string | null {
  try {
    const u = new URL(base.includes('://') ? base : `https://${base}`);
    u.searchParams.set(key, value);
    return u.toString();
  } catch {
    return null;
  }
}

function cacheBuster(): string {
  return `sf${Math.random().toString(36).slice(2, 10)}`;
}
