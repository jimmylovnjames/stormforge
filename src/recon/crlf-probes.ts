// CRLF / HTTP response splitting canary helpers (safe GET only).

export const CRLF_CANARY_HEADER = 'x-stormforge-crlf';
export const CRLF_CANARY_VALUE = 'sfCrlf9f3a7c';

/**
 * URL-encoded CRLF payloads that attempt to inject a response header.
 * Confirmed only when the Worker-parsed response headers contain the canary.
 */
export const CRLF_PAYLOADS = [
  `%0d%0a${CRLF_CANARY_HEADER}:%20${CRLF_CANARY_VALUE}`,
  `%0a${CRLF_CANARY_HEADER}:%20${CRLF_CANARY_VALUE}`,
  `%0d%0a${CRLF_CANARY_HEADER}:%20${CRLF_CANARY_VALUE}%0d%0a`,
  `%0d%0aSet-Cookie:%20sfCrlf=${CRLF_CANARY_VALUE}`,
] as const;

export const CRLF_PARAM_NAMES = [
  'url',
  'redirect',
  'next',
  'return',
  'returnUrl',
  'dest',
  'destination',
  'continue',
  'callback',
  'file',
  'path',
  'q',
  'search',
  'name',
] as const;

export const CRLF_PATHS: string[] = [
  '/redirect',
  '/logout',
  '/login',
  '/callback',
  '/oauth/callback',
  '/download',
  '/proxy',
  '/go',
  '/out',
  '/link',
];

export function buildCrlfProbeUrls(baseUrl: string, maxParams = 2): string[] {
  const out: string[] = [];
  try {
    for (const param of CRLF_PARAM_NAMES.slice(0, maxParams)) {
      for (const payload of CRLF_PAYLOADS.slice(0, 3)) {
        const u = new URL(baseUrl);
        for (const p of CRLF_PARAM_NAMES) u.searchParams.delete(p);
        // Keep payload URL-encoded as literal query value (do not double-decode).
        u.search = `${u.search ? u.search + '&' : '?'}${param}=${payload}`;
        out.push(u.toString());
      }
    }
  } catch {
    return [];
  }
  return out;
}

export function urlCarriesCrlfPayload(url: string): boolean {
  return (
    /%0d%0a|%0a|%0d/i.test(url) &&
    (url.includes(CRLF_CANARY_VALUE) || /sfCrlf/i.test(url) || /x-stormforge-crlf/i.test(url))
  );
}

/** True when the canary appears as a distinct response header (not just body echo). */
export function hasCrlfHeaderInjection(headers: Record<string, string>): boolean {
  const canaryHdr = headers[CRLF_CANARY_HEADER];
  if (canaryHdr && canaryHdr.includes(CRLF_CANARY_VALUE)) return true;
  // Some stacks fold injected Set-Cookie.
  const cookie = headers['set-cookie'] ?? '';
  if (/sfCrlf\s*=\s*sfCrlf9f3a7c/i.test(cookie)) return true;
  // Rare: canary appended into Location via splitting.
  const loc = headers['location'] ?? '';
  if (loc.includes(CRLF_CANARY_VALUE) && /[\r\n]|%0d|%0a/i.test(loc) === false) {
    // Location may legitimately contain query; require header key presence elsewhere.
    return false;
  }
  return false;
}

export function shouldProbeCrlf(probe: {
  url: string;
  status: number;
  headers: Record<string, string>;
  body: string;
  error?: string;
}): boolean {
  if (probe.error || probe.status === 0) return false;
  const path = safePath(probe.url);
  if (CRLF_PATHS.some((p) => path === p || path.endsWith(p))) return true;
  if (/[?&](?:url|redirect|next|return|dest|destination|callback)=/i.test(probe.url)) return true;
  if (probe.status >= 300 && probe.status < 400 && probe.headers['location']) return true;
  return false;
}

function safePath(url: string): string {
  try {
    return new URL(url).pathname.toLowerCase();
  } catch {
    return url.toLowerCase();
  }
}
