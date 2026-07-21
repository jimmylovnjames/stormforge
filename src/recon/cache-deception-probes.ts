// Path-based web cache deception helpers (safe GET only).

/** Static-looking suffixes that confuse CDN path classification. */
export const CACHE_DECEPTION_SUFFIXES = [
  '.css',
  '.js',
  '.ico',
  '%0a.css',
  '%0d.css',
  '/.css',
  ';.css',
  '.png',
  '.svg',
  '.woff',
  '.map',
  '..%2f..%2fstatic.css',
] as const;

/** Paths that often return personalized / authenticated-shaped content. */
export const CACHE_SENSITIVE_PATHS: string[] = [
  '/account',
  '/me',
  '/profile',
  '/settings',
  '/dashboard',
  '/api/v1/me',
  '/api/me',
  '/api/v1/user',
  '/user',
  '/users/me',
  '/my-account',
];

const DYNAMIC_MARKERS =
  /"(?:email|user_email|username|user_id|account_id)"\s*:\s*"|<input[^>]+(?:password|email|csrf)|Sign out|Log out|My account|Welcome,\s/i;

export function buildCacheDeceptionUrls(baseUrl: string): string[] {
  const out: string[] = [];
  try {
    const u = new URL(baseUrl);
    u.search = '';
    const path = u.pathname.endsWith('/') ? u.pathname.slice(0, -1) : u.pathname;
    if (!path || path === '/') return [];
    for (const suffix of CACHE_DECEPTION_SUFFIXES.slice(0, 8)) {
      // Concatenate on the path string so %0a / %2f payloads are not re-encoded by URL.pathname.
      out.push(`${u.origin}${path}${suffix}`);
    }
  } catch {
    return [];
  }
  return out;
}

export function looksLikeDynamicContent(body: string, headers: Record<string, string>): boolean {
  if (!body || body.length < 40) return false;
  const ct = (headers['content-type'] ?? '').toLowerCase();
  if (ct.includes('javascript') || ct.includes('css') || ct.includes('image/')) {
    // Misleading content-type with dynamic markers is still interesting.
    return DYNAMIC_MARKERS.test(body);
  }
  return DYNAMIC_MARKERS.test(body) || (ct.includes('json') && /"(?:email|username|id)"\s*:/.test(body));
}

export function hasCacheableResponse(headers: Record<string, string>): boolean {
  const cc = (headers['cache-control'] ?? '').toLowerCase();
  if (cc.includes('no-store') || cc.includes('private')) return false;
  const vary = (headers['vary'] ?? '').toLowerCase();
  if (vary.includes('cookie') || vary.includes('authorization')) return false;

  const cache =
    (headers['x-cache'] ?? headers['cf-cache-status'] ?? headers['age'] ?? headers['x-cache-status'] ?? '').toLowerCase();
  if (cache.includes('hit') || cache === '1' || Number(headers['age'] ?? '0') > 0) return true;
  if (cc.includes('public') || /max-age=\d+/.test(cc)) return true;
  return false;
}

export function shouldProbeCacheDeception(probe: {
  url: string;
  status: number;
  headers: Record<string, string>;
  body: string;
  error?: string;
}): boolean {
  if (probe.error || probe.status === 0) return false;
  if (probe.status < 200 || probe.status >= 400) return false;
  const path = safePath(probe.url);
  if (CACHE_SENSITIVE_PATHS.some((p) => path === p || path.endsWith(p))) return true;
  if (looksLikeDynamicContent(probe.body, probe.headers)) return true;
  return false;
}

function safePath(url: string): string {
  try {
    return new URL(url).pathname.toLowerCase();
  } catch {
    return url.toLowerCase();
  }
}
