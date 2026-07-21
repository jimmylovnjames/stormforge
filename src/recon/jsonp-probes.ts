// JSONP callback canary helpers (GET query params only).

export const JSONP_CANARY = 'stormforgeJsonp9f3a';

export const JSONP_PARAM_NAMES = ['callback', 'jsonp', 'cb', '_callback'] as const;

export const JSONP_PATHS: string[] = [
  '/api',
  '/api/v1',
  '/api/v1/users',
  '/api/v1/me',
  '/api/users',
  '/api/search',
  '/search',
  '/jsonp',
  '/callback',
];

/** Build GET URLs that inject a unique JSONP callback name. */
export function buildJsonpProbeUrls(baseUrl: string, maxParams = 3): string[] {
  const out: string[] = [];
  try {
    const base = new URL(baseUrl);
    base.search = '';
    for (const param of JSONP_PARAM_NAMES.slice(0, maxParams)) {
      const u = new URL(base.toString());
      u.searchParams.set(param, JSONP_CANARY);
      out.push(u.toString());
    }
  } catch {
    return [];
  }
  return out;
}

export function urlCarriesJsonpCanary(url: string): boolean {
  try {
    const u = new URL(url);
    for (const p of JSONP_PARAM_NAMES) {
      if (u.searchParams.get(p) === JSONP_CANARY) return true;
    }
  } catch {
    /* fall through */
  }
  return url.includes(JSONP_CANARY);
}

/** True when the response wraps JSON/JS as canary(...). */
export function hasJsonpWrapper(body: string, probeUrl: string): boolean {
  if (!urlCarriesJsonpCanary(probeUrl) || !body) return false;
  // Optional padding comment then function call: /**/canary( or canary(
  const re = new RegExp(
    `(?:\\/\\*[\\s\\S]*?\\*\\/\\s*)?\\b${escapeRe(JSONP_CANARY)}\\s*\\(`,
  );
  return re.test(body);
}

export function shouldProbeJsonp(probe: {
  url: string;
  status: number;
  headers: Record<string, string>;
  body: string;
  error?: string;
}): boolean {
  if (probe.error || probe.status === 0) return false;
  if (probe.status < 200 || probe.status >= 500) return false;
  const path = safePath(probe.url);
  if (JSONP_PATHS.some((p) => path === p || path.startsWith(p + '/'))) return true;
  const ct = (probe.headers['content-type'] ?? '').toLowerCase();
  if (ct.includes('json') || ct.includes('javascript') || ct.includes('ecmascript')) return true;
  if (/\/api(?:\/|$)/i.test(path) && /[?&]\w+=/.test(probe.url)) return true;
  return false;
}

function safePath(url: string): string {
  try {
    return new URL(url).pathname.toLowerCase();
  } catch {
    return url.toLowerCase();
  }
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
