// Prototype pollution / mass-assignment GET canary helpers.

export const PP_CANARY_KEY = 'sfPp';
export const PP_CANARY_VALUE = 'sfPp9f3a7c';

/** Classic GET PP payloads used against Node/Express query parsers. */
export const PP_PAYLOADS: Array<{ query: string; kind: 'proto' | 'constructor' | 'mass' }> = [
  { kind: 'proto', query: `__proto__[${PP_CANARY_KEY}]=${PP_CANARY_VALUE}` },
  { kind: 'proto', query: `__proto__.${PP_CANARY_KEY}=${PP_CANARY_VALUE}` },
  { kind: 'constructor', query: `constructor[prototype][${PP_CANARY_KEY}]=${PP_CANARY_VALUE}` },
  { kind: 'mass', query: `isAdmin=true&role=admin&${PP_CANARY_KEY}=${PP_CANARY_VALUE}` },
];

export const PP_PATHS: string[] = [
  '/api',
  '/api/v1',
  '/api/v1/users',
  '/api/v1/me',
  '/api/users',
  '/api/config',
  '/api/settings',
  '/search',
  '/graphql',
];

export function buildPrototypePollutionUrls(baseUrl: string): string[] {
  const out: string[] = [];
  try {
    const base = new URL(baseUrl);
    base.search = '';
    for (const p of PP_PAYLOADS) {
      const u = new URL(base.toString());
      u.search = `?${p.query}`;
      out.push(u.toString());
    }
  } catch {
    return [];
  }
  return out;
}

export function urlCarriesPpPayload(url: string): boolean {
  return (
    /__proto__|constructor\[prototype\]/i.test(url) ||
    (url.includes(PP_CANARY_VALUE) && /isAdmin=true|role=admin/i.test(url))
  );
}

/**
 * Confirmed PP when the canary key/value appears as a JSON object property
 * (not merely echoed inside a string that contains the raw query).
 */
export function hasPrototypePollutionReflection(body: string, probeUrl: string): boolean {
  if (!urlCarriesPpPayload(probeUrl)) return false;
  if (!body.includes(PP_CANARY_VALUE)) return false;

  // Strong: JSON property form "sfPp":"sfPp9f3a7c" or "sfPp": "sfPp9f3a7c"
  const propRe = new RegExp(`"${PP_CANARY_KEY}"\\s*:\\s*"${PP_CANARY_VALUE}"`);
  if (propRe.test(body)) return true;

  // Some serializers use single quotes or unquoted keys in debug dumps.
  if (body.includes(`${PP_CANARY_KEY}: '${PP_CANARY_VALUE}'`)) return true;
  if (body.includes(`${PP_CANARY_KEY}: "${PP_CANARY_VALUE}"`)) return true;

  // Pollution error fingerprints from Node when merging into frozen objects.
  if (
    /Cannot (?:create|set|assign) propert(?:y|ies).*__(?:proto|proto)__/i.test(body) ||
    /prototype pollution/i.test(body)
  ) {
    return true;
  }

  return false;
}

/** Mass-assignment signal: privileged fields appear accepted in JSON response. */
export function hasMassAssignmentSignal(body: string, probeUrl: string): boolean {
  if (!/isAdmin=true|role=admin/i.test(probeUrl)) return false;
  if (!/"isAdmin"\s*:\s*true/.test(body) && !/"role"\s*:\s*"admin"/.test(body)) return false;
  // Avoid flagging auth error pages that just echo the query string.
  if (/[?&]isAdmin=true/.test(body) && !/[{[]/.test(body)) return false;
  return true;
}

export function shouldProbePrototypePollution(probe: {
  url: string;
  status: number;
  headers: Record<string, string>;
  body: string;
  error?: string;
}): boolean {
  if (probe.error || probe.status === 0) return false;
  if (probe.status < 200 || probe.status >= 500) return false;
  const path = safePath(probe.url);
  if (PP_PATHS.some((p) => path === p || path.startsWith(p + '/') || path.endsWith(p))) return true;
  const ct = (probe.headers['content-type'] ?? '').toLowerCase();
  if (ct.includes('json') && path.includes('/api')) return true;
  // Node/Express fingerprints
  const server = (probe.headers['server'] ?? '') + (probe.headers['x-powered-by'] ?? '');
  if (/express|node|nestjs|koa|fastify/i.test(server) && probe.status < 500) return true;
  return false;
}

function safePath(url: string): string {
  try {
    return new URL(url).pathname.toLowerCase();
  } catch {
    return url.toLowerCase();
  }
}
