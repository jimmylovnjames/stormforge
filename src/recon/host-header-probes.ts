// Host-header / cache poisoning signal helpers.

export const HOST_CANARY = 'stormforge-host.example';

export function buildHostHeaderVariants(baseUrl: string): Array<{ url: string; headers: Record<string, string>; kind: string }> {
  const out: Array<{ url: string; headers: Record<string, string>; kind: string }> = [];
  try {
    const u = new URL(baseUrl);
    u.search = '';
    const url = u.toString();
    out.push({
      url,
      kind: 'host',
      headers: { host: HOST_CANARY },
    });
    out.push({
      url,
      kind: 'xfh',
      headers: { 'x-forwarded-host': HOST_CANARY },
    });
    out.push({
      url,
      kind: 'xfp',
      headers: { 'x-forwarded-host': HOST_CANARY, 'x-forwarded-proto': 'https' },
    });
  } catch {
    return [];
  }
  return out;
}

export function hostHeaderReflected(probe: {
  body: string;
  headers: Record<string, string>;
  url: string;
}): boolean {
  if (probe.body.includes(HOST_CANARY)) return true;
  const loc = probe.headers['location'] ?? '';
  if (loc.includes(HOST_CANARY)) return true;
  const link = probe.headers['link'] ?? '';
  if (link.includes(HOST_CANARY)) return true;
  return false;
}

export function cachePoisoningSignals(headers: Record<string, string>): string[] {
  const hits: string[] = [];
  const cache = (headers['x-cache'] ?? headers['cf-cache-status'] ?? headers['age'] ?? '').toLowerCase();
  if (cache.includes('hit') || cache === '1' || Number(headers['age'] ?? '0') > 0) {
    hits.push('cache-hit-or-age');
  }
  if (headers['vary'] && !/host/i.test(headers['vary']) && !/x-forwarded-host/i.test(headers['vary'])) {
    hits.push('vary-missing-host');
  }
  return hits;
}

export function shouldProbeHostHeader(probe: {
  status: number;
  headers: Record<string, string>;
  body: string;
  error?: string;
}): boolean {
  if (probe.error || probe.status === 0) return false;
  if (probe.status >= 200 && probe.status < 500) return true;
  return false;
}
