// HTTP Parameter Pollution (HPP) GET canary helpers.
// Duplicate query params to detect first-wins vs last-wins backend splits.

export const HPP_CANARY = 'sfHpp9f3a7c';

export const HPP_PATHS: string[] = [
  '/api',
  '/api/v1',
  '/api/v1/users',
  '/api/v1/me',
  '/api/users',
  '/api/orders',
  '/search',
  '/filter',
  '/login',
  '/redirect',
];

export interface HppProbeUrl {
  url: string;
  baselineUrl: string;
  kind: 'duplicate-last' | 'duplicate-first' | 'array-style';
  param: string;
}

/**
 * Build HPP variants for a base URL. Uses an existing query param when present,
 * otherwise defaults to `id`.
 */
export function buildHppProbeUrls(baseUrl: string): HppProbeUrl[] {
  const out: HppProbeUrl[] = [];
  try {
    const base = new URL(baseUrl);
    const param =
      [...base.searchParams.keys()].find((k) => k && !k.includes('[') && k !== '__proto__') ?? 'id';
    const original = base.searchParams.get(param) ?? '1';

    const baseline = new URL(base.toString());
    baseline.search = '';
    baseline.searchParams.set(param, original);
    const baselineUrl = baseline.toString();

    // Last-wins pollution: id=1&id=CANARY
    const last = new URL(baselineUrl);
    last.searchParams.append(param, HPP_CANARY);
    out.push({ url: last.toString(), baselineUrl, kind: 'duplicate-last', param });

    // First-wins style via raw query (URLSearchParams would reorder): id=CANARY&id=1
    const first = new URL(baselineUrl);
    first.search = '';
    first.search = `?${encodeURIComponent(param)}=${encodeURIComponent(HPP_CANARY)}&${encodeURIComponent(param)}=${encodeURIComponent(original)}`;
    out.push({ url: first.toString(), baselineUrl, kind: 'duplicate-first', param });

    // PHP/Rails array style: id[]=1&id[]=CANARY
    const arr = new URL(baselineUrl);
    arr.search = '';
    arr.search = `?${encodeURIComponent(param)}[]=${encodeURIComponent(original)}&${encodeURIComponent(param)}[]=${encodeURIComponent(HPP_CANARY)}`;
    out.push({ url: arr.toString(), baselineUrl, kind: 'array-style', param });
  } catch {
    return [];
  }
  return out;
}

export function urlCarriesHppPayload(url: string): boolean {
  return url.includes(HPP_CANARY) || /(?:[?&]\w+(?:%5B%5D|\[\])?=.*){2,}/i.test(url);
}

export function hasHppCanaryReflection(body: string, probeUrl: string): boolean {
  if (!urlCarriesHppPayload(probeUrl)) return false;
  if (!body.includes(HPP_CANARY)) return false;
  // Prefer structured reflection over raw query echo.
  if (new RegExp(`"${HPP_CANARY}"`).test(body)) return true;
  if (new RegExp(`:\\s*${HPP_CANARY}\\b`).test(body)) return true;
  if (body.includes(HPP_CANARY) && /[{[]/.test(body) && !probeUrl.includes(body.slice(0, 40))) {
    return true;
  }
  return false;
}

/**
 * Behavioral delta: polluted response differs meaningfully from single-param baseline
 * (status change, body length swing, or privilege/identity fields diverge).
 */
export function hasHppBehavioralDelta(
  polluted: { status: number; body: string; headers: Record<string, string> },
  baseline: { status: number; body: string; headers: Record<string, string> } | undefined,
): boolean {
  if (!baseline) return false;
  if (polluted.status !== baseline.status) {
    // 2xx ↔ 4xx flip is interesting for auth bypass via HPP.
    if (
      (polluted.status >= 200 && polluted.status < 300 && baseline.status >= 400) ||
      (baseline.status >= 200 && baseline.status < 300 && polluted.status >= 400)
    ) {
      return true;
    }
  }
  if (polluted.body === baseline.body) return false;

  const privPolluted = /"role"\s*:\s*"admin"|"isAdmin"\s*:\s*true|"is_admin"\s*:\s*true/i.test(
    polluted.body,
  );
  const privBaseline = /"role"\s*:\s*"admin"|"isAdmin"\s*:\s*true|"is_admin"\s*:\s*true/i.test(
    baseline.body,
  );
  if (privPolluted && !privBaseline) return true;

  const emailP = polluted.body.match(/"(?:email|user_email)"\s*:\s*"([^"]+)"/i)?.[1];
  const emailB = baseline.body.match(/"(?:email|user_email)"\s*:\s*"([^"]+)"/i)?.[1];
  if (emailP && emailB && emailP.toLowerCase() !== emailB.toLowerCase()) return true;

  const lenDelta = Math.abs(polluted.body.length - baseline.body.length);
  if (lenDelta >= 40 && (hasHppCanaryReflection(polluted.body, 'x' + HPP_CANARY) || privPolluted)) {
    return true;
  }
  // Canary appears in polluted but not baseline.
  if (polluted.body.includes(HPP_CANARY) && !baseline.body.includes(HPP_CANARY)) return true;

  return false;
}

export function shouldProbeHpp(probe: {
  url: string;
  status: number;
  headers: Record<string, string>;
  body: string;
  error?: string;
}): boolean {
  if (probe.error || probe.status === 0) return false;
  if (probe.status < 200 || probe.status >= 500) return false;
  const path = safePath(probe.url);
  if (HPP_PATHS.some((p) => path === p || path.startsWith(p + '/') || path.endsWith(p))) return true;
  if (/[?&]\w+=/.test(probe.url)) return true;
  const ct = (probe.headers['content-type'] ?? '').toLowerCase();
  if (ct.includes('json') && path.includes('/api')) return true;
  return false;
}

function safePath(url: string): string {
  try {
    return new URL(url).pathname.toLowerCase();
  } catch {
    return url.toLowerCase();
  }
}
