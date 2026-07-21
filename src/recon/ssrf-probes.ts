// Safe GET helpers for open-redirect and SSRF canary probes.
// All requests hit in-scope hosts only; canary/metadata values are query params.
// Never directly contacts link-local metadata IPs from the Worker.

/** External host used only as an open-redirect destination canary. */
export const REDIRECT_CANARY_HOST = 'stormforge-redirect.example';
export const REDIRECT_CANARY_URL = `https://${REDIRECT_CANARY_HOST}/sf-open-redirect`;

/** Cloud / loopback targets embedded as url= values to detect SSRF sinks. */
export const SSRF_METADATA_TARGETS = [
  'http://169.254.169.254/latest/meta-data/',
  'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
  'http://metadata.google.internal/computeMetadata/v1/',
  'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
] as const;

export const SSRF_LOOPBACK_TARGETS = [
  'http://127.0.0.1/',
  'http://localhost/',
  'http://[::1]/',
] as const;

/** Query params commonly used for redirects and server-side fetches. */
export const URL_PARAM_NAMES = [
  'url',
  'uri',
  'redirect',
  'redirect_uri',
  'redirect_url',
  'next',
  'return',
  'returnTo',
  'return_to',
  'goto',
  'dest',
  'destination',
  'continue',
  'target',
  'link',
  'feed',
  'u',
  'r',
  'path',
  'image',
  'src',
  'file',
] as const;

/** Paths that often accept redirect / fetch URL parameters. */
export const REDIRECT_SSRF_PATHS: string[] = [
  '/redirect',
  '/redir',
  '/out',
  '/outbound',
  '/go',
  '/goto',
  '/jump',
  '/leave',
  '/away',
  '/link',
  '/login',
  '/logout',
  '/signin',
  '/callback',
  '/oauth/callback',
  '/auth/callback',
  '/return',
  '/next',
  '/proxy',
  '/fetch',
  '/load',
  '/url',
  '/api/proxy',
  '/api/fetch',
  '/api/url',
  '/api/v1/proxy',
  '/api/v1/fetch',
  '/image',
  '/img',
  '/avatar',
  '/webhook',
  '/hook',
];

export interface SsrfRedirectProbeUrls {
  openRedirect: string[];
  metadata: string[];
  loopback: string[];
}

export function buildSsrfRedirectProbeUrls(baseUrl: string, maxParams = 2): SsrfRedirectProbeUrls {
  const openRedirect: string[] = [];
  const metadata: string[] = [];
  const loopback: string[] = [];
  try {
    const params = URL_PARAM_NAMES.slice(0, maxParams);
    for (const param of params) {
      openRedirect.push(withParam(baseUrl, param, REDIRECT_CANARY_URL));
      metadata.push(withParam(baseUrl, param, SSRF_METADATA_TARGETS[0]));
      loopback.push(withParam(baseUrl, param, SSRF_LOOPBACK_TARGETS[0]));
    }
    // One extra high-value metadata variant on the first param.
    if (params[0]) {
      metadata.push(withParam(baseUrl, params[0], SSRF_METADATA_TARGETS[1]));
      metadata.push(withParam(baseUrl, params[0], SSRF_METADATA_TARGETS[2]));
    }
  } catch {
    return { openRedirect: [], metadata: [], loopback: [] };
  }
  return { openRedirect, metadata, loopback };
}

function withParam(baseUrl: string, param: string, value: string): string {
  const u = new URL(baseUrl);
  for (const p of URL_PARAM_NAMES) u.searchParams.delete(p);
  u.searchParams.set(param, value);
  return u.toString();
}

export function urlCarriesRedirectCanary(url: string): boolean {
  return paramValues(url).some((v) => v.includes(REDIRECT_CANARY_HOST));
}

export function urlCarriesMetadataTarget(url: string): boolean {
  return paramValues(url).some(
    (v) =>
      v.includes('169.254.169.254') ||
      v.includes('metadata.google.internal') ||
      /metadata\/instance/i.test(v),
  );
}

export function urlCarriesLoopbackTarget(url: string): boolean {
  return paramValues(url).some(
    (v) =>
      /https?:\/\/127\.0\.0\.1\b/i.test(v) ||
      /https?:\/\/localhost\b/i.test(v) ||
      /https?:\/\/\[::1\]/i.test(v),
  );
}

function paramValues(url: string): string[] {
  try {
    return [...new URL(url).searchParams.values()];
  } catch {
    return [];
  }
}

/** Open redirect confirmed via Location, finalUrl, or meta/JS redirect to canary. */
export function hasOpenRedirectToCanary(probe: {
  url: string;
  finalUrl?: string;
  status: number;
  headers: Record<string, string>;
  body: string;
}): boolean {
  if (!urlCarriesRedirectCanary(probe.url)) return false;
  if (hostOf(probe.finalUrl) === REDIRECT_CANARY_HOST) return true;
  const location = probe.headers['location'] ?? '';
  if (location.includes(REDIRECT_CANARY_HOST)) return true;
  if (new RegExp(`content=["'][^"']*${REDIRECT_CANARY_HOST}`, 'i').test(probe.body)) return true;
  if (new RegExp(`(?:location|href)\\s*=\\s*["'][^"']*${REDIRECT_CANARY_HOST}`, 'i').test(probe.body)) {
    return true;
  }
  return false;
}

export type MetadataCloud = 'aws' | 'gcp' | 'azure' | 'generic';

/** Cloud metadata document signatures in a response body. */
export function detectCloudMetadataExposure(body: string): MetadataCloud | null {
  if (!body || body.length < 8) return null;

  // AWS IMDS / IAM credentials JSON
  if (
    (/"AccessKeyId"\s*:\s*"(?:AKIA|ASIA)[^"]{8,}"/i.test(body) && /SecretAccessKey/i.test(body)) ||
    (/\bami-[0-9a-z]+/.test(body) && /\binstance-id\b/i.test(body)) ||
    (/^\s*ami-id\s*$/m.test(body) && /instance-id/i.test(body)) ||
    (/local-ipv4|public-ipv4|security-credentials/i.test(body) &&
      /169\.254\.169\.254|meta-data/i.test(body))
  ) {
    return 'aws';
  }

  // GCP metadata
  if (
    /computeMetadata|metadata\.google\.internal/i.test(body) &&
    (/attributes\//i.test(body) || /serviceAccounts\//i.test(body) || /"projectId"/i.test(body))
  ) {
    return 'gcp';
  }
  if (/"projectId"\s*:\s*"[^"]+"/i.test(body) && /"numericProjectId"/i.test(body)) {
    return 'gcp';
  }

  // Azure IMDS
  if (
    (/azurenvironment|subscriptionid|vmId|resourceGroupName/i.test(body) &&
      /api-version=|metadata\/instance/i.test(body)) ||
    (/"compute"\s*:\s*\{/i.test(body) && /"azEnvironment"/i.test(body))
  ) {
    return 'azure';
  }

  // Generic IMDS directory listing
  if (
    /(?:^|\n)\s*(?:meta-data|latest|iam|hostname|public-keys)\/?\s*(?:\n|$)/i.test(body) &&
    /169\.254\.169\.254|meta-data/i.test(body)
  ) {
    return 'generic';
  }

  return null;
}

/** Soft SSRF signal: response discusses loopback/metadata fetch errors after our probe. */
export function hasSsrfFetchSignal(body: string, probeUrl: string): boolean {
  if (!urlCarriesMetadataTarget(probeUrl) && !urlCarriesLoopbackTarget(probeUrl)) return false;
  return (
    /connection refused|ECONNREFUSED|connect\(\) failed|Failed to connect|Name or service not known|getaddrinfo|ENOTFOUND|169\.254\.169\.254|metadata\.google\.internal/i.test(
      body,
    ) || /curl_error|httpx\.ConnectError|requests\.exceptions/i.test(body)
  );
}

export function shouldProbeSsrfRedirect(probe: {
  url: string;
  status: number;
  headers: Record<string, string>;
  body: string;
  error?: string;
}): boolean {
  if (probe.error) return false;
  if (probe.status === 0) return false;
  const path = safePath(probe.url);
  if (REDIRECT_SSRF_PATHS.some((p) => path === p || path.endsWith(p))) return true;
  // HTML with outbound links / forms mentioning redirect params
  const ct = (probe.headers['content-type'] ?? '').toLowerCase();
  if (ct.includes('text/html') && /name=["'](?:url|redirect|next|return|goto)["']/i.test(probe.body)) {
    return true;
  }
  if (/[?&](?:url|redirect|next|return|goto|dest)=/i.test(probe.url)) return true;
  return false;
}

function hostOf(url?: string): string | null {
  if (!url) return null;
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

function safePath(url: string): string {
  try {
    return new URL(url).pathname.toLowerCase();
  } catch {
    return url.toLowerCase();
  }
}
