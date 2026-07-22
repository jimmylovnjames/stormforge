// Authenticated differential access — compare unauth vs cookie-authenticated GETs.
// Requires SCAN_COOKIE (secret). Detection-only; never mutates remote state.

import type { Check, Finding, ProbeResult } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';

/** Scanner stamps these on differential probe pairs. */
export const DIFF_MARKER_HEADER = 'x-stormforge-diff';
export const DIFF_PAIR_HEADER = 'x-stormforge-diff-pair';

/** Strong account/PII markers (shared with auth-access intent). */
const MARKERS: { id: string; re: RegExp }[] = [
  { id: 'email', re: /"(?:email|user_email|mail)"\s*:\s*"[^"]+@[^"]+"/i },
  { id: 'phone', re: /"(?:phone|mobile|telephone)"\s*:\s*"?\+?\d{7,}"?/i },
  { id: 'api-key-field', re: /"(?:api_key|apiKey|access_token|refresh_token)"\s*:\s*"[^"]{12,}"/i },
  {
    id: 'admin-role',
    re: /"(?:role|roles|user_role)"\s*:\s*(?:"admin"|"root"|"superuser"|"super_admin"|\[[^\]]*"admin"[^\]]*\])/i,
  },
  { id: 'is-admin', re: /"(?:is_admin|isAdmin|is_staff|isStaff)"\s*:\s*true/i },
  { id: 'user-object', re: /"(?:user|account|profile)"\s*:\s*\{[^}]{0,200}"(?:id|email|username)"/i },
  { id: 'users-array', re: /"(?:users|accounts|results|data)"\s*:\s*\[\s*\{[^[\]]*(?:email|username)/i },
];

export function markerIds(body: string): string[] {
  return MARKERS.filter((m) => m.re.test(body)).map((m) => m.id);
}

export function authSessionConfigured(cookie?: string, authorization?: string): boolean {
  return Boolean((cookie && cookie.trim()) || (authorization && authorization.trim()));
}

/** Build Cookie / Authorization headers for authenticated probes. */
export function authProbeHeaders(cookie?: string, authorization?: string): Record<string, string> {
  const h: Record<string, string> = {};
  if (cookie?.trim()) h.cookie = cookie.trim();
  if (authorization?.trim()) h.authorization = authorization.trim();
  return h;
}

/**
 * Compare an unauthenticated probe against its authenticated twin.
 * Returns a finding when auth reveals more privilege/data than anonymous.
 */
export function compareAuthDifferential(unauth: ProbeResult, auth: ProbeResult): Finding | null {
  if (unauth.error || auth.error) return null;
  const unauthMarkers = markerIds(unauth.body ?? '');
  const authMarkers = markerIds(auth.body ?? '');
  const statusDelta = unauth.status !== auth.status;
  const bodyDelta = Math.abs((auth.body?.length ?? 0) - (unauth.body?.length ?? 0)) >= 64;
  const markerGain = authMarkers.filter((m) => !unauthMarkers.includes(m));
  const authGotData = auth.status >= 200 && auth.status < 300 && authMarkers.length >= 1;
  const unauthDenied =
    unauth.status === 401 ||
    unauth.status === 403 ||
    (unauth.status >= 200 && unauth.status < 300 && unauthMarkers.length === 0 && (unauth.body?.length ?? 0) < 80);

  // Classic: anonymous denied / empty, authenticated returns account markers.
  const classic = unauthDenied && authGotData;
  // Subtle: both 2xx but auth response gains PII markers or large body delta with markers.
  const subtle =
    unauth.status >= 200 &&
    unauth.status < 300 &&
    authGotData &&
    (markerGain.length >= 1 || (bodyDelta && authMarkers.length >= 2));

  if (!classic && !subtle) return null;
  // Avoid filing when unauth already had the same privileged data (public demo).
  if (unauthMarkers.length >= 2 && markerGain.length === 0 && !statusDelta) return null;

  const severity: Finding['severity'] =
    authMarkers.includes('admin-role') || authMarkers.includes('is-admin') ? 'critical' : 'high';

  return {
    id: makeFindingId('auth-differential', auth.url, `${unauth.status}->${auth.status}:${authMarkers.sort().join(',')}`),
    checkId: 'auth-differential',
    title: classic
      ? `Authenticated differential access — anonymous denied, session reveals data`
      : `Authenticated differential — session response discloses extra account data`,
    severity,
    target: auth.url,
    description:
      'Comparing an unauthenticated GET against the same URL with an operator-supplied session cookie/Authorization shows a meaningful privilege or data delta. This confirms the endpoint is auth-gated and exposes account/PII to the session — useful for IDOR follow-up and access-control reports.',
    evidence: `URL: ${auth.url}\nUnauth status: ${unauth.status} (markers: ${unauthMarkers.join(', ') || 'none'}, bodyLen=${unauth.body?.length ?? 0})\nAuth status: ${auth.status} (markers: ${authMarkers.join(', ') || 'none'}, bodyLen=${auth.body?.length ?? 0})\nMarker gain: ${markerGain.join(', ') || 'none'}\nStatus delta: ${statusDelta}\nBody delta ≥64B: ${bodyDelta}`,
    reproduction: [
      `curl -s -o /dev/null -w '%{http_code}' '${auth.url}'`,
      `curl -s -H 'Cookie: <session>' '${auth.url}'  # or Authorization header`,
      'Confirm anonymous is denied/empty while the session returns account fields',
      'If IDOR-shaped: repeat with neighboring object IDs under the same session (read-only)',
    ],
    remediation:
      'Enforce object-level authorization independent of mere authentication; ensure anonymous callers always receive 401/403 without data leakage; avoid reflecting other users’ objects to any authenticated caller.',
    cwe: 'CWE-284',
    references: [
      'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/',
      'https://cwe.mitre.org/data/definitions/284.html',
    ],
    needsManualReview: true,
    evidenceGrade: 'canary',
    confidence: classic ? 0.9 : 0.78,
    submitReady: classic && authMarkers.length >= 1,
    source: 'worker',
    discoveredAt: new Date().toISOString(),
  };
}

export const authDifferentialCheck: Check = {
  id: 'auth-differential',
  title: 'Authenticated differential access',
  cwe: 'CWE-284',
  run(probe: ProbeResult, ctx): Finding[] {
    if ((probe.headers[DIFF_MARKER_HEADER] ?? '') !== 'auth') return [];
    const pairKey = probe.headers[DIFF_PAIR_HEADER] ?? probe.url;
    const siblings = ctx.siblings ?? [];
    const unauth = siblings.find(
      (s) =>
        (s.headers[DIFF_MARKER_HEADER] ?? '') === 'unauth' &&
        (s.headers[DIFF_PAIR_HEADER] ?? s.url) === pairKey,
    );
    if (!unauth) return [];
    const f = compareAuthDifferential(unauth, probe);
    return f ? [f] : [];
  },
};
