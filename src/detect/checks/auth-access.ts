// Auth bypass / IDOR detection from unauthenticated 2xx probes.
//
// StormForge only issues unauthenticated safe GETs. When a sensitive
// /user|/api/v1/... path returns 2xx AND the body confirms user/object data
// (email, roles, etc.), flag a candidate access-control issue.
// Path/status alone never flags — body signatures keep false positives low.

import type { Check, Finding, ProbeResult } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';

interface PathClass {
  kind: 'idor' | 'auth-bypass' | 'admin-bypass';
  label: string;
}

/** Strong PII / account markers — need ≥2 (or 1 admin-role) to confirm. */
const STRONG_MARKERS: { id: string; re: RegExp }[] = [
  { id: 'email', re: /"(?:email|user_email|mail)"\s*:\s*"[^"]+@[^"]+"/i },
  { id: 'phone', re: /"(?:phone|mobile|telephone)"\s*:\s*"?\+?\d{7,}"?/i },
  { id: 'password-hash', re: /"(?:password|passwd|password_hash|hashed_password)"\s*:\s*"[^"]{8,}"/i },
  { id: 'ssn', re: /"(?:ssn|social_security)"\s*:\s*"?\d{3}-?\d{2}-?\d{4}"?/i },
  { id: 'api-key-field', re: /"(?:api_key|apiKey|access_token|refresh_token)"\s*:\s*"[^"]{12,}"/i },
  { id: 'admin-role', re: /"(?:role|roles|user_role)"\s*:\s*(?:"admin"|"root"|"superuser"|"super_admin"|\[[^\]]*"admin"[^\]]*\])/i },
  { id: 'is-admin', re: /"(?:is_admin|isAdmin|is_staff|isStaff)"\s*:\s*true/i },
  { id: 'user-object', re: /"(?:user|account|profile)"\s*:\s*\{[^}]{0,200}"(?:id|email|username)"/i },
  { id: 'users-array', re: /"(?:users|accounts|results|data)"\s*:\s*\[\s*\{[^[\]]*(?:email|username)/i },
];

const LOGIN_PAGE =
  /<form[^>]*(?:login|signin|sign-in|password)[^>]*>|(?:name|id)=["'](?:username|password|email)["']/i;

export const authAccessCheck: Check = {
  id: 'auth-access-control',
  title: 'Auth bypass / IDOR (unauthenticated object access)',
  cwe: 'CWE-284',
  run(probe: ProbeResult): Finding[] {
    if (probe.error || !probe.body) return [];
    if (probe.status < 200 || probe.status >= 300) return [];

    const pathClass = classifyPath(probe.finalUrl ?? probe.url);
    if (!pathClass) return [];

    // Skip obvious login/HTML chrome with no JSON account data.
    const ct = (probe.headers['content-type'] ?? '').toLowerCase();
    if (ct.includes('text/html') && LOGIN_PAGE.test(probe.body) && !hasJsonAccountShape(probe.body)) {
      return [];
    }

    const markers = STRONG_MARKERS.filter((m) => m.re.test(probe.body)).map((m) => m.id);
    const hasAdmin = markers.includes('admin-role') || markers.includes('is-admin');
    const confirmed = hasAdmin || markers.length >= 2;
    if (!confirmed) return [];

    const severity: Finding['severity'] = hasAdmin || pathClass.kind === 'admin-bypass' ? 'critical' : 'high';
    const cwe = pathClass.kind === 'idor' ? 'CWE-639' : 'CWE-284';

    return [
      {
        id: makeFindingId(this.id, probe.url, `${pathClass.kind}:${markers.sort().join(',')}`),
        checkId: this.id,
        title:
          pathClass.kind === 'idor'
            ? `Possible IDOR — unauthenticated access via predictable ID (${pathClass.label})`
            : pathClass.kind === 'admin-bypass'
              ? `Possible admin auth bypass (${pathClass.label})`
              : `Possible missing authentication on ${pathClass.label}`,
        severity,
        target: probe.url,
        description:
          pathClass.kind === 'idor'
            ? `An unauthenticated GET to a predictable object path returned 2xx with account/PII markers (${markers.join(', ')}). This is a strong IDOR / broken object-level authorization candidate.`
            : `An unauthenticated GET to a sensitive auth surface returned 2xx with account/PII markers (${markers.join(', ')}). Authorization may be missing or ineffective.`,
        evidence: `URL: ${probe.url}\nStatus: ${probe.status}\nPath class: ${pathClass.kind}\nMarkers: ${markers.join(', ')}\nBody preview: ${preview(probe.body)}`,
        reproduction: [
          `curl -s '${probe.url}'`,
          'Confirm the response is 2xx and contains account fields without any Authorization / session cookie',
          'If IDOR: repeat with neighboring IDs (e.g. /users/2) and confirm cross-object reads — do not modify data',
          'Verify manually before reporting (public demo data can look similar)',
        ],
        remediation:
          pathClass.kind === 'idor'
            ? 'Enforce object-level authorization on every request; use opaque IDs; never trust client-supplied object identifiers alone.'
            : 'Require authentication and authorization on all account/admin API routes; return 401/403 for anonymous callers.',
        cwe,
        references: [
          `https://cwe.mitre.org/data/definitions/${cwe.replace('CWE-', '')}.html`,
          'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/',
          'https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/',
        ],
        needsManualReview: true,
        discoveredAt: new Date().toISOString(),
      },
    ];
  },
};

export function classifyPath(url: string): PathClass | null {
  let pathname: string;
  try {
    pathname = new URL(url).pathname.toLowerCase();
  } catch {
    pathname = url.toLowerCase();
  }

  // Strip trailing slash for matching (keep root as "/").
  if (pathname.length > 1 && pathname.endsWith('/')) pathname = pathname.slice(0, -1);

  if (
    /\/admin(?:\/|$)/.test(pathname) ||
    /\/api\/v\d+\/admin(?:\/|$)/.test(pathname) ||
    /\/api\/admin(?:\/|$)/.test(pathname)
  ) {
    return { kind: 'admin-bypass', label: pathname };
  }

  // Predictable object ID in path → IDOR class.
  if (
    /\/(?:users?|accounts?|profiles?|orders?|customers?)\/(?:\d+|me)(?:\/|$)/.test(pathname) ||
    /\/(?:user|account|profile|order)\/(?:\d+|me)(?:\/|$)/.test(pathname)
  ) {
    return { kind: 'idor', label: pathname };
  }

  // Collection / self endpoints that should normally require auth.
  if (
    /\/(?:api\/)?(?:v\d+\/)?(?:me|users?|accounts?|profiles?|session)(?:\/|$)/.test(pathname) ||
    pathname === '/me' ||
    pathname === '/user' ||
    pathname === '/users' ||
    pathname === '/account' ||
    pathname === '/profile'
  ) {
    return { kind: 'auth-bypass', label: pathname };
  }

  return null;
}

function hasJsonAccountShape(body: string): boolean {
  return /"(?:email|username|user)"\s*:/.test(body) && /[{[]/.test(body);
}

function preview(body: string): string {
  return body.slice(0, 240).replace(/\s+/g, ' ');
}
