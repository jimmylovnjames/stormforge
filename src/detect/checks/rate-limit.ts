// Rate limiting / DoS / brute-force surface detection.
//
// Passive: inspects response headers and auth-related path/body signals.
// Missing RateLimit-* / X-RateLimit-* on login/token/OTP surfaces is high
// severity (credential stuffing / online guessing). A 429 response is treated
// as evidence that limiting exists (no missing-header finding). Never floods
// the target — StormForge only issues single safe GETs.

import type { Check, Finding, ProbeResult, Severity } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';

/** Common rate-limit / quota response headers (lower-cased). */
export const RATE_LIMIT_HEADER_NAMES = [
  'ratelimit-limit',
  'ratelimit-remaining',
  'ratelimit-reset',
  'ratelimit-policy',
  'x-ratelimit-limit',
  'x-ratelimit-remaining',
  'x-ratelimit-reset',
  'x-rate-limit-limit',
  'x-rate-limit-remaining',
  'x-rate-limit-reset',
  'x-ratelimit-requests-limit',
  'x-ratelimit-requests-remaining',
] as const;

const LOGIN_FORM =
  /<form[^>]*>[\s\S]{0,4000}?(?:type=["']password["']|name=["']password["'])/i;

const STATIC_EXT = /\.(?:css|js|mjs|map|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|webp|pdf|xml|txt)$/i;

export type AuthSurfaceKind = 'login' | 'token' | 'password-reset' | 'otp' | 'register' | 'api-auth';

export interface AuthSurface {
  kind: AuthSurfaceKind;
  label: string;
}

export function hasRateLimitHeaders(headers: Record<string, string>): boolean {
  return RATE_LIMIT_HEADER_NAMES.some((h) => headers[h] !== undefined && headers[h] !== '');
}

/** Server clearly enforces limiting on this response. */
export function showsRateLimiting(probe: ProbeResult): boolean {
  if (probe.status === 429) return true;
  if (hasRateLimitHeaders(probe.headers)) return true;
  // Some stacks only send Retry-After with 429; still count as limiting signal.
  if (probe.status === 429 && probe.headers['retry-after']) return true;
  return false;
}

export function classifyAuthSurface(url: string, body = '', headers: Record<string, string> = {}): AuthSurface | null {
  let pathname: string;
  try {
    pathname = new URL(url).pathname.toLowerCase();
  } catch {
    pathname = url.toLowerCase();
  }
  if (pathname.length > 1 && pathname.endsWith('/')) pathname = pathname.slice(0, -1);

  if (STATIC_EXT.test(pathname)) return null;

  if (/\/(?:forgot|reset)[-_]?password(?:\/|$)/.test(pathname) || /\/password\/(?:forgot|reset)(?:\/|$)/.test(pathname)) {
    return { kind: 'password-reset', label: pathname };
  }
  if (/\/(?:otp|mfa|2fa|totp|verify[-_]?code)(?:\/|$)/.test(pathname)) {
    return { kind: 'otp', label: pathname };
  }
  if (/\/oauth(?:2)?\/token(?:\/|$)/.test(pathname) || /\/(?:api\/)?(?:v\d+\/)?token(?:\/|$)/.test(pathname)) {
    return { kind: 'token', label: pathname };
  }
  if (/\/(?:sign[-_]?up|register|registration)(?:\/|$)/.test(pathname)) {
    return { kind: 'register', label: pathname };
  }
  if (
    /\/(?:login|signin|sign[-_]?in|log[-_]?in|authenticate)(?:\/|$)/.test(pathname) ||
    /\/auth(?:\/login)?(?:\/|$)/.test(pathname) ||
    /\/session(?:\/|$)/.test(pathname)
  ) {
    return { kind: 'login', label: pathname };
  }
  if (/\/api\/(?:v\d+\/)?(?:auth|login|signin)(?:\/|$)/.test(pathname)) {
    return { kind: 'api-auth', label: pathname };
  }

  // Body / header soft signals for auth pages served on generic paths.
  if (LOGIN_FORM.test(body)) return { kind: 'login', label: `${pathname} (login form)` };
  if (headers['www-authenticate']) return { kind: 'api-auth', label: `${pathname} (WWW-Authenticate)` };

  return null;
}

function isApiJsonSurface(probe: ProbeResult): boolean {
  const ct = (probe.headers['content-type'] ?? '').toLowerCase();
  if (ct.includes('application/json')) return true;
  let path: string;
  try {
    path = new URL(probe.finalUrl ?? probe.url).pathname.toLowerCase();
  } catch {
    path = probe.url.toLowerCase();
  }
  return /\/api(?:\/|$)/.test(path);
}

function severityFor(surface: AuthSurface | null, apiJson: boolean): Severity | null {
  if (surface) {
    // Unprotected auth / token / OTP / reset → high (brute-force / stuffing).
    return 'high';
  }
  if (apiJson) return 'medium';
  return null;
}

export const rateLimitCheck: Check = {
  id: 'rate-limit-missing',
  title: 'Missing rate limiting signals',
  cwe: 'CWE-770',
  run(probe: ProbeResult): Finding[] {
    if (probe.error || probe.status === 0) return [];

    // 429 proves limiting exists — optionally note missing Retry-After only.
    if (probe.status === 429) {
      if (!probe.headers['retry-after']) {
        return [
          {
            id: makeFindingId(this.id, probe.url, '429-no-retry-after'),
            checkId: this.id,
            title: '429 Too Many Requests without Retry-After',
            severity: 'low',
            target: probe.url,
            description:
              'The endpoint returned HTTP 429 (rate limited) but omitted `Retry-After`, which makes well-behaved clients retry aggressively and can amplify load.',
            evidence: `URL: ${probe.url}\nStatus: 429\nRetry-After: <absent>\nRateLimit headers present: ${hasRateLimitHeaders(probe.headers)}`,
            reproduction: [`curl -sI '${probe.url}'`, 'Trigger enough requests to obtain 429', 'Observe Retry-After is missing'],
            remediation: 'Include a `Retry-After` (or RateLimit-Reset) header on 429 responses.',
            cwe: 'CWE-770',
            references: [
              'https://cwe.mitre.org/data/definitions/770.html',
              'https://www.rfc-editor.org/rfc/rfc6585#section-4',
            ],
            needsManualReview: false,
            discoveredAt: new Date().toISOString(),
          },
        ];
      }
      return [];
    }

    if (showsRateLimiting(probe)) return [];

    const surface = classifyAuthSurface(probe.finalUrl ?? probe.url, probe.body, probe.headers);
    const apiJson = isApiJsonSurface(probe);
    const severity = severityFor(surface, apiJson);
    if (!severity) return [];

    // Skip empty error shells that are clearly CDN blocks without auth semantics.
    if (!surface && (probe.status === 404 || probe.status === 410)) return [];

    const kind = surface?.kind ?? 'api';
    const title = surface
      ? `Missing rate-limit headers on ${surface.kind} endpoint (${surface.label})`
      : 'Missing rate-limit headers on API response';

    return [
      {
        id: makeFindingId(this.id, probe.url, `missing:${kind}`),
        checkId: this.id,
        title,
        severity,
        target: probe.url,
        description: surface
          ? `An authentication-related surface (${surface.kind}) responded without RateLimit / X-RateLimit headers and was not HTTP 429. Without request throttling, attackers can brute-force credentials, OTPs, or tokens (credential stuffing / online guessing) and cause availability impact.`
          : 'An API response lacked RateLimit / X-RateLimit headers. Missing quota signals often correlate with weak or absent request throttling, increasing DoS and abuse risk.',
        evidence: `URL: ${probe.url}\nStatus: ${probe.status}\nSurface: ${surface ? surface.kind : 'api-json'}\nChecked headers: ${RATE_LIMIT_HEADER_NAMES.join(', ')}\nPresent: none`,
        reproduction: [
          `curl -sI '${probe.url}'`,
          'Confirm RateLimit-* / X-RateLimit-* headers are absent',
          'Manually verify throttling with a small authorized burst (do not DoS) — missing headers alone are a signal, not proof',
        ],
        remediation:
          'Apply per-IP and per-account rate limits on auth, token, OTP, and password-reset endpoints; emit standardized RateLimit headers; return 429 with Retry-After when limits are exceeded.',
        cwe: 'CWE-770',
        references: [
          'https://cwe.mitre.org/data/definitions/770.html',
          'https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks',
          'https://datatracker.ietf.org/doc/html/draft-ietf-httpapi-ratelimit-headers',
        ],
        needsManualReview: true,
        discoveredAt: new Date().toISOString(),
      },
    ];
  },
};
