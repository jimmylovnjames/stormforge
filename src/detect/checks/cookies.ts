// Insecure cookie attributes. Passive: inspects Set-Cookie headers.

import type { Check, Finding, ProbeResult } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';

export const cookiesCheck: Check = {
  id: 'insecure-cookies',
  title: 'Insecure cookie attributes',
  cwe: 'CWE-614',
  run(probe: ProbeResult): Finding[] {
    if (probe.error) return [];
    // Workers Headers collapses duplicate Set-Cookie with ", " — split carefully.
    const raw = probe.headers['set-cookie'];
    if (!raw) return [];

    const cookies = splitSetCookie(raw);
    const findings: Finding[] = [];

    for (const cookie of cookies) {
      const name = cookie.split('=')[0]?.trim() ?? 'cookie';
      const attrs = parseCookieAttrs(cookie);
      const looksSession = /sess|token|auth|sid|jwt|login|csrf/i.test(name);

      // ── Prefix policy violations ───────────────────────────────────────
      if (name.startsWith('__Host-')) {
        const hostIssues: string[] = [];
        if (!attrs.secure) hostIssues.push('missing Secure');
        if (attrs.domain) hostIssues.push('Domain is set (forbidden)');
        if (attrs.path !== '/') hostIssues.push('Path must be /');
        if (hostIssues.length) {
          findings.push({
            id: makeFindingId(this.id, probe.url, `host-prefix:${name}`),
            checkId: this.id,
            title: `__Host- cookie "${name}" violates prefix rules (${hostIssues.join(', ')})`,
            severity: 'medium',
            target: probe.url,
            description: `Cookie "${name}" uses the __Host- prefix but violates required constraints (${hostIssues.join(
              ', ',
            )}). Browsers may reject it or the app may be relying on a false sense of host-only binding.`,
            evidence: `URL: ${probe.url}\nSet-Cookie: ${cookie}`,
            reproduction: [`curl -sI ${probe.url}`, `Inspect Set-Cookie for "${name}"`],
            remediation:
              'For __Host- cookies: set Secure, Path=/, and omit Domain. Prefer SameSite=Strict|Lax.',
            cwe: 'CWE-614',
            references: [
              'https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis#name-cookie-name-prefixes',
              'https://cwe.mitre.org/data/definitions/614.html',
            ],
            needsManualReview: false,
            discoveredAt: new Date().toISOString(),
          });
        }
      }

      if (name.startsWith('__Secure-') && !attrs.secure) {
        findings.push({
          id: makeFindingId(this.id, probe.url, `secure-prefix:${name}`),
          checkId: this.id,
          title: `__Secure- cookie "${name}" missing Secure attribute`,
          severity: 'medium',
          target: probe.url,
          description: `Cookie "${name}" uses the __Secure- prefix but is missing the Secure attribute. Browsers reject such cookies; misconfiguration often indicates broken session hardening.`,
          evidence: `URL: ${probe.url}\nSet-Cookie: ${cookie}`,
          reproduction: [`curl -sI ${probe.url}`, `Inspect Set-Cookie for "${name}"`],
          remediation: 'Always set Secure on __Secure- prefixed cookies (and prefer HttpOnly + SameSite).',
          cwe: 'CWE-614',
          references: ['https://cwe.mitre.org/data/definitions/614.html'],
          needsManualReview: false,
          discoveredAt: new Date().toISOString(),
        });
      }

      // ── SameSite=None without Secure ───────────────────────────────────
      if (attrs.sameSite === 'none' && !attrs.secure) {
        findings.push({
          id: makeFindingId(this.id, probe.url, `samesite-none:${name}`),
          checkId: this.id,
          title: `Cookie "${name}" uses SameSite=None without Secure`,
          severity: looksSession ? 'medium' : 'low',
          target: probe.url,
          description: `Cookie "${name}" sets SameSite=None but omits Secure. Modern browsers reject or restrict this combination, and cross-site cookies without Secure enable interception on HTTP.`,
          evidence: `URL: ${probe.url}\nSet-Cookie: ${cookie}`,
          reproduction: [`curl -sI ${probe.url}`, `Confirm SameSite=None without Secure on "${name}"`],
          remediation: 'Pair SameSite=None with Secure, or use Lax/Strict when cross-site cookies are unnecessary.',
          cwe: 'CWE-614',
          references: [
            'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#samesitenone_requires_secure',
            'https://cwe.mitre.org/data/definitions/614.html',
          ],
          needsManualReview: false,
          discoveredAt: new Date().toISOString(),
        });
      }

      // ── Missing core attributes ────────────────────────────────────────
      const issues: string[] = [];
      if (!attrs.secure) issues.push('missing Secure');
      if (!attrs.httpOnly) issues.push('missing HttpOnly');
      if (!attrs.sameSite) issues.push('missing SameSite');

      if (issues.length === 0) continue;

      findings.push({
        id: makeFindingId(this.id, probe.url, name),
        checkId: this.id,
        title: `Cookie "${name}" set without ${issues.join(', ')}`,
        severity: looksSession ? 'medium' : 'info',
        target: probe.url,
        description: `The cookie "${name}" is set with insecure attributes (${issues.join(', ')}). ${
          looksSession ? 'This appears to be a session/auth cookie, raising the impact.' : ''
        }`,
        evidence: `URL: ${probe.url}\nSet-Cookie: ${cookie}`,
        reproduction: [`curl -sI ${probe.url}`, `Inspect the Set-Cookie header for "${name}"`],
        remediation: 'Set Secure, HttpOnly, and an appropriate SameSite attribute on sensitive cookies.',
        cwe: 'CWE-614',
        references: ['https://cwe.mitre.org/data/definitions/614.html'],
        needsManualReview: false,
        discoveredAt: new Date().toISOString(),
      });
    }
    return findings;
  },
};

/** Split a collapsed Set-Cookie header into individual cookies. */
export function splitSetCookie(raw: string): string[] {
  // Split on commas that precede a `token=` pattern (cookie boundary), not on
  // commas inside Expires dates ("Wed, 09 Jun ...").
  return raw
    .split(/,(?=\s*[^;=,\s]+=)/)
    .map((s) => s.trim())
    .filter(Boolean);
}

interface CookieAttrs {
  secure: boolean;
  httpOnly: boolean;
  sameSite?: string;
  domain?: string;
  path?: string;
}

function parseCookieAttrs(cookie: string): CookieAttrs {
  const parts = cookie.split(';').map((p) => p.trim());
  const attrs: CookieAttrs = { secure: false, httpOnly: false };
  for (let i = 1; i < parts.length; i++) {
    const part = parts[i]!;
    const eq = part.indexOf('=');
    const key = (eq >= 0 ? part.slice(0, eq) : part).trim().toLowerCase();
    const val = eq >= 0 ? part.slice(eq + 1).trim() : '';
    if (key === 'secure') attrs.secure = true;
    else if (key === 'httponly') attrs.httpOnly = true;
    else if (key === 'samesite') attrs.sameSite = val.toLowerCase();
    else if (key === 'domain') attrs.domain = val;
    else if (key === 'path') attrs.path = val;
  }
  return attrs;
}
