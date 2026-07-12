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
      const lower = cookie.toLowerCase();
      const issues: string[] = [];
      if (!lower.includes('secure')) issues.push('missing Secure');
      if (!lower.includes('httponly')) issues.push('missing HttpOnly');
      if (!lower.includes('samesite')) issues.push('missing SameSite');

      if (issues.length === 0) continue;

      // Session-looking cookies are higher signal.
      const looksSession = /sess|token|auth|sid|jwt/i.test(name);
      findings.push({
        id: makeFindingId(this.id, probe.url, name),
        checkId: this.id,
        title: `Cookie "${name}" set without ${issues.join(', ')}`,
        severity: looksSession ? 'low' : 'info',
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
