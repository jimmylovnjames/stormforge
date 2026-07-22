// Weak CSP analysis — missing CSP is covered by security-headers; this flags
// dangerous present policies (unsafe-inline / wildcard script-src).

import type { Check, Finding, ProbeResult } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';

export const weakCspCheck: Check = {
  id: 'weak-csp',
  title: 'Weak Content Security Policy',
  cwe: 'CWE-1021',
  run(probe: ProbeResult): Finding[] {
    if (probe.error || probe.status === 0) return [];
    const contentType = probe.headers['content-type'] ?? '';
    const isDocument = contentType.includes('text/html') || contentType === '';
    if (!isDocument) return [];

    const csp = probe.headers['content-security-policy'];
    if (!csp) return [];

    const issues: string[] = [];
    if (/script-src[^;]*'unsafe-inline'/i.test(csp) || (/script-src/i.test(csp) === false && /default-src[^;]*'unsafe-inline'/i.test(csp))) {
      issues.push("'unsafe-inline' in script-src/default-src");
    }
    if (/script-src[^;]*\*/i.test(csp) || (/script-src/i.test(csp) === false && /default-src[^;]*\*/i.test(csp))) {
      issues.push('wildcard (*) script-src/default-src');
    }
    if (/script-src[^;]*'unsafe-eval'/i.test(csp) || (/script-src/i.test(csp) === false && /default-src[^;]*'unsafe-eval'/i.test(csp))) {
      issues.push("'unsafe-eval' in script-src/default-src");
    }
    if (/object-src[^;]*\*/i.test(csp) || (!/object-src/i.test(csp) && /default-src[^;]*\*/i.test(csp))) {
      // only flag object-src * explicitly if present
    }
    if (/object-src[^;]*\*/i.test(csp)) {
      issues.push('object-src *');
    }

    if (!issues.length) return [];

    const highSignal = issues.some((i) => i.includes('unsafe-inline') || i.includes('wildcard'));
    return [
      {
        id: makeFindingId(this.id, probe.url, issues.join('|')),
        checkId: this.id,
        title: `Weak CSP (${issues[0]})`,
        severity: highSignal ? 'medium' : 'low',
        target: probe.url,
        description: `Content-Security-Policy is present but weak: ${issues.join('; ')}. This often enables XSS chains when a reflection sink exists.`,
        evidence: `URL: ${probe.url}\nContent-Security-Policy: ${csp}`,
        reproduction: [`curl -sI ${probe.url}`, 'Inspect Content-Security-Policy for unsafe-inline / * / unsafe-eval'],
        remediation:
          "Tighten script-src to nonces/hashes; remove 'unsafe-inline' and 'unsafe-eval'; avoid * host wildcards for scripts.",
        cwe: 'CWE-1021',
        references: [
          'https://cwe.mitre.org/data/definitions/1021.html',
          'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
        ],
        needsManualReview: true,
        evidenceGrade: 'fingerprint',
        confidence: 0.7,
        submitReady: false,
        source: 'worker',
        discoveredAt: new Date().toISOString(),
      },
    ];
  },
};
