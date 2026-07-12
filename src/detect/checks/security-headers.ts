// Missing / weak security headers. Passive: inspects response headers only.

import type { Check, Finding, ProbeResult } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';

interface HeaderExpectation {
  header: string;
  title: string;
  severity: Finding['severity'];
  remediation: string;
  cwe: string;
  /** Optional predicate: return true if the present value is still weak. */
  weakIf?: (value: string) => boolean;
}

const EXPECTATIONS: HeaderExpectation[] = [
  {
    header: 'strict-transport-security',
    title: 'Missing HTTP Strict Transport Security (HSTS)',
    severity: 'low',
    cwe: 'CWE-319',
    remediation: 'Add `Strict-Transport-Security: max-age=31536000; includeSubDomains`.',
  },
  {
    header: 'content-security-policy',
    title: 'Missing Content Security Policy',
    severity: 'low',
    cwe: 'CWE-1021',
    remediation: 'Define a restrictive Content-Security-Policy to mitigate XSS and data injection.',
  },
  {
    header: 'x-content-type-options',
    title: 'Missing X-Content-Type-Options: nosniff',
    severity: 'info',
    cwe: 'CWE-693',
    remediation: 'Add `X-Content-Type-Options: nosniff`.',
    weakIf: (v) => v.trim().toLowerCase() !== 'nosniff',
  },
  {
    header: 'x-frame-options',
    title: 'Missing clickjacking protection (X-Frame-Options / frame-ancestors)',
    severity: 'low',
    cwe: 'CWE-1021',
    remediation: 'Set `X-Frame-Options: DENY` or a CSP `frame-ancestors` directive.',
  },
];

export const securityHeadersCheck: Check = {
  id: 'security-headers',
  title: 'Security header hardening',
  cwe: 'CWE-693',
  run(probe: ProbeResult): Finding[] {
    // Only meaningful for successful HTML/document responses.
    if (probe.error || probe.status === 0) return [];
    const contentType = probe.headers['content-type'] ?? '';
    const isDocument = contentType.includes('text/html') || contentType === '';
    if (!isDocument) return [];

    const findings: Finding[] = [];
    for (const exp of EXPECTATIONS) {
      const value = probe.headers[exp.header];
      const missing = value === undefined;
      // CSP frame-ancestors can substitute for X-Frame-Options.
      if (exp.header === 'x-frame-options' && !missing) continue;
      if (
        exp.header === 'x-frame-options' &&
        missing &&
        (probe.headers['content-security-policy'] ?? '').includes('frame-ancestors')
      ) {
        continue;
      }
      const weak = !missing && exp.weakIf ? exp.weakIf(value) : false;
      if (missing || weak) {
        findings.push({
          id: makeFindingId(this.id, probe.url, exp.header),
          checkId: this.id,
          title: exp.title,
          severity: exp.severity,
          target: probe.url,
          description: missing
            ? `The response does not set the \`${exp.header}\` header.`
            : `The \`${exp.header}\` header is present but weak (value: "${value}").`,
          evidence: `URL: ${probe.url}\nHeader \`${exp.header}\`: ${value ?? '<absent>'}`,
          reproduction: [
            `Send: curl -sI ${probe.url}`,
            `Observe the \`${exp.header}\` response header is ${missing ? 'absent' : 'weak'}`,
          ],
          remediation: exp.remediation,
          cwe: exp.cwe,
          references: [`https://cwe.mitre.org/data/definitions/${exp.cwe.replace('CWE-', '')}.html`],
          needsManualReview: false,
          discoveredAt: new Date().toISOString(),
        });
      }
    }
    return findings;
  },
};
