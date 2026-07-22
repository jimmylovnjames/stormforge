// Email spoofing / weak email-auth (SPF, DMARC) from DoH TXT lookups.
// Reads the synthetic email-DNS probe emitted by the scanner (marker header).

import type { Check, Finding, ProbeResult } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';
import { EMAIL_DNS_MARKER, analyzeEmailPosture, type EmailDnsInput } from '../../recon/dns-email.js';

export const emailSpoofingCheck: Check = {
  id: 'email-spoofing',
  title: 'Email spoofing (weak SPF / DMARC)',
  cwe: 'CWE-290',
  run(probe: ProbeResult): Finding[] {
    if ((probe.headers['x-stormforge-dns'] ?? '') !== EMAIL_DNS_MARKER) return [];

    let input: EmailDnsInput;
    try {
      input = JSON.parse(probe.body) as EmailDnsInput;
    } catch {
      return [];
    }
    if (!input?.domain) return [];

    const issues = analyzeEmailPosture(input).slice(0, 3);
    return issues.map((issue) => ({
      id: makeFindingId(this.id, `https://${input.domain}/`, issue.key),
      checkId: this.id,
      title: issue.title,
      severity: issue.severity,
      target: `https://${input.domain}/`,
      description: `${issue.detail} Weak email authentication lets attackers send phishing that appears to originate from ${input.domain}.`,
      evidence: `Domain: ${input.domain}\nIssue: ${issue.key}\nRecord(s): ${issue.record}`,
      reproduction: [
        `dig TXT ${input.domain} +short`,
        `dig TXT _dmarc.${input.domain} +short`,
        `Confirm the SPF/DMARC posture matches: ${issue.key}`,
      ],
      remediation:
        'Publish a strict SPF record ending in `-all` (or `~all`) listing only authorized senders, and a DMARC record with `p=reject` (or at least `p=quarantine`) plus aggregate reporting (rua).',
      cwe: 'CWE-290',
      references: [
        'https://cwe.mitre.org/data/definitions/290.html',
        'https://datatracker.ietf.org/doc/html/rfc7208',
        'https://datatracker.ietf.org/doc/html/rfc7489',
      ],
      needsManualReview: true,
      evidenceGrade: 'canary',
      confidence: issue.severity === 'high' ? 0.9 : issue.severity === 'medium' ? 0.8 : 0.7,
      submitReady: false,
      source: 'worker',
      discoveredAt: new Date().toISOString(),
    }));
  },
};
