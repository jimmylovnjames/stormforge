// Passive secret / sensitive-token scanner for response bodies (typically JS).
// Flags high-entropy or well-known credential patterns for MANUAL review.
// Never validates or uses the discovered token.

import type { ProbeResult, Finding } from '../types.js';
import { makeFindingId } from '../findings/id.js';

interface SecretRule {
  name: string;
  regex: RegExp;
  severity: Finding['severity'];
}

// Patterns are intentionally specific to reduce false positives.
const SECRET_RULES: SecretRule[] = [
  { name: 'AWS Access Key ID', regex: /\bAKIA[0-9A-Z]{16}\b/g, severity: 'high' },
  { name: 'Google API Key', regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g, severity: 'high' },
  { name: 'Slack Token', regex: /\bxox[baprs]-[0-9A-Za-z-]{10,48}\b/g, severity: 'high' },
  { name: 'Stripe Live Secret Key', regex: /\bsk_live_[0-9a-zA-Z]{24,}\b/g, severity: 'critical' },
  { name: 'GitHub Token', regex: /\bgh[pousr]_[0-9A-Za-z]{36,}\b/g, severity: 'high' },
  { name: 'Private Key Block', regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g, severity: 'critical' },
  { name: 'JWT', regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, severity: 'low' },
  { name: 'Generic API secret assignment', regex: /['"]?(?:api[_-]?key|secret|token|password)['"]?\s*[:=]\s*['"][0-9a-zA-Z\-_]{16,}['"]/gi, severity: 'medium' },
];

/** Redact the middle of a token so evidence is safe to store/paste. */
export function redact(token: string): string {
  if (token.length <= 8) return `${token[0] ?? ''}***`;
  return `${token.slice(0, 4)}…${token.slice(-4)} (len ${token.length})`;
}

export function scanSecrets(probe: ProbeResult): Finding[] {
  if (!probe.body) return [];
  const findings: Finding[] = [];
  const seen = new Set<string>();

  for (const rule of SECRET_RULES) {
    rule.regex.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = rule.regex.exec(probe.body)) !== null) {
      const token = m[0];
      const key = `${rule.name}:${token}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({
        id: makeFindingId('secret-exposure', probe.url, `${rule.name}:${redact(token)}`),
        checkId: 'secret-exposure',
        title: `Possible ${rule.name} exposed in response body`,
        severity: rule.severity,
        target: probe.url,
        description: `A string matching the pattern for ${rule.name} was found in a response served from an in-scope asset. If this is a live credential, it may allow unauthorized access.`,
        evidence: `Pattern: ${rule.name}\nRedacted match: ${redact(token)}\nURL: ${probe.url}`,
        reproduction: [
          `Fetch ${probe.url}`,
          `Search the response body for a value matching ${rule.name}`,
          'Confirm (out of band, without using the credential) whether it is live before reporting',
        ],
        remediation:
          'Remove the secret from client-served assets, rotate the credential immediately, and move secrets to server-side/secret storage.',
        cwe: 'CWE-312',
        references: ['https://cwe.mitre.org/data/definitions/312.html'],
        needsManualReview: true,
        discoveredAt: new Date().toISOString(),
      });
    }
  }
  return findings;
}
