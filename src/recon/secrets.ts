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

// Patterns are intentionally specific (fixed vendor prefixes + length anchors)
// to reduce false positives on minified JS. Ordered high→low value.
const SECRET_RULES: SecretRule[] = [
  // Cloud providers
  { name: 'AWS Access Key ID', regex: /\bAKIA[0-9A-Z]{16}\b/g, severity: 'high' },
  { name: 'Google API Key', regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g, severity: 'high' },
  { name: 'Google OAuth client secret', regex: /\bGOCSPX-[0-9A-Za-z\-_]{28}\b/g, severity: 'high' },
  // Source hosting / package registries
  { name: 'GitHub Token', regex: /\bgh[pousr]_[0-9A-Za-z]{36,}\b/g, severity: 'high' },
  { name: 'GitHub fine-grained PAT', regex: /\bgithub_pat_[0-9A-Za-z_]{60,}\b/g, severity: 'high' },
  { name: 'GitLab Personal Access Token', regex: /\bglpat-[0-9A-Za-z\-_]{20,}\b/g, severity: 'high' },
  { name: 'npm access token', regex: /\bnpm_[0-9A-Za-z]{36}\b/g, severity: 'high' },
  // Messaging / comms
  { name: 'Slack Token', regex: /\bxox[baprs]-[0-9A-Za-z-]{10,48}\b/g, severity: 'high' },
  { name: 'Slack Webhook URL', regex: /https:\/\/hooks\.slack\.com\/services\/T[0-9A-Z]{6,}\/B[0-9A-Z]{6,}\/[0-9A-Za-z]{20,}/g, severity: 'medium' },
  { name: 'SendGrid API Key', regex: /\bSG\.[0-9A-Za-z\-_]{16,32}\.[0-9A-Za-z\-_]{16,64}\b/g, severity: 'high' },
  { name: 'Mailgun API Key', regex: /\bkey-[0-9a-f]{32}\b/g, severity: 'high' },
  { name: 'Twilio API Key', regex: /\bSK[0-9a-fA-F]{32}\b/g, severity: 'high' },
  // Payments
  { name: 'Stripe Live Secret Key', regex: /\b[rs]k_live_[0-9a-zA-Z]{24,}\b/g, severity: 'critical' },
  { name: 'Square Access Token', regex: /\bsq0atp-[0-9A-Za-z\-_]{22}\b/g, severity: 'high' },
  { name: 'Shopify Access Token', regex: /\bshp(?:at|ca|pa|ss)_[0-9a-fA-F]{32}\b/g, severity: 'high' },
  // AI / misc SaaS
  { name: 'OpenAI API Key', regex: /\bsk-(?:proj-)?[0-9A-Za-z\-_]{20,}\b/g, severity: 'high' },
  // Crypto material
  { name: 'Private Key Block', regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g, severity: 'critical' },
  // Lower-signal / generic (kept last; medium/low)
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
        evidenceGrade: 'fingerprint',
        confidence: rule.severity === 'critical' ? 0.85 : rule.severity === 'low' ? 0.4 : 0.7,
        submitReady: false,
        source: 'worker',
        discoveredAt: new Date().toISOString(),
      });
    }
  }
  return findings;
}
