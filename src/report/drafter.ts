// Report drafting. Turns a Finding into a platform-flavored Markdown writeup
// that the operator reviews and submits. The tool never auto-submits.

import type { Finding, Scope } from '../types.js';
import { CVSS_BAND } from '../findings/severity.js';

export function draftFinding(finding: Finding, scope: Scope): string {
  const lines: string[] = [];
  const platformTitle = platformLabel(scope.platform);

  lines.push(`# ${finding.title}`);
  lines.push('');
  lines.push(`**Program:** ${scope.program} (${platformTitle})`);
  lines.push(`**Severity:** ${finding.severity} (CVSS band ${CVSS_BAND[finding.severity]})`);
  lines.push(`**Asset:** ${finding.target}`);
  if (finding.cwe) lines.push(`**Weakness:** ${finding.cwe}`);
  if (finding.needsManualReview) {
    lines.push('');
    lines.push('> ⚠️ **Candidate finding — verify manually before submitting.** This was surfaced by passive detection and has not been confirmed exploitable.');
  }
  lines.push('');

  lines.push('## Summary');
  lines.push(finding.description);
  lines.push('');

  lines.push('## Steps to Reproduce');
  finding.reproduction.forEach((step, i) => lines.push(`${i + 1}. ${step}`));
  lines.push('');

  lines.push('## Evidence');
  lines.push('```');
  lines.push(finding.evidence);
  lines.push('```');
  lines.push('');

  lines.push('## Impact');
  lines.push(impactStatement(finding));
  lines.push('');

  lines.push('## Remediation');
  lines.push(finding.remediation);
  lines.push('');

  if (finding.references.length) {
    lines.push('## References');
    finding.references.forEach((r) => lines.push(`- ${r}`));
    lines.push('');
  }

  lines.push('---');
  lines.push('_Drafted by StormForge. Reviewed and submitted by the operator. Testing performed within authorized program scope._');
  return lines.join('\n');
}

/** A combined disclosure document for a whole program. */
export function draftDisclosure(findings: Finding[], scope: Scope): string {
  const sorted = [...findings].sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
  const secrets = sorted.filter((f) => f.checkId === 'secret-exposure');
  const sections = sorted.map((f) => draftFinding(f, scope));
  const secretLine =
    secrets.length > 0
      ? `Secret exposures: ${secrets.length} (${secrets.filter((s) => s.severity === 'critical').length} critical, ${secrets.filter((s) => s.severity === 'high').length} high) — rotate before broad disclosure.`
      : '';
  const header = [
    `# Security Findings — ${scope.program}`,
    '',
    `Platform: ${platformLabel(scope.platform)}`,
    `Total findings: ${findings.length}`,
    secretLine,
    scope.notes ? `Scope reference: ${scope.notes}` : '',
    '',
    'All testing was non-destructive and limited to the authorized scope.',
    '',
    '---',
    '',
  ]
    .filter(Boolean)
    .join('\n');
  return `${header}\n\n${sections.join('\n\n---\n\n')}`;
}

function impactStatement(f: Finding): string {
  // CWE-specific impact for access-control / JWT / secret findings.
  if (f.cwe === 'CWE-639') {
    return 'Broken object-level authorization (IDOR) can expose or manipulate other users’ objects by changing predictable identifiers — often leading to bulk personal data disclosure.';
  }
  if (f.cwe === 'CWE-284') {
    return 'Missing or ineffective authorization on authenticated/admin surfaces can grant anonymous callers access to account data or privileged operations.';
  }
  if (f.cwe === 'CWE-347') {
    return 'Acceptance or issuance of weak JWTs (alg=none / empty signature) can allow forged identity claims and full authentication bypass.';
  }
  if (f.cwe === 'CWE-798') {
    return 'Hard-coded or publicly served credentials can be extracted by anyone who can fetch the asset, enabling cloud takeover, data-store access, or abuse of third-party APIs until the secret is rotated.';
  }
  if (f.cwe === 'CWE-312') {
    return 'Cleartext credentials (connection strings, embedded basic-auth URLs) in HTTP responses expose infrastructure secrets and often unlock direct database or message-bus access.';
  }
  if (f.cwe === 'CWE-770') {
    return 'Missing or weak rate limiting on authentication and token endpoints enables credential stuffing, OTP/password guessing, and request floods that degrade availability.';
  }
  if (f.cwe === 'CWE-79') {
    return 'Cross-site scripting lets attackers execute script in victims’ browsers, steal sessions, deface content, or pivot to further account takeover.';
  }
  if (f.cwe === 'CWE-94') {
    return 'Server-side template injection can escalate from expression evaluation to remote code execution depending on the template engine and sandbox.';
  }
  if (f.cwe === 'CWE-209') {
    return 'Verbose error messages disclose implementation details that help attackers refine injection and template attacks.';
  }

  switch (f.severity) {
    case 'critical':
      return 'If confirmed, this issue could lead to full compromise of the affected asset or exposure of highly sensitive data.';
    case 'high':
      return 'This issue could allow significant unauthorized access or data exposure.';
    case 'medium':
      return 'This issue weakens the security posture and could be chained with others for greater impact.';
    case 'low':
      return 'This is a hardening gap with limited direct impact but worth remediating.';
    case 'info':
      return 'Informational — documents a deviation from best practice.';
    default: {
      const _exhaustive: never = f.severity;
      return `Severity ${_exhaustive}`;
    }
  }
}

function platformLabel(p: Scope['platform']): string {
  return (
    { hackerone: 'HackerOne', bugcrowd: 'Bugcrowd', immunefi: 'Immunefi', intigriti: 'Intigriti', generic: 'Generic' }[p] ??
    'Generic'
  );
}

function severityRank(s: Finding['severity']): number {
  return { info: 0, low: 1, medium: 2, high: 3, critical: 4 }[s];
}
