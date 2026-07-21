// Report drafting. Turns a Finding into a platform-flavored Markdown writeup
// that the operator reviews and submits. The tool never auto-submits.

import type { Finding, Scope } from '../types.js';
import { cvssFor } from './cvss.js';

export function draftFinding(finding: Finding, scope: Scope): string {
  const lines: string[] = [];
  const platformTitle = platformLabel(scope.platform);
  const cvss = cvssFor(finding);

  lines.push(`# ${finding.title}`);
  lines.push('');
  lines.push(`**Program:** ${scope.program} (${platformTitle})`);
  lines.push(`**Severity:** ${finding.severity} (CVSS ${cvss.score.toFixed(1)} — ${cvss.severity})`);
  lines.push(`**CVSS:3.1 Vector:** \`${cvss.vector}\``);
  lines.push(`**Asset:** ${finding.target}`);
  if (finding.cwe) lines.push(`**Weakness:** ${finding.cwe}`);
  if (typeof finding.confidence === 'number') {
    lines.push(`**Detection confidence:** ${(finding.confidence * 100).toFixed(0)}%`);
  }
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
export function draftDisclosure(
  findings: Finding[],
  scope: Scope,
  opts: { submitReadyOnly?: boolean; minSeverity?: Finding['severity'] } = {},
): string {
  const minRank = severityRank(opts.minSeverity ?? 'info');
  let filtered = findings.filter((f) => severityRank(f.severity) >= minRank);
  if (opts.submitReadyOnly) {
    const ready = filtered.filter((f) => f.submitReady === true || (!f.needsManualReview && severityRank(f.severity) >= 3));
    if (ready.length) filtered = ready;
  }
  const sorted = [...filtered].sort((a, b) => {
    const sev = severityRank(b.severity) - severityRank(a.severity);
    if (sev !== 0) return sev;
    return (b.confidence ?? 0) - (a.confidence ?? 0);
  });
  const sections = sorted.map((f) => draftFinding(f, scope));
  const dropped = findings.length - sorted.length;
  const header = [
    `# Security Findings — ${scope.program}`,
    '',
    `Platform: ${platformLabel(scope.platform)}`,
    `Findings in report: ${sorted.length}${dropped ? ` (${dropped} filtered as lower-signal)` : ''} / ${findings.length} total`,
    opts.submitReadyOnly ? 'Filter: prefer submitReady / high|critical confirmed' : '',
    scope.notes ? `Scope reference: ${scope.notes}` : '',
    '',
    'All testing was non-destructive and limited to the authorized scope.',
    'StormForge never auto-submits — review every finding before filing.',
    '',
    '---',
    '',
  ]
    .filter(Boolean)
    .join('\n');
  return `${header}\n\n${sections.join('\n\n---\n\n')}`;
}

function impactStatement(f: Finding): string {
  switch (f.severity) {
    case 'critical':
      return 'If confirmed, this issue could lead to full compromise of the affected asset or exposure of highly sensitive data.';
    case 'high':
      return 'This issue could allow significant unauthorized access or data exposure.';
    case 'medium':
      return 'This issue weakens the security posture and could be chained with others for greater impact.';
    case 'low':
      return 'This is a hardening gap with limited direct impact but worth remediating.';
    default:
      return 'Informational — documents a deviation from best practice.';
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
