// Report drafting. Turns a Finding into a platform-flavored Markdown writeup
// that the operator reviews and submits. The tool never auto-submits.

import type { Finding, Scope } from '../types.js';
import { CVSS_BAND } from '../findings/severity.js';
import { estimateCvss, sortByCvss } from './cvss.js';
import { impactForFinding } from './impact.js';
import { buildBountyPackets, type BountyPlatform } from './templates.js';

export function draftFinding(finding: Finding, scope: Scope): string {
  const lines: string[] = [];
  const platformTitle = platformLabel(scope.platform);
  const cvss = estimateCvss(finding);

  lines.push(`# ${finding.title}`);
  lines.push('');
  lines.push(`**Program:** ${scope.program} (${platformTitle})`);
  lines.push(`**Severity:** ${finding.severity} (CVSS ${cvss.score.toFixed(1)} / band ${CVSS_BAND[finding.severity]})`);
  lines.push(`**CVSS Vector:** \`${cvss.vector}\``);
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
  lines.push(impactForFinding(finding));
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

/** A combined disclosure document for a whole program (CVSS-ordered). */
export function draftDisclosure(findings: Finding[], scope: Scope): string {
  const sorted = sortByCvss(findings);
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
    `Ordered by: CVSS base score (desc)`,
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

/**
 * Auto-generate platform bounty submission packs for high/critical findings.
 * Does not submit — returns markdown + form fields for the operator.
 */
export function draftBountyAutomation(
  findings: Finding[],
  scope: Scope,
  platform?: BountyPlatform,
): {
  platform: BountyPlatform;
  count: number;
  packets: ReturnType<typeof buildBountyPackets>;
  combinedMarkdown: string;
} {
  const resolved: BountyPlatform =
    platform ?? (scope.platform === 'immunefi' ? 'immunefi' : 'hackerone');
  const packets = buildBountyPackets(findings, scope, { platform: resolved, minScore: 7.0 });
  const combinedMarkdown = packets
    .map(
      (p, i) =>
        `# Bounty Draft ${i + 1}/${packets.length} — CVSS ${p.cvssScore.toFixed(1)}\n\n${p.markdown}`,
    )
    .join('\n\n---\n\n');
  return { platform: resolved, count: packets.length, packets, combinedMarkdown };
}

function platformLabel(p: Scope['platform']): string {
  return (
    { hackerone: 'HackerOne', bugcrowd: 'Bugcrowd', immunefi: 'Immunefi', intigriti: 'Intigriti', generic: 'Generic' }[p] ??
    'Generic'
  );
}
