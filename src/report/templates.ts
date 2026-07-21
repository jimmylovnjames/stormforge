// Platform-specific bounty report templates (HackerOne + Immunefi).
// Never auto-submits — operator copies/reviews before filing.

import type { Finding, Scope } from '../types.js';
import { estimateCvss, sortByCvss } from './cvss.js';
import { impactForFinding } from './impact.js';

export type BountyPlatform = 'hackerone' | 'immunefi';

export interface BountyReportPacket {
  platform: BountyPlatform;
  program: string;
  findingId: string;
  title: string;
  /** Suggested title for the platform submission form. */
  submissionTitle: string;
  cvssScore: number;
  cvssVector: string;
  cvssRating: string;
  severity: Finding['severity'];
  asset: string;
  cwe?: string;
  markdown: string;
  /** Structured fields matching common platform form labels. */
  fields: Record<string, string>;
  needsManualReview: boolean;
}

/** HackerOne weakness (CWE) + asset type hints commonly used in reports. */
function h1AssetType(target: string): string {
  try {
    const u = new URL(target);
    if (u.hostname.includes('s3') || u.hostname.includes('blob') || u.hostname.includes('storage')) {
      return 'Other Asset';
    }
    return 'URL';
  } catch {
    return 'URL';
  }
}

export function draftHackerOneReport(finding: Finding, scope: Scope): BountyReportPacket {
  const cvss = estimateCvss(finding);
  const impact = impactForFinding(finding);
  const submissionTitle = `[${cvss.rating.toUpperCase()}] ${finding.title}`.slice(0, 150);
  const markdown = [
    `## Summary`,
    finding.description,
    '',
    `## Steps To Reproduce`,
    ...finding.reproduction.map((s, i) => `${i + 1}. ${s}`),
    '',
    `## Supporting Material/References`,
    '```',
    finding.evidence,
    '```',
    finding.references.length ? finding.references.map((r) => `- ${r}`).join('\n') : '',
    '',
    `## Impact`,
    impact,
    '',
    `## CVSS`,
    `- **Score:** ${cvss.score.toFixed(1)} (${cvss.rating})`,
    `- **Vector:** \`${cvss.vector}\``,
    `- **Rationale:** ${cvss.rationale}`,
    '',
    finding.needsManualReview
      ? '> **Note:** Candidate finding from passive detection — verify before submit.'
      : '',
    '',
    `_Drafted by StormForge for ${scope.program} (HackerOne). Operator must review and submit._`,
  ]
    .filter((l) => l !== '')
    .join('\n');

  return {
    platform: 'hackerone',
    program: scope.program,
    findingId: finding.id,
    title: finding.title,
    submissionTitle,
    cvssScore: cvss.score,
    cvssVector: cvss.vector,
    cvssRating: cvss.rating,
    severity: finding.severity,
    asset: finding.target,
    cwe: finding.cwe,
    markdown,
    needsManualReview: finding.needsManualReview,
    fields: {
      'Title': submissionTitle,
      'Asset': finding.target,
      'Asset type': h1AssetType(finding.target),
      'Weakness': finding.cwe ?? 'Other',
      'Severity': cvss.rating,
      'CVSS': `${cvss.score.toFixed(1)} — ${cvss.vector}`,
      'Impact': impact,
      'Remediation': finding.remediation,
    },
  };
}

/**
 * Immunefi-style report: blockchain/web3 programs emphasize funds-at-risk,
 * but the same structure works for their web/app assets.
 */
export function draftImmunefiReport(finding: Finding, scope: Scope): BountyReportPacket {
  const cvss = estimateCvss(finding);
  const impact = impactForFinding(finding);
  const submissionTitle = `${finding.title} (${cvss.score.toFixed(1)})`.slice(0, 150);
  const fundsAtRisk =
    cvss.score >= 9.0
      ? 'Critical — potential full compromise / unrestricted access; estimate funds-at-risk per program rules before submit.'
      : cvss.score >= 7.0
        ? 'High — significant unauthorized access or data exposure; quantify assets touched.'
        : 'See Impact; confirm Immunefi severity taxonomy (Critical/High/Medium/Low) against program brief.';

  const markdown = [
    `# Bug Report — ${scope.program}`,
    '',
    `**Title:** ${submissionTitle}`,
    `**Target:** ${finding.target}`,
    `**Severity (CVSS):** ${cvss.score.toFixed(1)} / ${cvss.rating} — \`${cvss.vector}\``,
    finding.cwe ? `**CWE:** ${finding.cwe}` : '',
    '',
    `## Bug Description`,
    finding.description,
    '',
    `## Vulnerability Details / PoC`,
    ...finding.reproduction.map((s, i) => `${i + 1}. ${s}`),
    '',
    '### Evidence',
    '```',
    finding.evidence,
    '```',
    '',
    `## Impact`,
    impact,
    '',
    `## Funds / Assets at Risk`,
    fundsAtRisk,
    '',
    `## Suggested Fix`,
    finding.remediation,
    '',
    finding.references.length ? `## References\n${finding.references.map((r) => `- ${r}`).join('\n')}` : '',
    '',
    finding.needsManualReview
      ? '> **Verification required:** Passive detection candidate — do not submit until confirmed.'
      : '',
    '',
    `_Drafted by StormForge for Immunefi program ${scope.program}. Operator reviews and submits via Immunefi dashboard._`,
  ]
    .filter((l) => l !== '')
    .join('\n');

  return {
    platform: 'immunefi',
    program: scope.program,
    findingId: finding.id,
    title: finding.title,
    submissionTitle,
    cvssScore: cvss.score,
    cvssVector: cvss.vector,
    cvssRating: cvss.rating,
    severity: finding.severity,
    asset: finding.target,
    cwe: finding.cwe,
    markdown,
    needsManualReview: finding.needsManualReview,
    fields: {
      'Title': submissionTitle,
      'Target': finding.target,
      'Severity': cvss.rating,
      'CVSS Score': cvss.score.toFixed(1),
      'CVSS Vector': cvss.vector,
      'Bug Description': finding.description,
      'Impact': impact,
      'Funds at Risk': fundsAtRisk,
      'Suggested Fix': finding.remediation,
    },
  };
}

export function draftPlatformReport(
  finding: Finding,
  scope: Scope,
  platform: BountyPlatform = scope.platform === 'immunefi' ? 'immunefi' : 'hackerone',
): BountyReportPacket {
  return platform === 'immunefi' ? draftImmunefiReport(finding, scope) : draftHackerOneReport(finding, scope);
}

/** Build CVSS-prioritized bounty packets for high/critical findings only. */
export function buildBountyPackets(
  findings: Finding[],
  scope: Scope,
  opts: { platform?: BountyPlatform; minScore?: number } = {},
): BountyReportPacket[] {
  const platform: BountyPlatform =
    opts.platform ?? (scope.platform === 'immunefi' ? 'immunefi' : 'hackerone');
  const minScore = opts.minScore ?? 7.0;
  const eligible = sortByCvss(findings).filter((f) => {
    if (f.severity !== 'high' && f.severity !== 'critical') return false;
    return estimateCvss(f).score >= minScore;
  });
  return eligible.map((f) => draftPlatformReport(f, scope, platform));
}
