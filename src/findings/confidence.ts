// Confidence scoring — gates bounty drafts so only high-signal findings ship.

import type { Finding } from '../types.js';

export type EvidenceGrade = NonNullable<Finding['evidenceGrade']>;

/** Check ids whose Worker canaries are high-confidence when needsManualReview=false. */
const CANARY_CHECKS = new Set([
  'command-injection',
  'sql-injection-error',
  'path-traversal',
  'xss-injection',
  'ssrf-open-redirect',
  'ssrf-blind-canary',
  'crlf-header-injection',
  'prototype-pollution',
  'http-parameter-pollution',
  'weak-jwt',
  'secret-exposure',
  'cloud-bucket-exposure',
  'auth-access-control',
  'auth-differential',
]);

const TOOL_CONFIRMED = new Set([
  'sqlmap-injection',
  'nuclei-critical',
  'nuclei-high',
]);

const HEURISTIC_NOISE = new Set([
  'httpx-tech-detect',
  'subfinder-enumeration',
  'ffuf-directory',
  'gobuster-directory',
  'sqlmap-parameter',
  'nmap-open-port',
  'katana-crawl',
  'security-headers',
  'insecure-cookies',
]);

/**
 * Derive confidence / evidence grade / submitReady for a finding.
 * Idempotent — safe to call repeatedly.
 */
export function enrichFinding(f: Finding): Finding {
  const grade = f.evidenceGrade ?? inferGrade(f);
  const confidence = f.confidence ?? confidenceFor(f, grade);
  const submitReady =
    f.submitReady ??
    (!f.needsManualReview &&
      confidence >= 0.75 &&
      (f.severity === 'critical' || f.severity === 'high') &&
      grade !== 'heuristic');

  return {
    ...f,
    evidenceGrade: grade,
    confidence,
    submitReady,
    source: f.source ?? inferSource(f),
  };
}

export function enrichFindings(findings: Finding[]): Finding[] {
  return findings.map(enrichFinding);
}

export function isSubmitReady(f: Finding): boolean {
  return enrichFinding(f).submitReady === true;
}

/** Findings eligible for bounty automation packs. */
export function submitReadyFindings(findings: Finding[]): Finding[] {
  return enrichFindings(findings).filter((f) => f.submitReady);
}

function inferGrade(f: Finding): EvidenceGrade {
  if (f.checkId === 'sqlmap-injection' || /^nuclei-/.test(f.checkId) && !f.needsManualReview) {
    return 'tool-confirmed';
  }
  if (TOOL_CONFIRMED.has(f.checkId)) return 'tool-confirmed';
  if (CANARY_CHECKS.has(f.checkId) && !f.needsManualReview) return 'canary';
  if (CANARY_CHECKS.has(f.checkId)) return 'fingerprint';
  if (HEURISTIC_NOISE.has(f.checkId) || f.checkId.startsWith('recon-') || f.checkId.startsWith('nuclei-')) {
    return f.severity === 'critical' || f.severity === 'high' ? 'fingerprint' : 'heuristic';
  }
  if (f.needsManualReview) return 'fingerprint';
  return 'canary';
}

function confidenceFor(f: Finding, grade: EvidenceGrade): number {
  if (grade === 'tool-confirmed') return f.needsManualReview ? 0.85 : 0.95;
  if (grade === 'canary') return f.needsManualReview ? 0.7 : 0.9;
  if (grade === 'fingerprint') return f.needsManualReview ? 0.55 : 0.72;
  return 0.35;
}

function inferSource(f: Finding): string {
  if (f.checkId.startsWith('nuclei')) return 'nuclei';
  if (f.checkId.startsWith('sqlmap')) return 'sqlmap';
  if (f.checkId.startsWith('httpx')) return 'httpx';
  if (f.checkId.startsWith('ffuf') || f.checkId.startsWith('gobuster')) return 'dirbust';
  if (f.checkId.startsWith('subfinder') || f.checkId.startsWith('recon-')) return 'recon';
  if (f.checkId.startsWith('nmap')) return 'nmap';
  if (f.checkId.startsWith('katana')) return 'katana';
  return 'worker';
}

/**
 * Promote a Worker candidate when an executor tool confirms the same target/class.
 * Returns the upgraded finding (new id preserved from existing when possible).
 */
export function promoteWithToolConfirmation(
  existing: Finding,
  toolFinding: Finding,
): Finding {
  const merged: Finding = {
    ...existing,
    severity:
      severityRank(toolFinding.severity) > severityRank(existing.severity)
        ? toolFinding.severity
        : existing.severity,
    evidence: `${existing.evidence}\n\n--- tool confirmation (${toolFinding.checkId}) ---\n${toolFinding.evidence}`.slice(
      0,
      4000,
    ),
    reproduction: [...new Set([...existing.reproduction, ...toolFinding.reproduction])].slice(0, 12),
    needsManualReview: false,
    evidenceGrade: 'tool-confirmed',
    confidence: 0.95,
    submitReady: true,
    source: `${existing.source ?? 'worker'}+${toolFinding.source ?? toolFinding.checkId}`,
    title: existing.title.startsWith('[CONFIRMED]')
      ? existing.title
      : `[CONFIRMED] ${existing.title}`,
  };
  return enrichFinding(merged);
}

/** Match Worker finding to tool result by target host+path affinity and vuln class. */
export function findPromotionTarget(
  stored: Finding[],
  toolFinding: Finding,
): Finding | null {
  const toolClass = vulnClass(toolFinding.checkId);
  if (!toolClass) return null;
  const toolHost = hostOf(toolFinding.target);
  let best: Finding | null = null;
  let bestScore = 0;
  for (const f of stored) {
    if (vulnClass(f.checkId) !== toolClass) continue;
    if (hostOf(f.target) !== toolHost) continue;
    let s = 1;
    if (pathOf(f.target) === pathOf(toolFinding.target)) s += 2;
    if (f.needsManualReview) s += 1;
    if (s > bestScore) {
      bestScore = s;
      best = f;
    }
  }
  return best;
}

function vulnClass(checkId: string): string | null {
  if (/sql|sqli/i.test(checkId)) return 'sqli';
  if (/xss|ssti/i.test(checkId)) return 'xss';
  if (/command|rce|exec/i.test(checkId)) return 'rce';
  if (/ssrf|redirect/i.test(checkId)) return 'ssrf';
  if (/path-traversal|lfi/i.test(checkId)) return 'lfi';
  if (/secret|bucket/i.test(checkId)) return 'secret';
  if (/takeover/i.test(checkId)) return 'takeover';
  if (/auth-access|idor|jwt/i.test(checkId)) return 'auth';
  return null;
}

function hostOf(url: string): string {
  try {
    return new URL(url.includes('://') ? url : `https://${url}`).hostname.toLowerCase();
  } catch {
    return url.toLowerCase();
  }
}

function pathOf(url: string): string {
  try {
    return new URL(url.includes('://') ? url : `https://${url}`).pathname;
  } catch {
    return '/';
  }
}

function severityRank(s: string): number {
  return ({ info: 0, low: 1, medium: 2, high: 3, critical: 4 } as Record<string, number>)[s] ?? 0;
}
