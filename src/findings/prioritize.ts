// Finding prioritization for autonomy dispatch and report drafting.

import type { Finding, Severity } from '../types.js';
import { SEVERITY_ORDER } from '../types.js';
import { estimateCvss } from '../report/cvss.js';

/** Prefer confirmed critical/high injection & takeover classes for executor waves. */
const BOOST: Record<string, number> = {
  'sql-injection-error': 40,
  'command-injection': 40,
  'ssrf-open-redirect': 35,
  'path-traversal': 35,
  'weak-jwt': 30,
  'secret-exposure': 30,
  'cloud-bucket-exposure': 30,
  'subdomain-takeover': 28,
  'auth-access-control': 25,
  'prototype-pollution': 25,
  'crlf-header-injection': 22,
  'xss-injection': 22,
  'cache-deception': 20,
  'cors-misconfig': 15,
  'host-header-injection': 15,
  'debug-error-disclosure': 10,
};

export function prioritizeFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => score(b) - score(a));
}

export function score(f: Finding): number {
  const cvss = estimateCvss(f).score;
  const sev = SEVERITY_ORDER[f.severity as Severity] ?? 0;
  const boost = BOOST[f.checkId] ?? 0;
  const reviewPenalty = f.needsManualReview ? -5 : 5;
  // CVSS dominates; severity/boost break ties for autonomy budgeting.
  return cvss * 100 + sev * 10 + boost + reviewPenalty;
}

/** True when the scan warrants an automatic disclosure draft. */
export function shouldAutoDraft(findings: Finding[]): boolean {
  return findings.some((f) => f.severity === 'critical' || f.severity === 'high');
}

export function highImpactFindings(findings: Finding[]): Finding[] {
  return prioritizeFindings(findings).filter(
    (f) => f.severity === 'critical' || f.severity === 'high',
  );
}
