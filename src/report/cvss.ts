// CVSS v3.1 vector suggestions per check/CWE for bounty report automation.
// Scores are conservative defaults the operator can refine before submit.

import type { Finding, Severity } from '../types.js';

export interface CvssEstimate {
  /** CVSS v3.1 base vector string. */
  vector: string;
  /** Numeric base score 0.0–10.0. */
  score: number;
  /** Qualitative rating derived from score. */
  rating: Severity;
  /** Short rationale for the metrics chosen. */
  rationale: string;
}

/** Check-id / CWE → suggested CVSS v3.1 base metrics (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H style). */
const BY_CHECK: Record<string, Omit<CvssEstimate, 'rating'>> = {
  'command-injection': {
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
    score: 10.0,
    rationale: 'Unauthenticated OS command execution → full host compromise',
  },
  'sql-injection-error': {
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    score: 9.8,
    rationale: 'Network SQLi without auth often yields full DB read/write',
  },
  'ssrf-open-redirect': {
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N',
    score: 9.3,
    rationale: 'SSRF to metadata/internal services can leak cloud credentials',
  },
  'path-traversal': {
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    score: 7.5,
    rationale: 'Arbitrary file read of OS/config secrets',
  },
  'weak-jwt': {
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    score: 9.1,
    rationale: 'Forged JWT → authentication bypass',
  },
  'secret-exposure': {
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N',
    score: 9.6,
    rationale: 'Public credential enables cloud/API takeover',
  },
  'cloud-bucket-exposure': {
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N',
    score: 8.2,
    rationale: 'Public object listing exposes sensitive keys/backups',
  },
  'auth-access-control': {
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N',
    score: 8.2,
    rationale: 'Broken authz / IDOR exposes other users’ data',
  },
  'prototype-pollution': {
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L',
    score: 9.4,
    rationale: 'PP gadgets frequently escalate to RCE or auth bypass',
  },
  'xss-injection': {
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N',
    score: 8.2,
    rationale: 'Reflected XSS with user interaction, scope change via browser',
  },
  'crlf-header-injection': {
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N',
    score: 8.2,
    rationale: 'Response splitting enables session fixation / cache poison',
  },
  'subdomain-takeover': {
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N',
    score: 9.6,
    rationale: 'Attacker-controlled content on trusted subdomain',
  },
  'cache-deception': {
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N',
    score: 6.5,
    rationale: 'Cached authenticated content leak (needs victim visit)',
  },
  'host-header-injection': {
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N',
    score: 7.1,
    rationale: 'Password-reset / cache poisoning via Host reflection',
  },
  'cors-misconfig': {
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N',
    score: 6.5,
    rationale: 'Credentialed cross-origin reads require a malicious page visit',
  },
  'rate-limit-missing': {
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L',
    score: 7.3,
    rationale: 'Auth brute-force / stuffing without throttling',
  },
  'graphql-introspection': {
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
    score: 5.3,
    rationale: 'Schema disclosure aids further attacks',
  },
  'api-schema-exposure': {
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
    score: 5.3,
    rationale: 'OpenAPI/Swagger exposure expands attack surface',
  },
  'debug-error-disclosure': {
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
    score: 5.3,
    rationale: 'Stack/debug leaks aid exploitation',
  },
};

const BY_CWE: Record<string, Omit<CvssEstimate, 'rating'>> = {
  'CWE-78': BY_CHECK['command-injection']!,
  'CWE-89': BY_CHECK['sql-injection-error']!,
  'CWE-918': BY_CHECK['ssrf-open-redirect']!,
  'CWE-22': BY_CHECK['path-traversal']!,
  'CWE-347': BY_CHECK['weak-jwt']!,
  'CWE-798': BY_CHECK['secret-exposure']!,
  'CWE-79': BY_CHECK['xss-injection']!,
  'CWE-113': BY_CHECK['crlf-header-injection']!,
  'CWE-1321': BY_CHECK['prototype-pollution']!,
  'CWE-639': BY_CHECK['auth-access-control']!,
};

const SEVERITY_FALLBACK: Record<Severity, Omit<CvssEstimate, 'rating'>> = {
  critical: {
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    score: 9.8,
    rationale: 'Qualitative critical — refine vector before submit',
  },
  high: {
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N',
    score: 8.2,
    rationale: 'Qualitative high — refine vector before submit',
  },
  medium: {
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
    score: 6.5,
    rationale: 'Qualitative medium — refine vector before submit',
  },
  low: {
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
    score: 5.3,
    rationale: 'Qualitative low — refine vector before submit',
  },
  info: {
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',
    score: 0.0,
    rationale: 'Informational',
  },
};

export function ratingFromScore(score: number): Severity {
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  if (score > 0) return 'low';
  return 'info';
}

/** Suggest a CVSS v3.1 estimate for a finding (check → CWE → severity fallback). */
export function estimateCvss(finding: Finding): CvssEstimate {
  const fromCheck = BY_CHECK[finding.checkId];
  const fromCwe = finding.cwe ? BY_CWE[finding.cwe] : undefined;
  const base = fromCheck ?? fromCwe ?? SEVERITY_FALLBACK[finding.severity];
  return { ...base, rating: ratingFromScore(base.score) };
}

/** Sort findings by CVSS score descending (then severity, then title). */
export function sortByCvss(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const sa = estimateCvss(a).score;
    const sb = estimateCvss(b).score;
    if (sb !== sa) return sb - sa;
    return a.title.localeCompare(b.title);
  });
}
