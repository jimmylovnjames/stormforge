// CVSS v3.1 base-score + vector generation for report drafts.
//
// Passive detections don't carry a hand-authored vector, so we map each checkId
// to a representative metric profile (falling back to a severity-derived one)
// and compute the real CVSS v3.1 base score. The operator refines before filing;
// a concrete vector string is what HackerOne/Bugcrowd forms expect.

import type { Finding, Severity } from '../types.js';

export type AttackVector = 'N' | 'A' | 'L' | 'P';
export type AttackComplexity = 'L' | 'H';
export type PrivilegesRequired = 'N' | 'L' | 'H';
export type UserInteraction = 'N' | 'R';
export type ScopeMetric = 'U' | 'C';
export type Impact = 'N' | 'L' | 'H';

export interface CvssMetrics {
  AV: AttackVector;
  AC: AttackComplexity;
  PR: PrivilegesRequired;
  UI: UserInteraction;
  S: ScopeMetric;
  C: Impact;
  I: Impact;
  A: Impact;
}

export interface CvssResult {
  vector: string;
  score: number;
  severity: Severity;
}

const AV_W: Record<AttackVector, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC_W: Record<AttackComplexity, number> = { L: 0.77, H: 0.44 };
const UI_W: Record<UserInteraction, number> = { N: 0.85, R: 0.62 };
const CIA_W: Record<Impact, number> = { N: 0, L: 0.22, H: 0.56 };
const PR_W_UNCHANGED: Record<PrivilegesRequired, number> = { N: 0.85, L: 0.62, H: 0.27 };
const PR_W_CHANGED: Record<PrivilegesRequired, number> = { N: 0.85, L: 0.68, H: 0.5 };

/** Representative metric profile per checkId (overrides the severity default). */
const PROFILES: Record<string, Partial<CvssMetrics>> = {
  // Info disclosure of API surface — network, no privs, confidentiality only.
  'api-schema-exposure': { C: 'L' },
  'graphql-introspection': { C: 'L' },
  'sourcemap-exposure': { C: 'L' },
  'known-cve-version': { C: 'L' },
  // Sensitive files / secrets — confidentiality high.
  'exposed-files': { C: 'H' },
  'secret-exposure': { C: 'H' },
  'open-cloud-bucket': { C: 'H' },
  // Debug pages leak internals/secrets (Werkzeug/Django can reach RCE).
  'debug-disclosure': { C: 'H' },
  // Directory listing discloses file inventory.
  'directory-listing': { C: 'L' },
  // Email spoofing impacts integrity (forged mail), needs a victim to act.
  'email-spoofing': { C: 'N', I: 'L', A: 'N', UI: 'R' },
  // Open redirect — victim-driven, crosses to an attacker origin (scope changed).
  'open-redirect': { S: 'C', C: 'L', I: 'L', UI: 'R' },
  // Host-header injection — integrity of generated links / cache.
  'host-header-injection': { C: 'L', I: 'L', UI: 'R' },
  // SSRF candidate — a lead until OAST confirms.
  'ssrf-candidate': { C: 'L', I: 'N', A: 'N' },
  // Confirmed (blind) SSRF — network pivot, crosses trust boundary.
  'ssrf-oast-confirmed': { S: 'C', C: 'H', I: 'L', A: 'N' },
  // JWT exposure — confidentiality of session/authz; alg=none escalates via severity default.
  'jwt-exposure': { C: 'H', UI: 'N' },
  // Reflected XSS — victim-driven, integrity + confidentiality of the victim session.
  'xss-reflection': { C: 'L', I: 'L', UI: 'R' },
  // CORS credentialed read crosses a trust boundary → Scope changed.
  'cors-misconfig': { S: 'C', C: 'H', UI: 'R' },
  // Cookies / headers / CSP are hardening; require user interaction, low impact.
  'insecure-cookies': { C: 'L', UI: 'R' },
  'security-headers': { AC: 'H', C: 'L', UI: 'R' },
  'weak-csp': { C: 'L', I: 'L', UI: 'R' },
  // Cache deception leaks a victim's authenticated response → needs UI.
  'cache-deception': { C: 'H', UI: 'R' },
  // Auth bypass / IDOR — direct confidentiality (and integrity when admin).
  'auth-access-control': { C: 'H', I: 'L' },
  // OAuth token leak / open redirect — token theft, UI-driven.
  'oauth-misconfig': { C: 'H', UI: 'R' },
  // Subdomain takeover — attacker fully controls a host → Scope changed.
  'subdomain-takeover': { S: 'C', C: 'H', I: 'H' },

  // Attack-chain composites (checkId = chain-<ruleId>) — escalated impact.
  'chain-source-to-secret': { C: 'H', I: 'H' },
  'chain-debug-to-rce': { C: 'H', I: 'H', A: 'H' },
  'chain-oauth-token-theft': { C: 'H', UI: 'R' },
  'chain-cors-cred-theft': { S: 'C', C: 'H', UI: 'R' },
  'chain-ssrf-cloud-pivot': { S: 'C', C: 'H', I: 'L' },
  'chain-takeover-cookie-theft': { S: 'C', C: 'H', UI: 'R' },
  'chain-schema-idor': { C: 'H', I: 'L' },
  'chain-cache-poison-auth': { C: 'H', UI: 'R' },
  'chain-xss-csp': { C: 'H', I: 'L', UI: 'R' },
  'chain-jwt-cors-theft': { S: 'C', C: 'H', UI: 'R' },
};

/** Default metrics derived from the qualitative severity band. */
function defaultMetrics(sev: Severity): CvssMetrics {
  switch (sev) {
    case 'critical':
      return { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' };
    case 'high':
      return { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' };
    case 'medium':
      return { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'N', A: 'N' };
    case 'low':
      return { AV: 'N', AC: 'H', PR: 'N', UI: 'R', S: 'U', C: 'L', I: 'N', A: 'N' };
    case 'info':
      return { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'N', I: 'N', A: 'N' };
    default:
      return { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'N', A: 'N' };
  }
}

export function metricsForFinding(f: Pick<Finding, 'checkId' | 'severity'>): CvssMetrics {
  return { ...defaultMetrics(f.severity), ...(PROFILES[f.checkId] ?? {}) };
}

/** CVSS v3.1 roundup: smallest 1-decimal number ≥ input (spec Appendix A). */
export function roundUp1(input: number): number {
  const intInput = Math.round(input * 100000);
  if (intInput % 10000 === 0) return intInput / 100000;
  return (Math.floor(intInput / 10000) + 1) / 10;
}

export function cvssBaseScore(m: CvssMetrics): number {
  const iscBase = 1 - (1 - CIA_W[m.C]) * (1 - CIA_W[m.I]) * (1 - CIA_W[m.A]);
  const impact =
    m.S === 'U'
      ? 6.42 * iscBase
      : 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15);
  const prW = m.S === 'U' ? PR_W_UNCHANGED[m.PR] : PR_W_CHANGED[m.PR];
  const exploitability = 8.22 * AV_W[m.AV] * AC_W[m.AC] * prW * UI_W[m.UI];
  if (impact <= 0) return 0;
  const raw = m.S === 'U' ? impact + exploitability : 1.08 * (impact + exploitability);
  return roundUp1(Math.min(raw, 10));
}

export function cvssVector(m: CvssMetrics): string {
  return `CVSS:3.1/AV:${m.AV}/AC:${m.AC}/PR:${m.PR}/UI:${m.UI}/S:${m.S}/C:${m.C}/I:${m.I}/A:${m.A}`;
}

/** Qualitative band for a numeric CVSS base score (v3.1 rating scale). */
export function scoreSeverity(score: number): Severity {
  if (score === 0) return 'info';
  if (score < 4.0) return 'low';
  if (score < 7.0) return 'medium';
  if (score < 9.0) return 'high';
  return 'critical';
}

/** Full CVSS result (vector + numeric score + derived band) for a finding. */
export function cvssFor(f: Pick<Finding, 'checkId' | 'severity'>): CvssResult {
  const metrics = metricsForFinding(f);
  const score = cvssBaseScore(metrics);
  return { vector: cvssVector(metrics), score, severity: scoreSeverity(score) };
}
