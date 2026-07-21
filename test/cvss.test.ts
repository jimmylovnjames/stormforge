import { describe, it, expect } from 'vitest';
import {
  cvssBaseScore,
  cvssVector,
  cvssFor,
  metricsForFinding,
  roundUp1,
  scoreSeverity,
} from '../src/report/cvss.js';
import { draftFinding } from '../src/report/drafter.js';
import type { Finding, Scope } from '../src/types.js';

describe('cvss base score (v3.1 reference vectors)', () => {
  // Known reference: CVE-style full-impact network vector = 9.8.
  it('computes 9.8 for AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', () => {
    const score = cvssBaseScore({ AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' });
    expect(score).toBe(9.8);
  });

  it('computes 7.5 for a confidentiality-only network vector', () => {
    const score = cvssBaseScore({ AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' });
    expect(score).toBe(7.5);
  });

  it('scope change raises the score (credentialed CORS style)', () => {
    const score = cvssBaseScore({ AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'C', C: 'H', I: 'N', A: 'N' });
    expect(score).toBeGreaterThan(6);
    expect(scoreSeverity(score)).toMatch(/medium|high/);
  });

  it('roundUp1 matches the spec examples', () => {
    expect(roundUp1(4.02)).toBe(4.1);
    expect(roundUp1(4.0)).toBe(4.0);
  });
});

describe('metricsForFinding profiles', () => {
  it('marks subdomain takeover as scope-changed', () => {
    expect(metricsForFinding({ checkId: 'subdomain-takeover', severity: 'high' }).S).toBe('C');
  });
  it('vector string is well-formed', () => {
    const v = cvssVector(metricsForFinding({ checkId: 'exposed-files', severity: 'critical' }));
    expect(v).toMatch(/^CVSS:3\.1\/AV:[NALP]\/AC:[LH]\/PR:[NLH]\/UI:[NR]\/S:[UC]\/C:[NLH]\/I:[NLH]\/A:[NLH]$/);
  });
});

describe('drafter embeds CVSS vector', () => {
  const scope: Scope = { program: 'acme', platform: 'hackerone', inScope: ['*.acme.com'], outOfScope: [], authorized: true };
  const finding: Finding = {
    id: 'x', checkId: 'open-cloud-bucket', title: 'Public S3 bucket', severity: 'high',
    target: 'https://a.acme.com/', description: 'listable', evidence: 'ListBucketResult',
    reproduction: ['curl'], remediation: 'lock it', references: [], needsManualReview: false,
    confidence: 0.85, discoveredAt: new Date().toISOString(),
  };
  it('renders a CVSS:3.1 vector and score line', () => {
    const md = draftFinding(finding, scope);
    expect(md).toMatch(/CVSS:3\.1\/AV:/);
    expect(md).toMatch(/\*\*Severity:\*\* high \(CVSS \d\.\d/);
    expect(md).toContain('Detection confidence:');
    // Sanity: matches direct computation.
    expect(md).toContain(cvssFor(finding).vector);
  });
});
