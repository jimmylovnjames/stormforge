import { describe, it, expect } from 'vitest';
import { draftFinding, draftDisclosure } from '../src/report/drafter.js';
import { compareVersions } from '../src/util/semver.js';
import { makeFindingId, fnv1a } from '../src/findings/id.js';
import { maxSeverity, emptySummary } from '../src/findings/severity.js';
import type { Finding, Scope } from '../src/types.js';

const scope: Scope = { program: 'acme', platform: 'hackerone', inScope: ['*.acme.com'], outOfScope: [], authorized: true };

const finding: Finding = {
  id: 'x', checkId: 'security-headers', title: 'Missing HSTS', severity: 'low',
  target: 'https://a.acme.com/', description: 'no hsts', evidence: 'header absent',
  reproduction: ['curl -sI https://a.acme.com/'], remediation: 'add HSTS',
  cwe: 'CWE-319', references: ['https://example'], needsManualReview: false,
  discoveredAt: new Date().toISOString(),
};

describe('draftFinding', () => {
  it('produces a markdown report with required sections', () => {
    const md = draftFinding(finding, scope);
    expect(md).toContain('# Missing HSTS');
    expect(md).toContain('## Steps to Reproduce');
    expect(md).toContain('## Remediation');
    expect(md).toContain('HackerOne');
  });
  it('marks manual-review findings with a warning', () => {
    const md = draftFinding({ ...finding, needsManualReview: true }, scope);
    expect(md).toContain('verify manually');
  });
});

describe('draftDisclosure', () => {
  it('orders findings by severity descending', () => {
    const md = draftDisclosure(
      [
        { ...finding, title: 'Low one', severity: 'low' },
        { ...finding, title: 'Critical one', severity: 'critical' },
      ],
      scope,
    );
    expect(md.indexOf('Critical one')).toBeLessThan(md.indexOf('Low one'));
  });
});

describe('compareVersions', () => {
  it('orders correctly', () => {
    expect(compareVersions('1.18.0', '1.21.0')).toBe(-1);
    expect(compareVersions('2.4.51', '2.4.51')).toBe(0);
    expect(compareVersions('3.6.0', '3.5.0')).toBe(1);
    expect(compareVersions('1.9', '1.10')).toBe(-1);
  });
});

describe('finding ids', () => {
  it('is deterministic', () => {
    expect(makeFindingId('c', 't', 'e')).toBe(makeFindingId('c', 't', 'e'));
    expect(fnv1a('abc')).toBe(fnv1a('abc'));
  });
  it('differs by input', () => {
    expect(makeFindingId('c', 't', 'e1')).not.toBe(makeFindingId('c', 't', 'e2'));
  });
});

describe('severity helpers', () => {
  it('maxSeverity picks the higher', () => {
    expect(maxSeverity('low', 'critical')).toBe('critical');
    expect(maxSeverity('high', 'medium')).toBe('high');
  });
  it('emptySummary zeroes all bands', () => {
    expect(emptySummary()).toEqual({ info: 0, low: 0, medium: 0, high: 0, critical: 0 });
  });
});
