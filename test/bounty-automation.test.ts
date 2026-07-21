import { describe, it, expect } from 'vitest';
import { estimateCvss, ratingFromScore, sortByCvss } from '../src/report/cvss.js';
import {
  buildBountyPackets,
  draftHackerOneReport,
  draftImmunefiReport,
} from '../src/report/templates.js';
import { draftBountyAutomation, draftFinding, draftDisclosure } from '../src/report/drafter.js';
import type { Finding, Scope } from '../src/types.js';

const h1Scope: Scope = {
  program: 'acme-h1',
  platform: 'hackerone',
  inScope: ['*.acme.com'],
  outOfScope: [],
  authorized: true,
};

const immunoScope: Scope = {
  ...h1Scope,
  program: 'acme-immuno',
  platform: 'immunefi',
};

function finding(over: Partial<Finding> & Pick<Finding, 'checkId' | 'severity' | 'title'>): Finding {
  return {
    id: over.id ?? 'f1',
    target: over.target ?? 'https://api.acme.com/exec?cmd=id',
    description: 'd',
    evidence: 'uid=0(root)',
    reproduction: ['curl ...'],
    remediation: 'fix',
    references: ['https://cwe.mitre.org'],
    needsManualReview: over.needsManualReview ?? false,
    discoveredAt: new Date().toISOString(),
    cwe: over.cwe,
    ...over,
  };
}

describe('CVSS estimates', () => {
  it('maps RCE command-injection to 10.0 critical', () => {
    const cvss = estimateCvss(
      finding({ checkId: 'command-injection', severity: 'critical', title: 'RCE', cwe: 'CWE-78' }),
    );
    expect(cvss.score).toBe(10.0);
    expect(cvss.rating).toBe('critical');
    expect(cvss.vector).toContain('CVSS:3.1');
  });

  it('ratingFromScore bands correctly', () => {
    expect(ratingFromScore(9.8)).toBe('critical');
    expect(ratingFromScore(7.5)).toBe('high');
    expect(ratingFromScore(5.0)).toBe('medium');
    expect(ratingFromScore(0)).toBe('info');
  });

  it('sortByCvss puts higher scores first', () => {
    const sorted = sortByCvss([
      finding({ checkId: 'cors-misconfig', severity: 'high', title: 'CORS', id: 'c' }),
      finding({ checkId: 'command-injection', severity: 'critical', title: 'RCE', id: 'r', cwe: 'CWE-78' }),
    ]);
    expect(sorted[0]!.checkId).toBe('command-injection');
  });
});

describe('HackerOne template', () => {
  it('includes H1 sections, CVSS, and form fields', () => {
    const f = finding({
      checkId: 'command-injection',
      severity: 'critical',
      title: 'OS command injection',
      cwe: 'CWE-78',
    });
    const pack = draftHackerOneReport(f, h1Scope);
    expect(pack.platform).toBe('hackerone');
    expect(pack.cvssScore).toBeGreaterThanOrEqual(9.0);
    expect(pack.markdown).toContain('## Steps To Reproduce');
    expect(pack.markdown).toContain('## Impact');
    expect(pack.fields['Weakness']).toBe('CWE-78');
    expect(pack.fields['CVSS']).toContain('CVSS:3.1');
    expect(pack.submissionTitle).toMatch(/CRITICAL/i);
  });
});

describe('Immunefi template', () => {
  it('includes funds-at-risk and Immunefi framing', () => {
    const f = finding({
      checkId: 'sql-injection-error',
      severity: 'critical',
      title: 'SQLi',
      cwe: 'CWE-89',
    });
    const pack = draftImmunefiReport(f, immunoScope);
    expect(pack.platform).toBe('immunefi');
    expect(pack.markdown).toContain('Funds / Assets at Risk');
    expect(pack.markdown).toContain('Immunefi');
    expect(pack.fields['CVSS Score']).toBeDefined();
    expect(pack.cvssScore).toBeGreaterThanOrEqual(9.0);
  });
});

describe('bounty automation', () => {
  it('only emits high/critical with CVSS >= 7 and ranks by score', () => {
    const packets = buildBountyPackets(
      [
        finding({ checkId: 'security-headers', severity: 'low', title: 'HSTS', id: 'l' }),
        finding({ checkId: 'xss-injection', severity: 'high', title: 'XSS', id: 'x', cwe: 'CWE-79' }),
        finding({
          checkId: 'command-injection',
          severity: 'critical',
          title: 'RCE',
          id: 'r',
          cwe: 'CWE-78',
        }),
      ],
      h1Scope,
    );
    expect(packets.every((p) => p.cvssScore >= 7)).toBe(true);
    expect(packets[0]!.cvssScore).toBeGreaterThanOrEqual(packets[1]?.cvssScore ?? 0);
    expect(packets[0]!.title).toContain('RCE');
  });

  it('draftBountyAutomation picks immunefi from scope', () => {
    const out = draftBountyAutomation(
      [
        finding({
          checkId: 'secret-exposure',
          severity: 'critical',
          title: 'AWS key',
          cwe: 'CWE-798',
        }),
      ],
      immunoScope,
    );
    expect(out.platform).toBe('immunefi');
    expect(out.count).toBe(1);
    expect(out.combinedMarkdown).toContain('Bug Report');
  });

  it('draftFinding includes CVSS vector', () => {
    const md = draftFinding(
      finding({ checkId: 'path-traversal', severity: 'critical', title: 'LFI', cwe: 'CWE-22' }),
      h1Scope,
    );
    expect(md).toMatch(/CVSS Vector/);
    expect(md).toContain('CVSS:3.1');
  });

  it('draftDisclosure orders by CVSS', () => {
    const md = draftDisclosure(
      [
        finding({ checkId: 'cors-misconfig', severity: 'high', title: 'CORS weak', id: 'a' }),
        finding({
          checkId: 'command-injection',
          severity: 'critical',
          title: 'RCE root',
          id: 'b',
          cwe: 'CWE-78',
        }),
      ],
      h1Scope,
    );
    expect(md.indexOf('RCE root')).toBeLessThan(md.indexOf('CORS weak'));
    expect(md).toContain('Ordered by: CVSS');
  });
});
