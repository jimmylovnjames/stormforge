import { describe, it, expect } from 'vitest';
import {
  prioritizeFindings,
  topSubmitReady,
  isSubmitReady,
  triageScore,
  draftTriageReport,
} from '../src/findings/prioritize.js';
import type { Finding } from '../src/types.js';

function finding(over: Partial<Finding> & Pick<Finding, 'checkId' | 'target' | 'severity'>): Finding {
  return {
    id: over.id ?? Math.random().toString(36).slice(2),
    title: over.title ?? over.checkId,
    description: '',
    evidence: over.evidence ?? 'e',
    reproduction: [],
    remediation: '',
    references: [],
    needsManualReview: false,
    discoveredAt: new Date().toISOString(),
    ...over,
  };
}

const critical = finding({
  checkId: 'secret-exposure',
  target: 'https://a.acme.com/main.js',
  severity: 'critical',
  title: 'Stripe live key',
  confidence: 0.9,
  submitReady: true,
});
const highGql = finding({
  checkId: 'graphql-introspection',
  target: 'https://api.acme.com/graphql',
  severity: 'high',
  title: 'GraphQL introspection',
  confidence: 0.88,
  submitReady: true,
});
const mediumHeader = finding({
  checkId: 'security-headers',
  target: 'https://a.acme.com/',
  severity: 'low',
  title: 'Missing HSTS',
  confidence: 0.5,
});
const infoTech = finding({
  checkId: 'httpx-tech-detect',
  target: 'https://a.acme.com/',
  severity: 'info',
  title: 'Tech',
  confidence: 0.4,
});

describe('triageScore + isSubmitReady', () => {
  it('scores criticals above lows', () => {
    expect(triageScore(critical).score).toBeGreaterThan(triageScore(mediumHeader).score);
  });
  it('submit-ready follows explicit flag then severity/manual-review', () => {
    expect(isSubmitReady(critical)).toBe(true);
    expect(isSubmitReady(mediumHeader)).toBe(false);
    expect(isSubmitReady(finding({ checkId: 'x', target: 'https://a.acme.com', severity: 'high', needsManualReview: true }))).toBe(false);
    expect(isSubmitReady(finding({ checkId: 'x', target: 'https://a.acme.com', severity: 'high', needsManualReview: false }))).toBe(true);
  });
});

describe('prioritizeFindings', () => {
  it('ranks submit-ready criticals/highs first and assigns ranks', () => {
    const r = prioritizeFindings([infoTech, mediumHeader, critical, highGql]);
    expect(r.entries[0]!.finding.title).toBe('Stripe live key');
    expect(r.entries[0]!.rank).toBe(1);
    expect(r.entries[1]!.finding.title).toBe('GraphQL introspection');
    expect(r.entries.at(-1)!.finding.severity).toBe('info');
    expect(r.submitReady).toBe(2);
    expect(r.total).toBe(4);
  });

  it('collapses canonical duplicates and counts them', () => {
    const dupA = finding({ checkId: 'cors-misconfig', target: 'https://a.acme.com/api', severity: 'medium', confidence: 0.6 });
    const dupB = finding({ checkId: 'cors-misconfig', target: 'https://a.acme.com/api/', severity: 'high', confidence: 0.75 });
    const r = prioritizeFindings([dupA, dupB]);
    expect(r.total).toBe(1);
    expect(r.entries[0]!.dupes).toBe(1);
    // Keeps the higher-severity representative.
    expect(r.entries[0]!.finding.severity).toBe('high');
  });

  it('is deterministic across calls', () => {
    const input = [infoTech, mediumHeader, critical, highGql];
    const a = prioritizeFindings(input).entries.map((e) => e.finding.title);
    const b = prioritizeFindings(input).entries.map((e) => e.finding.title);
    expect(a).toEqual(b);
  });

  it('attaches a CVSS score/vector per entry', () => {
    const r = prioritizeFindings([highGql]);
    expect(r.entries[0]!.cvssScore).toBeGreaterThan(0);
    expect(r.entries[0]!.cvssVector).toMatch(/^CVSS:3\.1\//);
  });
});

describe('topSubmitReady + draftTriageReport', () => {
  it('returns only submit-ready entries up to the limit', () => {
    const top = topSubmitReady([infoTech, mediumHeader, critical, highGql], 1);
    expect(top).toHaveLength(1);
    expect(top[0]!.submitReady).toBe(true);
  });

  it('renders a ranked Markdown table with a submit-ready marker', () => {
    const md = draftTriageReport(prioritizeFindings([critical, mediumHeader]), 'acme');
    expect(md).toContain('# Triage queue — acme');
    expect(md).toMatch(/\|\s*1\s*\|/);
    expect(md.indexOf('Stripe live key')).toBeLessThan(md.indexOf('Missing HSTS'));
    expect(md).toContain('✅');
  });
});
