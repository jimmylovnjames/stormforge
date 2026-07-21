import { describe, it, expect } from 'vitest';
import {
  highImpactFindings,
  prioritizeFindings,
  score,
  shouldAutoDraft,
} from '../src/findings/prioritize.js';
import type { Finding } from '../src/types.js';

function f(over: Partial<Finding> & Pick<Finding, 'checkId' | 'severity' | 'title'>): Finding {
  return {
    id: over.id ?? crypto.randomUUID(),
    target: over.target ?? 'https://a.x.com/',
    description: 'd',
    evidence: 'e',
    reproduction: ['r'],
    remediation: 'fix',
    references: [],
    needsManualReview: over.needsManualReview ?? false,
    discoveredAt: new Date().toISOString(),
    ...over,
  };
}

describe('prioritizeFindings', () => {
  it('ranks critical SQLi above medium CORS', () => {
    const ranked = prioritizeFindings([
      f({ checkId: 'cors-misconfig', severity: 'medium', title: 'cors' }),
      f({ checkId: 'sql-injection-error', severity: 'critical', title: 'sqli' }),
      f({ checkId: 'security-headers', severity: 'low', title: 'hdr' }),
    ]);
    expect(ranked[0]!.checkId).toBe('sql-injection-error');
    expect(score(ranked[0]!)).toBeGreaterThan(score(ranked[1]!));
  });

  it('shouldAutoDraft only for high/critical', () => {
    expect(shouldAutoDraft([f({ checkId: 'security-headers', severity: 'low', title: 'x' })])).toBe(false);
    expect(shouldAutoDraft([f({ checkId: 'weak-jwt', severity: 'critical', title: 'jwt' })])).toBe(true);
  });

  it('highImpactFindings filters and sorts', () => {
    const hits = highImpactFindings([
      f({ checkId: 'xss-injection', severity: 'high', title: 'xss' }),
      f({ checkId: 'security-headers', severity: 'info', title: 'h' }),
      f({ checkId: 'command-injection', severity: 'critical', title: 'rce' }),
    ]);
    expect(hits).toHaveLength(2);
    expect(hits[0]!.checkId).toBe('command-injection');
  });
});
