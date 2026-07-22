import { describe, it, expect } from 'vitest';
import { canonicalizeTarget, canonicalizeEvidenceKey, hashTokenList } from '../src/findings/canonicalize.js';
import { makeFindingId, fnv1a } from '../src/findings/id.js';
import {
  enrichAndFilterFindings,
  isNoiseFinding,
  scoreConfidence,
  adjustSeverity,
} from '../src/findings/quality.js';
import type { Finding } from '../src/types.js';

function finding(over: Partial<Finding> & Pick<Finding, 'checkId' | 'severity' | 'target'>): Finding {
  return {
    id: over.id || 'x',
    title: 't',
    description: 'd',
    evidence: 'e',
    reproduction: [],
    remediation: '',
    references: [],
    needsManualReview: false,
    discoveredAt: new Date().toISOString(),
    ...over,
  };
}

describe('canonicalize', () => {
  it('normalizes scheme, host case, trailing slash', () => {
    expect(canonicalizeTarget('HTTPS://API.Acme.com/v1/')).toBe('api.acme.com/v1');
    expect(canonicalizeTarget('api.acme.com')).toBe('api.acme.com/');
  });

  it('stable query order', () => {
    expect(canonicalizeTarget('https://a.com/x?b=2&a=1')).toBe(
      canonicalizeTarget('https://a.com/x?a=1&b=2'),
    );
  });

  it('hashTokenList ignores order and dupes', () => {
    expect(hashTokenList(['B', 'a', 'a'])).toBe(hashTokenList(['a', 'B']));
  });
});

describe('makeFindingId', () => {
  it('is stable across URL variants', () => {
    const a = makeFindingId('nuclei-cve', 'https://API.acme.com/path/', 'tmpl');
    const b = makeFindingId('nuclei-cve', 'http://api.acme.com/path', 'tmpl');
    expect(a).toBe(b);
    expect(a).toMatch(/^nuclei-cve-[0-9a-f]{8}$/);
  });

  it('fnv1a is deterministic', () => {
    expect(fnv1a('hello')).toBe(fnv1a('hello'));
    expect(fnv1a(canonicalizeEvidenceKey('  a  b '))).toBe(fnv1a('a b'));
  });
});

describe('quality filter', () => {
  it('drops nmap info open-port noise and httpx tech info', () => {
    expect(isNoiseFinding(finding({ checkId: 'nmap-open-port', severity: 'info', target: 'h' }))).toBe(true);
    expect(isNoiseFinding(finding({ checkId: 'httpx-tech-detect', severity: 'info', target: 'h' }))).toBe(true);
    expect(isNoiseFinding(finding({ checkId: 'nmap-open-port', severity: 'high', target: 'h' }))).toBe(false);
  });

  it('scores confidence and adjusts severity with auth context', () => {
    const f = finding({
      checkId: 'auth-access-control',
      severity: 'medium',
      target: 'https://a.com/api/1',
      needsManualReview: false,
    });
    expect(scoreConfidence(f)).toBeGreaterThan(0.4);
    expect(adjustSeverity(f, { authenticated: true })).toBe('high');
  });

  it('enrichAndFilterFindings dedupes and attaches confidence', () => {
    const a = finding({
      id: 'same',
      checkId: 'sqlmap-injection',
      severity: 'critical',
      target: 'https://a.com/?id=1',
      needsManualReview: true,
    });
    const out = enrichAndFilterFindings([a, { ...a }]);
    expect(out).toHaveLength(1);
    expect(out[0]!.confidence).toBeGreaterThan(0);
  });
});
