import { describe, it, expect } from 'vitest';
import { canonicalTarget, stableEvidenceKey, stripStormforgeNoise } from '../src/findings/canonicalize.js';
import { makeFindingId } from '../src/findings/id.js';
import { findPromotionTarget } from '../src/findings/confidence.js';
import type { Finding } from '../src/types.js';

function finding(over: Partial<Finding> & Pick<Finding, 'checkId' | 'target'>): Finding {
  return {
    id: over.id ?? 'x',
    title: 't',
    severity: over.severity ?? 'high',
    description: 'd',
    evidence: over.evidence ?? '',
    reproduction: [],
    remediation: '',
    references: [],
    needsManualReview: over.needsManualReview ?? true,
    discoveredAt: new Date().toISOString(),
    ...over,
  };
}

describe('canonicalTarget', () => {
  it('strips trailing slash and normalizes host case', () => {
    expect(canonicalTarget('https://App.Acme.com/api/v1/users/')).toBe(
      'https://app.acme.com/api/v1/users',
    );
  });

  it('strips StormForge canary query params', () => {
    const noisy =
      'https://app.acme.com/search?q=test&url=https%3A%2F%2Fsf.example%2Fapi%2Fcanary%2Fabcdef0123456789';
    const clean = canonicalTarget(noisy);
    expect(clean).not.toMatch(/canary/i);
    expect(clean).toContain('q=test');
  });

  it('sorts query params for stable keys', () => {
    expect(canonicalTarget('https://a.com/x?b=2&a=1')).toBe(canonicalTarget('https://a.com/x?a=1&b=2'));
  });
});

describe('makeFindingId uses canonical target', () => {
  it('produces the same id for equivalent noisy URLs', () => {
    const a = makeFindingId('xss-injection', 'https://app.acme.com/search?q=1', 'xss');
    const b = makeFindingId('xss-injection', 'https://app.acme.com/search/?q=1', 'xss');
    expect(a).toBe(b);
  });

  it('stableEvidenceKey collapses whitespace', () => {
    expect(stableEvidenceKey('  a   b\n')).toBe(stableEvidenceKey('a b'));
  });

  it('stripStormforgeNoise removes HPP/PP/SSRF canary tokens from evidence keys', () => {
    expect(stripStormforgeNoise(`id=1&id=sfHpp9f3a7c`)).not.toContain('sfHpp');
  });
});

describe('findPromotionTarget with canonical paths', () => {
  it('matches worker and tool findings despite query noise', () => {
    const stored = [
      finding({
        id: 'w1',
        checkId: 'sql-injection-error',
        target: 'https://app.acme.com/api/users?id=1',
        needsManualReview: true,
      }),
    ];
    const tool = finding({
      checkId: 'sqlmap-injection',
      target: 'https://app.acme.com/api/users/?id=1&utm=x',
      severity: 'critical',
      needsManualReview: false,
    });
    expect(findPromotionTarget(stored, tool)?.id).toBe('w1');
  });
});
