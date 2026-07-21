import { describe, it, expect } from 'vitest';
import {
  buildAutonomyStatus,
  summarizeTactics,
} from '../src/planning/autonomy-status.js';
import { correlateAttackChains } from '../src/findings/attack-chains.js';
import type { Finding, Scope } from '../src/types.js';

function finding(over: Partial<Finding> & Pick<Finding, 'checkId' | 'severity' | 'target' | 'title'>): Finding {
  return {
    id: over.id ?? crypto.randomUUID(),
    description: 'd',
    evidence: '',
    reproduction: [],
    remediation: '',
    references: [],
    needsManualReview: over.needsManualReview ?? false,
    discoveredAt: new Date().toISOString(),
    submitReady: over.submitReady,
    confidence: over.confidence,
    ...over,
  };
}

describe('autonomy status', () => {
  it('summarizes tactics and findings for operator visibility', () => {
    const status = buildAutonomyStatus({
      program: 'acme',
      tactics: ['/api/v1/users/1', '/graphql'],
      findings: [
        finding({
          checkId: 'sql-injection-error',
          severity: 'critical',
          target: 'https://app.acme.com/q?x=1',
          title: 'SQLi',
          submitReady: true,
          confidence: 0.9,
        }),
        finding({
          checkId: 'security-headers',
          severity: 'low',
          target: 'https://app.acme.com/',
          title: 'headers',
          needsManualReview: true,
        }),
      ],
      rescans: [
        {
          scanId: 's1',
          sourceTool: 'katana',
          targets: ['https://app.acme.com/a'],
          createdAt: '2026-01-01T00:00:00.000Z',
        },
      ],
      bountyDraftCount: 1,
    });
    expect(status.program).toBe('acme');
    expect(status.tacticsCount).toBe(2);
    expect(status.submitReadyCount).toBe(1);
    expect(status.findingCount).toBe(2);
    expect(status.recentRescans).toHaveLength(1);
    expect(status.topTactics).toContain('/graphql');
    expect(status.bountyDraftCount).toBe(1);
  });

  it('summarizeTactics caps and preserves order preference', () => {
    expect(summarizeTactics(['/a', '/b', '/c'], 2)).toEqual(['/a', '/b']);
  });
});

describe('attack chain correlation', () => {
  const scope: Scope = {
    program: 'acme',
    platform: 'hackerone',
    inScope: ['*.acme.com'],
    outOfScope: [],
    authorized: true,
  };

  it('chains IDOR + weak JWT on the same host', () => {
    const chains = correlateAttackChains([
      finding({
        checkId: 'auth-access-control',
        severity: 'high',
        target: 'https://api.acme.com/users/1',
        title: 'IDOR',
      }),
      finding({
        checkId: 'weak-jwt',
        severity: 'critical',
        target: 'https://api.acme.com/login',
        title: 'alg=none',
      }),
    ], scope);
    expect(chains.length).toBeGreaterThan(0);
    expect(chains[0]!.kind).toBe('auth-takeover');
    expect(chains[0]!.findingIds.length).toBe(2);
    expect(chains[0]!.severity).toBe('critical');
  });

  it('chains open-redirect + SSRF on same host', () => {
    const chains = correlateAttackChains([
      finding({
        checkId: 'ssrf-open-redirect',
        severity: 'high',
        target: 'https://app.acme.com/redirect?url=x',
        title: 'Open redirect',
        cwe: 'CWE-601',
      }),
      finding({
        checkId: 'ssrf-blind-canary',
        severity: 'critical',
        target: 'https://app.acme.com/proxy?url=y',
        title: 'Blind SSRF',
      }),
    ], scope);
    expect(chains.some((c) => c.kind === 'ssrf-chain')).toBe(true);
  });

  it('does not chain unrelated hosts', () => {
    const chains = correlateAttackChains([
      finding({
        checkId: 'auth-access-control',
        severity: 'high',
        target: 'https://a.acme.com/users/1',
        title: 'IDOR',
      }),
      finding({
        checkId: 'weak-jwt',
        severity: 'critical',
        target: 'https://b.acme.com/login',
        title: 'jwt',
      }),
    ], scope);
    expect(chains.every((c) => c.findingIds.length < 2 || c.kind !== 'auth-takeover')).toBe(true);
  });
});
