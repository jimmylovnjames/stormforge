import { describe, it, expect } from 'vitest';
import {
  deriveBlackSwanScenarios,
  scenariosToFindings,
  draftBlackSwanReport,
} from '../src/findings/black-swan.js';
import type { Finding } from '../src/types.js';

function finding(over: Partial<Finding> & Pick<Finding, 'checkId' | 'target' | 'severity'>): Finding {
  return {
    id: over.id ?? Math.random().toString(36).slice(2),
    title: over.title ?? over.checkId,
    description: over.description ?? '',
    evidence: over.evidence ?? 'e',
    reproduction: over.reproduction ?? [],
    remediation: over.remediation ?? '',
    references: over.references ?? [],
    needsManualReview: over.needsManualReview ?? false,
    discoveredAt: over.discoveredAt ?? new Date().toISOString(),
    confidence: over.confidence ?? 0.8,
    submitReady: over.submitReady ?? true,
    source: over.source ?? 'worker',
    evidenceGrade: over.evidenceGrade ?? 'fingerprint',
    ...over,
  };
}

describe('deriveBlackSwanScenarios', () => {
  it('derives Ghost Cookie Lateral Hijack when takeover + broad cookie + auth signal co-occur', () => {
    const scenarios = deriveBlackSwanScenarios([
      finding({ checkId: 'subdomain-takeover', target: 'https://dangling.acme.com', severity: 'high' }),
      finding({
        checkId: 'insecure-cookies',
        target: 'https://www.acme.com',
        severity: 'medium',
        evidence: 'Scope: broad-domain\nDomain: .acme.com',
      }),
      finding({ checkId: 'auth-differential', target: 'https://api.acme.com/v1/me', severity: 'high' }),
    ]);
    const ghost = scenarios.find((s) => s.scenarioId === 'ghost-cookie-lateral');
    expect(ghost).toBeDefined();
    expect(ghost!.score).toBeGreaterThan(0);
    expect(ghost!.components.length).toBeGreaterThanOrEqual(3);
    expect(ghost!.domain).toBe('acme.com');
  });

  it('derives schema-shadow scenario and sorts by score descending', () => {
    const scenarios = deriveBlackSwanScenarios([
      finding({ checkId: 'graphql-introspection', target: 'https://api.acme.com/graphql', severity: 'high' }),
      finding({ checkId: 'auth-access-control', target: 'https://api.acme.com/v1/users/1', severity: 'critical' }),
      finding({ checkId: 'cors-misconfig', target: 'https://api.acme.com', severity: 'high' }),
      finding({ checkId: 'ssrf-candidate', target: 'https://app.acme.com/fetch?url=', severity: 'medium' }),
      finding({ checkId: 'open-cloud-bucket', target: 'https://assets.acme.com', severity: 'high' }),
    ]);
    expect(scenarios.some((s) => s.scenarioId === 'schema-shadow-exfil')).toBe(true);
    for (let i = 1; i < scenarios.length; i++) {
      expect(scenarios[i - 1]!.score).toBeGreaterThanOrEqual(scenarios[i]!.score);
    }
  });

  it('ignores existing black-swan synthetic findings', () => {
    const scenarios = deriveBlackSwanScenarios([
      finding({ checkId: 'black-swan-foo', target: 'https://app.acme.com', severity: 'high' }),
      finding({ checkId: 'graphql-introspection', target: 'https://api.acme.com/graphql', severity: 'high' }),
      finding({ checkId: 'auth-access-control', target: 'https://api.acme.com/v1/users/1', severity: 'high' }),
    ]);
    expect(scenarios.some((s) => s.scenarioId === 'schema-shadow-exfil')).toBe(true);
  });
});

describe('scenario renderers', () => {
  it('converts scenarios to synthetic findings', () => {
    const scenarios = deriveBlackSwanScenarios([
      finding({ checkId: 'jwt-exposure', target: 'https://app.acme.com/main.js', severity: 'high' }),
      finding({ checkId: 'auth-differential', target: 'https://api.acme.com/v1/me', severity: 'high' }),
      finding({ checkId: 'open-redirect', target: 'https://auth.acme.com/login?next=', severity: 'medium' }),
    ]);
    const out = scenariosToFindings(scenarios);
    expect(out.length).toBe(scenarios.length);
    expect(out[0]!.checkId.startsWith('black-swan-')).toBe(true);
    expect(out[0]!.evidence).toMatch(/Scenario:/);
  });

  it('renders markdown report', () => {
    const scenarios = deriveBlackSwanScenarios([
      finding({ checkId: 'ssrf-candidate', target: 'https://app.acme.com/fetch?url=', severity: 'medium' }),
      finding({ checkId: 'open-cloud-bucket', target: 'https://assets.acme.com', severity: 'high' }),
    ]);
    const md = draftBlackSwanReport('acme', scenarios);
    expect(md).toContain('Black Swan scenarios - acme');
    if (scenarios.length) {
      expect(md).toContain('Momentum score');
      expect(md).toContain('Prerequisites');
    }
  });
});
