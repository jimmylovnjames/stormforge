import { describe, it, expect } from 'vitest';
import {
  extractWinningTactics,
  heuristicPlan,
  mergeTactics,
  pathsFromParamEndpoints,
} from '../src/planning/llm-planner.js';
import type { Finding } from '../src/types.js';

function finding(over: Partial<Finding> & Pick<Finding, 'checkId' | 'severity' | 'target'>): Finding {
  return {
    id: '1',
    title: 't',
    description: 'd',
    evidence: '',
    reproduction: [],
    remediation: '',
    references: [],
    needsManualReview: false,
    discoveredAt: new Date().toISOString(),
    ...over,
  };
}

describe('tactic memory helpers', () => {
  it('extractWinningTactics pulls pathnames from high-signal findings', () => {
    const tactics = extractWinningTactics([
      finding({
        checkId: 'sql-injection-error',
        severity: 'critical',
        target: 'https://app.acme.com/api/v1/search?q=1',
        submitReady: true,
      }),
      finding({
        checkId: 'security-headers',
        severity: 'info',
        target: 'https://app.acme.com/',
      }),
      finding({
        checkId: 'auth-access-control',
        severity: 'high',
        target: 'https://app.acme.com/api/v1/users/1',
        needsManualReview: true,
      }),
    ]);
    expect(tactics).toContain('/api/v1/search');
    expect(tactics).toContain('/api/v1/users/1');
    expect(tactics.every((t) => t.startsWith('/'))).toBe(true);
  });

  it('mergeTactics dedupes and caps', () => {
    expect(mergeTactics(['/a', '/b'], ['/b', '/c'], 2)).toEqual(['/a', '/b']);
  });
});

describe('smarter heuristicPlan', () => {
  it('seeds from prior tactics and param endpoints', () => {
    const plan = heuristicPlan(
      {
        products: ['Express'],
        seenPaths: ['/'],
        statuses: { '200': 3 },
        interestingHeaders: [],
        paramEndpoints: ['/search?q=1', '/api/items?id=2'],
      },
      ['/api/v1/users/1'],
    );
    expect(plan.suggestedPaths).toContain('/api/v1/users/1');
    expect(plan.suggestedPaths.some((p) => p.includes('search') || p === '/api/search')).toBe(true);
    expect(plan.source).toBe('evolved');
  });

  it('adds auth-bypass pack when 401/403 seen', () => {
    const plan = heuristicPlan(
      {
        products: [],
        seenPaths: ['/'],
        statuses: { '401': 2, '403': 1 },
        interestingHeaders: [],
        paramEndpoints: [],
      },
      [],
    );
    expect(plan.suggestedPaths).toContain('/admin');
    expect(plan.suggestedPaths).toContain('/api/v1/me');
  });

  it('pathsFromParamEndpoints derives sibling API paths', () => {
    const paths = pathsFromParamEndpoints(['/search?q=1', '/api/v1/items?id=2']);
    expect(paths).toContain('/search');
    expect(paths).toContain('/api/search');
    expect(paths).toContain('/api/v1/items');
  });
});
