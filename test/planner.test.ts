import { describe, it, expect } from 'vitest';
import {
  heuristicAttackPlan,
  planFromFindings,
  sanitizeTasks,
  nucleiTemplatesFromText,
} from '../src/planning/vuln-planner.js';
import { heuristicPlan } from '../src/planning/llm-planner.js';
import type { Finding, Scope } from '../src/types.js';

const scope: Scope = {
  program: 'acme',
  platform: 'hackerone',
  inScope: ['*.acme.com', 'acme.com', 'httpbin.org'],
  outOfScope: [],
  authorized: true,
};

describe('vuln-planner', () => {
  it('heuristic plan includes core tools and sqlmap only for param URLs', () => {
    const plan = heuristicAttackPlan(['https://app.acme.com', 'https://app.acme.com/search?q=1'], scope);
    const tools = new Set(plan.tasks.map((t) => t.tool));
    expect(tools.has('httpx')).toBe(true);
    expect(tools.has('nuclei')).toBe(true);
    expect(tools.has('subfinder')).toBe(true);
    expect(tools.has('katana')).toBe(true);
    expect(tools.has('ffuf')).toBe(true);
    expect(plan.tasks.some((t) => t.tool === 'sqlmap')).toBe(true);
    expect(plan.tasks.filter((t) => t.tool === 'sqlmap').every((t) => /[?&]\w+=/.test(t.target))).toBe(true);
  });

  it('sanitizeTasks refuses out-of-scope and destructive sqlmap', () => {
    const cleaned = sanitizeTasks(
      [
        { tool: 'httpx', target: 'https://evil.com', args: {}, timeoutSec: 60, rationale: 'x' },
        {
          tool: 'sqlmap',
          target: 'https://app.acme.com/?id=1',
          args: { flags: '--batch --dump' },
          timeoutSec: 60,
          rationale: 'bad',
        },
        {
          tool: 'nuclei',
          target: 'https://app.acme.com',
          args: { templates: 'cves' },
          timeoutSec: 60,
          rationale: 'ok',
        },
      ],
      scope,
    );
    expect(cleaned).toHaveLength(1);
    expect(cleaned[0]!.tool).toBe('nuclei');
  });

  it('planFromFindings emits tech-tagged nuclei from httpx tech', () => {
    const findings: Finding[] = [
      {
        id: '1',
        checkId: 'httpx-tech-detect',
        title: 'Tech detected: WordPress,PHP',
        severity: 'info',
        target: 'https://blog.acme.com',
        description: '',
        evidence: 'WordPress,PHP,nginx',
        reproduction: [],
        remediation: '',
        references: [],
        needsManualReview: false,
        discoveredAt: new Date().toISOString(),
      },
    ];
    const plan = planFromFindings(findings, scope);
    expect(plan.source).toBe('evolved');
    expect(plan.tasks.some((t) => t.tool === 'nuclei' && /wordpress/i.test(t.args.templates || ''))).toBe(true);
  });

  it('nucleiTemplatesFromText maps products', () => {
    expect(nucleiTemplatesFromText('GraphQL Yoga on nginx')).toMatch(/graphql/);
  });

  it('refuses tasks when scope is not authorized', async () => {
    const { sanitizeTasks: st } = await import('../src/planning/vuln-planner.js');
    const raw = heuristicAttackPlan(['https://app.acme.com'], scope);
    expect(st(raw.tasks, { ...scope, authorized: false })).toHaveLength(0);
  });
});

describe('llm-planner heuristic', () => {
  it('suggests auth paths when 401/403 seen and product-specific paths', () => {
    const plan = heuristicPlan(
      {
        products: ['Express', 'nginx'],
        seenPaths: ['/'],
        statuses: { '401': 2 },
        paramEndpoints: ['/search?q=1'],
      },
      ['/api/v1/users/1'],
    );
    expect(plan.suggestedPaths).toContain('/api/v1/users/1');
    expect(plan.suggestedPaths).toContain('/admin');
    expect(plan.suggestedPaths.some((p) => p.includes('session') || p.includes('search'))).toBe(true);
  });
});
