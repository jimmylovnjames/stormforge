import { describe, it, expect } from 'vitest';
import { nucleiArgsForTech, templatesForProducts } from '../src/planning/tech-templates.js';
import { planFollowUpTasks } from '../src/planning/vuln-planner.js';
import type { Scope } from '../src/types.js';

const scope: Scope = {
  program: 'acme',
  platform: 'hackerone',
  inScope: ['*.acme.com', 'acme.com'],
  outOfScope: [],
  authorized: true,
};

describe('tech → nuclei templates', () => {
  it('maps WordPress / GraphQL / nginx products to focused tags', () => {
    expect(templatesForProducts(['WordPress'])).toMatch(/wordpress/i);
    expect(templatesForProducts(['GraphQL Yoga', 'Apollo GraphQL'])).toMatch(/graphql/i);
    expect(templatesForProducts(['nginx'])).toMatch(/nginx|misconfiguration|cves/i);
  });

  it('nucleiArgsForTech returns flags + templates without inventing out-of-scope targets', () => {
    const args = nucleiArgsForTech(['WordPress', 'PHP']);
    expect(args.templates.toLowerCase()).toContain('wordpress');
    expect(args.flags).toMatch(/-silent|-severity/);
  });

  it('planFollowUpTasks uses tech-tagged nuclei for httpx-tech findings', () => {
    const plan = planFollowUpTasks(
      [
        {
          checkId: 'httpx-tech-detect',
          severity: 'info',
          target: 'https://blog.acme.com',
          title: 'tech detect',
          evidence: 'WordPress,PHP,nginx',
        },
      ],
      scope,
      { maxTasks: 8 },
    );
    const nuclei = plan.tasks.filter((t) => t.tool === 'nuclei');
    expect(nuclei.length).toBeGreaterThan(0);
    expect(nuclei.some((t) => /wordpress/i.test(t.args.templates ?? ''))).toBe(true);
  });

  it('falls back to generic pack when no tech is recognized', () => {
    const args = nucleiArgsForTech(['TotallyUnknownFramework']);
    expect(args.templates).toMatch(/cves|vulnerabilities|misconfiguration/);
  });
});
