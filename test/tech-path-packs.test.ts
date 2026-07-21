import { describe, it, expect } from 'vitest';
import { pathsForProducts, normalizeProduct } from '../src/planning/tech-path-packs.js';
import { heuristicPlan } from '../src/planning/llm-planner.js';
import { fingerprint } from '../src/recon/fingerprint.js';
import type { ProbeResult } from '../src/types.js';

function probe(over: Partial<ProbeResult>): ProbeResult {
  return {
    url: 'https://a.x.com/',
    method: 'GET',
    status: 200,
    headers: {},
    body: '',
    elapsedMs: 5,
    ...over,
  };
}

describe('tech → worker path packs', () => {
  it('maps WordPress / Spring / Express products to focused probe paths', () => {
    const wp = pathsForProducts(['WordPress']);
    expect(wp).toContain('/wp-json/wp/v2/users');
    expect(wp).toContain('/xmlrpc.php');

    const spring = pathsForProducts(['Spring Boot']);
    expect(spring.some((p) => p.startsWith('/actuator'))).toBe(true);

    const express = pathsForProducts(['Express']);
    expect(express).toContain('/api/auth/session');
  });

  it('normalizeProduct lowercases and collapses separators', () => {
    expect(normalizeProduct('ASP.NET')).toBe('asp.net');
    expect(normalizeProduct('Microsoft_IIS')).toBe('microsoft iis');
  });

  it('heuristicPlan merges fingerprint-backed path packs', () => {
    const plan = heuristicPlan(
      {
        products: ['WordPress', 'nginx'],
        seenPaths: ['/'],
        statuses: { '200': 1 },
        interestingHeaders: [],
        paramEndpoints: [],
      },
      [],
    );
    expect(plan.suggestedPaths).toContain('/wp-json/wp/v2/users');
    expect(plan.suggestedPaths.some((p) => /phpinfo|xmlrpc|wp-login/i.test(p))).toBe(true);
  });

  it('fingerprint products feed path packs for GraphQL / OIDC stacks', () => {
    const tech = fingerprint(
      probe({
        headers: { 'x-graphql-yoga-csrf': '1' },
        body: '<html>GraphiQL</html>',
      }),
    );
    const products = tech.map((t) => t.product);
    expect(products.some((p) => /graphql/i.test(p))).toBe(true);
    const paths = pathsForProducts(products);
    expect(paths.some((p) => /graphql|graphiql|playground/i.test(p))).toBe(true);
  });
});
