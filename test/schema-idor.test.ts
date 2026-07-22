import { describe, it, expect } from 'vitest';
import {
  extractOpenApiRoutes,
  idorishRoutes,
  materializeIdorUrls,
  buildSchemaIdorFollowUps,
} from '../src/recon/openapi-extract.js';
import { apiSchemaExposureCheck } from '../src/detect/checks/api-schema-exposure.js';
import { planFromFindings } from '../src/planning/vuln-planner.js';
import type { CheckContext, Finding, ProbeResult, Scope } from '../src/types.js';

const scope: Scope = {
  program: 'acme',
  platform: 'hackerone',
  inScope: ['*.acme.com', 'acme.com'],
  outOfScope: [],
  authorized: true,
};
const ctx: CheckContext = { scope };

const SPEC = JSON.stringify({
  openapi: '3.0.3',
  info: { title: 'Acme API', version: '1.0.0' },
  paths: {
    '/health': { get: { summary: 'ok' } },
    '/users/{userId}': { get: { summary: 'user' }, put: { summary: 'update' } },
    '/orders/{orderId}/items': { get: { summary: 'items' } },
    '/admin/stats': { get: { summary: 'stats' } },
  },
});

function probe(over: Partial<ProbeResult> & Pick<ProbeResult, 'url' | 'body'>): ProbeResult {
  return {
    method: 'GET',
    status: 200,
    headers: { 'content-type': 'application/json' },
    elapsedMs: 1,
    ...over,
  };
}

describe('openapi-extract', () => {
  it('extracts path templates and flags IDOR-shaped ones', () => {
    const routes = extractOpenApiRoutes(SPEC);
    expect(routes.map((r) => r.path).sort()).toEqual(
      ['/admin/stats', '/health', '/orders/{orderId}/items', '/users/{userId}'].sort(),
    );
    const idor = idorishRoutes(routes).map((r) => r.path).sort();
    expect(idor).toEqual(['/orders/{orderId}/items', '/users/{userId}'].sort());
    expect(routes.find((r) => r.path === '/users/{userId}')!.methods).toContain('get');
  });

  it('materializes sample GET URLs under the API origin', () => {
    const urls = materializeIdorUrls('https://api.acme.com', extractOpenApiRoutes(SPEC), 10);
    expect(urls.some((u) => u === 'https://api.acme.com/users/1')).toBe(true);
    expect(urls.some((u) => u === 'https://api.acme.com/users/me')).toBe(true);
    expect(urls.some((u) => u.includes('/orders/1/items'))).toBe(true);
    expect(urls.every((u) => !u.includes('{'))).toBe(true);
  });

  it('buildSchemaIdorFollowUps is scope-gated and skips already-probed URLs', () => {
    const p = probe({
      url: 'https://api.acme.com/openapi.json',
      body: SPEC,
      signals: {
        kind: 'json',
        openApiPathCount: 4,
        openApiVersion: 'openapi-3.0.3',
        graphqlIntrospection: false,
        graphqlExplorer: false,
        swaggerUi: false,
        graphqlEndpointHint: false,
        preview: '',
      },
    });
    const follow = buildSchemaIdorFollowUps([p], scope, 8);
    expect(follow.length).toBeGreaterThan(0);
    expect(follow.every((u) => u.startsWith('https://api.acme.com/'))).toBe(true);
    expect(buildSchemaIdorFollowUps([p], { ...scope, inScope: ['other.com'] }, 8)).toEqual([]);
  });
});

describe('api-schema-exposure + planner fan-out', () => {
  it('embeds IDOR candidates in evidence', () => {
    const findings = apiSchemaExposureCheck.run(
      probe({ url: 'https://api.acme.com/openapi.json', body: SPEC }),
      ctx,
    );
    expect(findings[0]!.title).toMatch(/IDOR-shaped/);
    expect(findings[0]!.evidence).toMatch(/Candidate GETs:/);
    expect(findings[0]!.evidence).toMatch(/https:\/\/api\.acme\.com\/users\/1/);
  });

  it('planFromFindings emits httpx on candidate URLs from evidence', () => {
    const finding: Finding = {
      id: 'x',
      checkId: 'api-schema-exposure',
      title: 'Exposed OpenAPI',
      severity: 'high',
      target: 'https://api.acme.com/openapi.json',
      description: '',
      evidence:
        'Spec: openapi-3.0.3\nCandidate GETs:\n  - https://api.acme.com/users/1\n  - https://api.acme.com/orders/2/items',
      reproduction: [],
      remediation: '',
      references: [],
      needsManualReview: true,
      discoveredAt: new Date().toISOString(),
    };
    const plan = planFromFindings([finding], scope);
    const httpx = plan.tasks.filter((t) => t.tool === 'httpx');
    expect(httpx.some((t) => t.target === 'https://api.acme.com/users/1')).toBe(true);
    expect(httpx.some((t) => /schema IDOR candidate/i.test(t.rationale))).toBe(true);
  });
});
