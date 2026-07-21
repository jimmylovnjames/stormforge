import { describe, it, expect } from 'vitest';
import { extractOpenApiPaths } from '../src/recon/body-parse.js';
import {
  extractApiPathsFromJs,
  extractUrlsFromHtml,
  harvestPathsFromProbe,
} from '../src/recon/url-harvest.js';
import { planPathsFromFindings } from '../src/planning/llm-planner.js';
import type { Finding, ProbeResult } from '../src/types.js';

describe('extractOpenApiPaths', () => {
  it('extracts path keys from OpenAPI JSON', () => {
    const body = JSON.stringify({
      openapi: '3.0.1',
      info: { title: 'Demo', version: '1' },
      paths: {
        '/api/v1/users': { get: {} },
        '/api/v1/orders/{id}': { get: {} },
        '/health': { get: {} },
      },
    });
    const paths = extractOpenApiPaths(body);
    expect(paths).toContain('/api/v1/users');
    expect(paths).toContain('/api/v1/orders/{id}');
    expect(paths).toContain('/health');
  });

  it('returns empty for non-schema bodies', () => {
    expect(extractOpenApiPaths('{"hello":"world"}')).toEqual([]);
  });
});

describe('url harvest', () => {
  it('extracts same-origin href/src and absolute in-page URLs', () => {
    const html = `
      <a href="/api/v1/me">me</a>
      <a href="https://a.x.com/admin/users">admin</a>
      <script src="/static/app.js"></script>
      <img src="https://cdn.evil.com/x.png" />
    `;
    const urls = extractUrlsFromHtml(html, 'https://a.x.com/');
    expect(urls.some((u) => u.includes('/api/v1/me'))).toBe(true);
    expect(urls.some((u) => u.includes('/admin/users'))).toBe(true);
    expect(urls.some((u) => u.includes('/static/app.js'))).toBe(true);
  });

  it('extracts API-looking paths from JS bundles', () => {
    const js = `
      fetch("/api/v1/profile");
      axios.get('/api/v1/orders');
      const u = "/graphql";
    `;
    const paths = extractApiPathsFromJs(js);
    expect(paths).toContain('/api/v1/profile');
    expect(paths).toContain('/api/v1/orders');
    expect(paths).toContain('/graphql');
  });

  it('harvestPathsFromProbe prefers OpenAPI then HTML/JS', () => {
    const openapi: ProbeResult = {
      url: 'https://a.x.com/openapi.json',
      method: 'GET',
      status: 200,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        openapi: '3.0.0',
        info: { title: 't', version: '1' },
        paths: { '/api/v1/widgets': { get: {} } },
      }),
      elapsedMs: 1,
      signals: {
        kind: 'json',
        openApiPathCount: 1,
        openApiVersion: 'openapi-3.0.0',
        graphqlIntrospection: false,
        graphqlExplorer: false,
        swaggerUi: false,
        graphqlEndpointHint: false,
        preview: '',
      },
    };
    expect(harvestPathsFromProbe(openapi)).toContain('/api/v1/widgets');
  });
});

describe('planPathsFromFindings OpenAPI harvest bridge', () => {
  it('includes concrete paths from finding evidence when present', () => {
    const f: Finding = {
      id: '1',
      checkId: 'api-schema-exposure',
      title: 'OpenAPI',
      severity: 'high',
      target: 'https://api.acme.com/openapi.json',
      description: 'd',
      evidence: 'paths: /api/v1/widgets, /api/v1/billing',
      reproduction: [],
      remediation: '',
      references: [],
      needsManualReview: false,
      discoveredAt: new Date().toISOString(),
    };
    const plan = planPathsFromFindings([f]);
    expect(plan.suggestedPaths).toContain('/api/v1/widgets');
    expect(plan.suggestedPaths).toContain('/api/v1/billing');
  });
});
