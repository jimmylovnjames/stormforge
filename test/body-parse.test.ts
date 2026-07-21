import { describe, it, expect } from 'vitest';
import {
  parseBodySignals,
  buildGraphqlIntrospectionUrl,
  shouldFollowUpGraphqlIntrospection,
  pathLooksLikeGraphql,
  graphqlIntrospectionQuery,
} from '../src/recon/body-parse.js';
import { fingerprint } from '../src/recon/fingerprint.js';
import { attachSignals, collectGraphqlFollowUps } from '../src/engine/scanner.js';
import { GRAPHQL_PATHS, OPENAPI_PATHS } from '../src/recon/wordlists.js';
import type { ProbeResult } from '../src/types.js';

function probe(over: Partial<ProbeResult>): ProbeResult {
  return { url: 'https://a.x.com/graphql', method: 'GET', status: 200, headers: {}, body: '', elapsedMs: 5, ...over };
}

describe('parseBodySignals', () => {
  it('detects OpenAPI paths array and counts keys', () => {
    const body = JSON.stringify({
      openapi: '3.0.1',
      info: { title: 't', version: '1' },
      paths: { '/a': {}, '/b': {}, '/c': {} },
    });
    const s = parseBodySignals(body, { 'content-type': 'application/json' });
    expect(s.openApiVersion).toBe('openapi-3.0.1');
    expect(s.openApiPathCount).toBe(3);
    expect(s.kind).toBe('json');
  });

  it('detects GraphQL introspection success', () => {
    const body = '{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"name":"A"}]}}}';
    const s = parseBodySignals(body);
    expect(s.graphqlIntrospection).toBe(true);
  });

  it('detects GraphiQL HTML markers', () => {
    const s = parseBodySignals('<html><title>GraphiQL</title></html>', { 'content-type': 'text/html' });
    expect(s.graphqlExplorer).toBe(true);
    expect(s.kind).toBe('html');
  });

  it('hints GraphQL endpoint from error body', () => {
    const s = parseBodySignals('{"errors":[{"message":"Must provide query string."}]}', {}, 400);
    expect(s.graphqlEndpointHint).toBe(true);
    expect(s.graphqlIntrospection).toBe(false);
  });
});

describe('graphql introspection URL helpers', () => {
  it('builds a GET URL with the introspection query', () => {
    const u = buildGraphqlIntrospectionUrl('https://a.x.com/graphql');
    expect(u).toContain('query=');
    expect(decodeURIComponent(u)).toContain(graphqlIntrospectionQuery());
  });

  it('pathLooksLikeGraphql matches common routes', () => {
    expect(pathLooksLikeGraphql('https://a.x.com/api/graphql')).toBe(true);
    expect(pathLooksLikeGraphql('https://a.x.com/v1/graphql')).toBe(true);
    expect(pathLooksLikeGraphql('https://a.x.com/login')).toBe(false);
  });

  it('shouldFollowUp when path is graphql and no schema yet', () => {
    const signals = parseBodySignals('{"errors":[{"message":"Must provide query string."}]}', {}, 400);
    expect(shouldFollowUpGraphqlIntrospection('https://a.x.com/graphql', 400, signals)).toBe(true);
  });

  it('skips follow-up when introspection already confirmed', () => {
    const signals = parseBodySignals(
      '{"data":{"__schema":{"queryType":{"name":"Query"},"types":[]}}}',
    );
    expect(shouldFollowUpGraphqlIntrospection('https://a.x.com/graphql', 200, signals)).toBe(false);
  });
});

describe('attachSignals + collectGraphqlFollowUps', () => {
  it('attaches signals on 2xx bodies', () => {
    const p = probe({
      body: JSON.stringify({ openapi: '3.0.0', info: { title: 't', version: '1' }, paths: { '/x': {} } }),
    });
    attachSignals(p);
    expect(p.signals?.openApiVersion).toBe('openapi-3.0.0');
    expect(p.signals?.openApiPathCount).toBeGreaterThan(0);
  });

  it('collects introspection follow-up URLs for GraphQL candidates', () => {
    const p = probe({
      status: 400,
      body: '{"errors":[{"message":"Must provide query string."}]}',
    });
    attachSignals(p);
    const urls = collectGraphqlFollowUps([p]);
    expect(urls).toHaveLength(1);
    expect(urls[0]).toContain('query=');
  });
});

describe('fingerprint API stacks', () => {
  it('fingerprints GraphQL Yoga header and OpenAPI body', () => {
    const yoga = fingerprint(probe({ headers: { 'x-graphql-yoga-csrf': 'true' }, body: '' }));
    expect(yoga.some((t) => t.product === 'GraphQL Yoga')).toBe(true);

    const oa = fingerprint(
      probe({
        url: 'https://a.x.com/openapi.json',
        body: '{"openapi":"3.0.0","info":{"title":"t","version":"1"},"paths":{"/z":{}}}',
      }),
    );
    expect(oa.some((t) => t.product === 'OpenAPI')).toBe(true);
  });
});

describe('wordlists', () => {
  it('exports expanded GraphQL and OpenAPI path sets', () => {
    expect(GRAPHQL_PATHS).toContain('/api/graphql');
    expect(GRAPHQL_PATHS).toContain('/v1/graphql');
    expect(OPENAPI_PATHS).toContain('/v3/api-docs');
    expect(OPENAPI_PATHS).toContain('/swagger-ui.html');
  });
});
