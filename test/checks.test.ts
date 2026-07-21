import { describe, it, expect } from 'vitest';
import { securityHeadersCheck } from '../src/detect/checks/security-headers.js';
import { corsCheck, PROBE_ORIGIN } from '../src/detect/checks/cors.js';
import { exposedFilesCheck } from '../src/detect/checks/exposed-files.js';
import { cookiesCheck, splitSetCookie } from '../src/detect/checks/cookies.js';
import { versionCveCheck } from '../src/detect/checks/version-cve.js';
import { apiSchemaExposureCheck } from '../src/detect/checks/api-schema-exposure.js';
import { graphqlIntrospectionCheck } from '../src/detect/checks/graphql-introspection.js';
import { scanSecrets } from '../src/recon/secrets.js';
import type { ProbeResult, Scope, CheckContext } from '../src/types.js';

const scope: Scope = { program: 'p', platform: 'generic', inScope: ['*.x.com'], outOfScope: [], authorized: true };
const ctx: CheckContext = { scope };

function probe(over: Partial<ProbeResult>): ProbeResult {
  return { url: 'https://a.x.com/', method: 'GET', status: 200, headers: {}, body: '', elapsedMs: 5, ...over };
}

describe('securityHeadersCheck', () => {
  it('flags missing HSTS and CSP on an HTML response', () => {
    const f = securityHeadersCheck.run(probe({ headers: { 'content-type': 'text/html' } }), ctx);
    const ids = f.map((x) => x.title);
    expect(ids.some((t) => t.includes('HSTS'))).toBe(true);
    expect(ids.some((t) => t.includes('Content Security Policy'))).toBe(true);
  });
  it('does not flag when headers present', () => {
    const f = securityHeadersCheck.run(
      probe({
        headers: {
          'content-type': 'text/html',
          'strict-transport-security': 'max-age=31536000',
          'content-security-policy': "default-src 'self'",
          'x-content-type-options': 'nosniff',
          'x-frame-options': 'DENY',
        },
      }),
      ctx,
    );
    expect(f).toHaveLength(0);
  });
  it('ignores non-document responses', () => {
    const f = securityHeadersCheck.run(probe({ headers: { 'content-type': 'application/json' } }), ctx);
    expect(f).toHaveLength(0);
  });
});

describe('corsCheck', () => {
  it('flags reflected origin with credentials as high', () => {
    const f = corsCheck.run(
      probe({ headers: { 'access-control-allow-origin': PROBE_ORIGIN, 'access-control-allow-credentials': 'true' } }),
      ctx,
    );
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('high');
  });
  it('ignores same-origin / no ACAO', () => {
    expect(corsCheck.run(probe({}), ctx)).toHaveLength(0);
  });
});

describe('exposedFilesCheck', () => {
  it('confirms .git/config only when body matches signature', () => {
    const hit = exposedFilesCheck.run(probe({ url: 'https://a.x.com/.git/config', body: '[core]\n\trepositoryformatversion = 0' }), ctx);
    expect(hit).toHaveLength(1);
    expect(hit[0].severity).toBe('high');

    const miss = exposedFilesCheck.run(probe({ url: 'https://a.x.com/.git/config', body: '<html>not found</html>' }), ctx);
    expect(miss).toHaveLength(0);
  });
  it('flags .env as critical', () => {
    const f = exposedFilesCheck.run(probe({ url: 'https://a.x.com/.env', body: 'SECRET_KEY=abc123' }), ctx);
    expect(f[0].severity).toBe('critical');
  });
});

describe('cookiesCheck', () => {
  it('flags session cookie missing flags', () => {
    const f = cookiesCheck.run(probe({ headers: { 'set-cookie': 'sessionid=abc; Path=/' } }), ctx);
    expect(f).toHaveLength(1);
    expect(f[0].title).toContain('Secure');
  });
});

describe('splitSetCookie', () => {
  it('does not split on Expires comma', () => {
    const parts = splitSetCookie('a=1; Expires=Wed, 09 Jun 2027 10:18:14 GMT, b=2; Path=/');
    expect(parts).toHaveLength(2);
    expect(parts[0]).toContain('a=1');
    expect(parts[1]).toContain('b=2');
  });
});

describe('versionCveCheck', () => {
  it('flags outdated nginx', () => {
    const f = versionCveCheck.run(probe({ headers: { server: 'nginx/1.18.0' } }), ctx);
    expect(f.some((x) => x.title.includes('CVE-2021-23017'))).toBe(true);
  });
  it('does not flag patched nginx', () => {
    const f = versionCveCheck.run(probe({ headers: { server: 'nginx/1.25.0' } }), ctx);
    expect(f).toHaveLength(0);
  });
});

describe('scanSecrets', () => {
  it('detects an AWS key and redacts it', () => {
    const f = scanSecrets(probe({ body: 'const k = "AKIAIOSFODNN7EXAMPLE";' }));
    expect(f).toHaveLength(1);
    expect(f[0].evidence).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(f[0].needsManualReview).toBe(true);
  });
});

describe('apiSchemaExposureCheck', () => {
  it('flags OpenAPI 3 JSON with paths as high', () => {
    const body = JSON.stringify({
      openapi: '3.0.3',
      info: { title: 'Internal API', version: '1.0.0' },
      paths: { '/admin/users': { get: { summary: 'List users' } } },
    });
    const f = apiSchemaExposureCheck.run(
      probe({ url: 'https://a.x.com/openapi.json', headers: { 'content-type': 'application/json' }, body }),
      ctx,
    );
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('high');
    expect(f[0].title).toMatch(/OpenAPI 3/);
    expect(f[0].title).toContain('paths');
  });

  it('flags Swagger 2.0 specs as high', () => {
    const body = '{"swagger":"2.0","info":{"title":"t","version":"1"},"paths":{"/x":{}}}';
    const f = apiSchemaExposureCheck.run(probe({ url: 'https://a.x.com/swagger.json', body }), ctx);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('high');
    expect(f[0].title).toMatch(/Swagger 2\.0/);
  });

  it('does not flag unrelated JSON that mentions openapi in a string', () => {
    const f = apiSchemaExposureCheck.run(
      probe({ body: '{"message":"see openapi docs","code":200}' }),
      ctx,
    );
    expect(f).toHaveLength(0);
  });

  it('flags Swagger UI HTML as high', () => {
    const f = apiSchemaExposureCheck.run(
      probe({
        url: 'https://a.x.com/swagger-ui/',
        headers: { 'content-type': 'text/html' },
        body: '<div id="swagger-ui"></div><script>SwaggerUIBundle({url:"/swagger.json"})</script>',
      }),
      ctx,
    );
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('high');
    expect(f[0].needsManualReview).toBe(true);
  });

  it('ignores non-2xx responses', () => {
    const body = '{"openapi":"3.0.0","info":{"title":"t","version":"1"},"paths":{}}';
    expect(apiSchemaExposureCheck.run(probe({ status: 404, body }), ctx)).toHaveLength(0);
  });
});

describe('graphqlIntrospectionCheck', () => {
  it('flags GraphQL introspection payloads as high without manual review', () => {
    const body = JSON.stringify({
      data: {
        __schema: {
          queryType: { name: 'Query' },
          types: [{ name: 'User' }, { name: 'Mutation' }],
        },
      },
    });
    const f = graphqlIntrospectionCheck.run(probe({ url: 'https://a.x.com/graphql', body }), ctx);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('high');
    expect(f[0].needsManualReview).toBe(false);
    expect(f[0].title).toContain('introspection');
  });

  it('flags GraphiQL HTML explorer as high', () => {
    const f = graphqlIntrospectionCheck.run(
      probe({
        url: 'https://a.x.com/graphiql',
        headers: { 'content-type': 'text/html' },
        body: '<!doctype html><title>GraphiQL</title><script src="https://cdn.jsdelivr.net/npm/graphiql/graphiql.min.js"></script>',
      }),
      ctx,
    );
    expect(f).toHaveLength(1);
    expect(f[0].title).toContain('GraphiQL');
    expect(f[0].severity).toBe('high');
  });

  it('does not flag GraphQL error-only bodies without __schema', () => {
    const f = graphqlIntrospectionCheck.run(
      probe({
        url: 'https://a.x.com/graphql',
        body: '{"errors":[{"message":"Must provide query string."}]}',
      }),
      ctx,
    );
    expect(f).toHaveLength(0);
  });
});
