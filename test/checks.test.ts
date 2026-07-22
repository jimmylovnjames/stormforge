import { describe, it, expect } from 'vitest';
import { securityHeadersCheck } from '../src/detect/checks/security-headers.js';
import { corsCheck, PROBE_ORIGIN, corsBypassOriginFor } from '../src/detect/checks/cors.js';
import { exposedFilesCheck } from '../src/detect/checks/exposed-files.js';
import { cookiesCheck, splitSetCookie } from '../src/detect/checks/cookies.js';
import { versionCveCheck } from '../src/detect/checks/version-cve.js';
import { apiSchemaExposureCheck } from '../src/detect/checks/api-schema-exposure.js';
import { graphqlIntrospectionCheck } from '../src/detect/checks/graphql-introspection.js';
import { weakCspCheck } from '../src/detect/checks/weak-csp.js';
import { sourcemapCheck } from '../src/detect/checks/sourcemap.js';
import { scanSecrets } from '../src/recon/secrets.js';
import { listChecks } from '../src/detect/registry.js';
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
  it('flags subdomain-trust bypass origin', () => {
    const bypass = corsBypassOriginFor('https://a.x.com/api');
    expect(bypass).toBeTruthy();
    const f = corsCheck.run(
      probe({
        url: 'https://a.x.com/api',
        headers: { 'access-control-allow-origin': bypass!, 'access-control-allow-credentials': 'true' },
      }),
      ctx,
    );
    expect(f).toHaveLength(1);
    expect(f[0].title.toLowerCase()).toMatch(/subdomain|ends-with|bypass/);
  });
  it('ignores same-origin / no ACAO', () => {
    expect(corsCheck.run(probe({}), ctx)).toHaveLength(0);
  });
});

describe('apiSchemaExposureCheck', () => {
  it('flags OpenAPI with paths as high', () => {
    const body = JSON.stringify({
      openapi: '3.0.1',
      info: { title: 'API', version: '1' },
      paths: { '/users': { get: {} }, '/orders': { post: {} } },
    });
    const f = apiSchemaExposureCheck.run(
      probe({ url: 'https://a.x.com/openapi.json', body, headers: { 'content-type': 'application/json' } }),
      ctx,
    );
    expect(f.some((x) => x.checkId === 'api-schema-exposure' && x.severity === 'high')).toBe(true);
  });
});

describe('graphqlIntrospectionCheck', () => {
  it('flags confirmed __schema payload', () => {
    const body = JSON.stringify({
      data: { __schema: { queryType: { name: 'Query' }, types: [{ name: 'User', kind: 'OBJECT' }] } },
    });
    const f = graphqlIntrospectionCheck.run(
      probe({ url: 'https://a.x.com/graphql?query=x', body, headers: { 'content-type': 'application/json' } }),
      ctx,
    );
    expect(f[0]?.severity).toBe('high');
    expect(f[0]?.submitReady).toBe(true);
  });
});

describe('weakCspCheck', () => {
  it('flags unsafe-inline script-src', () => {
    const f = weakCspCheck.run(
      probe({
        headers: {
          'content-type': 'text/html',
          'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline'",
        },
      }),
      ctx,
    );
    expect(f).toHaveLength(1);
    expect(f[0].title).toMatch(/unsafe-inline/);
  });
});

describe('sourcemapCheck', () => {
  it('flags sourcesContent maps', () => {
    const body = JSON.stringify({
      version: 3,
      sources: ['src/app.ts'],
      mappings: 'AAAA',
      sourcesContent: ['const secret = "x"'],
    });
    const f = sourcemapCheck.run(
      probe({ url: 'https://a.x.com/app.js.map', body, headers: { 'content-type': 'application/json' } }),
      ctx,
    );
    expect(f[0]?.severity).toBe('medium');
    expect(f[0]?.submitReady).toBe(true);
  });
});

describe('registry', () => {
  it('registers high-signal BBP checks', () => {
    const ids = listChecks().map((c) => c.id);
    expect(ids).toContain('api-schema-exposure');
    expect(ids).toContain('graphql-introspection');
    expect(ids).toContain('weak-csp');
    expect(ids).toContain('sourcemap-exposure');
    expect(ids).toContain('oauth-misconfig');
    expect(ids).toContain('auth-access-control');
    expect(ids).toContain('cache-deception');
    expect(ids).toContain('subdomain-takeover');
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
    expect(f[0].severity).toBe('medium');
  });
  it('flags SameSite=None without Secure', () => {
    const f = cookiesCheck.run(
      probe({ headers: { 'set-cookie': 'sid=abc; Path=/; SameSite=None' } }),
      ctx,
    );
    expect(f.some((x) => /SameSite=None without Secure/.test(x.title))).toBe(true);
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
