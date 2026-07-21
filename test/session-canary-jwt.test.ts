import { describe, it, expect } from 'vitest';
import {
  buildCanaryUrl,
  isCanaryToken,
  newCanaryToken,
  urlCarriesBlindCanary,
} from '../src/recon/canary.js';
import { hasSession, sessionHeaders, validateSession } from '../src/recon/session.js';
import {
  buildNeighborIdUrls,
  extractAccountMarkers,
  findHorizontalIdor,
} from '../src/detect/checks/auth-differential.js';
import { analyzeWeakJwt } from '../src/recon/jwt.js';
import { makeBlindSsrfFinding } from '../src/detect/checks/ssrf-redirect.js';
import { buildSsrfRedirectProbeUrls } from '../src/recon/ssrf-probes.js';
import { collectSsrfRedirectFollowUps } from '../src/engine/scanner.js';
import { listChecks } from '../src/detect/registry.js';
import type { ProbeResult } from '../src/types.js';

function probe(over: Partial<ProbeResult>): ProbeResult {
  return {
    url: 'https://a.x.com/api/v1/users/1',
    method: 'GET',
    status: 200,
    headers: { 'content-type': 'application/json' },
    body: '',
    elapsedMs: 3,
    ...over,
  };
}

describe('session helpers', () => {
  it('builds cookie and authorization headers', () => {
    expect(hasSession({ cookie: 'a=1' })).toBe(true);
    expect(sessionHeaders({ cookie: 'a=1', authorization: 'Bearer x' })).toEqual({
      cookie: 'a=1',
      authorization: 'Bearer x',
    });
  });

  it('rejects header injection and host override', () => {
    expect(validateSession({ cookie: 'a=1\r\nX-Injected: 1' })).toMatch(/newlines/);
    expect(validateSession({ headers: { Host: 'evil.com' } })).toMatch(/host/i);
    expect(validateSession({ cookie: 'ok=1' })).toBeNull();
  });
});

describe('JWT jku / x5u / url-kid', () => {
  function b64url(obj: unknown): string {
    return btoa(JSON.stringify(obj)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  }
  function jwt(header: Record<string, unknown>): string {
    return `${b64url(header)}.${b64url({ sub: '1' })}.sig`;
  }

  it('flags jku and x5u as critical', () => {
    const jku = analyzeWeakJwt(jwt({ alg: 'RS256', jku: 'https://evil.example/jwks.json' }));
    expect(jku.some((i) => i.kind === 'jku-url' && i.severity === 'critical')).toBe(true);
    const x5u = analyzeWeakJwt(jwt({ alg: 'RS256', x5u: 'https://evil.example/cert.pem' }));
    expect(x5u.some((i) => i.kind === 'x5u-url')).toBe(true);
  });

  it('flags URL kid', () => {
    const issues = analyzeWeakJwt(jwt({ alg: 'RS256', kid: 'https://evil.example/key' }));
    expect(issues.some((i) => i.kind === 'url-kid')).toBe(true);
  });
});

describe('blind SSRF canary', () => {
  it('builds canary URLs and detects param carriage', () => {
    const token = 'abcdef0123456789abcdef0123456789';
    expect(isCanaryToken(token)).toBe(true);
    const canary = buildCanaryUrl('https://sf.example', token);
    expect(canary).toBe(`https://sf.example/api/canary/${token}`);
    const built = buildSsrfRedirectProbeUrls('https://a.x.com/proxy', {
      maxParams: 1,
      blindCanaryUrl: canary,
    });
    expect(built.blind.length).toBeGreaterThan(0);
    expect(urlCarriesBlindCanary(built.blind[0]!, token)).toBe(true);
  });

  it('collectSsrfRedirectFollowUps emits blind mode when canaryBase set', () => {
    const items = collectSsrfRedirectFollowUps(
      [probe({ url: 'https://a.x.com/proxy', status: 200 })],
      { canaryBase: 'https://worker.example' },
    );
    expect(items.some((i) => i.mode === 'blind' && i.canaryToken && i.canaryUrl)).toBe(true);
  });

  it('makeBlindSsrfFinding is critical and submit-grade', () => {
    const token = newCanaryToken();
    const f = makeBlindSsrfFinding(
      'https://a.x.com/fetch?url=x',
      buildCanaryUrl('https://sf.example', token),
      {
        token,
        hitAt: new Date().toISOString(),
        method: 'GET',
        userAgent: 'curl/8',
        path: `/api/canary/${token}`,
      },
    );
    expect(f.checkId).toBe('ssrf-blind-canary');
    expect(f.severity).toBe('critical');
    expect(f.needsManualReview).toBe(false);
  });

  it('registers auth-differential check', () => {
    expect(listChecks().some((c) => c.id === 'auth-differential')).toBe(true);
  });
});

describe('horizontal IDOR', () => {
  it('extracts account markers and neighbor URLs', () => {
    expect(extractAccountMarkers('{"email":"a@b.com","username":"alice","id":1}')).toEqual({
      email: 'a@b.com',
      username: 'alice',
      objectId: '1',
    });
    expect(buildNeighborIdUrls('https://a.x.com/api/v1/users/1')).toEqual([
      'https://a.x.com/api/v1/users/2',
      'https://a.x.com/api/v1/users/3',
    ]);
  });

  it('flags when one session reads two different users', () => {
    const findings = findHorizontalIdor([
      probe({
        url: 'https://a.x.com/api/v1/users/1',
        body: JSON.stringify({ user: { id: 1, email: 'alice@example.com', username: 'alice' } }),
      }),
      probe({
        url: 'https://a.x.com/api/v1/users/2',
        body: JSON.stringify({ user: { id: 2, email: 'bob@example.com', username: 'bob' } }),
      }),
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.checkId).toBe('auth-differential');
    expect(findings[0]!.cwe).toBe('CWE-639');
  });

  it('does not flag when both IDs return the same identity', () => {
    const body = JSON.stringify({ email: 'same@example.com', username: 'same', id: 1 });
    expect(
      findHorizontalIdor([
        probe({ url: 'https://a.x.com/api/v1/users/1', body }),
        probe({ url: 'https://a.x.com/api/v1/users/2', body: body.replace('"id":1', '"id":2') }),
      ]),
    ).toHaveLength(0);
  });
});
