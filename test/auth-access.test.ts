import { describe, it, expect } from 'vitest';
import { analyzeWeakJwt, findJwtCandidates, parseJwt, redactJwt } from '../src/recon/jwt.js';
import { authAccessCheck, classifyPath } from '../src/detect/checks/auth-access.js';
import { weakJwtCheck } from '../src/detect/checks/weak-jwt.js';
import { draftFinding } from '../src/report/drafter.js';
import { AUTH_IDOR_PATHS } from '../src/recon/wordlists.js';
import { fingerprint } from '../src/recon/fingerprint.js';
import type { Finding, ProbeResult, Scope, CheckContext } from '../src/types.js';

const scope: Scope = {
  program: 'p',
  platform: 'hackerone',
  inScope: ['*.x.com'],
  outOfScope: [],
  authorized: true,
};
const ctx: CheckContext = { scope };

function probe(over: Partial<ProbeResult>): ProbeResult {
  return { url: 'https://a.x.com/api/v1/users/1', method: 'GET', status: 200, headers: {}, body: '', elapsedMs: 5, ...over };
}

function b64url(obj: unknown): string {
  const json = JSON.stringify(obj);
  // Workers/vitest: btoa needs binary string
  const b64 = btoa(json);
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function makeJwt(header: Record<string, unknown>, payload: Record<string, unknown>, sig?: string): string {
  const h = b64url(header);
  const p = b64url(payload);
  if (sig === undefined) return `${h}.${p}.`; // empty signature segment
  if (sig === null as unknown as string) return `${h}.${p}`; // two-segment
  return `${h}.${p}.${sig}`;
}

describe('classifyPath', () => {
  it('classifies predictable user IDs as idor', () => {
    expect(classifyPath('https://a.x.com/api/v1/users/1')?.kind).toBe('idor');
    expect(classifyPath('https://a.x.com/user/1')?.kind).toBe('idor');
  });
  it('classifies admin routes', () => {
    expect(classifyPath('https://a.x.com/api/v1/admin/users')?.kind).toBe('admin-bypass');
  });
  it('classifies /me as auth-bypass', () => {
    expect(classifyPath('https://a.x.com/api/v1/me')?.kind).toBe('auth-bypass');
  });
  it('ignores unrelated paths', () => {
    expect(classifyPath('https://a.x.com/about')).toBeNull();
  });
});

describe('authAccessCheck', () => {
  it('flags IDOR when 2xx body has email + user object markers', () => {
    const body = JSON.stringify({
      user: { id: 1, email: 'victim@example.com', username: 'victim' },
    });
    const f = authAccessCheck.run(probe({ body }), ctx);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('high');
    expect(f[0].cwe).toBe('CWE-639');
    expect(f[0].needsManualReview).toBe(true);
    expect(f[0].title).toContain('IDOR');
  });

  it('flags admin bypass as critical when is_admin true', () => {
    const body = '{"email":"a@b.com","is_admin":true}';
    const f = authAccessCheck.run(
      probe({ url: 'https://a.x.com/api/v1/admin/users', body }),
      ctx,
    );
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('critical');
    expect(f[0].cwe).toBe('CWE-284');
  });

  it('does not flag status-only without body markers', () => {
    const f = authAccessCheck.run(probe({ body: '{"status":"ok"}' }), ctx);
    expect(f).toHaveLength(0);
  });

  it('does not flag login HTML pages', () => {
    const f = authAccessCheck.run(
      probe({
        url: 'https://a.x.com/user',
        headers: { 'content-type': 'text/html' },
        body: '<form id="login"><input name="username"><input name="password"></form>',
      }),
      ctx,
    );
    expect(f).toHaveLength(0);
  });

  it('ignores non-2xx', () => {
    const body = '{"email":"a@b.com","user":{"id":1,"email":"a@b.com"}}';
    expect(authAccessCheck.run(probe({ status: 401, body }), ctx)).toHaveLength(0);
  });
});

describe('jwt helpers + weakJwtCheck', () => {
  it('detects alg=none with empty signature as critical', () => {
    const token = makeJwt({ alg: 'none', typ: 'JWT' }, { sub: '1' });
    const issues = analyzeWeakJwt(token);
    expect(issues.some((i) => i.kind === 'alg-none')).toBe(true);
    expect(issues.some((i) => i.kind === 'empty-signature')).toBe(true);

    const f = weakJwtCheck.run(probe({ url: 'https://a.x.com/login', body: `token=${token}` }), ctx);
    expect(f.length).toBeGreaterThan(0);
    expect(f.some((x) => x.severity === 'critical')).toBe(true);
    expect(f[0].evidence).not.toContain(token.split('.')[1]!);
  });

  it('detects path-traversal kid', () => {
    const token = makeJwt({ alg: 'RS256', kid: '../../.env', typ: 'JWT' }, { sub: '1' }, 'sig');
    const issues = analyzeWeakJwt(token);
    expect(issues.some((i) => i.kind === 'path-traversal-kid')).toBe(true);
  });

  it('does not flag a normal three-part JWT as weak', () => {
    const token = makeJwt({ alg: 'HS256', typ: 'JWT' }, { sub: '1' }, 'abc123sig');
    expect(analyzeWeakJwt(token)).toHaveLength(0);
    expect(findJwtCandidates(`Bearer ${token}`)).toContain(token);
    expect(parseJwt(token)?.header.alg).toBe('HS256');
    expect(redactJwt(token)).toContain('[payload-redacted]');
  });

  it('finds weak JWT in Set-Cookie', () => {
    const token = makeJwt({ alg: 'none' }, { sub: '1' });
    const f = weakJwtCheck.run(
      probe({ url: 'https://a.x.com/', body: '', headers: { 'set-cookie': `session=${token}; Path=/` } }),
      ctx,
    );
    expect(f.some((x) => x.title.includes('alg=none'))).toBe(true);
  });
});

describe('report integration for auth CWEs', () => {
  it('uses IDOR-specific impact text', () => {
    const finding: Finding = {
      id: '1',
      checkId: 'auth-access-control',
      title: 'IDOR',
      severity: 'high',
      target: 'https://a.x.com/users/1',
      description: 'd',
      evidence: 'e',
      reproduction: ['r'],
      remediation: 'fix',
      cwe: 'CWE-639',
      references: [],
      needsManualReview: true,
      discoveredAt: new Date().toISOString(),
    };
    const md = draftFinding(finding, scope);
    expect(md).toContain('Broken object-level authorization');
    expect(md).toContain('CWE-639');
  });
});

describe('AUTH_IDOR_PATHS + fingerprint', () => {
  it('includes common /api/v1/ and /user/ probe paths', () => {
    expect(AUTH_IDOR_PATHS).toContain('/api/v1/users/1');
    expect(AUTH_IDOR_PATHS).toContain('/user/1');
    expect(AUTH_IDOR_PATHS).toContain('/api/v1/me');
  });

  it('fingerprints JWT in body', () => {
    const token = makeJwt({ alg: 'HS256' }, { sub: '1' }, 'sig');
    const tech = fingerprint(probe({ body: `const t="${token}";` }));
    expect(tech.some((t) => t.product === 'JWT')).toBe(true);
  });
});
