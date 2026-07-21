import { describe, it, expect } from 'vitest';
import {
  rateLimitCheck,
  classifyAuthSurface,
  hasRateLimitHeaders,
  showsRateLimiting,
  RATE_LIMIT_HEADER_NAMES,
} from '../src/detect/checks/rate-limit.js';
import { BRUTEFORCE_PATHS } from '../src/recon/wordlists.js';
import { fingerprint } from '../src/recon/fingerprint.js';
import { draftFinding } from '../src/report/drafter.js';
import { listChecks } from '../src/detect/registry.js';
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
  return {
    url: 'https://a.x.com/login',
    method: 'GET',
    status: 200,
    headers: { 'content-type': 'text/html' },
    body: '',
    elapsedMs: 4,
    ...over,
  };
}

describe('classifyAuthSurface', () => {
  it('classifies login, token, otp, and reset paths', () => {
    expect(classifyAuthSurface('https://a.x.com/login')?.kind).toBe('login');
    expect(classifyAuthSurface('https://a.x.com/api/v1/auth/login')?.kind).toBe('login');
    expect(classifyAuthSurface('https://a.x.com/oauth/token')?.kind).toBe('token');
    expect(classifyAuthSurface('https://a.x.com/api/v1/otp')?.kind).toBe('otp');
    expect(classifyAuthSurface('https://a.x.com/forgot-password')?.kind).toBe('password-reset');
    expect(classifyAuthSurface('https://a.x.com/register')?.kind).toBe('register');
  });

  it('detects login forms on generic paths', () => {
    const html = '<form action="/x"><input name="email"><input type="password" name="password"></form>';
    expect(classifyAuthSurface('https://a.x.com/account', html)?.kind).toBe('login');
  });

  it('ignores static assets', () => {
    expect(classifyAuthSurface('https://a.x.com/login.css')).toBeNull();
  });
});

describe('rate-limit header helpers', () => {
  it('detects standard and vendor rate-limit headers', () => {
    expect(hasRateLimitHeaders({ 'x-ratelimit-limit': '100' })).toBe(true);
    expect(hasRateLimitHeaders({ 'ratelimit-limit': '60' })).toBe(true);
    expect(hasRateLimitHeaders({})).toBe(false);
    expect(RATE_LIMIT_HEADER_NAMES.length).toBeGreaterThan(5);
  });

  it('treats 429 as evidence of rate limiting', () => {
    expect(showsRateLimiting(probe({ status: 429, headers: {} }))).toBe(true);
  });
});

describe('rateLimitCheck', () => {
  it('flags missing rate-limit headers on login as high', () => {
    const f = rateLimitCheck.run(probe({ url: 'https://a.x.com/login', headers: {} }), ctx);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('high');
    expect(f[0].cwe).toBe('CWE-770');
    expect(f[0].title).toContain('login');
    expect(f[0].needsManualReview).toBe(true);
  });

  it('flags oauth token and password-reset endpoints as high', () => {
    const token = rateLimitCheck.run(probe({ url: 'https://a.x.com/oauth/token', headers: {} }), ctx);
    const reset = rateLimitCheck.run(probe({ url: 'https://a.x.com/password/reset', headers: {} }), ctx);
    expect(token[0].severity).toBe('high');
    expect(reset[0].severity).toBe('high');
  });

  it('does not flag when X-RateLimit-Limit is present', () => {
    const f = rateLimitCheck.run(
      probe({ headers: { 'x-ratelimit-limit': '100', 'x-ratelimit-remaining': '99' } }),
      ctx,
    );
    expect(f).toHaveLength(0);
  });

  it('does not flag 429 with Retry-After', () => {
    const f = rateLimitCheck.run(
      probe({ status: 429, headers: { 'retry-after': '30' } }),
      ctx,
    );
    expect(f).toHaveLength(0);
  });

  it('flags 429 without Retry-After as low', () => {
    const f = rateLimitCheck.run(probe({ status: 429, headers: {} }), ctx);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('low');
    expect(f[0].title).toContain('Retry-After');
  });

  it('flags JSON API without rate-limit headers as medium', () => {
    const f = rateLimitCheck.run(
      probe({
        url: 'https://a.x.com/api/v1/items',
        headers: { 'content-type': 'application/json' },
        body: '[]',
      }),
      ctx,
    );
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('medium');
  });

  it('ignores ordinary HTML pages without auth signals', () => {
    const f = rateLimitCheck.run(
      probe({
        url: 'https://a.x.com/about',
        headers: { 'content-type': 'text/html' },
        body: '<html><body>About us</body></html>',
      }),
      ctx,
    );
    expect(f).toHaveLength(0);
  });
});

describe('bruteforce wordlist + fingerprint + report', () => {
  it('exports BRUTEFORCE_PATHS covering auth surfaces', () => {
    expect(BRUTEFORCE_PATHS).toContain('/login');
    expect(BRUTEFORCE_PATHS).toContain('/oauth/token');
    expect(BRUTEFORCE_PATHS).toContain('/api/v1/otp');
  });

  it('fingerprints rate limiting from headers', () => {
    const tech = fingerprint(
      probe({ headers: { 'x-ratelimit-limit': '60', 'content-type': 'text/html' }, body: '' }),
    );
    expect(tech.some((t) => t.product === 'Rate Limiting')).toBe(true);
  });

  it('registers the check and drafts CWE-770 impact', () => {
    expect(listChecks().some((c) => c.id === 'rate-limit-missing')).toBe(true);
    const finding: Finding = {
      id: '1',
      checkId: 'rate-limit-missing',
      title: 'Missing rate-limit headers on login',
      severity: 'high',
      target: 'https://a.x.com/login',
      description: 'd',
      evidence: 'e',
      reproduction: ['r'],
      remediation: 'fix',
      cwe: 'CWE-770',
      references: [],
      needsManualReview: true,
      discoveredAt: new Date().toISOString(),
    };
    expect(draftFinding(finding, scope)).toContain('credential stuffing');
  });
});
