import { describe, it, expect } from 'vitest';
import type { CheckContext, ProbeResult, Scope } from '../src/types.js';
import { oauthMisconfigCheck } from '../src/detect/checks/oauth.js';
import { authAccessCheck, classifyPath } from '../src/detect/checks/auth-access.js';
import { cacheDeceptionCheck } from '../src/detect/checks/cache-deception.js';
import { subdomainTakeoverCheck } from '../src/detect/checks/subdomain-takeover.js';
import {
  isTakeoverCandidate,
  matchTakeoverFingerprint,
  matchTakeoverBody,
  parseDohResponse,
} from '../src/recon/takeover.js';
import { hasCacheableResponse, looksLikeDynamicContent } from '../src/recon/cache-probes.js';
import { listChecks } from '../src/detect/registry.js';
import { planFromFindings } from '../src/planning/vuln-planner.js';
import type { Finding } from '../src/types.js';

const scope: Scope = {
  program: 'p',
  platform: 'generic',
  inScope: ['*.x.com', 'x.com'],
  outOfScope: [],
  authorized: true,
};
const ctx: CheckContext = { scope };

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

describe('oauthMisconfigCheck', () => {
  it('flags access_token in callback URL as high + submitReady', () => {
    const f = oauthMisconfigCheck.run(
      probe({
        url: 'https://a.x.com/oauth/callback?access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aaaa.bbbb',
        status: 200,
      }),
      ctx,
    );
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('high');
    expect(f[0]!.submitReady).toBe(true);
    expect(f[0]!.evidence).not.toMatch(/eyJhbGci/);
  });

  it('flags off-site redirect_uri follow on OAuth path', () => {
    const f = oauthMisconfigCheck.run(
      probe({
        url: 'https://a.x.com/oauth/authorize?redirect_uri=https://evil.com/cb',
        status: 302,
        headers: { location: 'https://evil.com/cb?code=abc' },
      }),
      ctx,
    );
    expect(f.some((x) => /redirect/i.test(x.title))).toBe(true);
    expect(f[0]!.severity).toBe('high');
  });

  it('ignores non-oauth paths without tokens', () => {
    expect(oauthMisconfigCheck.run(probe({ url: 'https://a.x.com/about' }), ctx)).toHaveLength(0);
  });
});

describe('authAccessCheck', () => {
  it('classifyPath detects idor and admin surfaces', () => {
    expect(classifyPath('https://a.x.com/api/v1/users/42')?.kind).toBe('idor');
    expect(classifyPath('https://a.x.com/admin/dashboard')?.kind).toBe('admin-bypass');
    expect(classifyPath('https://a.x.com/') ).toBeNull();
  });

  it('flags unauthenticated user object with ≥2 PII markers as high', () => {
    const body = JSON.stringify({
      user: { id: 1, email: 'alice@x.com', username: 'alice' },
      phone: '+15551234567',
    });
    const f = authAccessCheck.run(
      probe({
        url: 'https://a.x.com/api/v1/users/1',
        body,
        headers: { 'content-type': 'application/json' },
      }),
      ctx,
    );
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('high');
    expect(f[0]!.checkId).toBe('auth-access-control');
  });

  it('flags admin role marker as critical', () => {
    const body = JSON.stringify({ role: 'admin', email: 'root@x.com', profile: { id: 1 } });
    const f = authAccessCheck.run(
      probe({
        url: 'https://a.x.com/api/admin/users',
        body,
        headers: { 'content-type': 'application/json' },
      }),
      ctx,
    );
    expect(f[0]!.severity).toBe('critical');
  });

  it('does not flag login HTML chrome alone', () => {
    const f = authAccessCheck.run(
      probe({
        url: 'https://a.x.com/login',
        headers: { 'content-type': 'text/html' },
        body: '<form id="login"><input name="username"><input name="password"></form>',
      }),
      ctx,
    );
    expect(f).toHaveLength(0);
  });
});

describe('cache deception helpers + check', () => {
  it('detects cacheable + dynamic content', () => {
    expect(hasCacheableResponse({ 'cache-control': 'public, max-age=60', age: '12' })).toBe(true);
    expect(hasCacheableResponse({ 'cache-control': 'private, no-store' })).toBe(false);
    expect(
      looksLikeDynamicContent('{"email":"a@x.com","username":"a"}', {
        'content-type': 'application/json',
      }),
    ).toBe(true);
  });

  it('flags dynamic body under static suffix when cacheable', () => {
    const f = cacheDeceptionCheck.run(
      probe({
        url: 'https://a.x.com/account/.css',
        status: 200,
        headers: {
          'content-type': 'application/json',
          'cache-control': 'public, max-age=120',
          'cf-cache-status': 'HIT',
        },
        body: JSON.stringify({ email: 'victim@x.com', username: 'victim', balance: 12 }),
      }),
      ctx,
    );
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('high');
    expect(f[0]!.checkId).toBe('cache-deception');
  });

  it('ignores static asset without dynamic markers', () => {
    const f = cacheDeceptionCheck.run(
      probe({
        url: 'https://a.x.com/app.css',
        headers: { 'content-type': 'text/css', 'cache-control': 'public, max-age=3600' },
        body: 'body{color:red}',
      }),
      ctx,
    );
    expect(f).toHaveLength(0);
  });
});

describe('subdomain takeover', () => {
  it('matchTakeoverFingerprint recognizes github.io', () => {
    expect(matchTakeoverFingerprint('dangling.github.io.')?.service).toMatch(/GitHub/i);
  });

  it('isTakeoverCandidate requires dangling CNAME without A/AAAA', () => {
    expect(
      isTakeoverCandidate({
        host: 'blog.x.com',
        cname: 'x.github.io',
        aRecords: [],
        nxdomain: true,
      })?.service,
    ).toMatch(/GitHub/i);
    expect(
      isTakeoverCandidate({
        host: 'blog.x.com',
        cname: 'x.github.io',
        aRecords: ['1.2.3.4'],
        nxdomain: false,
      }),
    ).toBeNull();
  });

  it('parseDohResponse maps NXDOMAIN + CNAME', () => {
    const r = parseDohResponse('blog.x.com', {
      Status: 3,
      Answer: [{ type: 5, data: 'x.github.io.' }],
    });
    expect(r.nxdomain).toBe(true);
    expect(r.cname).toBe('x.github.io.');
  });

  it('check flags synthetic DNS takeover probe', () => {
    const body = JSON.stringify({
      host: 'blog.x.com',
      cname: 'shop.myshopify.com',
      aRecords: [],
      nxdomain: true,
    });
    const f = subdomainTakeoverCheck.run(
      probe({
        url: 'https://blog.x.com/',
        headers: { 'x-stormforge-dns': 'takeover-lookup' },
        body,
      }),
      ctx,
    );
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('high');
    expect(f[0]!.title).toMatch(/Shopify/i);
  });

  it('matchTakeoverBody flags known unclaimed service pages', () => {
    expect(matchTakeoverBody("There isn't a GitHub Pages site here.")?.service).toMatch(/GitHub/i);
    expect(matchTakeoverBody('hello world')).toBeNull();
  });

  it('check flags HTTP body takeover fingerprint', () => {
    const f = subdomainTakeoverCheck.run(
      probe({
        url: 'https://blog.x.com/',
        status: 404,
        body: "There isn't a GitHub Pages site here.",
      }),
      ctx,
    );
    expect(f).toHaveLength(1);
    expect(f[0]!.needsManualReview).toBe(true);
  });
});

describe('registry + planner fan-out for new signals', () => {
  it('registers new BBP checks', () => {
    const ids = listChecks().map((c) => c.id);
    expect(ids).toContain('oauth-misconfig');
    expect(ids).toContain('auth-access-control');
    expect(ids).toContain('cache-deception');
    expect(ids).toContain('subdomain-takeover');
  });

  it('planFromFindings schedules nuclei takeovers / oauth follow-ups', () => {
    const findings: Finding[] = [
      {
        id: 't1',
        checkId: 'subdomain-takeover',
        title: 'Possible subdomain takeover — blog.x.com → GitHub Pages',
        severity: 'high',
        target: 'https://blog.x.com/',
        description: '',
        evidence: 'CNAME: x.github.io',
        reproduction: [],
        remediation: '',
        references: [],
        needsManualReview: true,
        discoveredAt: new Date().toISOString(),
      },
      {
        id: 'o1',
        checkId: 'oauth-misconfig',
        title: 'OAuth redirect_uri open redirect',
        severity: 'high',
        target: 'https://a.x.com/oauth/authorize',
        description: '',
        evidence: '',
        reproduction: [],
        remediation: '',
        references: [],
        needsManualReview: true,
        discoveredAt: new Date().toISOString(),
      },
    ];
    const plan = planFromFindings(findings, scope);
    expect(plan.tasks.some((t) => t.tool === 'nuclei' && /takeover/i.test(t.args.templates || ''))).toBe(
      true,
    );
    expect(plan.tasks.some((t) => /oauth|misconfig/i.test(t.rationale + (t.args.templates || '')))).toBe(
      true,
    );
  });
});
