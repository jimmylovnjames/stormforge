import { describe, it, expect } from 'vitest';
import {
  extractGraphqlIdorFields,
  materializeGraphqlUrls,
  buildGraphqlIdorFollowUps,
} from '../src/recon/graphql-extract.js';
import {
  compareAuthDifferential,
  authDifferentialCheck,
  authSessionConfigured,
  authProbeHeaders,
  DIFF_MARKER_HEADER,
  DIFF_PAIR_HEADER,
} from '../src/detect/checks/auth-differential.js';
import {
  cookiesCheck,
  isParentDomainScope,
  isBroadScopeCookieFinding,
} from '../src/detect/checks/cookies.js';
import { graphqlIntrospectionCheck } from '../src/detect/checks/graphql-introspection.js';
import { deriveAttackChains } from '../src/findings/attack-chains.js';
import { listChecks } from '../src/detect/registry.js';
import { metricsForFinding } from '../src/report/cvss.js';
import type { CheckContext, Finding, ProbeResult, Scope } from '../src/types.js';

const scope: Scope = {
  program: 'acme',
  platform: 'hackerone',
  inScope: ['*.acme.com', 'acme.com'],
  outOfScope: [],
  authorized: true,
};
const ctx: CheckContext = { scope };

function probe(over: Partial<ProbeResult> & Pick<ProbeResult, 'url'>): ProbeResult {
  return {
    method: 'GET',
    status: 200,
    headers: {},
    body: '',
    elapsedMs: 1,
    ...over,
  };
}

function finding(over: Partial<Finding> & Pick<Finding, 'checkId' | 'target' | 'severity'>): Finding {
  return {
    id: over.id ?? Math.random().toString(36).slice(2),
    title: over.title ?? over.checkId,
    description: '',
    evidence: over.evidence ?? 'e',
    reproduction: [],
    remediation: '',
    references: [],
    needsManualReview: false,
    discoveredAt: new Date().toISOString(),
    ...over,
  };
}

const INTROSPECTION = JSON.stringify({
  data: {
    __schema: {
      queryType: { name: 'Query' },
      mutationType: { name: 'Mutation' },
      types: [
        {
          name: 'Query',
          kind: 'OBJECT',
          fields: [
            { name: 'user', args: [{ name: 'id' }], type: { name: 'User' } },
            { name: 'orders', args: [{ name: 'orderId' }], type: { name: 'Order' } },
            { name: 'health', args: [], type: { name: 'String' } },
          ],
        },
        {
          name: 'Mutation',
          kind: 'OBJECT',
          fields: [{ name: 'deleteUser', args: [{ name: 'id' }], type: { name: 'Boolean' } }],
        },
      ],
    },
  },
});

describe('graphql IDOR extract', () => {
  it('extracts Query fields with ID-like args and skips Mutation writes', () => {
    const fields = extractGraphqlIdorFields(INTROSPECTION);
    expect(fields.map((f) => f.field).sort()).toEqual(['orders', 'user'].sort());
    expect(fields.every((f) => f.root === 'Query')).toBe(true);
  });

  it('materializes GET query URLs', () => {
    const urls = materializeGraphqlUrls(
      'https://api.acme.com/graphql',
      extractGraphqlIdorFields(INTROSPECTION),
      6,
    );
    expect(urls.some((u) => /query=/.test(u) && /user\(id:1\)/.test(decodeURIComponent(u)))).toBe(true);
    expect(urls.every((u) => u.startsWith('https://api.acme.com/graphql'))).toBe(true);
  });

  it('buildGraphqlIdorFollowUps is scope-gated', () => {
    const p = probe({
      url: 'https://api.acme.com/graphql?query=%7B__schema',
      body: INTROSPECTION,
      signals: {
        kind: 'json',
        openApiPathCount: 0,
        graphqlIntrospection: true,
        graphqlExplorer: false,
        swaggerUi: false,
        graphqlEndpointHint: true,
        preview: '',
      },
    });
    expect(buildGraphqlIdorFollowUps([p], scope, 8).length).toBeGreaterThan(0);
    expect(buildGraphqlIdorFollowUps([p], { ...scope, inScope: ['other.com'] }, 8)).toEqual([]);
  });

  it('graphql-introspection finding embeds IDOR candidates', () => {
    const f = graphqlIntrospectionCheck.run(
      probe({ url: 'https://api.acme.com/graphql', body: INTROSPECTION, status: 200 }),
      ctx,
    );
    expect(f[0]!.title).toMatch(/IDOR-shaped/);
    expect(f[0]!.evidence).toMatch(/Candidate GETs:/);
  });
});

describe('auth differential', () => {
  it('detects classic anonymous-denied → session-data delta', () => {
    const unauth = probe({
      url: 'https://api.acme.com/v1/me',
      status: 401,
      body: '{"error":"unauthorized"}',
    });
    const auth = probe({
      url: 'https://api.acme.com/v1/me',
      status: 200,
      body: '{"user":{"id":1,"email":"a@acme.com","username":"a"},"role":"admin"}',
    });
    const f = compareAuthDifferential(unauth, auth);
    expect(f).not.toBeNull();
    expect(f!.checkId).toBe('auth-differential');
    expect(f!.severity).toBe('critical');
    expect(f!.submitReady).toBe(true);
  });

  it('check correlates auth/unauth siblings via markers', () => {
    const pair = 'https://api.acme.com/account';
    const unauth = probe({
      url: pair,
      status: 403,
      body: 'forbidden',
      headers: { [DIFF_MARKER_HEADER]: 'unauth', [DIFF_PAIR_HEADER]: pair },
    });
    const auth = probe({
      url: pair,
      status: 200,
      body: '{"email":"a@acme.com","profile":{"id":1,"username":"a"}}',
      headers: { [DIFF_MARKER_HEADER]: 'auth', [DIFF_PAIR_HEADER]: pair },
    });
    const findings = authDifferentialCheck.run(auth, { scope, siblings: [unauth, auth] });
    expect(findings).toHaveLength(1);
  });

  it('authSessionConfigured + headers helpers', () => {
    expect(authSessionConfigured(undefined, undefined)).toBe(false);
    expect(authSessionConfigured('sid=1', undefined)).toBe(true);
    expect(authProbeHeaders('sid=1', 'Bearer x')).toEqual({ cookie: 'sid=1', authorization: 'Bearer x' });
    expect(listChecks().some((c) => c.id === 'auth-differential')).toBe(true);
    expect(metricsForFinding({ checkId: 'auth-differential', severity: 'high' }).C).toBe('H');
  });
});

describe('cookie Domain/SameSite precision', () => {
  it('flags parent-domain session cookies', () => {
    const f = cookiesCheck.run(
      probe({
        url: 'https://www.acme.com/',
        headers: { 'set-cookie': 'sid=abc; Domain=.acme.com; Path=/; Secure; HttpOnly; SameSite=Lax' },
      }),
      ctx,
    );
    expect(f.some((x) => /parent Domain/i.test(x.title))).toBe(true);
    expect(f.some((x) => /Scope: broad-domain/.test(x.evidence))).toBe(true);
  });

  it('flags SameSite=None;Secure session cookies as cross-site', () => {
    const f = cookiesCheck.run(
      probe({
        url: 'https://www.acme.com/',
        headers: { 'set-cookie': 'session=xyz; Secure; HttpOnly; SameSite=None; Path=/' },
      }),
      ctx,
    );
    expect(f.some((x) => /SameSite=None;Secure/i.test(x.title))).toBe(true);
  });

  it('isParentDomainScope / isBroadScopeCookieFinding helpers', () => {
    expect(isParentDomainScope('.acme.com', 'https://www.acme.com/')).toBe(true);
    expect(isParentDomainScope('www.acme.com', 'https://www.acme.com/')).toBe(false);
    expect(
      isBroadScopeCookieFinding({
        checkId: 'insecure-cookies',
        evidence: 'Scope: broad-domain\nDomain: .acme.com',
      }),
    ).toBe(true);
    expect(
      isBroadScopeCookieFinding({
        checkId: 'insecure-cookies',
        evidence: 'Set-Cookie: a=1\nDomain: (host-only)',
      }),
    ).toBe(false);
  });

  it('takeover chain requires broad-scope cookie evidence', () => {
    expect(
      deriveAttackChains([
        finding({ checkId: 'subdomain-takeover', target: 'https://x.acme.com/', severity: 'high' }),
        finding({
          checkId: 'insecure-cookies',
          target: 'https://www.acme.com/',
          severity: 'medium',
          evidence: 'Scope: cross-site\nSameSite: none',
        }),
      ]).some((c) => c.checkId === 'chain-takeover-cookie-theft'),
    ).toBe(true);
  });
});
