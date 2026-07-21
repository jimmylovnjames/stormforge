import { describe, it, expect } from 'vitest';
import {
  CACHE_SENSITIVE_PATHS,
  buildCacheDeceptionUrls,
  hasCacheableResponse,
  looksLikeDynamicContent,
  shouldProbeCacheDeception,
} from '../src/recon/cache-deception-probes.js';
import { cacheDeceptionCheck } from '../src/detect/checks/cache-deception.js';
import { collectCacheDeceptionFollowUps } from '../src/engine/scanner.js';
import { listChecks } from '../src/detect/registry.js';
import { draftFinding } from '../src/report/drafter.js';
import type { CheckContext, Finding, ProbeResult, Scope } from '../src/types.js';

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
    url: 'https://a.x.com/account',
    method: 'GET',
    status: 200,
    headers: { 'content-type': 'text/html' },
    body: '<html>Welcome, Alice <a href="/logout">Sign out</a></html>',
    elapsedMs: 5,
    ...over,
  };
}

describe('cache deception probes', () => {
  it('forges static suffixes onto account paths', () => {
    const urls = buildCacheDeceptionUrls('https://a.x.com/account');
    expect(urls.some((u) => u.endsWith('/account.css'))).toBe(true);
    expect(urls.some((u) => u.includes('%0a.css'))).toBe(true);
    expect(CACHE_SENSITIVE_PATHS).toContain('/account');
  });

  it('detects dynamic content and cacheability', () => {
    expect(looksLikeDynamicContent(probe({}).body, probe({}).headers)).toBe(true);
    expect(hasCacheableResponse({ 'cache-control': 'public, max-age=3600', 'x-cache': 'HIT' })).toBe(true);
    expect(hasCacheableResponse({ 'cache-control': 'private', vary: 'Cookie' })).toBe(false);
  });

  it('shouldProbeCacheDeception matches account paths', () => {
    expect(shouldProbeCacheDeception(probe({}))).toBe(true);
  });
});

describe('cacheDeceptionCheck', () => {
  it('flags dynamic body under .css with cache HIT as high', () => {
    const findings = cacheDeceptionCheck.run(
      probe({
        url: 'https://a.x.com/account.css',
        headers: {
          'content-type': 'text/html',
          'cache-control': 'public, max-age=600',
          'x-cache': 'HIT',
        },
        body: '<html>Welcome, Alice <a>Sign out</a> email field <input name="email"></html>',
      }),
      ctx,
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('high');
    expect(findings[0]!.cwe).toBe('CWE-444');
    expect(findings[0]!.needsManualReview).toBe(true);
  });

  it('ignores real static assets', () => {
    expect(
      cacheDeceptionCheck.run(
        probe({
          url: 'https://a.x.com/app.css',
          headers: { 'content-type': 'text/css', 'cache-control': 'public' },
          body: 'body{color:#000}',
        }),
        ctx,
      ),
    ).toHaveLength(0);
  });

  it('is registered and drafts impact', () => {
    expect(listChecks().some((c) => c.id === 'cache-deception')).toBe(true);
    const f: Finding = {
      id: 'cd1',
      checkId: 'cache-deception',
      title: 'WCD',
      severity: 'high',
      target: 'https://a.x.com/me.css',
      description: 'd',
      evidence: 'e',
      reproduction: ['r'],
      remediation: 'fix',
      cwe: 'CWE-444',
      references: [],
      needsManualReview: true,
      discoveredAt: new Date().toISOString(),
    };
    expect(draftFinding(f, scope)).toMatch(/cache deception/i);
  });
});

describe('collectCacheDeceptionFollowUps', () => {
  it('emits forged static paths for /account', () => {
    const urls = collectCacheDeceptionFollowUps([probe({})]);
    expect(urls.length).toBeGreaterThan(0);
    expect(urls.some((u) => u.includes('/account.css'))).toBe(true);
  });
});
