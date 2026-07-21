import { describe, it, expect } from 'vitest';
import {
  XSS_CANARY,
  XSS_PAYLOAD,
  SSTI_EXPR,
  SSTI_RESULT,
  REFLECTION_PATHS,
  buildInjectionProbeUrls,
  hasUnescapedXssReflection,
  hasSstiEvaluation,
  shouldProbeInjection,
  urlCarriesXssCanary,
} from '../src/recon/injection-probes.js';
import { xssInjectionCheck } from '../src/detect/checks/xss-injection.js';
import { collectInjectionFollowUps } from '../src/engine/scanner.js';
import { listChecks } from '../src/detect/registry.js';
import { draftFinding } from '../src/report/drafter.js';
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
    url: 'https://a.x.com/search',
    method: 'GET',
    status: 200,
    headers: { 'content-type': 'text/html' },
    body: '',
    elapsedMs: 5,
    ...over,
  };
}

describe('injection probe helpers', () => {
  it('builds XSS and SSTI canary URLs', () => {
    const built = buildInjectionProbeUrls('https://a.x.com/search', 2);
    expect(built.xss.length).toBe(2);
    expect(built.ssti.length).toBe(2);
    expect(built.xss[0]).toContain(encodeURIComponent(XSS_PAYLOAD).slice(0, 8));
    expect(urlCarriesXssCanary(built.xss[0])).toBe(true);
  });

  it('detects unescaped XSS reflection and ignores entity-encoded', () => {
    expect(hasUnescapedXssReflection(`Hello ${XSS_PAYLOAD} world`)).toBe(true);
    expect(hasUnescapedXssReflection(`&lt;${XSS_CANARY}&gt;`)).toBe(false);
  });

  it('detects SSTI evaluation only when expression was sent and result appears', () => {
    const url = `https://a.x.com/search?q=${encodeURIComponent(SSTI_EXPR)}`;
    expect(hasSstiEvaluation(`result=${SSTI_RESULT}`, url)).toBe(true);
    expect(hasSstiEvaluation(`echo ${SSTI_EXPR}`, url)).toBe(false);
    expect(hasSstiEvaluation(`result=${SSTI_RESULT}`, 'https://a.x.com/')).toBe(false);
  });

  it('shouldProbeInjection targets HTML and reflection paths', () => {
    expect(
      shouldProbeInjection(
        probe({ url: 'https://a.x.com/search', headers: { 'content-type': 'text/html' }, body: '<html/>' }),
      ),
    ).toBe(true);
    expect(
      shouldProbeInjection(
        probe({ url: 'https://a.x.com/logo.png', status: 200, headers: { 'content-type': 'image/png' }, body: '' }),
      ),
    ).toBe(false);
    expect(REFLECTION_PATHS).toContain('/search');
  });
});

describe('xssInjectionCheck', () => {
  it('flags reflected XSS as high when canary is unescaped', () => {
    const url = `https://a.x.com/search?q=${encodeURIComponent(XSS_PAYLOAD)}`;
    const f = xssInjectionCheck.run(
      probe({
        url,
        body: `<html><body>Results for ${XSS_PAYLOAD}</body></html>`,
      }),
      ctx,
    );
    expect(f.some((x) => x.title.includes('Reflected XSS'))).toBe(true);
    expect(f.find((x) => x.title.includes('Reflected XSS'))!.severity).toBe('high');
    expect(f.find((x) => x.title.includes('Reflected XSS'))!.needsManualReview).toBe(false);
  });

  it('does not flag HTML-encoded canary reflection', () => {
    const url = `https://a.x.com/search?q=${encodeURIComponent(XSS_PAYLOAD)}`;
    const f = xssInjectionCheck.run(
      probe({
        url,
        body: `<html>Results for &quot;&gt;&lt;${XSS_CANARY}&gt;</html>`,
      }),
      ctx,
    );
    expect(f.some((x) => x.title.includes('Reflected XSS'))).toBe(false);
  });

  it('flags SSTI evaluation as high', () => {
    const url = `https://a.x.com/search?q=${encodeURIComponent(SSTI_EXPR)}`;
    const f = xssInjectionCheck.run(
      probe({
        url,
        headers: { 'content-type': 'text/html' },
        body: `<p>Hello 635201</p>`,
      }),
      ctx,
    );
    expect(f.some((x) => x.title.includes('template injection'))).toBe(true);
    expect(f.find((x) => x.title.includes('template injection'))!.severity).toBe('high');
    expect(f.find((x) => x.title.includes('template injection'))!.cwe).toBe('CWE-94');
  });

  it('flags CSP unsafe-inline+unsafe-eval as high', () => {
    const f = xssInjectionCheck.run(
      probe({
        url: 'https://a.x.com/',
        headers: {
          'content-type': 'text/html',
          'content-security-policy': "default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval'",
        },
        body: '<html><script>eval(1)</script></html>',
      }),
      ctx,
    );
    expect(f.some((x) => x.severity === 'high' && x.title.includes('unsafe-inline'))).toBe(true);
  });

  it('flags wildcard script-src as high', () => {
    const f = xssInjectionCheck.run(
      probe({
        headers: {
          'content-type': 'text/html',
          'content-security-policy': 'script-src *',
        },
        body: '<html></html>',
      }),
      ctx,
    );
    expect(f.some((x) => x.title.includes('wildcard'))).toBe(true);
  });

  it('flags unsafe sinks without CSP as medium', () => {
    const f = xssInjectionCheck.run(
      probe({
        url: 'https://a.x.com/app',
        headers: { 'content-type': 'text/html' },
        body: '<script>document.write(location.hash)</script>',
      }),
      ctx,
    );
    expect(f.some((x) => x.title.includes('Unsafe client-side sinks'))).toBe(true);
  });

  it('flags nonce + unsafe-inline as weak CSP', () => {
    const f = xssInjectionCheck.run(
      probe({
        headers: {
          'content-type': 'text/html',
          'content-security-policy': "script-src 'nonce-abc123' 'unsafe-inline'",
        },
        body: '<html><body></body></html>',
      }),
      ctx,
    );
    expect(f.some((x) => /nonce/i.test(x.title) && /unsafe-inline/i.test(x.title))).toBe(true);
  });

  it('flags missing base-uri/object-src when dangerous sinks present', () => {
    const f = xssInjectionCheck.run(
      probe({
        headers: {
          'content-type': 'text/html',
          'content-security-policy': "default-src 'self'; script-src 'self'",
        },
        body: '<html><script>el.innerHTML = location.hash</script></html>',
      }),
      ctx,
    );
    expect(f.some((x) => /base-uri|object-src/i.test(x.title))).toBe(true);
  });

  it('flags Report-Only CSP without an enforcing policy', () => {
    const f = xssInjectionCheck.run(
      probe({
        headers: {
          'content-type': 'text/html',
          'content-security-policy-report-only': "default-src 'self'",
        },
        body: '<html></html>',
      }),
      ctx,
    );
    expect(f.some((x) => /report-only/i.test(x.title))).toBe(true);
  });

  it('is registered in the check registry', () => {
    expect(listChecks().some((c) => c.id === 'xss-injection')).toBe(true);
  });
});

describe('collectInjectionFollowUps + report', () => {
  it('emits canary URLs for HTML candidates', () => {
    const urls = collectInjectionFollowUps([
      probe({ url: 'https://a.x.com/search', headers: { 'content-type': 'text/html' }, body: '<html/>' }),
    ]);
    expect(urls.length).toBeGreaterThan(0);
    expect(urls.some((u) => u.includes('sfXss') || decodeURIComponent(u).includes(XSS_CANARY))).toBe(true);
  });

  it('drafts XSS impact text for CWE-79', () => {
    const finding: Finding = {
      id: '1',
      checkId: 'xss-injection',
      title: 'Reflected XSS',
      severity: 'high',
      target: 'https://a.x.com/search',
      description: 'd',
      evidence: 'e',
      reproduction: ['r'],
      remediation: 'fix',
      cwe: 'CWE-79',
      references: [],
      needsManualReview: false,
      discoveredAt: new Date().toISOString(),
    };
    expect(draftFinding(finding, scope)).toContain('Cross-site scripting');
  });
});
