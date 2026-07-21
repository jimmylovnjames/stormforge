import { describe, it, expect } from 'vitest';
import {
  HOST_CANARY,
  buildHostHeaderVariants,
  cachePoisoningSignals,
  hostHeaderReflected,
  shouldProbeHostHeader,
} from '../src/recon/host-header-probes.js';
import { hostHeaderCheck } from '../src/detect/checks/host-header.js';
import { collectHostHeaderFollowUps } from '../src/engine/scanner.js';
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
    url: 'https://a.x.com/',
    method: 'GET',
    status: 200,
    headers: { 'content-type': 'text/html' },
    body: '',
    elapsedMs: 5,
    ...over,
  };
}

describe('host header probes', () => {
  it('builds Host and X-Forwarded-Host variants with canary', () => {
    const variants = buildHostHeaderVariants('https://a.x.com/login?x=1');
    expect(variants.length).toBeGreaterThanOrEqual(2);
    expect(variants.some((v) => v.headers.host === HOST_CANARY)).toBe(true);
    expect(variants.some((v) => v.headers['x-forwarded-host'] === HOST_CANARY)).toBe(true);
    expect(variants.every((v) => !v.url.includes('?'))).toBe(true);
  });

  it('detects canary reflection and cache signals', () => {
    expect(
      hostHeaderReflected(
        probe({
          body: `<a href="https://${HOST_CANARY}/reset">reset</a>`,
        }),
      ),
    ).toBe(true);
    expect(
      hostHeaderReflected(
        probe({
          body: 'ok',
          headers: { location: `https://${HOST_CANARY}/next` },
        }),
      ),
    ).toBe(true);
    expect(cachePoisoningSignals({ 'x-cache': 'HIT', vary: 'Accept-Encoding' })).toContain('cache-hit-or-age');
    expect(cachePoisoningSignals({ vary: 'Accept-Encoding' })).toContain('vary-missing-host');
  });

  it('shouldProbeHostHeader accepts typical 2xx/4xx pages', () => {
    expect(shouldProbeHostHeader(probe({ status: 200 }))).toBe(true);
    expect(shouldProbeHostHeader(probe({ status: 404 }))).toBe(true);
    expect(shouldProbeHostHeader(probe({ status: 0, error: 'dns' }))).toBe(false);
  });
});

describe('hostHeaderCheck', () => {
  it('flags Host canary reflection as high', () => {
    const findings = hostHeaderCheck.run(
      probe({
        body: `Password reset: https://${HOST_CANARY}/r/abc`,
        headers: { 'content-type': 'text/html', 'x-cache': 'HIT', vary: 'Accept-Encoding' },
      }),
      ctx,
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('high');
    expect(findings[0]!.cwe).toBe('CWE-644');
    expect(findings[0]!.checkId).toBe('host-header-injection');
    expect(findings[0]!.title).toMatch(/cache/i);
  });

  it('ignores responses without canary', () => {
    expect(hostHeaderCheck.run(probe({ body: '<html>ok</html>' }), ctx)).toHaveLength(0);
  });

  it('is registered and drafts impact text', () => {
    expect(listChecks().some((c) => c.id === 'host-header-injection')).toBe(true);
    const f: Finding = {
      id: 'h1',
      checkId: 'host-header-injection',
      title: 'Host reflect',
      severity: 'high',
      target: 'https://a.x.com/',
      description: 'd',
      evidence: 'e',
      reproduction: ['r'],
      remediation: 'fix',
      cwe: 'CWE-644',
      references: [],
      needsManualReview: true,
      discoveredAt: new Date().toISOString(),
    };
    expect(draftFinding(f, scope)).toMatch(/Host header|cache poisoning/i);
  });
});

describe('collectHostHeaderFollowUps', () => {
  it('emits variants for site roots', () => {
    const variants = collectHostHeaderFollowUps([
      probe({ url: 'https://a.x.com/', status: 200, body: 'ok' }),
    ]);
    expect(variants.length).toBeGreaterThan(0);
    expect(variants.some((v) => v.headers['x-forwarded-host'] === HOST_CANARY)).toBe(true);
  });
});
