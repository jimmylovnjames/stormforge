import { describe, it, expect } from 'vitest';
import {
  CRLF_CANARY_HEADER,
  CRLF_CANARY_VALUE,
  CRLF_PATHS,
  buildCrlfProbeUrls,
  hasCrlfHeaderInjection,
  shouldProbeCrlf,
  urlCarriesCrlfPayload,
} from '../src/recon/crlf-probes.js';
import { crlfInjectionCheck } from '../src/detect/checks/crlf-injection.js';
import { collectCrlfFollowUps } from '../src/engine/scanner.js';
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
    url: 'https://a.x.com/redirect',
    method: 'GET',
    status: 302,
    headers: {},
    body: '',
    elapsedMs: 5,
    ...over,
  };
}

describe('crlf probes', () => {
  it('builds %0d%0a canary URLs', () => {
    const urls = buildCrlfProbeUrls('https://a.x.com/redirect', 2);
    expect(urls.length).toBeGreaterThan(0);
    expect(urls.every((u) => urlCarriesCrlfPayload(u))).toBe(true);
    expect(CRLF_PATHS).toContain('/redirect');
  });

  it('detects injected response headers', () => {
    expect(
      hasCrlfHeaderInjection({ [CRLF_CANARY_HEADER]: CRLF_CANARY_VALUE }),
    ).toBe(true);
    expect(hasCrlfHeaderInjection({ 'set-cookie': `sfCrlf=${CRLF_CANARY_VALUE}; Path=/` })).toBe(true);
    expect(hasCrlfHeaderInjection({ location: 'https://a.x.com/' })).toBe(false);
  });

  it('shouldProbeCrlf matches redirect paths and Location responses', () => {
    expect(shouldProbeCrlf(probe({ status: 302, headers: { location: 'https://a.x.com/' } }))).toBe(true);
    expect(shouldProbeCrlf(probe({ url: 'https://a.x.com/about', status: 200 }))).toBe(false);
  });
});

describe('crlfInjectionCheck', () => {
  it('flags canary header injection as high', () => {
    const url = `https://a.x.com/redirect?url=%0d%0a${CRLF_CANARY_HEADER}:%20${CRLF_CANARY_VALUE}`;
    const findings = crlfInjectionCheck.run(
      probe({
        url,
        status: 200,
        headers: { [CRLF_CANARY_HEADER]: CRLF_CANARY_VALUE },
      }),
      ctx,
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('high');
    expect(findings[0]!.cwe).toBe('CWE-113');
  });

  it('ignores body-only canary echo without header', () => {
    const url = `https://a.x.com/redirect?url=%0d%0a${CRLF_CANARY_HEADER}:%20${CRLF_CANARY_VALUE}`;
    expect(
      crlfInjectionCheck.run(probe({ url, status: 200, body: CRLF_CANARY_VALUE, headers: {} }), ctx),
    ).toHaveLength(0);
  });

  it('is registered and drafts impact', () => {
    expect(listChecks().some((c) => c.id === 'crlf-header-injection')).toBe(true);
    const f: Finding = {
      id: 'c1',
      checkId: 'crlf-header-injection',
      title: 'CRLF',
      severity: 'high',
      target: 'https://a.x.com/r',
      description: 'd',
      evidence: 'e',
      reproduction: ['r'],
      remediation: 'fix',
      cwe: 'CWE-113',
      references: [],
      needsManualReview: false,
      discoveredAt: new Date().toISOString(),
    };
    expect(draftFinding(f, scope)).toMatch(/CRLF|response splitting/i);
  });
});

describe('collectCrlfFollowUps', () => {
  it('emits CRLF URLs for redirect endpoints', () => {
    const urls = collectCrlfFollowUps([
      probe({ url: 'https://a.x.com/redirect', status: 302, headers: { location: '/' } }),
    ]);
    expect(urls.length).toBeGreaterThan(0);
  });
});
