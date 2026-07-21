import { describe, it, expect } from 'vitest';
import {
  HPP_CANARY,
  HPP_PATHS,
  buildHppProbeUrls,
  hasHppBehavioralDelta,
  hasHppCanaryReflection,
  shouldProbeHpp,
  urlCarriesHppPayload,
} from '../src/recon/hpp-probes.js';
import { hppCheck } from '../src/detect/checks/hpp.js';
import { collectHppFollowUps } from '../src/engine/scanner.js';
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
    url: 'https://a.x.com/api/v1/users?id=1',
    method: 'GET',
    status: 200,
    headers: { 'content-type': 'application/json' },
    body: '{"id":1}',
    elapsedMs: 4,
    ...over,
  };
}

describe('hpp probes', () => {
  it('builds duplicate-param pollution URLs with a canary', () => {
    const built = buildHppProbeUrls('https://a.x.com/api/v1/users?id=1');
    expect(built.length).toBeGreaterThanOrEqual(2);
    expect(built.every((b) => urlCarriesHppPayload(b.url))).toBe(true);
    expect(built.some((b) => b.url.includes(HPP_CANARY))).toBe(true);
    expect(built.every((b) => b.baselineUrl.includes('id=1'))).toBe(true);
    expect(HPP_PATHS).toContain('/api/v1/users');
  });

  it('detects canary reflection and behavioral delta vs baseline', () => {
    const pollutedUrl = `https://a.x.com/api?id=1&id=${HPP_CANARY}`;
    expect(hasHppCanaryReflection(`{"id":"${HPP_CANARY}"}`, pollutedUrl)).toBe(true);
    expect(hasHppCanaryReflection('{"id":1}', pollutedUrl)).toBe(false);

    const baseline = probe({ url: 'https://a.x.com/api?id=1', body: '{"id":1,"role":"user"}' });
    const polluted = probe({
      url: pollutedUrl,
      status: 200,
      body: '{"id":"' + HPP_CANARY + '","role":"admin"}',
    });
    expect(hasHppBehavioralDelta(polluted, baseline)).toBe(true);
    expect(hasHppBehavioralDelta(baseline, baseline)).toBe(false);
  });

  it('shouldProbeHpp matches API/param surfaces', () => {
    expect(shouldProbeHpp(probe({}))).toBe(true);
    expect(
      shouldProbeHpp(
        probe({
          url: 'https://a.x.com/about',
          headers: { 'content-type': 'text/html' },
          body: '<html></html>',
        }),
      ),
    ).toBe(false);
  });
});

describe('hppCheck', () => {
  it('flags when polluted param wins and returns different identity/privilege', () => {
    const baseline = probe({
      url: 'https://a.x.com/api/v1/users?id=1',
      body: '{"id":1,"email":"a@b.com","role":"user"}',
    });
    const pollutedUrl = `https://a.x.com/api/v1/users?id=1&id=${HPP_CANARY}`;
    const findings = hppCheck.run(
      probe({
        url: pollutedUrl,
        body: `{"id":"${HPP_CANARY}","email":"admin@x.com","role":"admin"}`,
      }),
      { ...ctx, siblings: [baseline] },
    );
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.checkId).toBe('http-parameter-pollution');
    expect(findings[0]!.cwe).toBe('CWE-235');
    expect(findings[0]!.severity).toMatch(/high|medium/);
  });

  it('is registered and drafts impact', () => {
    expect(listChecks().some((c) => c.id === 'http-parameter-pollution')).toBe(true);
    const f: Finding = {
      id: 'h1',
      checkId: 'http-parameter-pollution',
      title: 'HPP',
      severity: 'high',
      target: 'https://a.x.com/api',
      description: 'd',
      evidence: 'e',
      reproduction: ['r'],
      remediation: 'fix',
      cwe: 'CWE-235',
      references: [],
      needsManualReview: true,
      discoveredAt: new Date().toISOString(),
    };
    expect(draftFinding(f, scope)).toMatch(/parameter pollution|HPP|duplicate/i);
  });
});

describe('collectHppFollowUps', () => {
  it('emits polluted URLs for candidate probes', () => {
    const items = collectHppFollowUps([probe({})]);
    expect(items.length).toBeGreaterThan(0);
    expect(items.some((i) => i.url.includes(HPP_CANARY))).toBe(true);
  });
});
