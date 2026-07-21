import { describe, it, expect } from 'vitest';
import {
  PP_CANARY_KEY,
  PP_CANARY_VALUE,
  PP_PATHS,
  buildPrototypePollutionUrls,
  hasMassAssignmentSignal,
  hasPrototypePollutionReflection,
  shouldProbePrototypePollution,
  urlCarriesPpPayload,
} from '../src/recon/pp-probes.js';
import { prototypePollutionCheck } from '../src/detect/checks/prototype-pollution.js';
import { collectPrototypePollutionFollowUps } from '../src/engine/scanner.js';
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
    url: 'https://a.x.com/api/v1/users',
    method: 'GET',
    status: 200,
    headers: { 'content-type': 'application/json', 'x-powered-by': 'Express' },
    body: '{}',
    elapsedMs: 5,
    ...over,
  };
}

describe('pp probes', () => {
  it('builds __proto__ and mass-assignment URLs', () => {
    const urls = buildPrototypePollutionUrls('https://a.x.com/api/v1/users');
    expect(urls.length).toBeGreaterThanOrEqual(3);
    expect(urls.every((u) => urlCarriesPpPayload(u))).toBe(true);
    expect(PP_PATHS).toContain('/api/v1/users');
  });

  it('detects JSON property pollution and mass assignment', () => {
    const url = `https://a.x.com/api?__proto__[${PP_CANARY_KEY}]=${PP_CANARY_VALUE}`;
    expect(
      hasPrototypePollutionReflection(`{"ok":true,"${PP_CANARY_KEY}":"${PP_CANARY_VALUE}"}`, url),
    ).toBe(true);
    expect(hasPrototypePollutionReflection('{"ok":true}', url)).toBe(false);
    expect(
      hasMassAssignmentSignal('{"role":"admin","isAdmin":true}', 'https://a.x.com/api?isAdmin=true&role=admin'),
    ).toBe(true);
  });

  it('shouldProbePrototypePollution matches Express APIs', () => {
    expect(shouldProbePrototypePollution(probe({}))).toBe(true);
    expect(
      shouldProbePrototypePollution(
        probe({ url: 'https://a.x.com/about', headers: { 'content-type': 'text/html' }, status: 200 }),
      ),
    ).toBe(false);
  });
});

describe('prototypePollutionCheck', () => {
  it('flags polluted JSON property as high', () => {
    const url = `https://a.x.com/api/v1/users?__proto__[${PP_CANARY_KEY}]=${PP_CANARY_VALUE}`;
    const findings = prototypePollutionCheck.run(
      probe({
        url,
        body: JSON.stringify({ data: [], [PP_CANARY_KEY]: PP_CANARY_VALUE }),
      }),
      ctx,
    );
    expect(findings.some((f) => f.title.includes('Prototype pollution'))).toBe(true);
    expect(findings[0]!.cwe).toBe('CWE-1321');
  });

  it('flags mass assignment separately', () => {
    const url = `https://a.x.com/api/v1/me?isAdmin=true&role=admin&${PP_CANARY_KEY}=${PP_CANARY_VALUE}`;
    const findings = prototypePollutionCheck.run(
      probe({ url, body: '{"isAdmin":true,"role":"admin"}' }),
      ctx,
    );
    expect(findings.some((f) => f.cwe === 'CWE-915')).toBe(true);
  });

  it('is registered and drafts impact', () => {
    expect(listChecks().some((c) => c.id === 'prototype-pollution')).toBe(true);
    const f: Finding = {
      id: 'p1',
      checkId: 'prototype-pollution',
      title: 'PP',
      severity: 'high',
      target: 'https://a.x.com/api',
      description: 'd',
      evidence: 'e',
      reproduction: ['r'],
      remediation: 'fix',
      cwe: 'CWE-1321',
      references: [],
      needsManualReview: false,
      discoveredAt: new Date().toISOString(),
    };
    expect(draftFinding(f, scope)).toMatch(/Prototype pollution/i);
  });
});

describe('collectPrototypePollutionFollowUps', () => {
  it('emits PP URLs for API paths', () => {
    const urls = collectPrototypePollutionFollowUps([probe({})]);
    expect(urls.length).toBeGreaterThan(0);
    expect(urls.some((u) => u.includes('__proto__'))).toBe(true);
  });
});
