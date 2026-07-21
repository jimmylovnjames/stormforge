import { describe, it, expect } from 'vitest';
import {
  JSONP_CANARY,
  JSONP_PATHS,
  buildJsonpProbeUrls,
  hasJsonpWrapper,
  shouldProbeJsonp,
  urlCarriesJsonpCanary,
} from '../src/recon/jsonp-probes.js';
import { jsonpCheck } from '../src/detect/checks/jsonp.js';
import { collectJsonpFollowUps } from '../src/engine/scanner.js';
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
    headers: { 'content-type': 'application/json' },
    body: '{"ok":true}',
    elapsedMs: 4,
    ...over,
  };
}

describe('jsonp probes', () => {
  it('builds callback/jsonp canary URLs', () => {
    const built = buildJsonpProbeUrls('https://a.x.com/api/v1/users');
    expect(built.length).toBeGreaterThanOrEqual(2);
    expect(built.every((u) => urlCarriesJsonpCanary(u))).toBe(true);
    expect(built.some((u) => u.includes('callback='))).toBe(true);
    expect(JSONP_PATHS).toContain('/api/v1/users');
  });

  it('detects JSONP wrapper around canary', () => {
    expect(hasJsonpWrapper(`${JSONP_CANARY}({"id":1})`, `https://a.x.com/x?callback=${JSONP_CANARY}`)).toBe(
      true,
    );
    expect(
      hasJsonpWrapper(`/**/${JSONP_CANARY}({"email":"a@b.com"});`, `https://a.x.com/x?jsonp=${JSONP_CANARY}`),
    ).toBe(true);
    expect(hasJsonpWrapper(`callback=${JSONP_CANARY}`, `https://a.x.com/x?callback=${JSONP_CANARY}`)).toBe(
      false,
    );
  });

  it('shouldProbeJsonp targets API/JSON surfaces', () => {
    expect(shouldProbeJsonp(probe({}))).toBe(true);
    expect(
      shouldProbeJsonp(
        probe({
          url: 'https://a.x.com/about',
          headers: { 'content-type': 'text/html' },
          body: '<html>about us</html>',
        }),
      ),
    ).toBe(false);
  });
});

describe('jsonpCheck', () => {
  it('flags JSONP callback reflection as medium/high when wrapping JSON', () => {
    const url = `https://a.x.com/api/v1/me?callback=${JSONP_CANARY}`;
    const f = jsonpCheck.run(
      probe({
        url,
        headers: { 'content-type': 'application/javascript' },
        body: `${JSONP_CANARY}({"id":1,"email":"victim@x.com","role":"user"});`,
      }),
      ctx,
    );
    expect(f.length).toBeGreaterThan(0);
    expect(f[0]!.checkId).toBe('jsonp-callback');
    expect(f[0]!.severity).toMatch(/high|medium/);
    expect(f[0]!.cwe).toBe('CWE-942');
  });

  it('does not flag when canary is only echoed without function call', () => {
    const url = `https://a.x.com/api?callback=${JSONP_CANARY}`;
    const f = jsonpCheck.run(
      probe({
        url,
        body: `<html>callback=${JSONP_CANARY}</html>`,
        headers: { 'content-type': 'text/html' },
      }),
      ctx,
    );
    expect(f).toHaveLength(0);
  });

  it('is registered and drafts impact', () => {
    expect(listChecks().some((c) => c.id === 'jsonp-callback')).toBe(true);
    const finding: Finding = {
      id: '1',
      checkId: 'jsonp-callback',
      title: 'JSONP',
      severity: 'high',
      target: 'https://a.x.com/api',
      description: 'd',
      evidence: 'e',
      reproduction: ['r'],
      remediation: 'fix',
      cwe: 'CWE-942',
      references: [],
      needsManualReview: false,
      discoveredAt: new Date().toISOString(),
    };
    expect(draftFinding(finding, scope)).toMatch(/JSONP|callback|CORS/i);
  });
});

describe('collectJsonpFollowUps', () => {
  it('emits capped canary URLs for candidates', () => {
    const urls = collectJsonpFollowUps([probe({})]);
    expect(urls.length).toBeGreaterThan(0);
    expect(urls.every((u) => urlCarriesJsonpCanary(u))).toBe(true);
  });
});
