import { describe, it, expect } from 'vitest';
import {
  activeTestingEnabled,
  buildOpenRedirectProbes,
  buildHostHeaderProbes,
  redirectHostOf,
  isCanaryRedirect,
  bodyReflectsCanary,
  CANARY_HOST,
  CANARY_REDIRECT_URL,
  ACTIVE_MARKER_HEADER,
  ACTIVE_CANARY_HEADER,
  ACTIVE_PARAM_HEADER,
} from '../src/recon/active-probes.js';
import { openRedirectCheck } from '../src/detect/checks/open-redirect.js';
import { hostHeaderCheck } from '../src/detect/checks/host-header.js';
import { listChecks } from '../src/detect/registry.js';
import { cvssFor } from '../src/report/cvss.js';
import type { CheckContext, Env, ProbeResult, Scope } from '../src/types.js';

const scope: Scope = { program: 'p', platform: 'generic', inScope: ['*.acme.com', 'acme.com'], outOfScope: [], authorized: true };
const ctx: CheckContext = { scope };

function env(over: Partial<Env> = {}): Env {
  return {
    SCAN_ORCHESTRATOR: {} as Env['SCAN_ORCHESTRATOR'],
    STORMFORGE_KV: {} as Env['STORMFORGE_KV'],
    MAX_RPS: '5',
    MAX_CONCURRENCY: '5',
    SCAN_MODE: 'hybrid',
    LLM_PLANNER_ENDPOINT: '',
    LLM_PLANNER_MODEL: 'grok-4',
    ...over,
  };
}

function probe(over: Partial<ProbeResult>): ProbeResult {
  return { url: 'https://app.acme.com/go', method: 'GET', status: 302, headers: {}, body: '', elapsedMs: 1, ...over };
}

describe('activeTestingEnabled gate (OFF by default, requires authorization)', () => {
  it('is off unless explicitly enabled', () => {
    expect(activeTestingEnabled(env(), scope)).toBe(false);
    expect(activeTestingEnabled(env({ ACTIVE_TESTING: 'true' }), scope)).toBe(true);
    expect(activeTestingEnabled(env({ SCAN_MODE: 'hybrid-active' }), scope)).toBe(true);
  });
  it('never enables for an unauthorized scope', () => {
    expect(activeTestingEnabled(env({ ACTIVE_TESTING: 'true' }), { ...scope, authorized: false })).toBe(false);
  });
});

describe('canary redirect analysis', () => {
  it('resolves absolute, protocol-relative, and backslash hosts', () => {
    expect(redirectHostOf('https://stormforge-oob.example/x')).toBe('stormforge-oob.example');
    expect(redirectHostOf('//stormforge-oob.example/x')).toBe('stormforge-oob.example');
    expect(redirectHostOf('/\\/\\stormforge-oob.example')).toBe('stormforge-oob.example');
    expect(redirectHostOf('/relative/path')).toBeNull();
  });
  it('isCanaryRedirect matches canary + subdomains only', () => {
    expect(isCanaryRedirect('https://stormforge-oob.example/a')).toBe(true);
    expect(isCanaryRedirect('https://x.stormforge-oob.example/a')).toBe(true);
    expect(isCanaryRedirect('https://app.acme.com/a')).toBe(false);
  });
  it('bodyReflectsCanary finds absolute canary URLs', () => {
    expect(bodyReflectsCanary('<a href="https://stormforge-oob.example/x">go</a>')).toBe(true);
    expect(bodyReflectsCanary('nothing here')).toBe(false);
  });
});

describe('probe builders (bounded + canary-scoped)', () => {
  it('open-redirect probes inject the canary while keeping the base host', () => {
    const probes = buildOpenRedirectProbes(['https://app.acme.com/go'], 6);
    expect(probes.length).toBeGreaterThan(0);
    expect(probes.length).toBeLessThanOrEqual(6);
    for (const p of probes) {
      const u = new URL(p.url);
      expect(u.hostname).toBe('app.acme.com'); // host stays in-scope
      expect(u.searchParams.get(p.param)).toBe(CANARY_REDIRECT_URL);
    }
  });
  it('host-header probes are cache-busted and set X-Forwarded-Host', () => {
    const probes = buildHostHeaderProbes(['https://app.acme.com/'], 4);
    expect(probes[0]!.headers['x-forwarded-host']).toBe(CANARY_HOST);
    expect(new URL(probes[0]!.url).searchParams.has('sf_cb')).toBe(true);
  });
});

describe('openRedirectCheck', () => {
  it('confirms a 302 redirect to the canary as medium + submitReady', () => {
    const f = openRedirectCheck.run(
      probe({
        status: 302,
        headers: { [ACTIVE_MARKER_HEADER]: 'open-redirect', [ACTIVE_PARAM_HEADER]: 'next', location: `${CANARY_REDIRECT_URL}?x=1` },
      }),
      ctx,
    );
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('medium');
    expect(f[0]!.submitReady).toBe(true);
    expect(f[0]!.title).toMatch(/next/);
  });
  it('does not flag a redirect that stays on the target host', () => {
    const f = openRedirectCheck.run(
      probe({ status: 302, headers: { [ACTIVE_MARKER_HEADER]: 'open-redirect', location: 'https://app.acme.com/home' } }),
      ctx,
    );
    expect(f).toHaveLength(0);
  });
  it('ignores probes without the active marker', () => {
    const f = openRedirectCheck.run(probe({ status: 302, headers: { location: `${CANARY_REDIRECT_URL}` } }), ctx);
    expect(f).toHaveLength(0);
  });
});

describe('hostHeaderCheck', () => {
  it('flags reflected X-Forwarded-Host in Location as medium', () => {
    const f = hostHeaderCheck.run(
      probe({
        status: 302,
        headers: { [ACTIVE_MARKER_HEADER]: 'host-header', [ACTIVE_CANARY_HEADER]: CANARY_HOST, location: `https://${CANARY_HOST}/login` },
      }),
      ctx,
    );
    expect(f[0]!.severity).toBe('medium');
    expect(f[0]!.checkId).toBe('host-header-injection');
  });
  it('escalates to high when the reflected response is cacheable', () => {
    const f = hostHeaderCheck.run(
      probe({
        status: 200,
        headers: {
          [ACTIVE_MARKER_HEADER]: 'host-header',
          [ACTIVE_CANARY_HEADER]: CANARY_HOST,
          'cache-control': 'public, max-age=300',
        },
        body: `<link rel="canonical" href="https://${CANARY_HOST}/p"/>`,
      }),
      ctx,
    );
    expect(f[0]!.severity).toBe('high');
  });
  it('ignores unmarked probes', () => {
    expect(hostHeaderCheck.run(probe({ body: `https://${CANARY_HOST}/` }), ctx)).toHaveLength(0);
  });
});

describe('registry + cvss wiring', () => {
  it('registers the active checks', () => {
    const ids = listChecks().map((c) => c.id);
    expect(ids).toContain('open-redirect');
    expect(ids).toContain('host-header-injection');
  });
  it('open-redirect CVSS is scope-changed', () => {
    expect(cvssFor({ checkId: 'open-redirect', severity: 'medium' }).vector).toMatch(/\/S:C\//);
  });
});
