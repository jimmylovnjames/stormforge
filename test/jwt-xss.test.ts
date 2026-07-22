import { describe, it, expect } from 'vitest';
import { jwtExposureCheck, parseJwt, b64urlJson } from '../src/detect/checks/jwt.js';
import {
  xssReflectionCheck,
  reflectsUnescaped,
  classifyReflection,
} from '../src/detect/checks/xss-reflection.js';
import { buildXssReflectionProbes, activeTestingEnabled } from '../src/recon/active-probes.js';
import { listChecks } from '../src/detect/registry.js';
import { scanSecrets } from '../src/recon/secrets.js';
import { deriveAttackChains } from '../src/findings/attack-chains.js';
import { planFromFindings } from '../src/planning/vuln-planner.js';
import { metricsForFinding } from '../src/report/cvss.js';
import type { Finding, ProbeResult, Scope } from '../src/types.js';
import {
  ACTIVE_MARKER_HEADER,
  ACTIVE_PARAM_HEADER,
  ACTIVE_CANARY_HEADER,
} from '../src/recon/active-probes.js';

function b64url(obj: unknown): string {
  return globalThis
    .btoa(JSON.stringify(obj))
    .replace(/=+$/, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function makeJwt(header: Record<string, unknown>, payload: Record<string, unknown>, sig = 'sig'): string {
  return `${b64url(header)}.${b64url(payload)}.${sig}`;
}

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

const scope: Scope = {
  program: 'acme',
  platform: 'hackerone',
  inScope: ['*.acme.com', 'acme.com'],
  outOfScope: [],
  authorized: true,
};

const ctx = { scope };

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
    confidence: 0.8,
    submitReady: true,
    ...over,
  };
}

describe('jwt helpers', () => {
  it('decodes base64url JSON', () => {
    const part = b64url({ alg: 'none', typ: 'JWT' });
    expect(b64urlJson(part)).toEqual({ alg: 'none', typ: 'JWT' });
  });

  it('parses compact JWTs', () => {
    const token = makeJwt({ alg: 'HS256', typ: 'JWT' }, { sub: '1', role: 'user' });
    const parsed = parseJwt(token);
    expect(parsed?.alg).toBe('HS256');
    expect(parsed?.payload.sub).toBe('1');
  });
});

describe('jwt-exposure check', () => {
  it('flags alg=none as critical + submitReady', () => {
    const token = makeJwt({ alg: 'none', typ: 'JWT' }, { sub: 'admin' }, '');
    const findings = jwtExposureCheck.run(
      probe({ url: 'https://app.acme.com/config.js', body: `window.t="${token}"` }),
      ctx,
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('critical');
    expect(findings[0]!.submitReady).toBe(true);
    expect(findings[0]!.evidence).toMatch(/alg=none/);
  });

  it('escalates privileged role claims to high', () => {
    const token = makeJwt({ alg: 'RS256', typ: 'JWT' }, { sub: '1', role: 'admin' });
    const findings = jwtExposureCheck.run(
      probe({ url: 'https://app.acme.com/', body: token }),
      ctx,
    );
    expect(findings[0]!.severity).toBe('high');
    expect(findings[0]!.submitReady).toBe(true);
  });

  it('flags path-like kid', () => {
    const token = makeJwt({ alg: 'HS256', kid: '../../.env' }, { sub: '1' });
    const findings = jwtExposureCheck.run(
      probe({ url: 'https://app.acme.com/', headers: { authorization: `Bearer ${token}` }, body: '' }),
      ctx,
    );
    expect(findings[0]!.severity).toBe('high');
    expect(findings[0]!.evidence).toMatch(/kid=/);
  });

  it('is registered and secrets no longer emit generic JWT findings', () => {
    expect(listChecks().some((c) => c.id === 'jwt-exposure')).toBe(true);
    const token = makeJwt({ alg: 'RS256' }, { sub: '1' });
    const secrets = scanSecrets(probe({ url: 'https://app.acme.com/a.js', body: `t=${token}` }));
    expect(secrets.every((f) => !/JWT/i.test(f.title))).toBe(true);
  });
});

describe('xss-reflection helpers + check', () => {
  it('detects unescaped reflection and classifies html context', () => {
    const body = '<html><body>Hello sfXssabc</body></html>';
    expect(reflectsUnescaped(body, 'sfXssabc')).toBe(true);
    expect(classifyReflection(body, 'sfXssabc')).toBe('html');
  });

  it('classifies attribute context', () => {
    const body = `<input value="sfXssabc">`;
    expect(classifyReflection(body, 'sfXssabc')).toBe('attribute');
  });

  it('passive: reports query value reflected in HTML', () => {
    const findings = xssReflectionCheck.run(
      probe({
        url: 'https://app.acme.com/search?q=uniqueNeedle42',
        headers: { 'content-type': 'text/html' },
        body: '<html><body>Results for uniqueNeedle42</body></html>',
      }),
      ctx,
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.checkId).toBe('xss-reflection');
    expect(findings[0]!.evidenceGrade).toBe('fingerprint');
  });

  it('active canary: submitReady in attribute context', () => {
    const canary = 'sfXssdeadbeef';
    const findings = xssReflectionCheck.run(
      probe({
        url: `https://app.acme.com/search?q=${canary}`,
        headers: {
          'content-type': 'text/html',
          [ACTIVE_MARKER_HEADER]: 'xss-reflection',
          [ACTIVE_PARAM_HEADER]: 'q',
          [ACTIVE_CANARY_HEADER]: canary,
        },
        body: `<html><body><img alt="${canary}"></body></html>`,
      }),
      ctx,
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.evidenceGrade).toBe('canary');
    expect(findings[0]!.submitReady).toBe(true);
    expect(findings[0]!.severity).toBe('high');
  });

  it('buildXssReflectionProbes stays bounded and uses XSS params', () => {
    const probes = buildXssReflectionProbes(['https://app.acme.com/'], 4);
    expect(probes.length).toBeLessThanOrEqual(4);
    expect(probes.every((p) => /[?&](q|s|search|query)=sfXss/.test(p.url))).toBe(true);
  });

  it('activeTestingEnabled still requires auth + flag', () => {
    expect(activeTestingEnabled({ ACTIVE_TESTING: 'true' } as import('../src/types.js').Env, { ...scope, authorized: false })).toBe(false);
    expect(activeTestingEnabled({ ACTIVE_TESTING: 'true' } as import('../src/types.js').Env, scope)).toBe(true);
  });
});

describe('planner + chains + cvss wiring', () => {
  it('plans nuclei follow-up for jwt-exposure and xss-reflection', () => {
    const jwtPlan = planFromFindings(
      [finding({ checkId: 'jwt-exposure', severity: 'high', target: 'https://app.acme.com/a.js' })],
      scope,
    );
    expect(jwtPlan.tasks.some((t) => /token/.test(t.args.templates || ''))).toBe(true);

    const xssPlan = planFromFindings(
      [finding({ checkId: 'xss-reflection', severity: 'medium', target: 'https://app.acme.com/search?q=1' })],
      scope,
    );
    expect(xssPlan.tasks.some((t) => /xss/.test(t.args.templates || ''))).toBe(true);
  });

  it('derives xss-csp and jwt-cors-theft chains', () => {
    const xssChain = deriveAttackChains([
      finding({ checkId: 'weak-csp', target: 'https://app.acme.com/', severity: 'medium' }),
      finding({ checkId: 'xss-reflection', target: 'https://app.acme.com/search?q=x', severity: 'high' }),
    ]);
    expect(xssChain.some((c) => c.checkId === 'chain-xss-csp')).toBe(true);

    const jwtChain = deriveAttackChains([
      finding({ checkId: 'jwt-exposure', target: 'https://app.acme.com/app.js', severity: 'high' }),
      finding({ checkId: 'cors-misconfig', target: 'https://app.acme.com/api', severity: 'high' }),
    ]);
    expect(jwtChain.some((c) => c.checkId === 'chain-jwt-cors-theft')).toBe(true);
    expect(jwtChain.find((c) => c.checkId === 'chain-jwt-cors-theft')!.severity).toBe('critical');
  });

  it('has CVSS profiles for new checkIds', () => {
    expect(metricsForFinding({ checkId: 'jwt-exposure', severity: 'high' }).C).toBe('H');
    expect(metricsForFinding({ checkId: 'xss-reflection', severity: 'medium' }).UI).toBe('R');
    expect(metricsForFinding({ checkId: 'chain-xss-csp', severity: 'high' }).C).toBe('H');
  });
});
