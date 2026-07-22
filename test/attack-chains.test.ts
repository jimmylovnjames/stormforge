import { describe, it, expect } from 'vitest';
import { deriveAttackChains, chainFollowUpTasks } from '../src/findings/attack-chains.js';
import { planFromFindings, MAX_EVOLVED_TASKS } from '../src/planning/vuln-planner.js';
import { metricsForFinding, cvssFor } from '../src/report/cvss.js';
import type { Finding, Scope } from '../src/types.js';

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
    confidence: over.confidence ?? 0.8,
    submitReady: over.submitReady ?? true,
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

describe('deriveAttackChains — major rules', () => {
  it('fires source-to-secret when exposed files + secret co-occur', () => {
    const chains = deriveAttackChains([
      finding({ checkId: 'exposed-files', target: 'https://app.acme.com/.env', severity: 'high' }),
      finding({ checkId: 'secret-exposure', target: 'https://app.acme.com/main.js', severity: 'critical' }),
    ]);
    expect(chains.some((c) => c.checkId === 'chain-source-to-secret')).toBe(true);
    const chain = chains.find((c) => c.checkId === 'chain-source-to-secret')!;
    expect(chain.severity).toBe('critical');
    expect(chain.evidence).toMatch(/Chain: source-to-secret/);
    expect(chain.needsManualReview).toBe(true);
  });

  it('fires debug-to-rce for high+ Werkzeug debug alone', () => {
    const chains = deriveAttackChains([
      finding({
        checkId: 'debug-disclosure',
        title: 'Werkzeug debugger exposed',
        target: 'https://app.acme.com/debug',
        severity: 'high',
      }),
    ]);
    const chain = chains.find((c) => c.checkId === 'chain-debug-to-rce');
    expect(chain).toBeDefined();
    expect(chain!.severity).toBe('critical');
    expect(chain!.title).toMatch(/Werkzeug/);
  });

  it('fires oauth-token-theft for open-redirect + oauth surface', () => {
    const chains = deriveAttackChains([
      finding({
        checkId: 'open-redirect',
        title: 'Open redirect via next=',
        target: 'https://auth.acme.com/login?next=',
        severity: 'medium',
      }),
      finding({
        checkId: 'oauth-misconfig',
        title: 'OAuth redirect_uri loose',
        target: 'https://auth.acme.com/oauth/authorize',
        severity: 'high',
      }),
    ]);
    expect(chains.some((c) => c.checkId === 'chain-oauth-token-theft')).toBe(true);
  });

  it('fires cors-cred-theft for permissive CORS + authz surface', () => {
    const chains = deriveAttackChains([
      finding({ checkId: 'cors-misconfig', target: 'https://api.acme.com/', severity: 'high' }),
      finding({ checkId: 'auth-access-control', target: 'https://api.acme.com/v1/me', severity: 'high' }),
    ]);
    expect(chains.some((c) => c.checkId === 'chain-cors-cred-theft')).toBe(true);
  });

  it('fires ssrf-cloud-pivot for SSRF + cloud bucket', () => {
    const chains = deriveAttackChains([
      finding({ checkId: 'ssrf-candidate', target: 'https://app.acme.com/fetch?url=', severity: 'medium' }),
      // Same registrable domain — chains correlate per eTLD+1, not raw host.
      finding({ checkId: 'open-cloud-bucket', target: 'https://assets.acme.com/', severity: 'high', evidence: 'AWS S3 ListBucketResult' }),
    ]);
    const chain = chains.find((c) => c.checkId === 'chain-ssrf-cloud-pivot');
    expect(chain).toBeDefined();
    expect(chain!.severity).toBe('high');
  });

  it('escalates ssrf-cloud-pivot to critical when OAST-confirmed', () => {
    const chains = deriveAttackChains([
      finding({ checkId: 'ssrf-oast-confirmed', target: 'https://app.acme.com/fetch?url=', severity: 'critical' }),
      finding({ checkId: 'open-cloud-bucket', target: 'https://bucket.acme.com/', severity: 'high' }),
    ]);
    expect(chains.find((c) => c.checkId === 'chain-ssrf-cloud-pivot')!.severity).toBe('critical');
  });

  it('fires takeover-cookie-theft for subdomain takeover + broadly-scoped cookies', () => {
    const chains = deriveAttackChains([
      finding({ checkId: 'subdomain-takeover', target: 'https://dangling.acme.com/', severity: 'high' }),
      finding({
        checkId: 'insecure-cookies',
        target: 'https://www.acme.com/',
        severity: 'medium',
        title: 'Session cookie "sid" scoped to parent Domain=.acme.com',
        evidence: 'URL: https://www.acme.com/\nSet-Cookie: sid=abc; Domain=.acme.com\nScope: broad-domain\nDomain: .acme.com',
      }),
    ]);
    expect(chains.some((c) => c.checkId === 'chain-takeover-cookie-theft')).toBe(true);
  });

  it('does not fire takeover-cookie-theft for mere missing-Secure cookies', () => {
    const chains = deriveAttackChains([
      finding({ checkId: 'subdomain-takeover', target: 'https://dangling.acme.com/', severity: 'high' }),
      finding({
        checkId: 'insecure-cookies',
        target: 'https://www.acme.com/',
        severity: 'medium',
        title: 'Cookie "sid" set without Secure',
        evidence: 'URL: https://www.acme.com/\nSet-Cookie: sid=abc\nDomain: (host-only)\nSameSite: (absent)',
      }),
    ]);
    expect(chains.some((c) => c.checkId === 'chain-takeover-cookie-theft')).toBe(false);
  });

  it('fires schema-idor for API schema + auth-access-control', () => {
    const chains = deriveAttackChains([
      finding({ checkId: 'api-schema-exposure', target: 'https://api.acme.com/openapi.json', severity: 'medium' }),
      finding({ checkId: 'auth-access-control', target: 'https://api.acme.com/v1/users/1', severity: 'high' }),
    ]);
    expect(chains.some((c) => c.checkId === 'chain-schema-idor')).toBe(true);
  });

  it('fires cache-poison-auth for cache deception + auth surface', () => {
    const chains = deriveAttackChains([
      finding({ checkId: 'cache-deception', target: 'https://app.acme.com/account.css', severity: 'high' }),
      finding({ checkId: 'auth-access-control', target: 'https://app.acme.com/account', severity: 'high' }),
    ]);
    expect(chains.some((c) => c.checkId === 'chain-cache-poison-auth')).toBe(true);
  });
});

describe('deriveAttackChains — negative cases', () => {
  it('does not fire source-to-secret on a lone secret', () => {
    const chains = deriveAttackChains([
      finding({ checkId: 'secret-exposure', target: 'https://app.acme.com/a.js', severity: 'critical' }),
    ]);
    expect(chains.some((c) => c.checkId === 'chain-source-to-secret')).toBe(false);
  });

  it('does not correlate across different registrable domains', () => {
    const chains = deriveAttackChains([
      finding({ checkId: 'exposed-files', target: 'https://app.acme.com/.env', severity: 'high' }),
      finding({ checkId: 'secret-exposure', target: 'https://other.com/main.js', severity: 'critical' }),
    ]);
    expect(chains.some((c) => c.checkId === 'chain-source-to-secret')).toBe(false);
  });

  it('never chains on chain-* findings', () => {
    const base = [
      finding({ checkId: 'exposed-files', target: 'https://app.acme.com/.env', severity: 'high' }),
      finding({ checkId: 'secret-exposure', target: 'https://app.acme.com/a.js', severity: 'critical' }),
    ];
    const once = deriveAttackChains(base);
    expect(once.length).toBeGreaterThan(0);
    const twice = deriveAttackChains([...base, ...once]);
    expect(twice.map((c) => c.checkId).sort()).toEqual(once.map((c) => c.checkId).sort());
  });

  it('is deterministic across runs', () => {
    const input = [
      finding({ id: 'a', checkId: 'cors-misconfig', target: 'https://api.acme.com/', severity: 'high' }),
      finding({ id: 'b', checkId: 'auth-access-control', target: 'https://api.acme.com/me', severity: 'high' }),
    ];
    const a = deriveAttackChains(input).map((c) => c.id);
    const b = deriveAttackChains(input).map((c) => c.id);
    expect(a).toEqual(b);
  });
});

describe('chainFollowUpTasks + planner integration', () => {
  it('emits follow-up tasks with srcChain for chains that define them', () => {
    const tasks = chainFollowUpTasks([
      finding({ checkId: 'exposed-files', target: 'https://app.acme.com/.env', severity: 'high' }),
      finding({ checkId: 'secret-exposure', target: 'https://app.acme.com/a.js', severity: 'critical' }),
    ]);
    expect(tasks.some((t) => t.args.srcChain === 'source-to-secret')).toBe(true);
    expect(tasks.every((t) => t.rationale.includes('Chain follow-up'))).toBe(true);
  });

  it('planFromFindings appends chain follow-ups within the evolved cap', () => {
    const plan = planFromFindings(
      [
        finding({ checkId: 'ssrf-candidate', target: 'https://app.acme.com/fetch?url=', severity: 'medium' }),
        finding({ checkId: 'open-cloud-bucket', target: 'https://assets.acme.com/', severity: 'high' }),
      ],
      scope,
    );
    expect(plan.tasks.length).toBeLessThanOrEqual(MAX_EVOLVED_TASKS);
    expect(plan.tasks.some((t) => t.args.srcChain === 'ssrf-cloud-pivot')).toBe(true);
  });
});

describe('CVSS profiles for chain-*', () => {
  it('maps chain-cors-cred-theft to scope-changed + UI:R', () => {
    const m = metricsForFinding({ checkId: 'chain-cors-cred-theft', severity: 'high' });
    expect(m.S).toBe('C');
    expect(m.UI).toBe('R');
    expect(m.C).toBe('H');
  });

  it('maps chain-ssrf-cloud-pivot to scope-changed confidentiality', () => {
    const m = metricsForFinding({ checkId: 'chain-ssrf-cloud-pivot', severity: 'critical' });
    expect(m.S).toBe('C');
    expect(m.C).toBe('H');
    expect(cvssFor({ checkId: 'chain-ssrf-cloud-pivot', severity: 'critical' }).score).toBeGreaterThan(7);
  });

  it('maps chain-debug-to-rce to full CIA high', () => {
    const m = metricsForFinding({ checkId: 'chain-debug-to-rce', severity: 'critical' });
    expect(m.C).toBe('H');
    expect(m.I).toBe('H');
    expect(m.A).toBe('H');
  });
});
