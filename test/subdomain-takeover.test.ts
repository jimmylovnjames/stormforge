import { describe, it, expect } from 'vitest';
import {
  DOH_ENDPOINT,
  isTakeoverCandidate,
  matchTakeoverFingerprint,
  parseDohResponse,
} from '../src/recon/takeover.js';
import { subdomainTakeoverCheck } from '../src/detect/checks/subdomain-takeover.js';
import { listChecks } from '../src/detect/registry.js';
import { draftFinding } from '../src/report/drafter.js';
import { planFollowUpTasks } from '../src/planning/vuln-planner.js';
import type { CheckContext, Finding, ProbeResult, Scope } from '../src/types.js';

const scope: Scope = {
  program: 'p',
  platform: 'hackerone',
  inScope: ['*.x.com'],
  outOfScope: [],
  authorized: true,
};
const ctx: CheckContext = { scope };

function dnsProbe(lookup: unknown): ProbeResult {
  return {
    url: 'https://blog.x.com/',
    method: 'GET',
    status: 200,
    headers: { 'x-stormforge-dns': 'takeover-lookup', 'content-type': 'application/json' },
    body: JSON.stringify(lookup),
    elapsedMs: 5,
  };
}

describe('takeover helpers', () => {
  it('matches known dangling CNAME services', () => {
    expect(matchTakeoverFingerprint('unowned.github.io.')?.service).toBe('GitHub Pages');
    expect(matchTakeoverFingerprint('x.s3-website-us-east-1.amazonaws.com')?.severity).toBe('critical');
    expect(matchTakeoverFingerprint('cdn.cloudflare.com')).toBeNull();
  });

  it('parses DoH JSON and flags NXDOMAIN + dangling CNAME', () => {
    const lookup = parseDohResponse('blog.x.com', {
      Status: 3,
      Answer: [{ type: 5, data: 'dead.github.io.' }],
    });
    expect(lookup.nxdomain).toBe(true);
    expect(lookup.cname).toBe('dead.github.io.');
    const hit = isTakeoverCandidate(lookup);
    expect(hit?.service).toBe('GitHub Pages');
    expect(DOH_ENDPOINT).toContain('cloudflare-dns.com');
  });

  it('does not flag when A records exist', () => {
    const lookup = parseDohResponse('blog.x.com', {
      Status: 0,
      Answer: [
        { type: 5, data: 'alive.github.io.' },
        { type: 1, data: '1.2.3.4' },
      ],
    });
    expect(isTakeoverCandidate(lookup)).toBeNull();
  });
});

describe('subdomainTakeoverCheck', () => {
  it('emits high finding for dangling GitHub Pages CNAME', () => {
    const findings = subdomainTakeoverCheck.run(
      dnsProbe({
        host: 'blog.x.com',
        cname: 'dead.github.io',
        aRecords: [],
        nxdomain: true,
      }),
      ctx,
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('high');
    expect(findings[0]!.checkId).toBe('subdomain-takeover');
    expect(findings[0]!.needsManualReview).toBe(true);
  });

  it('ignores normal probes without DNS tag', () => {
    expect(
      subdomainTakeoverCheck.run(
        {
          url: 'https://blog.x.com/',
          method: 'GET',
          status: 200,
          headers: {},
          body: 'ok',
          elapsedMs: 1,
        },
        ctx,
      ),
    ).toHaveLength(0);
  });

  it('is registered and drafts impact', () => {
    expect(listChecks().some((c) => c.id === 'subdomain-takeover')).toBe(true);
    const f: Finding = {
      id: 't1',
      checkId: 'subdomain-takeover',
      title: 'takeover',
      severity: 'high',
      target: 'https://blog.x.com/',
      description: 'd',
      evidence: 'e',
      reproduction: ['r'],
      remediation: 'fix',
      cwe: 'CWE-284',
      references: [],
      needsManualReview: true,
      discoveredAt: new Date().toISOString(),
    };
    expect(draftFinding(f, scope)).toMatch(/dangling DNS|subdomain/i);
  });
});

describe('autonomy for takeover', () => {
  it('schedules nuclei takeover templates', () => {
    const plan = planFollowUpTasks(
      [
        {
          checkId: 'subdomain-takeover',
          severity: 'high',
          target: 'https://blog.x.com/',
          title: 'takeover',
        },
      ],
      scope,
    );
    expect(plan.tasks.some((t) => t.tool === 'nuclei' && String(t.args.templates).includes('takeover'))).toBe(
      true,
    );
  });
});
