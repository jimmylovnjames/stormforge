import { describe, it, expect } from 'vitest';
import {
  parseSubdomains,
  rankSubdomains,
  scoreSubdomain,
} from '../src/recon/subdomain-intel.js';
import { planFollowUpTasks } from '../src/planning/vuln-planner.js';
import type { Scope } from '../src/types.js';

const scope: Scope = {
  program: 'acme',
  platform: 'hackerone',
  inScope: ['*.acme.com', 'acme.com'],
  outOfScope: ['blog.acme.com'],
  authorized: true,
};

describe('subdomain intel', () => {
  it('parses hostnames from subfinder-like stdout', () => {
    const hosts = parseSubdomains(
      ['api.acme.com', 'https://staging.acme.com', 'www.acme.com', 'not a host', 'evil.com'].join('\n'),
      'acme.com',
    );
    expect(hosts).toContain('api.acme.com');
    expect(hosts).toContain('staging.acme.com');
    expect(hosts).toContain('www.acme.com');
    expect(hosts).not.toContain('evil.com');
  });

  it('ranks api/staging/admin above www', () => {
    expect(scoreSubdomain('api.acme.com')).toBeGreaterThan(scoreSubdomain('www.acme.com'));
    expect(scoreSubdomain('staging.acme.com')).toBeGreaterThan(scoreSubdomain('www.acme.com'));
    expect(scoreSubdomain('admin.acme.com')).toBeGreaterThan(scoreSubdomain('cdn.acme.com'));
    const ranked = rankSubdomains(
      ['www.acme.com', 'api.acme.com', 'staging.acme.com', 'cdn.acme.com'],
      3,
    );
    expect(ranked[0]).toBe('api.acme.com');
    expect(ranked).toContain('staging.acme.com');
    expect(ranked).not.toContain('cdn.acme.com');
  });
});

describe('planFollowUpTasks subdomain enum', () => {
  it('schedules httpx + takeover nuclei for top ranked hosts from evidence', () => {
    const plan = planFollowUpTasks(
      [
        {
          checkId: 'subfinder-enumeration',
          severity: 'info',
          target: 'acme.com',
          title: 'subfinder',
          evidence: 'www.acme.com\napi.acme.com\nstaging.acme.com\nblog.acme.com\n',
        },
      ],
      scope,
      { maxTasks: 10 },
    );
    expect(plan.tasks.some((t) => t.tool === 'httpx' && t.target.includes('api.acme.com'))).toBe(
      true,
    );
    expect(plan.tasks.some((t) => t.tool === 'nuclei' && /takeover/i.test(JSON.stringify(t.args)))).toBe(
      true,
    );
    expect(plan.tasks.every((t) => !t.target.includes('blog.acme.com'))).toBe(true);
  });
});
