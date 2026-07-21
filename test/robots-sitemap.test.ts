import { describe, it, expect } from 'vitest';
import {
  extractRobotsPaths,
  extractSitemapLocPaths,
  isSensitiveRobotsPath,
} from '../src/recon/robots-sitemap.js';
import { harvestPathsFromProbe } from '../src/recon/url-harvest.js';
import { robotsDisclosureCheck } from '../src/detect/checks/robots-disclosure.js';
import { listChecks } from '../src/detect/registry.js';
import { planPathsFromFindings } from '../src/planning/llm-planner.js';
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
    url: 'https://a.x.com/robots.txt',
    method: 'GET',
    status: 200,
    headers: { 'content-type': 'text/plain' },
    body: '',
    elapsedMs: 3,
    ...over,
  };
}

describe('robots / sitemap harvest', () => {
  it('extracts Disallow paths from robots.txt', () => {
    const body = `
User-agent: *
Disallow: /admin
Disallow: /.env
Allow: /public
# Disallow: /commented
Disallow: /backup/
`;
    const paths = extractRobotsPaths(body);
    expect(paths).toContain('/admin');
    expect(paths).toContain('/.env');
    expect(paths).toContain('/backup/');
    expect(paths).not.toContain('/commented');
    expect(paths).not.toContain('/public');
  });

  it('extracts same-origin sitemap <loc> pathnames', () => {
    const body = `<?xml version="1.0"?>
<urlset>
  <url><loc>https://a.x.com/api/v1/secret</loc></url>
  <url><loc>https://a.x.com/admin/users</loc></url>
  <url><loc>https://evil.com/out</loc></url>
  <url><loc>/relative/path</loc></url>
</urlset>`;
    const paths = extractSitemapLocPaths(body, 'https://a.x.com/sitemap.xml');
    expect(paths).toContain('/api/v1/secret');
    expect(paths).toContain('/admin/users');
    expect(paths).toContain('/relative/path');
    expect(paths.every((p) => !p.includes('evil.com'))).toBe(true);
  });

  it('harvestPathsFromProbe pulls robots and sitemap paths', () => {
    const robots = harvestPathsFromProbe(
      probe({
        body: 'User-agent: *\nDisallow: /internal/admin\nDisallow: /.git/\n',
      }),
    );
    expect(robots).toContain('/internal/admin');
    expect(robots).toContain('/.git/');

    const sitemap = harvestPathsFromProbe(
      probe({
        url: 'https://a.x.com/sitemap.xml',
        headers: { 'content-type': 'application/xml' },
        body: '<urlset><url><loc>https://a.x.com/api/v1/billing</loc></url></urlset>',
      }),
    );
    expect(sitemap).toContain('/api/v1/billing');
  });

  it('flags sensitive Disallow entries via robotsDisclosureCheck', () => {
    expect(isSensitiveRobotsPath('/.env')).toBe(true);
    expect(isSensitiveRobotsPath('/about')).toBe(false);
    expect(listChecks().some((c) => c.id === 'robots-disclosure')).toBe(true);

    const f = robotsDisclosureCheck.run(
      probe({
        body: 'User-agent: *\nDisallow: /admin\nDisallow: /.git/config\nDisallow: /backup.zip\n',
      }),
      ctx,
    );
    expect(f.length).toBeGreaterThan(0);
    expect(f[0]!.checkId).toBe('robots-disclosure');
    expect(f[0]!.severity).toMatch(/info|low/);
    expect(f[0]!.evidence).toMatch(/\.git|admin|backup/i);
  });

  it('planPathsFromFindings expands robots disclosure', () => {
    const finding: Finding = {
      id: '1',
      checkId: 'robots-disclosure',
      title: 'robots.txt discloses sensitive paths',
      severity: 'low',
      target: 'https://a.x.com/robots.txt',
      description: 'd',
      evidence: 'paths: /admin, /.env, /backup/',
      reproduction: [],
      remediation: '',
      references: [],
      needsManualReview: true,
      discoveredAt: new Date().toISOString(),
    };
    const plan = planPathsFromFindings([finding]);
    expect(plan.suggestedPaths).toContain('/admin');
    expect(plan.suggestedPaths).toContain('/.env');
  });
});
