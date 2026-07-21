import { describe, it, expect } from 'vitest';
import { planFollowUpTasks } from '../src/planning/vuln-planner.js';
import { collectCanaryRefreshUrls } from '../src/engine/scanner.js';
import type { ProbeResult, Scope } from '../src/types.js';

const scope: Scope = {
  program: 'acme',
  platform: 'hackerone',
  inScope: ['*.acme.com'],
  outOfScope: [],
  authorized: true,
};

function probe(over: Partial<ProbeResult>): ProbeResult {
  return {
    url: 'https://app.acme.com/api/v1/users',
    method: 'GET',
    status: 200,
    headers: { 'content-type': 'application/json', 'x-powered-by': 'Express' },
    body: '{"ok":true}',
    elapsedMs: 3,
    ...over,
  };
}

describe('planFollowUpTasks expanded classes', () => {
  it('schedules nuclei exposures for weak-jwt / oauth', () => {
    const plan = planFollowUpTasks(
      [
        {
          checkId: 'weak-jwt',
          severity: 'critical',
          target: 'https://app.acme.com/login',
          title: 'alg=none',
        },
      ],
      scope,
      { maxTasks: 10 },
    );
    expect(plan.tasks.some((t) => t.tool === 'nuclei' && /exposures|jwt/i.test(JSON.stringify(t.args)))).toBe(
      true,
    );
    expect(plan.tasks.some((t) => t.tool === 'katana')).toBe(true);
  });

  it('schedules nuclei misconfiguration for cache-deception / host-header', () => {
    const plan = planFollowUpTasks(
      [
        {
          checkId: 'cache-deception',
          severity: 'high',
          target: 'https://app.acme.com/account.css',
          title: 'cache deception',
        },
      ],
      scope,
    );
    expect(
      plan.tasks.some(
        (t) => t.tool === 'nuclei' && /misconfiguration/i.test(JSON.stringify(t.args)),
      ),
    ).toBe(true);
  });

  it('schedules sqlmap for HPP parameterized URLs', () => {
    const plan = planFollowUpTasks(
      [
        {
          checkId: 'http-parameter-pollution',
          severity: 'high',
          target: 'https://app.acme.com/api/users?id=1&id=2',
          title: 'HPP',
        },
      ],
      scope,
    );
    expect(plan.tasks.some((t) => t.tool === 'sqlmap')).toBe(true);
  });

  it('schedules ffuf/httpx for auth-differential', () => {
    const plan = planFollowUpTasks(
      [
        {
          checkId: 'auth-differential',
          severity: 'high',
          target: 'https://app.acme.com/api/v1/users/1',
          title: 'horizontal IDOR',
        },
      ],
      scope,
      { maxTasks: 10 },
    );
    expect(plan.tasks.some((t) => t.tool === 'ffuf' || t.tool === 'httpx')).toBe(true);
  });
});

describe('collectCanaryRefreshUrls', () => {
  it('includes cmd/LFI/CRLF/PP/cache/host canaries not only injection/ssrf', () => {
    const urls = collectCanaryRefreshUrls(
      [
        probe({ url: 'https://app.acme.com/ping', body: 'pong' }),
        probe({ url: 'https://app.acme.com/file', body: 'x' }),
        probe({ url: 'https://app.acme.com/api/v1/users', body: '{}' }),
        probe({
          url: 'https://app.acme.com/account',
          headers: { 'content-type': 'text/html' },
          body: '<html>Welcome, user</html>',
        }),
      ],
      { canaryBase: 'https://sf.example' },
    );
    expect(urls.length).toBeGreaterThan(0);
    // Should pull from multiple collector families.
    const joined = urls.join('\n');
    expect(
      /__proto__|sfPp|sfHpp|etc\/passwd|%0d%0a|X-Forwarded|169\.254|echo|id=|file=|\.css/i.test(joined) ||
        urls.length >= 4,
    ).toBe(true);
  });
});
