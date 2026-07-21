import { describe, it, expect } from 'vitest';
import { debugDisclosureCheck } from '../src/detect/checks/debug-disclosure.js';
import { corsCheck, corsBypassOriginFor, PROBE_ORIGIN } from '../src/detect/checks/cors.js';
import { collectCorsBypassFollowUps } from '../src/engine/scanner.js';
import { listChecks } from '../src/detect/registry.js';
import type { CheckContext, ProbeResult, Scope } from '../src/types.js';

const scope: Scope = {
  program: 'p',
  platform: 'hackerone',
  inScope: ['*.acme.com'],
  outOfScope: [],
  authorized: true,
};
const ctx: CheckContext = { scope };

function probe(over: Partial<ProbeResult>): ProbeResult {
  return {
    url: 'https://api.acme.com/v1',
    method: 'GET',
    status: 500,
    headers: { 'content-type': 'text/html' },
    body: '',
    elapsedMs: 5,
    ...over,
  };
}

describe('debugDisclosureCheck', () => {
  it('flags stack traces with path disclosure as medium', () => {
    const findings = debugDisclosureCheck.run(
      probe({
        body: 'Traceback (most recent call last):\n  File "/var/www/app/views.py", line 12',
      }),
      ctx,
    );
    expect(findings.some((f) => f.severity === 'medium')).toBe(true);
    expect(findings[0]!.cwe).toBe('CWE-209');
  });

  it('flags phpinfo / actuator env as high', () => {
    const findings = debugDisclosureCheck.run(
      probe({
        url: 'https://api.acme.com/actuator/env',
        status: 200,
        body: 'phpinfo() PHP Version 8.2',
      }),
      ctx,
    );
    expect(findings.some((f) => f.severity === 'high')).toBe(true);
  });

  it('is registered', () => {
    expect(listChecks().some((c) => c.id === 'debug-error-disclosure')).toBe(true);
  });
});

describe('CORS subdomain-trust bypass', () => {
  it('builds bypass origin under registrable domain', () => {
    expect(corsBypassOriginFor('https://api.acme.com/x')).toBe('https://stormforge-cors.acme.com');
  });

  it('flags reflection of bypass origin with credentials as high', () => {
    const origin = corsBypassOriginFor('https://api.acme.com/')!;
    const findings = corsCheck.run(
      probe({
        status: 200,
        headers: {
          'access-control-allow-origin': origin,
          'access-control-allow-credentials': 'true',
        },
      }),
      ctx,
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('high');
    expect(findings[0]!.evidence).toContain(origin);
  });

  it('still flags arbitrary PROBE_ORIGIN reflection', () => {
    const findings = corsCheck.run(
      probe({
        status: 200,
        headers: {
          'access-control-allow-origin': PROBE_ORIGIN,
          'access-control-allow-credentials': 'true',
        },
      }),
      ctx,
    );
    expect(findings[0]!.severity).toBe('high');
  });

  it('collectCorsBypassFollowUps emits crafted origins', () => {
    const items = collectCorsBypassFollowUps([
      probe({ url: 'https://api.acme.com/data', status: 200, body: '{}' }),
    ]);
    expect(items.length).toBeGreaterThan(0);
    expect(items[0]!.origin).toBe('https://stormforge-cors.acme.com');
  });
});
