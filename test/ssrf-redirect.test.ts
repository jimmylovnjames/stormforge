import { describe, it, expect } from 'vitest';
import {
  REDIRECT_CANARY_HOST,
  REDIRECT_CANARY_URL,
  REDIRECT_SSRF_PATHS,
  SSRF_METADATA_TARGETS,
  buildSsrfRedirectProbeUrls,
  detectCloudMetadataExposure,
  hasOpenRedirectToCanary,
  hasSsrfFetchSignal,
  shouldProbeSsrfRedirect,
  urlCarriesRedirectCanary,
} from '../src/recon/ssrf-probes.js';
import { ssrfRedirectCheck } from '../src/detect/checks/ssrf-redirect.js';
import { collectSsrfRedirectFollowUps } from '../src/engine/scanner.js';
import { listChecks } from '../src/detect/registry.js';
import { draftFinding } from '../src/report/drafter.js';
import type { Finding, ProbeResult, Scope, CheckContext } from '../src/types.js';

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
    url: 'https://a.x.com/redirect',
    method: 'GET',
    status: 302,
    headers: {},
    body: '',
    elapsedMs: 4,
    ...over,
  };
}

describe('ssrf/redirect probe helpers', () => {
  it('builds open-redirect and metadata canary URLs', () => {
    const built = buildSsrfRedirectProbeUrls('https://a.x.com/redirect', 2);
    expect(built.openRedirect.length).toBeGreaterThan(0);
    expect(built.metadata.length).toBeGreaterThan(0);
    expect(urlCarriesRedirectCanary(built.openRedirect[0])).toBe(true);
    expect(built.metadata.some((u) => u.includes('169.254.169.254'))).toBe(true);
    expect(SSRF_METADATA_TARGETS[0]).toContain('169.254.169.254');
  });

  it('detects open redirect to canary via Location', () => {
    const url = `https://a.x.com/redirect?url=${encodeURIComponent(REDIRECT_CANARY_URL)}`;
    expect(
      hasOpenRedirectToCanary(
        probe({
          url,
          status: 302,
          headers: { location: REDIRECT_CANARY_URL },
        }),
      ),
    ).toBe(true);
  });

  it('detects AWS/GCP/Azure metadata body signatures', () => {
    expect(
      detectCloudMetadataExposure('ami-id\nami-0abc\ninstance-id\ni-0123456789abcdef0\n'),
    ).toBe('aws');
    expect(
      detectCloudMetadataExposure('{"AccessKeyId":"ASIAEXAMPLEKEY00000","SecretAccessKey":"xxx","Token":"y"}'),
    ).toBe('aws');
    expect(
      detectCloudMetadataExposure('{"projectId":"demo","numericProjectId":123}'),
    ).toBe('gcp');
    expect(
      detectCloudMetadataExposure('{"compute":{"azEnvironment":"AzurePublicCloud","vmId":"x"}}'),
    ).toBe('azure');
  });

  it('shouldProbeSsrfRedirect matches redirect paths and forms', () => {
    expect(shouldProbeSsrfRedirect(probe({ url: 'https://a.x.com/proxy', status: 200 }))).toBe(true);
    expect(
      shouldProbeSsrfRedirect(
        probe({
          url: 'https://a.x.com/app',
          status: 200,
          headers: { 'content-type': 'text/html' },
          body: '<form><input name="redirect"></form>',
        }),
      ),
    ).toBe(true);
    expect(REDIRECT_SSRF_PATHS).toContain('/redirect');
    expect(REDIRECT_SSRF_PATHS).toContain('/api/fetch');
  });

  it('detects SSRF fetch error signals after metadata canary', () => {
    const url = `https://a.x.com/fetch?url=${encodeURIComponent('http://169.254.169.254/latest/meta-data/')}`;
    expect(hasSsrfFetchSignal('Error: connect() failed to 169.254.169.254', url)).toBe(true);
    expect(hasSsrfFetchSignal('ok', 'https://a.x.com/')).toBe(false);
  });
});

describe('ssrfRedirectCheck', () => {
  it('flags open redirect as high', () => {
    const url = `https://a.x.com/redirect?url=${encodeURIComponent(REDIRECT_CANARY_URL)}`;
    const f = ssrfRedirectCheck.run(
      probe({
        url,
        status: 302,
        headers: { location: `https://${REDIRECT_CANARY_HOST}/x` },
      }),
      ctx,
    );
    expect(f.some((x) => x.title.includes('Open redirect'))).toBe(true);
    expect(f.find((x) => x.title.includes('Open redirect'))!.severity).toBe('high');
    expect(f.find((x) => x.title.includes('Open redirect'))!.cwe).toBe('CWE-601');
    expect(f.find((x) => x.title.includes('Open redirect'))!.needsManualReview).toBe(false);
  });

  it('flags AWS metadata credentials as critical', () => {
    const url = `https://a.x.com/proxy?url=${encodeURIComponent('http://169.254.169.254/latest/meta-data/iam/security-credentials/role')}`;
    const f = ssrfRedirectCheck.run(
      probe({
        url,
        status: 200,
        headers: { 'content-type': 'application/json' },
        body: '{"Code":"Success","AccessKeyId":"ASIAEXAMPLEKEY00000","SecretAccessKey":"aaaa","Token":"bbbb"}',
      }),
      ctx,
    );
    expect(f.some((x) => x.severity === 'critical' && x.title.includes('metadata'))).toBe(true);
    expect(f.find((x) => x.severity === 'critical')!.cwe).toBe('CWE-918');
  });

  it('flags SSRF fetch signals as high with manual review', () => {
    const url = `https://a.x.com/fetch?url=${encodeURIComponent('http://127.0.0.1/')}`;
    const f = ssrfRedirectCheck.run(
      probe({
        url,
        status: 500,
        headers: { 'content-type': 'text/plain' },
        body: 'requests.exceptions.ConnectionError: ECONNREFUSED 127.0.0.1',
      }),
      ctx,
    );
    // status 500 - check doesn't require 2xx for SSRF signals
    expect(f.some((x) => x.title.includes('Possible SSRF'))).toBe(true);
    expect(f.find((x) => x.title.includes('Possible SSRF'))!.severity).toBe('high');
  });

  it('flags Location reflection of external param URL', () => {
    const dest = 'https://evil.example/phish';
    const f = ssrfRedirectCheck.run(
      probe({
        url: `https://a.x.com/login?next=${encodeURIComponent(dest)}`,
        status: 302,
        headers: { location: dest },
      }),
      ctx,
    );
    expect(f.some((x) => x.title.includes('Location header'))).toBe(true);
  });

  it('is registered', () => {
    expect(listChecks().some((c) => c.id === 'ssrf-open-redirect')).toBe(true);
  });
});

describe('collectSsrfRedirectFollowUps + report', () => {
  it('emits redirect and ssrf follow-up URLs', () => {
    const items = collectSsrfRedirectFollowUps([
      probe({ url: 'https://a.x.com/redirect', status: 200, headers: { 'content-type': 'text/html' }, body: '<a>x</a>' }),
    ]);
    expect(items.some((i) => i.mode === 'redirect')).toBe(true);
    expect(items.some((i) => i.mode === 'ssrf')).toBe(true);
    expect(items.some((i) => i.url.includes(REDIRECT_CANARY_HOST) || decodeURIComponent(i.url).includes(REDIRECT_CANARY_HOST))).toBe(
      true,
    );
  });

  it('drafts CWE-918 and CWE-601 impact text', () => {
    const ssrf: Finding = {
      id: '1',
      checkId: 'ssrf-open-redirect',
      title: 'SSRF',
      severity: 'critical',
      target: 'https://a.x.com/proxy',
      description: 'd',
      evidence: 'e',
      reproduction: ['r'],
      remediation: 'fix',
      cwe: 'CWE-918',
      references: [],
      needsManualReview: false,
      discoveredAt: new Date().toISOString(),
    };
    const redir: Finding = { ...ssrf, id: '2', cwe: 'CWE-601', title: 'Open redirect', severity: 'high' };
    expect(draftFinding(ssrf, scope)).toContain('request forgery');
    expect(draftFinding(redir, scope)).toContain('Open redirects');
  });
});
