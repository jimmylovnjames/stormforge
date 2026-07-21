import { describe, it, expect } from 'vitest';
import {
  LFI_PATHS,
  LFI_PAYLOADS,
  buildPathTraversalProbeUrls,
  hasPathTraversalSuccess,
  shouldProbePathTraversal,
  urlCarriesLfiPayload,
} from '../src/recon/path-traversal-probes.js';
import { pathTraversalCheck } from '../src/detect/checks/path-traversal.js';
import { collectPathTraversalFollowUps } from '../src/engine/scanner.js';
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
    url: 'https://a.x.com/download',
    method: 'GET',
    status: 200,
    headers: { 'content-type': 'text/plain' },
    body: '',
    elapsedMs: 5,
    ...over,
  };
}

describe('path traversal probes', () => {
  it('builds traversal canary URLs for LFI params', () => {
    const urls = buildPathTraversalProbeUrls('https://a.x.com/file', 2);
    expect(urls.length).toBeGreaterThan(0);
    expect(urls.some((u) => urlCarriesLfiPayload(u))).toBe(true);
    expect(LFI_PAYLOADS.some((p) => p.includes('etc/passwd'))).toBe(true);
    expect(LFI_PATHS).toContain('/download');
    expect(LFI_PATHS).toContain('/api/file');
  });

  it('confirms success only with passwd/win.ini markers and traversal URL', () => {
    const url = 'https://a.x.com/file?file=../../../../../../etc/passwd';
    expect(hasPathTraversalSuccess('root:x:0:0:root:/root:/bin/bash', url)).toBe(true);
    expect(hasPathTraversalSuccess('hello world', url)).toBe(false);
    expect(hasPathTraversalSuccess('root:x:0:0:', 'https://a.x.com/')).toBe(false);
  });

  it('shouldProbePathTraversal matches LFI paths and forms', () => {
    expect(shouldProbePathTraversal(probe({ url: 'https://a.x.com/download', status: 200 }))).toBe(true);
    expect(
      shouldProbePathTraversal(
        probe({
          url: 'https://a.x.com/app',
          status: 200,
          headers: { 'content-type': 'text/html' },
          body: '<form><input name="file"></form>',
        }),
      ),
    ).toBe(true);
    expect(shouldProbePathTraversal(probe({ url: 'https://a.x.com/about', status: 200, body: 'ok' }))).toBe(false);
  });
});

describe('pathTraversalCheck', () => {
  it('flags /etc/passwd disclosure as critical', () => {
    const url = 'https://a.x.com/file?file=../../../../../../etc/passwd';
    const findings = pathTraversalCheck.run(
      probe({ url, body: 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:' }),
      ctx,
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('critical');
    expect(findings[0]!.cwe).toBe('CWE-22');
    expect(findings[0]!.checkId).toBe('path-traversal');
  });

  it('ignores non-traversal responses', () => {
    expect(pathTraversalCheck.run(probe({ body: 'root:x:0:0:' }), ctx)).toHaveLength(0);
  });

  it('is registered and drafts impact text', () => {
    expect(listChecks().some((c) => c.id === 'path-traversal')).toBe(true);
    const f: Finding = {
      id: 't1',
      checkId: 'path-traversal',
      title: 'LFI',
      severity: 'critical',
      target: 'https://a.x.com/file?file=../etc/passwd',
      description: 'd',
      evidence: 'e',
      reproduction: ['r'],
      remediation: 'fix',
      cwe: 'CWE-22',
      references: [],
      needsManualReview: false,
      discoveredAt: new Date().toISOString(),
    };
    expect(draftFinding(f, scope)).toMatch(/Path traversal|LFI/i);
  });
});

describe('collectPathTraversalFollowUps', () => {
  it('emits LFI probe URLs for download paths', () => {
    const urls = collectPathTraversalFollowUps([
      probe({ url: 'https://a.x.com/download', status: 200, body: 'ok' }),
    ]);
    expect(urls.length).toBeGreaterThan(0);
    expect(urls.every((u) => urlCarriesLfiPayload(u))).toBe(true);
  });
});
