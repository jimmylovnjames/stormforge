import { describe, it, expect } from 'vitest';
import {
  buildWorkerRescanRequest,
  extractCrawlUrls,
  selectRescanTargets,
} from '../src/planning/worker-rescan.js';
import type { Scope, ToolName } from '../src/types.js';

const scope: Scope = {
  program: 'acme',
  platform: 'hackerone',
  inScope: ['*.acme.com', 'acme.com'],
  outOfScope: ['blog.acme.com'],
  authorized: true,
};

describe('extractCrawlUrls', () => {
  it('extracts http(s) URLs from katana stdout including non-param paths', () => {
    const stdout = [
      'https://app.acme.com/api/v1/users',
      'https://app.acme.com/search?q=test',
      'https://evil.out-of-scope.net/x',
      'not a url',
    ].join('\n');
    const urls = extractCrawlUrls('katana', stdout, 25);
    expect(urls).toContain('https://app.acme.com/api/v1/users');
    expect(urls).toContain('https://app.acme.com/search?q=test');
    expect(urls.some((u) => u.includes('evil.out-of-scope.net'))).toBe(true); // filter later
  });

  it('extracts URLs from ffuf-style lines', () => {
    const stdout = '[Status: 200, Size: 12] https://app.acme.com/admin\n';
    expect(extractCrawlUrls('ffuf', stdout)).toContain('https://app.acme.com/admin');
  });

  it('returns empty for unrelated tools', () => {
    expect(extractCrawlUrls('nmap' as ToolName, 'https://app.acme.com/')).toEqual([]);
  });
});

describe('selectRescanTargets', () => {
  it('scope-filters, prefers parameterized URLs, and caps', () => {
    const selected = selectRescanTargets(
      [
        'https://app.acme.com/search?q=1',
        'https://app.acme.com/api/v1/me',
        'https://blog.acme.com/post',
        'https://evil.net/',
        'https://app.acme.com/search?q=1',
      ],
      scope,
      10,
    );
    expect(selected.targets[0]).toContain('search?q=1');
    expect(selected.targets).toContain('https://app.acme.com/api/v1/me');
    expect(selected.targets.every((t) => !t.includes('blog.acme.com'))).toBe(true);
    expect(selected.targets.every((t) => !t.includes('evil.net'))).toBe(true);
    expect(new Set(selected.targets).size).toBe(selected.targets.length);
  });
});

describe('buildWorkerRescanRequest', () => {
  it('builds an authorized ScanRequest with parentScanId and canary', () => {
    const req = buildWorkerRescanRequest(scope, ['https://app.acme.com/api/v1/me'], {
      parentScanId: 'parent-1',
      canaryBaseUrl: 'https://sf.workers.dev',
      sourceTool: 'katana',
    });
    expect(req.scope.authorized).toBe(true);
    expect(req.targets).toEqual(['https://app.acme.com/api/v1/me']);
    expect(req.parentScanId).toBe('parent-1');
    expect(req.canaryBaseUrl).toBe('https://sf.workers.dev');
    expect(req.sourceTool).toBe('katana');
  });
});
