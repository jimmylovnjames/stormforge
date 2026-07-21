import { describe, it, expect } from 'vitest';
import {
  CACHE_POISON_CANARY_PREFIX,
  CACHE_POISON_HEADERS,
  buildCachePoisonVariants,
  shouldProbeCachePoison,
  urlCarriesCachePoisonCanary,
} from '../src/recon/cache-poison-probes.js';
import { cachePoisoningCheck } from '../src/detect/checks/cache-poisoning.js';
import { collectCachePoisonFollowUps } from '../src/engine/scanner.js';
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
    url: 'https://a.x.com/',
    method: 'GET',
    status: 200,
    headers: {
      'content-type': 'text/html',
      'cache-control': 'public, max-age=60',
      'x-cache': 'HIT',
    },
    body: '<html>ok</html>',
    elapsedMs: 5,
    ...over,
  };
}

describe('cache poison probes', () => {
  it('builds unkeyed-header poison variants with unique canary', () => {
    const variants = buildCachePoisonVariants('https://a.x.com/');
    expect(variants.length).toBeGreaterThanOrEqual(2);
    expect(CACHE_POISON_HEADERS.length).toBeGreaterThan(0);
    expect(variants.every((v) => v.poisonHeaders && Object.keys(v.poisonHeaders).length > 0)).toBe(
      true,
    );
    expect(variants.every((v) => urlCarriesCachePoisonCanary(v.canary))).toBe(true);
    expect(variants[0]!.canary.startsWith(CACHE_POISON_CANARY_PREFIX)).toBe(true);
  });

  it('shouldProbeCachePoison prefers cacheable HTML/API roots', () => {
    expect(shouldProbeCachePoison(probe({}))).toBe(true);
    expect(
      shouldProbeCachePoison(
        probe({
          headers: { 'cache-control': 'no-store', 'content-type': 'text/html' },
        }),
      ),
    ).toBe(false);
  });
});

describe('cachePoisoningCheck', () => {
  it('flags when clean response contains poison canary and is cacheable', () => {
    const canary = `${CACHE_POISON_CANARY_PREFIX}abc123`;
    const poison = probe({
      url: 'https://a.x.com/',
      headers: {
        'content-type': 'text/html',
        'cache-control': 'public, max-age=120',
        'x-cache': 'MISS',
        'x-stormforge-poison': canary,
      },
      body: `<html><a href="https://${canary}/">x</a></html>`,
    });
    const clean = probe({
      url: 'https://a.x.com/',
      headers: {
        'content-type': 'text/html',
        'cache-control': 'public, max-age=120',
        'x-cache': 'HIT',
        age: '5',
      },
      body: `<html><a href="https://${canary}/">cached</a></html>`,
    });
    const findings = cachePoisoningCheck.run(clean, {
      ...ctx,
      siblings: [poison, clean],
    });
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.checkId).toBe('cache-poisoning');
    expect(findings[0]!.severity).toBe('high');
    expect(findings[0]!.cwe).toBe('CWE-444');
  });

  it('is registered and drafts impact', () => {
    expect(listChecks().some((c) => c.id === 'cache-poisoning')).toBe(true);
    const f: Finding = {
      id: '1',
      checkId: 'cache-poisoning',
      title: 'Cache poison',
      severity: 'high',
      target: 'https://a.x.com/',
      description: 'd',
      evidence: 'e',
      reproduction: ['r'],
      remediation: 'fix',
      cwe: 'CWE-444',
      references: [],
      needsManualReview: true,
      discoveredAt: new Date().toISOString(),
    };
    expect(draftFinding(f, scope)).toMatch(/cache poison/i);
  });
});

describe('collectCachePoisonFollowUps', () => {
  it('emits poison variants for cacheable roots', () => {
    const items = collectCachePoisonFollowUps([probe({})]);
    expect(items.length).toBeGreaterThan(0);
    expect(items[0]!.poisonHeaders).toBeTruthy();
  });
});
