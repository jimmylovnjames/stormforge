import { describe, it, expect } from 'vitest';
import {
  buildSourcemapFollowUpUrls,
  extractSourceMappingUrls,
  hasSourcesContent,
  isSourceMapJson,
  shouldProbeSourcemap,
} from '../src/recon/sourcemap-probes.js';
import { sourcemapCheck } from '../src/detect/checks/sourcemap.js';
import { collectSourcemapFollowUps } from '../src/engine/scanner.js';
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
    url: 'https://a.x.com/static/app.js',
    method: 'GET',
    status: 200,
    headers: { 'content-type': 'application/javascript' },
    body: '',
    elapsedMs: 4,
    ...over,
  };
}

describe('sourcemap probes', () => {
  it('extracts relative and absolute sourceMappingURL comments', () => {
    const urls = extractSourceMappingUrls(
      `console.log(1);\n//# sourceMappingURL=app.js.map\n//@ sourceMappingURL=https://a.x.com/maps/app.js.map\n`,
      'https://a.x.com/static/app.js',
    );
    expect(urls).toContain('https://a.x.com/static/app.js.map');
    expect(urls).toContain('https://a.x.com/maps/app.js.map');
  });

  it('ignores data: source maps', () => {
    const urls = extractSourceMappingUrls(
      '//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbXX0=',
      'https://a.x.com/static/app.js',
    );
    expect(urls).toHaveLength(0);
  });

  it('confirms source map JSON and sourcesContent', () => {
    const map = JSON.stringify({
      version: 3,
      sources: ['webpack:///src/app.ts'],
      mappings: 'AAAA',
      sourcesContent: ['const SECRET = "not-a-real-secret";'],
    });
    expect(isSourceMapJson(map)).toBe(true);
    expect(hasSourcesContent(map)).toBe(true);
    expect(isSourceMapJson('{"hello":1}')).toBe(false);
  });

  it('shouldProbeSourcemap matches JS responses', () => {
    expect(shouldProbeSourcemap(probe({ body: 'var x=1;' }))).toBe(true);
    expect(
      shouldProbeSourcemap(
        probe({
          url: 'https://a.x.com/',
          headers: { 'content-type': 'text/html' },
          body: '<html></html>',
        }),
      ),
    ).toBe(false);
  });

  it('buildSourcemapFollowUpUrls resolves same-origin maps', () => {
    const urls = buildSourcemapFollowUpUrls(
      probe({
        body: '//# sourceMappingURL=../maps/app.js.map\n',
      }),
    );
    expect(urls.some((u) => u.endsWith('/maps/app.js.map'))).toBe(true);
  });
});

describe('sourcemapCheck', () => {
  it('flags JS responses that advertise a sourceMappingURL', () => {
    const f = sourcemapCheck.run(
      probe({
        body: '/*! app */\nconsole.log(1);\n//# sourceMappingURL=app.js.map\n',
      }),
      ctx,
    );
    expect(f.some((x) => /source.?map/i.test(x.title))).toBe(true);
    expect(f[0]!.severity).toMatch(/info|low|medium/);
  });

  it('elevates severity when .map includes sourcesContent', () => {
    const body = JSON.stringify({
      version: 3,
      file: 'app.js',
      sources: ['src/config.ts'],
      mappings: 'AAAA',
      sourcesContent: ['export const apiKey = "AKIA_FAKE_FOR_TEST_ONLY";'],
    });
    const f = sourcemapCheck.run(
      probe({
        url: 'https://a.x.com/static/app.js.map',
        headers: { 'content-type': 'application/json' },
        body,
      }),
      ctx,
    );
    expect(f.some((x) => x.severity === 'medium' || x.severity === 'high')).toBe(true);
    expect(f[0]!.checkId).toBe('sourcemap-exposure');
  });

  it('ignores unrelated JSON', () => {
    const f = sourcemapCheck.run(
      probe({
        url: 'https://a.x.com/api/config',
        headers: { 'content-type': 'application/json' },
        body: '{"version":1,"ok":true}',
      }),
      ctx,
    );
    expect(f).toHaveLength(0);
  });

  it('is registered', () => {
    expect(listChecks().some((c) => c.id === 'sourcemap-exposure')).toBe(true);
  });
});

describe('collectSourcemapFollowUps + planner', () => {
  it('collects map URLs from JS probes', () => {
    const urls = collectSourcemapFollowUps([
      probe({ body: '//# sourceMappingURL=app.js.map\n' }),
    ]);
    expect(urls.some((u) => u.endsWith('.map'))).toBe(true);
  });

  it('planPathsFromFindings expands sourcemap hits', () => {
    const finding: Finding = {
      id: '1',
      checkId: 'sourcemap-exposure',
      title: 'Source map exposed',
      severity: 'medium',
      target: 'https://a.x.com/static/app.js.map',
      description: 'd',
      evidence: '',
      reproduction: [],
      remediation: '',
      references: [],
      needsManualReview: true,
      discoveredAt: new Date().toISOString(),
    };
    const plan = planPathsFromFindings([finding]);
    expect(plan.suggestedPaths.some((p) => /\.map$|static|js/i.test(p))).toBe(true);
  });
});
