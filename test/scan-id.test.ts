import { describe, it, expect } from 'vitest';
import { runScan } from '../src/engine/scanner.js';
import type { Env, ScanRequest } from '../src/types.js';
import { memoryKv } from './helpers/memory-kv.js';

describe('runScan scanId stability', () => {
  it('preserves caller-provided scanId on the report', async () => {
    const prev = globalThis.fetch;
    globalThis.fetch = (async () =>
      new Response('', {
        status: 404,
        headers: { 'content-type': 'text/plain' },
      })) as typeof fetch;

    try {
      const req: ScanRequest = {
        scanId: 'operator-scan-fixed-id',
        scope: {
          program: 'lab',
          platform: 'generic',
          inScope: ['example.com'],
          outOfScope: [],
          authorized: true,
        },
        targets: ['https://example.com'],
        extraPaths: ['/'],
      };
      const env = {
        STORMFORGE_KV: memoryKv(),
        MAX_RPS: '50',
        MAX_CONCURRENCY: '4',
        SCAN_MODE: 'passive',
        LLM_PLANNER_ENDPOINT: '',
        LLM_PLANNER_MODEL: '',
        SCAN_ORCHESTRATOR: {} as Env['SCAN_ORCHESTRATOR'],
      } as Env;

      const report = await runScan(req, env);
      expect(report.scanId).toBe('operator-scan-fixed-id');
    } finally {
      globalThis.fetch = prev;
    }
  });
});
