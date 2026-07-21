import { describe, it, expect } from 'vitest';
import { handleOrchestrateMessage } from '../src/orchestrate/handler.js';
import { memoryKv } from './helpers/memory-kv.js';
import type { Env } from '../src/types.js';

function testEnv(overrides: Partial<Env> = {}): Env {
  return {
    SCAN_ORCHESTRATOR: {
      idFromName: (name: string) => ({ name }),
      get: () => ({
        fetch: async () =>
          new Response(JSON.stringify({ status: 'running', findingsCount: 0 }), {
            headers: { 'content-type': 'application/json' },
          }),
      }),
    } as unknown as Env['SCAN_ORCHESTRATOR'],
    STORMFORGE_KV: memoryKv(),
    MAX_RPS: '5',
    MAX_CONCURRENCY: '3',
    SCAN_MODE: 'passive',
    LLM_PLANNER_ENDPOINT: '',
    LLM_PLANNER_MODEL: '',
    ALLOW_INSECURE_EXECUTOR: 'true',
    ...overrides,
  };
}

describe('handleOrchestrateMessage', () => {
  it('returns help text', async () => {
    const r = await handleOrchestrateMessage(testEnv(), 'help', {
      baseUrl: 'https://sf.example',
    });
    expect(r.ok).toBe(true);
    expect(r.text).toMatch(/authorized/i);
    expect(r.text).toContain('/api/orchestrate');
  });

  it('refuses plan without authorized', async () => {
    const r = await handleOrchestrateMessage(testEnv(), 'plan https://httpbin.org');
    expect(r.ok).toBe(false);
    expect(r.text).toMatch(/authorized/i);
  });

  it('dispatches tool when authorized + in scope', async () => {
    const env = testEnv();
    const r = await handleOrchestrateMessage(
      env,
      'dispatch httpx https://httpbin.org authorized program=lab inScope=httpbin.org',
    );
    expect(r.ok).toBe(true);
    expect(r.text).toMatch(/Queued httpx/i);
    expect((r.data as { scanId: string }).scanId).toBeTruthy();
  });

  it('lists empty findings for program', async () => {
    const r = await handleOrchestrateMessage(testEnv(), 'findings lab-x');
    expect(r.ok).toBe(true);
    expect(r.text).toMatch(/No findings/i);
  });

  it('returns audit when empty', async () => {
    const r = await handleOrchestrateMessage(testEnv(), 'audit');
    expect(r.ok).toBe(true);
    expect(r.text).toMatch(/No audit|audit/i);
  });
});
