import { describe, it, expect } from 'vitest';
import { handleOrchestrateMessage } from '../src/orchestrate/handler.js';
import { memoryKv } from './helpers/memory-kv.js';
import type { Env, ToolTask } from '../src/types.js';
import { enqueueTasks } from '../src/tasks/queue.js';

function testEnv(overrides: Partial<Env> = {}): Env {
  return {
    SCAN_ORCHESTRATOR: {
      idFromName: (name: string) => ({ name }),
      get: () => ({
        fetch: async (url: string, init?: RequestInit) => {
          if (String(url).endsWith('/start') && init?.method === 'POST') {
            const body = JSON.parse(String(init.body || '{}')) as { scanId?: string };
            return new Response(JSON.stringify({ status: 'running', scanId: body.scanId }), {
              headers: { 'content-type': 'application/json' },
            });
          }
          return new Response(
            JSON.stringify({
              scanId: 'scan-live',
              status: 'done',
              phase: 'complete',
              probed: 12,
              total: 12,
              findings: 3,
              executorTasksEnqueued: 2,
              startedAt: '2026-01-01T00:00:00.000Z',
            }),
            { headers: { 'content-type': 'application/json' } },
          );
        },
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
    expect(r.text).toMatch(/executor queue/i);
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

  it('formats passive status with findings + hybrid hint', async () => {
    const r = await handleOrchestrateMessage(testEnv(), 'status scan-live');
    expect(r.ok).toBe(true);
    expect(r.text).toMatch(/status=done/);
    expect(r.text).toMatch(/findings=3/);
    expect(r.text).toMatch(/hybridTasksEnqueued=2/);
    expect(r.text).not.toMatch(/findingsCount/);
  });

  it('hints tasks when status is idle with no start', async () => {
    const env = testEnv({
      SCAN_ORCHESTRATOR: {
        idFromName: (name: string) => ({ name }),
        get: () => ({
          fetch: async () =>
            new Response(JSON.stringify({ status: 'idle', phase: '', probed: 0, total: 0, findings: 0 }), {
              headers: { 'content-type': 'application/json' },
            }),
        }),
      } as unknown as Env['SCAN_ORCHESTRATOR'],
    });
    const r = await handleOrchestrateMessage(env, 'status plan-only-id');
    expect(r.ok).toBe(true);
    expect(r.text).toMatch(/tasks /i);
  });

  it('summarizes executor tasks with counts', async () => {
    const env = testEnv();
    const task: ToolTask = {
      id: 'task-aaaaaaaa',
      scanId: 'scan-xyz',
      tool: 'httpx',
      target: 'https://httpbin.org',
      args: {},
      scope: {
        program: 'lab',
        platform: 'generic',
        inScope: ['httpbin.org'],
        outOfScope: [],
        authorized: true,
      },
      status: 'pending',
      timeoutSec: 300,
      createdAt: new Date().toISOString(),
      followUpDepth: 0,
    };
    await enqueueTasks(env, [task]);
    const r = await handleOrchestrateMessage(env, 'tasks scan-xyz');
    expect(r.ok).toBe(true);
    expect(r.text).toMatch(/pending=1/);
    expect(r.text).toMatch(/httpx/);
  });

  it('starts passive scan and returns scanId', async () => {
    const r = await handleOrchestrateMessage(
      testEnv({ SCAN_MODE: 'hybrid' }),
      'scan https://httpbin.org authorized program=httpbin-lab inScope=httpbin.org',
    );
    expect(r.ok).toBe(true);
    expect(r.text).toMatch(/Passive scan started/);
    expect((r.data as { scanId: string }).scanId).toMatch(/^[0-9a-f-]{36}$/i);
    expect(r.text).toMatch(/Hybrid mode/i);
  });

  it('plans and enqueues remote tasks', async () => {
    const r = await handleOrchestrateMessage(
      testEnv(),
      'plan https://httpbin.org authorized program=httpbin-lab inScope=httpbin.org',
    );
    expect(r.ok).toBe(true);
    expect(r.text).toMatch(/Plan ready/);
    expect((r.data as { tasksDispatched: number }).tasksDispatched).toBeGreaterThan(0);
  });
});
