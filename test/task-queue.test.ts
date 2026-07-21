import { describe, it, expect, beforeEach } from 'vitest';
import {
  enqueueTasks,
  leaseBatch,
  reclaimExpired,
  getPendingIds,
  taskDedupKey,
} from '../src/tasks/queue.js';
import type { Env, Scope, ToolTask } from '../src/types.js';
import { memoryKv } from './helpers/memory-kv.js';

const scope: Scope = {
  program: 'acme',
  platform: 'hackerone',
  inScope: ['*.acme.com', 'acme.com'],
  outOfScope: [],
  authorized: true,
};

function env(kv: KVNamespace): Env {
  return {
    SCAN_ORCHESTRATOR: {} as Env['SCAN_ORCHESTRATOR'],
    STORMFORGE_KV: kv,
    MAX_RPS: '5',
    MAX_CONCURRENCY: '5',
    SCAN_MODE: 'hybrid',
    LLM_PLANNER_ENDPOINT: '',
    LLM_PLANNER_MODEL: 'grok-4',
    EXECUTOR_SECRET: 's',
  };
}

function task(over: Partial<ToolTask> & Pick<ToolTask, 'id' | 'tool' | 'target'>): ToolTask {
  return {
    scanId: 'scan-1',
    args: {},
    scope,
    status: 'pending',
    timeoutSec: 60,
    createdAt: new Date().toISOString(),
    ...over,
  };
}

describe('task queue lease/reclaim', () => {
  let kv: KVNamespace;
  let e: Env;

  beforeEach(() => {
    kv = memoryKv();
    e = env(kv);
  });

  it('enqueue then leaseBatch moves tasks to running with lease expiry', async () => {
    await enqueueTasks(e, [
      task({ id: 't1', tool: 'httpx', target: 'https://app.acme.com' }),
      task({ id: 't2', tool: 'nuclei', target: 'https://app.acme.com' }),
      task({ id: 't3', tool: 'katana', target: 'https://app.acme.com' }),
    ]);
    expect(await getPendingIds(e)).toHaveLength(3);

    const leased = await leaseBatch(e, { limit: 2, leaseMs: 30_000 });
    expect(leased).toHaveLength(2);
    expect(leased.every((t) => t.status === 'running')).toBe(true);
    expect(leased.every((t) => typeof t.leaseExpiresAt === 'string')).toBe(true);
    expect(await getPendingIds(e)).toHaveLength(1);
  });

  it('does not re-lease the same IDs while lease is active', async () => {
    await enqueueTasks(e, [task({ id: 't1', tool: 'httpx', target: 'https://app.acme.com' })]);
    const first = await leaseBatch(e, { limit: 5, leaseMs: 60_000 });
    const second = await leaseBatch(e, { limit: 5, leaseMs: 60_000 });
    expect(first.map((t) => t.id)).toEqual(['t1']);
    expect(second).toHaveLength(0);
  });

  it('reclaimExpired returns timed-out running tasks to pending', async () => {
    await enqueueTasks(e, [task({ id: 't1', tool: 'httpx', target: 'https://app.acme.com' })]);
    await leaseBatch(e, { limit: 1, leaseMs: 1 });
    // Force expiry in the past
    const raw = await kv.get('task:t1');
    const t = JSON.parse(raw!) as ToolTask;
    t.leaseExpiresAt = new Date(Date.now() - 1000).toISOString();
    await kv.put('task:t1', JSON.stringify(t));

    const reclaimed = await reclaimExpired(e);
    expect(reclaimed).toContain('t1');
    expect(await getPendingIds(e)).toContain('t1');
    const again = await leaseBatch(e, { limit: 1, leaseMs: 30_000 });
    expect(again[0]!.id).toBe('t1');
  });

  it('refuses out-of-scope / unauthorized at lease time', async () => {
    await enqueueTasks(e, [
      task({
        id: 'bad',
        tool: 'httpx',
        target: 'https://evil.com',
        scope: { ...scope, authorized: true, inScope: ['*.acme.com'] },
      }),
    ]);
    const leased = await leaseBatch(e, { limit: 5, leaseMs: 30_000 });
    expect(leased).toHaveLength(0);
    const raw = await kv.get('task:bad');
    expect(JSON.parse(raw!).status).toBe('error');
  });

  it('taskDedupKey is stable for tool|target|templates', () => {
    expect(
      taskDedupKey({
        tool: 'nuclei',
        target: 'https://a.com',
        args: { templates: 'wordpress,cves' },
      }),
    ).toBe(
      taskDedupKey({
        tool: 'nuclei',
        target: 'https://a.com',
        args: { templates: 'wordpress,cves' },
      }),
    );
  });
});
