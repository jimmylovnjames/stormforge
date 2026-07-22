import { describe, it, expect, beforeEach } from 'vitest';
import { enqueueTasks, leaseBatch, reclaimExpired, getPendingIds } from '../src/tasks/queue.js';
import { backoffMs, taskLimits, swarmTickMs, autopilotOn } from '../src/tasks/config.js';
import {
  runMaintenanceTick,
  gcTerminalTasks,
  collectQueueStats,
} from '../src/tasks/maintenance.js';
import { processTaskCompletion } from '../src/tasks/complete-followup.js';
import type { Env, Scope, ToolTask, ToolTaskResult } from '../src/types.js';
import { memoryKv } from './helpers/memory-kv.js';

const scope: Scope = {
  program: 'acme',
  platform: 'hackerone',
  inScope: ['*.acme.com', 'acme.com'],
  outOfScope: [],
  authorized: true,
};

function env(kv: KVNamespace, over: Partial<Env> = {}): Env {
  return {
    SCAN_ORCHESTRATOR: {} as Env['SCAN_ORCHESTRATOR'],
    STORMFORGE_KV: kv,
    MAX_RPS: '5',
    MAX_CONCURRENCY: '5',
    SCAN_MODE: 'hybrid',
    LLM_PLANNER_ENDPOINT: '',
    LLM_PLANNER_MODEL: 'grok-4',
    EXECUTOR_SECRET: 's',
    TASK_MAX_ATTEMPTS: '3',
    TASK_RETRY_BASE_SEC: '10',
    TASK_RETRY_CAP_SEC: '100',
    TASK_GC_TTL_SEC: '3600',
    ...over,
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

describe('config helpers', () => {
  it('backoffMs is monotonic and capped', () => {
    expect(backoffMs(1, 10_000, 100_000)).toBe(10_000);
    expect(backoffMs(2, 10_000, 100_000)).toBe(20_000);
    expect(backoffMs(3, 10_000, 100_000)).toBe(40_000);
    expect(backoffMs(10, 10_000, 100_000)).toBe(100_000); // capped
    expect(backoffMs(0, 10_000, 100_000)).toBe(10_000); // floors at attempt 1
  });

  it('taskLimits reads env with sane defaults', () => {
    const kv = memoryKv();
    const l = taskLimits(env(kv));
    expect(l.maxAttempts).toBe(3);
    expect(l.retryBaseMs).toBe(10_000);
    expect(l.retryCapMs).toBe(100_000);
    expect(l.gcTtlMs).toBe(3_600_000);

    const d = taskLimits(env(kv, { TASK_MAX_ATTEMPTS: undefined, TASK_RETRY_BASE_SEC: undefined }));
    expect(d.maxAttempts).toBeGreaterThanOrEqual(2);
    expect(d.retryBaseMs).toBeGreaterThan(0);
  });

  it('swarm tick + autopilot defaults', () => {
    const kv = memoryKv();
    expect(swarmTickMs(env(kv))).toBeGreaterThan(0);
    expect(autopilotOn(env(kv))).toBe(true);
    expect(autopilotOn(env(kv, { SWARM_AUTOPILOT: 'false' }))).toBe(false);
  });
});

describe('leaseBatch backoff eligibility', () => {
  let kv: KVNamespace;
  let e: Env;
  beforeEach(() => {
    kv = memoryKv();
    e = env(kv);
  });

  it('does not lease a task whose nextEligibleAt is in the future, but keeps it pending', async () => {
    const now = 1_000_000;
    await enqueueTasks(e, [
      task({ id: 'later', tool: 'httpx', target: 'https://a.acme.com', nextEligibleAt: new Date(now + 60_000).toISOString() }),
      task({ id: 'ready', tool: 'nuclei', target: 'https://a.acme.com' }),
    ]);
    // Long lease so 'ready' stays leased and is not reclaimed by the 2nd call.
    const leased = await leaseBatch(e, { limit: 5, leaseMs: 10_000_000, now });
    expect(leased.map((t) => t.id)).toEqual(['ready']);
    expect(await getPendingIds(e)).toContain('later');

    const leasedLater = await leaseBatch(e, { limit: 5, leaseMs: 30_000, now: now + 61_000 });
    expect(leasedLater.map((t) => t.id)).toEqual(['later']);
  });
});

describe('reclaimExpired attempt counting', () => {
  let kv: KVNamespace;
  let e: Env;
  beforeEach(() => {
    kv = memoryKv();
    e = env(kv);
  });

  it('re-queues an expired lease and increments attempts', async () => {
    await enqueueTasks(e, [task({ id: 't1', tool: 'httpx', target: 'https://a.acme.com' })]);
    await leaseBatch(e, { limit: 1, leaseMs: 1, now: 1000 });
    const reclaimed = await reclaimExpired(e, 5000);
    expect(reclaimed).toContain('t1');
    const t = JSON.parse((await kv.get('task:t1'))!) as ToolTask;
    expect(t.status).toBe('pending');
    expect(t.attempts).toBe(1);
  });

  it('gives up (marks error) once attempts reach maxAttempts', async () => {
    await enqueueTasks(e, [
      task({
        id: 'tdead',
        tool: 'httpx',
        target: 'https://a.acme.com',
        status: 'running',
        attempts: 2, // one more failure hits max=3
        leaseExpiresAt: new Date(1000).toISOString(),
      }),
    ]);
    const reclaimed = await reclaimExpired(e, 5000);
    expect(reclaimed).not.toContain('tdead');
    const t = JSON.parse((await kv.get('task:tdead'))!) as ToolTask;
    expect(t.status).toBe('error');
    expect(t.attempts).toBe(3);
    expect(await getPendingIds(e)).not.toContain('tdead');
  });
});

describe('processTaskCompletion retry with backoff', () => {
  let kv: KVNamespace;
  let e: Env;
  beforeEach(() => {
    kv = memoryKv();
    e = env(kv);
  });

  function fail(over: Partial<ToolTaskResult> = {}): ToolTaskResult {
    return {
      exitCode: 1,
      stdout: '',
      stderr: 'boom',
      findings: [],
      durationMs: 5,
      completedAt: new Date().toISOString(),
      ...over,
    };
  }

  it('schedules a backed-off retry on transient failure', async () => {
    await kv.put(
      'task:tr',
      JSON.stringify(task({ id: 'tr', tool: 'httpx', target: 'https://a.acme.com', status: 'running' })),
    );
    const t0 = Date.now();
    const out = await processTaskCompletion(e, { taskId: 'tr', result: fail() });
    expect(out.status).toBe('pending');
    expect(out.retryScheduled).toBe(true);

    const t = JSON.parse((await kv.get('task:tr'))!) as ToolTask;
    expect(t.attempts).toBe(1);
    expect(t.status).toBe('pending');
    expect(Date.parse(t.nextEligibleAt!)).toBeGreaterThanOrEqual(t0);
    expect(t.lastError).toContain('boom');
    expect(await getPendingIds(e)).toContain('tr');
  });

  it('marks terminal error once attempts are exhausted (no re-queue)', async () => {
    await kv.put(
      'task:tx',
      JSON.stringify(
        task({ id: 'tx', tool: 'httpx', target: 'https://a.acme.com', status: 'running', attempts: 2 }),
      ),
    );
    const out = await processTaskCompletion(e, { taskId: 'tx', result: fail() });
    expect(out.status).toBe('error');
    expect(out.retryScheduled).toBe(false);
    expect(await getPendingIds(e)).not.toContain('tx');
  });

  it('timeouts are retried too', async () => {
    await kv.put(
      'task:tt',
      JSON.stringify(task({ id: 'tt', tool: 'nuclei', target: 'https://a.acme.com', status: 'running' })),
    );
    const out = await processTaskCompletion(e, {
      taskId: 'tt',
      result: fail({ exitCode: 124, timedOut: true, stderr: 'killed' }),
    });
    expect(out.retryScheduled).toBe(true);
    expect(out.status).toBe('pending');
  });
});

describe('gcTerminalTasks', () => {
  let kv: KVNamespace;
  let e: Env;
  beforeEach(() => {
    kv = memoryKv();
    e = env(kv);
  });

  it('deletes old terminal tasks but keeps recent and non-terminal', async () => {
    const now = 10_000_000;
    const old = new Date(now - 5 * 3_600_000).toISOString(); // 5h old (ttl 1h)
    const recent = new Date(now - 60_000).toISOString();
    await kv.put('task:done-old', JSON.stringify(task({ id: 'done-old', tool: 'httpx', target: 'https://a.acme.com', status: 'done', result: { exitCode: 0, stdout: '', stderr: '', findings: [], durationMs: 1, completedAt: old } })));
    await kv.put('task:done-new', JSON.stringify(task({ id: 'done-new', tool: 'httpx', target: 'https://a.acme.com', status: 'done', result: { exitCode: 0, stdout: '', stderr: '', findings: [], durationMs: 1, completedAt: recent } })));
    await enqueueTasks(e, [task({ id: 'pending-1', tool: 'httpx', target: 'https://a.acme.com' })]);

    const removed = await gcTerminalTasks(e, now);
    expect(removed).toBe(1);
    expect(await kv.get('task:done-old')).toBeNull();
    expect(await kv.get('task:done-new')).not.toBeNull();
    expect(await kv.get('task:pending-1')).not.toBeNull();
  });
});

describe('runMaintenanceTick', () => {
  let kv: KVNamespace;
  let e: Env;
  beforeEach(() => {
    kv = memoryKv();
    e = env(kv);
  });

  it('reclaims expired leases, GCs old terminal tasks, and reports queue stats', async () => {
    const now = 20_000_000;
    // expired running lease
    await kv.put('task:exp', JSON.stringify(task({ id: 'exp', tool: 'httpx', target: 'https://a.acme.com', status: 'running', leaseExpiresAt: new Date(now - 1000).toISOString() })));
    // old terminal
    await kv.put('task:gc', JSON.stringify(task({ id: 'gc', tool: 'httpx', target: 'https://a.acme.com', status: 'done', result: { exitCode: 0, stdout: '', stderr: '', findings: [], durationMs: 1, completedAt: new Date(now - 5 * 3_600_000).toISOString() } })));
    // fresh pending
    await enqueueTasks(e, [task({ id: 'p', tool: 'nuclei', target: 'https://a.acme.com' })]);

    const m = await runMaintenanceTick(e, { now });
    expect(m.reclaimed).toBe(1);
    expect(m.gc).toBe(1);
    expect(m.pendingDepth).toBeGreaterThanOrEqual(2); // 'p' + reclaimed 'exp'
    expect(typeof m.at).toBe('string');

    const stats = await collectQueueStats(e);
    expect(stats.pendingDepth).toBe(m.pendingDepth);
  });
});
