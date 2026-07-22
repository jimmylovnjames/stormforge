import { describe, it, expect, beforeEach } from 'vitest';
import { dispatchHybridFollowUp, shouldHybridDispatch } from '../src/tasks/hybrid.js';
import { getPendingIds } from '../src/tasks/queue.js';
import type { Env, Finding, Scope } from '../src/types.js';
import { memoryKv } from './helpers/memory-kv.js';

const scope: Scope = {
  program: 'acme',
  platform: 'hackerone',
  inScope: ['*.acme.com', 'acme.com'],
  outOfScope: [],
  authorized: true,
};

function env(kv: KVNamespace, mode: string): Env {
  return {
    SCAN_ORCHESTRATOR: {} as Env['SCAN_ORCHESTRATOR'],
    STORMFORGE_KV: kv,
    MAX_RPS: '5',
    MAX_CONCURRENCY: '5',
    SCAN_MODE: mode,
    LLM_PLANNER_ENDPOINT: '',
    LLM_PLANNER_MODEL: 'grok-4',
    EXECUTOR_SECRET: 's',
  };
}

describe('hybrid passive → enqueue', () => {
  let kv: KVNamespace;

  beforeEach(() => {
    kv = memoryKv();
  });

  it('shouldHybridDispatch only when mode is hybrid and authorized', () => {
    expect(shouldHybridDispatch(env(kv, 'detect'), scope)).toBe(false);
    expect(shouldHybridDispatch(env(kv, 'hybrid'), { ...scope, authorized: false })).toBe(false);
    expect(shouldHybridDispatch(env(kv, 'hybrid'), scope)).toBe(true);
  });

  it('detect mode enqueues nothing', async () => {
    const result = await dispatchHybridFollowUp(env(kv, 'detect'), {
      scanId: 's1',
      scope,
      targets: ['https://app.acme.com'],
      findings: [],
    });
    expect(result.enqueued).toBe(0);
    expect(await getPendingIds(env(kv, 'detect'))).toHaveLength(0);
  });

  it('hybrid mode enqueues in-scope tasks from heuristic plan', async () => {
    const e = env(kv, 'hybrid');
    const result = await dispatchHybridFollowUp(e, {
      scanId: 's1',
      scope,
      targets: ['https://app.acme.com'],
      findings: [],
    });
    expect(result.enqueued).toBeGreaterThan(0);
    expect(result.refused).toBe(0);
    const pending = await getPendingIds(e);
    expect(pending.length).toBe(result.enqueued);
  });

  it('unauthorized / out-of-scope targets enqueue nothing', async () => {
    const e = env(kv, 'hybrid');
    const result = await dispatchHybridFollowUp(e, {
      scanId: 's1',
      scope: { ...scope, authorized: false },
      targets: ['https://app.acme.com'],
      findings: [],
    });
    expect(result.enqueued).toBe(0);
  });

  it('dedupes identical tool|target|templates within one dispatch', async () => {
    const e = env(kv, 'hybrid');
    const findings: Finding[] = [
      {
        id: '1',
        checkId: 'httpx-tech-detect',
        title: 'Tech: WordPress',
        severity: 'info',
        target: 'https://blog.acme.com',
        description: '',
        evidence: 'WordPress,PHP',
        reproduction: [],
        remediation: '',
        references: [],
        needsManualReview: false,
        discoveredAt: new Date().toISOString(),
      },
      {
        id: '2',
        checkId: 'httpx-tech-detect',
        title: 'Tech: WordPress',
        severity: 'info',
        target: 'https://blog.acme.com',
        description: '',
        evidence: 'WordPress,PHP',
        reproduction: [],
        remediation: '',
        references: [],
        needsManualReview: false,
        discoveredAt: new Date().toISOString(),
      },
    ];
    const result = await dispatchHybridFollowUp(e, {
      scanId: 's1',
      scope,
      targets: ['https://blog.acme.com'],
      findings,
    });
    const keys = new Set(result.dedupKeys);
    expect(keys.size).toBe(result.dedupKeys.length);
    expect(result.enqueued).toBeGreaterThan(0);
  });
});
