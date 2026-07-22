import { describe, it, expect } from 'vitest';
import { authenticateExecutor } from '../src/index.js';
import type { Env } from '../src/types.js';

function env(over: Partial<Env> = {}): Env {
  return {
    SCAN_ORCHESTRATOR: {} as Env['SCAN_ORCHESTRATOR'],
    STORMFORGE_KV: {} as Env['STORMFORGE_KV'],
    MAX_RPS: '5',
    MAX_CONCURRENCY: '5',
    SCAN_MODE: 'hybrid',
    LLM_PLANNER_ENDPOINT: '',
    LLM_PLANNER_MODEL: 'grok-4',
    ...over,
  };
}

describe('authenticateExecutor fail-closed', () => {
  it('rejects when secret missing and insecure not allowed', () => {
    const req = new Request('https://c2/api/tasks/poll');
    expect(authenticateExecutor(req, env({ EXECUTOR_SECRET: undefined }))).toBe(false);
  });

  it('allows local insecure only with explicit flag', () => {
    const req = new Request('https://c2/api/tasks/poll');
    expect(
      authenticateExecutor(req, env({ EXECUTOR_SECRET: undefined, ALLOW_INSECURE_EXECUTOR: 'true' })),
    ).toBe(true);
  });

  it('requires matching header when secret set', () => {
    const bad = new Request('https://c2/api/tasks/poll');
    const good = new Request('https://c2/api/tasks/poll', {
      headers: { 'x-executor-secret': 's3cret' },
    });
    const e = env({ EXECUTOR_SECRET: 's3cret' });
    expect(authenticateExecutor(bad, e)).toBe(false);
    expect(authenticateExecutor(good, e)).toBe(true);
  });
});
