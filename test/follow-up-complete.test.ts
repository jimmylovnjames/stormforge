import { describe, it, expect, beforeEach } from 'vitest';
import { processTaskCompletion } from '../src/tasks/complete-followup.js';
import { getPendingIds } from '../src/tasks/queue.js';
import { FindingsStore } from '../src/findings/store.js';
import type { Env, Finding, Scope, ToolTask, ToolTaskResult } from '../src/types.js';
import { memoryKv } from './helpers/memory-kv.js';

const scope: Scope = {
  program: 'acme',
  platform: 'hackerone',
  inScope: ['*.acme.com', 'acme.com'],
  outOfScope: [],
  authorized: true,
};

function env(kv: KVNamespace, mode = 'hybrid'): Env {
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

describe('complete → evolved follow-up', () => {
  let kv: KVNamespace;
  let e: Env;

  beforeEach(() => {
    kv = memoryKv();
    e = env(kv);
  });

  it('stores nuclei findings with confidence and does not enqueue when depth exceeded', async () => {
    const task: ToolTask = {
      id: 't1',
      scanId: 'scan-1',
      tool: 'nuclei',
      target: 'https://app.acme.com',
      args: {},
      scope,
      status: 'running',
      timeoutSec: 60,
      createdAt: new Date().toISOString(),
      followUpDepth: 2,
    };
    await kv.put('task:t1', JSON.stringify(task));

    const result: ToolTaskResult = {
      exitCode: 0,
      stdout: '',
      stderr: '',
      durationMs: 10,
      completedAt: new Date().toISOString(),
      findings: [
        {
          id: 'n1',
          checkId: 'nuclei-cve-1',
          title: 'CVE',
          severity: 'high',
          target: 'https://app.acme.com',
          description: 'd',
          evidence: 'e',
          reproduction: [],
          remediation: '',
          references: [],
          needsManualReview: false,
          discoveredAt: new Date().toISOString(),
        },
      ],
    };

    const out = await processTaskCompletion(e, { taskId: 't1', result });
    expect(out.status).toBe('done');
    expect(out.findingsStored).toBeGreaterThan(0);

    const store = new FindingsStore(kv);
    const all = await store.getAll('acme');
    expect(all.some((f) => f.confidence && f.confidence > 0)).toBe(true);
  });

  it('httpx tech finding triggers tech-tagged nuclei follow-up enqueue', async () => {
    const task: ToolTask = {
      id: 't-httpx',
      scanId: 'scan-2',
      tool: 'httpx',
      target: 'https://blog.acme.com',
      args: {},
      scope,
      status: 'running',
      timeoutSec: 60,
      createdAt: new Date().toISOString(),
      followUpDepth: 0,
    };
    await kv.put('task:t-httpx', JSON.stringify(task));

    const tech: Finding = {
      id: 'tech1',
      checkId: 'httpx-tech-detect',
      title: 'Tech detected: WordPress,PHP',
      severity: 'info',
      target: 'https://blog.acme.com',
      description: '',
      evidence: 'WordPress,PHP,nginx',
      reproduction: [],
      remediation: '',
      references: [],
      needsManualReview: false,
      discoveredAt: new Date().toISOString(),
    };

    const before = (await getPendingIds(e)).length;
    const out = await processTaskCompletion(e, {
      taskId: 't-httpx',
      result: {
        exitCode: 0,
        stdout: '',
        stderr: '',
        durationMs: 5,
        completedAt: new Date().toISOString(),
        findings: [tech],
      },
    });
    expect(out.followUpsEnqueued).toBeGreaterThan(0);
    expect((await getPendingIds(e)).length).toBeGreaterThan(before);

    // Follow-up tasks should be nuclei with wordpress tags and depth+1
    const pending = await getPendingIds(e);
    let sawNuclei = false;
    for (const id of pending) {
      const raw = await kv.get(`task:${id}`);
      if (!raw) continue;
      const t = JSON.parse(raw) as ToolTask;
      if (t.tool === 'nuclei' && /wordpress/i.test(t.args.templates || '')) {
        sawNuclei = true;
        expect((t.followUpDepth ?? 0) >= 1).toBe(true);
      }
    }
    expect(sawNuclei).toBe(true);
  });

  it('does not unbounded re-dispatch when followUpDepth >= max', async () => {
    const task: ToolTask = {
      id: 't-deep',
      scanId: 'scan-3',
      tool: 'httpx',
      target: 'https://blog.acme.com',
      args: {},
      scope,
      status: 'running',
      timeoutSec: 60,
      createdAt: new Date().toISOString(),
      followUpDepth: 2, // max default 2
    };
    await kv.put('task:t-deep', JSON.stringify(task));
    const out = await processTaskCompletion(e, {
      taskId: 't-deep',
      result: {
        exitCode: 0,
        stdout: '',
        stderr: '',
        durationMs: 5,
        completedAt: new Date().toISOString(),
        findings: [
          {
            id: 'tech',
            checkId: 'httpx-tech-detect',
            title: 'WordPress',
            severity: 'info',
            target: 'https://blog.acme.com',
            description: '',
            evidence: 'WordPress',
            reproduction: [],
            remediation: '',
            references: [],
            needsManualReview: false,
            discoveredAt: new Date().toISOString(),
          },
        ],
      },
    });
    expect(out.followUpsEnqueued).toBe(0);
  });

  it('detect mode stores findings but skips follow-up enqueue', async () => {
    const detectEnv = env(kv, 'detect');
    const task: ToolTask = {
      id: 't-d',
      scanId: 'scan-d',
      tool: 'httpx',
      target: 'https://blog.acme.com',
      args: {},
      scope,
      status: 'running',
      timeoutSec: 60,
      createdAt: new Date().toISOString(),
      followUpDepth: 0,
    };
    await kv.put('task:t-d', JSON.stringify(task));
    const out = await processTaskCompletion(detectEnv, {
      taskId: 't-d',
      result: {
        exitCode: 0,
        stdout: '',
        stderr: '',
        durationMs: 1,
        completedAt: new Date().toISOString(),
        findings: [
          {
            id: 'tech',
            checkId: 'httpx-tech-detect',
            title: 'WordPress',
            severity: 'info',
            target: 'https://blog.acme.com',
            description: '',
            evidence: 'WordPress',
            reproduction: [],
            remediation: '',
            references: [],
            needsManualReview: false,
            discoveredAt: new Date().toISOString(),
          },
        ],
      },
    });
    expect(out.followUpsEnqueued).toBe(0);
  });
});
