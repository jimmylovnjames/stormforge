// Shared helpers to enqueue scoped ToolTasks onto the C2 pending queue.

import type { Env, Finding, Scope, ToolTask } from '../types.js';
import { planFollowUpTasks } from './vuln-planner.js';

type FindingLike = {
  checkId: string;
  severity: string;
  target: string;
  title: string;
  evidence?: string;
};

/**
 * Finding-driven executor dispatch — closes the Worker scan → remote tools loop.
 * Returns how many new tasks were enqueued.
 */
export async function dispatchFollowUpsFromFindings(
  env: Env,
  findings: FindingLike[] | Finding[],
  scope: Scope,
  opts: { scanId: string; maxTasks?: number } = { scanId: 'unknown' },
): Promise<number> {
  if (!env.STORMFORGE_KV || !findings.length) return 0;
  const follow = planFollowUpTasks(findings, scope, {
    scanId: opts.scanId,
    maxTasks: opts.maxTasks ?? 8,
  });
  if (!follow.tasks.length) return 0;

  const queue = await readQueue(env);
  let dispatched = 0;
  for (const planned of follow.tasks) {
    const next: ToolTask = {
      id: crypto.randomUUID(),
      scanId: opts.scanId,
      tool: planned.tool,
      target: planned.target,
      args: planned.args,
      scope,
      status: 'pending',
      timeoutSec: planned.timeoutSec || 300,
      createdAt: new Date().toISOString(),
    };
    await env.STORMFORGE_KV.put(`task:${next.id}`, JSON.stringify(next));
    queue.push(next.id);
    dispatched++;
  }
  await env.STORMFORGE_KV.put('task_queue:pending', JSON.stringify(queue));
  return dispatched;
}

async function readQueue(env: Env): Promise<string[]> {
  const raw = await env.STORMFORGE_KV.get('task_queue:pending');
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}
