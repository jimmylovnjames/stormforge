// Task completion: persist findings (keep recon for planner) + optional evolved follow-ups.

import type { Env, ToolTask, ToolTaskResult } from '../types.js';
import { FindingsStore } from '../findings/store.js';
import { auditLog } from '../audit/log.js';
import { dispatchHybridFollowUp, shouldHybridDispatch } from './hybrid.js';
import { enqueueTasks } from './queue.js';
import { backoffMs, taskLimits } from './config.js';

export const MAX_FOLLOW_UP_DEPTH = 2;

export interface CompleteInput {
  taskId: string;
  result: ToolTaskResult;
  /** Injectable clock for deterministic backoff scheduling (defaults to now). */
  now?: number;
}

export interface CompleteOutput {
  status: ToolTask['status'];
  findingsStored: number;
  followUpsEnqueued: number;
  /** True when a transient failure was re-queued with backoff rather than failed. */
  retryScheduled: boolean;
}

export async function processTaskCompletion(env: Env, input: CompleteInput): Promise<CompleteOutput> {
  const raw = await env.STORMFORGE_KV.get(`task:${input.taskId}`);
  if (!raw) {
    return { status: 'error', findingsStored: 0, followUpsEnqueued: 0, retryScheduled: false };
  }

  const now = input.now ?? Date.now();
  const task = JSON.parse(raw) as ToolTask;
  const outcome: ToolTask['status'] = input.result.timedOut
    ? 'timeout'
    : input.result.exitCode === 0
      ? 'done'
      : 'error';
  task.result = input.result;
  delete task.leaseExpiresAt;

  // Retry transient failures with exponential backoff before giving up.
  if (outcome !== 'done') {
    const { maxAttempts, retryBaseMs, retryCapMs } = taskLimits(env);
    const attempts = (task.attempts ?? 0) + 1;
    task.attempts = attempts;
    task.lastError =
      (input.result.stderr && input.result.stderr.slice(0, 300)) ||
      `${outcome} (exit ${input.result.exitCode})`;

    if (attempts < maxAttempts) {
      task.status = 'pending';
      task.nextEligibleAt = new Date(now + backoffMs(attempts, retryBaseMs, retryCapMs)).toISOString();
      await enqueueTasks(env, [task]);
      await auditLog(env, {
        action: 'task.complete',
        detail: `${task.tool} ${outcome} — retry ${attempts}/${maxAttempts} scheduled`,
        target: task.target,
        program: task.scope.program,
        meta: { taskId: task.id, attempts, nextEligibleAt: task.nextEligibleAt },
      });
      return { status: 'pending', findingsStored: 0, followUpsEnqueued: 0, retryScheduled: true };
    }

    // Exhausted: permanent failure.
    task.status = outcome;
    await env.STORMFORGE_KV.put(`task:${task.id}`, JSON.stringify(task));
    await auditLog(env, {
      action: 'task.complete',
      detail: `${task.tool} ${outcome} — attempts exhausted (${attempts}/${maxAttempts})`,
      target: task.target,
      program: task.scope.program,
      meta: { taskId: task.id, attempts, exitCode: input.result.exitCode },
    });
    return { status: outcome, findingsStored: 0, followUpsEnqueued: 0, retryScheduled: false };
  }

  task.status = 'done';
  await env.STORMFORGE_KV.put(`task:${task.id}`, JSON.stringify(task));

  let findingsStored = 0;
  const findings = input.result.findings ?? [];
  if (findings.length) {
    const store = new FindingsStore(env.STORMFORGE_KV);
    // Keep recon (httpx tech) so evolved planner can tech-tag nuclei; report paths can still filter.
    const stats = await store.upsertMany(task.scope.program, findings, { keepRecon: true });
    findingsStored = stats.added + stats.updated;
  }

  let followUpsEnqueued = 0;
  const depth = task.followUpDepth ?? 0;
  if (
    shouldHybridDispatch(env, task.scope) &&
    findings.length > 0 &&
    depth < MAX_FOLLOW_UP_DEPTH
  ) {
    const follow = await dispatchHybridFollowUp(env, {
      scanId: task.scanId,
      scope: task.scope,
      targets: [task.target],
      findings,
      followUpDepth: depth + 1,
      maxTasks: 6,
    });
    // Prefer finding-driven only: if heuristic flooded, still OK; depth caps loops.
    followUpsEnqueued = follow.enqueued;
  }

  await auditLog(env, {
    action: 'task.complete',
    detail: `${task.tool} ${task.status} — stored ${findingsStored}, follow-ups ${followUpsEnqueued}`,
    target: task.target,
    program: task.scope.program,
    meta: {
      taskId: task.id,
      exitCode: input.result.exitCode,
      timedOut: !!input.result.timedOut,
      followUpsEnqueued,
      followUpDepth: depth,
    },
  });

  return { status: task.status, findingsStored, followUpsEnqueued, retryScheduled: false };
}
