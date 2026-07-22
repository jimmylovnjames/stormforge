// KV-backed task queue with lease + reclaim (C2 ↔ executor).

import type { Env, ToolTask } from '../types.js';
import { evaluateScope } from '../scope/scope-guard.js';
import { canonicalizeTarget } from '../findings/canonicalize.js';
import { taskLimits } from './config.js';

const PENDING_KEY = 'task_queue:pending';
const DEFAULT_LEASE_MS = 15 * 60 * 1000;

export function taskDedupKey(t: {
  tool: string;
  target: string;
  args?: Record<string, string>;
}): string {
  const templates = t.args?.templates ?? '';
  return `${t.tool}|${canonicalizeTarget(t.target) || t.target}|${templates}`;
}

export async function getPendingIds(env: Env): Promise<string[]> {
  const raw = await env.STORMFORGE_KV.get(PENDING_KEY);
  return raw ? (JSON.parse(raw) as string[]) : [];
}

async function putPendingIds(env: Env, ids: string[]): Promise<void> {
  await env.STORMFORGE_KV.put(PENDING_KEY, JSON.stringify(ids));
}

/** Persist tasks and append to pending queue (dedupe by id). */
export async function enqueueTasks(env: Env, tasks: ToolTask[]): Promise<number> {
  if (!tasks.length) return 0;
  const pending = await getPendingIds(env);
  const seen = new Set(pending);
  let added = 0;
  for (const t of tasks) {
    const task: ToolTask = { ...t, status: t.status || 'pending' };
    await env.STORMFORGE_KV.put(`task:${task.id}`, JSON.stringify(task));
    if (!seen.has(task.id)) {
      pending.push(task.id);
      seen.add(task.id);
      added++;
    }
  }
  await putPendingIds(env, pending);
  return added;
}

export interface LeaseOptions {
  limit?: number;
  leaseMs?: number;
  now?: number;
}

/**
 * Lease up to `limit` pending tasks. Reclaims expired leases first.
 * - Out-of-scope / unauthorized tasks are marked error and dropped from pending.
 * - Tasks with a future `nextEligibleAt` (retry backoff) are left pending, in order.
 * Preserves FIFO order for tasks that are not yet eligible.
 */
export async function leaseBatch(env: Env, opts: LeaseOptions = {}): Promise<ToolTask[]> {
  const limit = opts.limit ?? 5;
  const leaseMs = opts.leaseMs ?? DEFAULT_LEASE_MS;
  const now = opts.now ?? Date.now();

  await reclaimExpired(env, now);

  const pending = await getPendingIds(env);
  if (!pending.length) return [];

  const leased: ToolTask[] = [];
  const remaining: string[] = [];

  for (const id of pending) {
    if (leased.length >= limit) {
      remaining.push(id);
      continue;
    }
    const raw = await env.STORMFORGE_KV.get(`task:${id}`);
    if (!raw) continue; // dangling id — drop it from the queue

    const task = JSON.parse(raw) as ToolTask;

    if (!task.scope?.authorized || !evaluateScope(task.target, task.scope).allowed) {
      task.status = 'error';
      task.result = {
        exitCode: 1,
        stdout: '',
        stderr: 'REFUSED: out of scope or not authorized at lease time',
        findings: [],
        durationMs: 0,
        completedAt: new Date(now).toISOString(),
      };
      await env.STORMFORGE_KV.put(`task:${id}`, JSON.stringify(task));
      continue; // dropped from pending (terminal)
    }

    // Retry backoff gate: not yet eligible → keep pending, preserve order.
    const eligibleAt = task.nextEligibleAt ? Date.parse(task.nextEligibleAt) : 0;
    if (Number.isFinite(eligibleAt) && eligibleAt > now) {
      remaining.push(id);
      continue;
    }

    task.status = 'running';
    task.leaseExpiresAt = new Date(now + leaseMs).toISOString();
    delete task.nextEligibleAt;
    await env.STORMFORGE_KV.put(`task:${id}`, JSON.stringify(task));
    leased.push(task);
  }

  await putPendingIds(env, remaining);
  return leased;
}

/**
 * Move expired running tasks back to pending (counting the failed attempt).
 * A task whose attempts reach `maxAttempts` is marked terminal `error` instead
 * of being re-queued, so a dead executor can never loop a task forever.
 * Returns the ids that were re-queued.
 */
export async function reclaimExpired(env: Env, now = Date.now()): Promise<string[]> {
  const list = await env.STORMFORGE_KV.list({ prefix: 'task:' });
  const pending = await getPendingIds(env);
  const pendingSet = new Set(pending);
  const reclaimed: string[] = [];
  let pendingMutated = false;
  const { maxAttempts } = taskLimits(env);

  for (const key of list.keys) {
    const raw = await env.STORMFORGE_KV.get(key.name);
    if (!raw) continue;
    const task = JSON.parse(raw) as ToolTask;
    if (task.status !== 'running' || !task.leaseExpiresAt) continue;
    const exp = Date.parse(task.leaseExpiresAt);
    if (!Number.isFinite(exp) || exp > now) continue;

    const attempts = (task.attempts ?? 0) + 1;
    task.attempts = attempts;
    delete task.leaseExpiresAt;

    if (attempts >= maxAttempts) {
      // Give up: permanently fail so it never re-loops. Leave out of pending.
      task.status = 'error';
      task.lastError = `lease expired ${attempts}× (max attempts reached)`;
      task.result = task.result ?? {
        exitCode: 1,
        stdout: '',
        stderr: task.lastError,
        findings: [],
        durationMs: 0,
        completedAt: new Date(now).toISOString(),
      };
      await env.STORMFORGE_KV.put(`task:${task.id}`, JSON.stringify(task));
      // A permanently-failed task must never linger in the pending queue.
      if (pendingSet.has(task.id)) {
        pendingSet.delete(task.id);
        const idx = pending.indexOf(task.id);
        if (idx !== -1) pending.splice(idx, 1);
        pendingMutated = true;
      }
      continue;
    }

    // Reclaimable: immediately eligible (no backoff — the executor died mid-run).
    task.status = 'pending';
    await env.STORMFORGE_KV.put(`task:${task.id}`, JSON.stringify(task));
    if (!pendingSet.has(task.id)) {
      pending.push(task.id);
      pendingSet.add(task.id);
      pendingMutated = true;
    }
    reclaimed.push(task.id);
  }

  if (pendingMutated) await putPendingIds(env, pending);
  return reclaimed;
}
