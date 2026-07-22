// Swarm maintenance tick: the recurring, executor-independent housekeeping that
// keeps a 24/7 autonomous run healthy. Reclaims expired leases, garbage-collects
// terminal tasks, and reports queue metrics. Pure over (env, now) for testing;
// invoked by the SwarmCoordinator alarm and the Cron watchdog.

import type { Env, ToolTask } from '../types.js';
import { getPendingIds, reclaimExpired } from './queue.js';
import { taskLimits } from './config.js';

export interface QueueStats {
  pendingDepth: number;
  running: number;
  done: number;
  error: number;
  timeout: number;
  /** Tasks with a future retry backoff gate (pending but not yet eligible). */
  scheduledRetries: number;
  total: number;
}

export interface MaintenanceMetrics extends QueueStats {
  /** ISO timestamp of this tick. */
  at: string;
  /** Expired leases returned to pending this tick. */
  reclaimed: number;
  /** Terminal tasks garbage-collected this tick. */
  gc: number;
}

const TERMINAL = new Set<ToolTask['status']>(['done', 'error', 'timeout']);

/** One pass over the task keyspace collecting status counts + queue depth. */
export async function collectQueueStats(env: Env, now = Date.now()): Promise<QueueStats> {
  const pending = await getPendingIds(env);
  const pendingDepth = pending.length;
  const list = await env.STORMFORGE_KV.list({ prefix: 'task:' });
  const stats: QueueStats = {
    pendingDepth,
    running: 0,
    done: 0,
    error: 0,
    timeout: 0,
    scheduledRetries: 0,
    total: 0,
  };
  for (const key of list.keys) {
    const raw = await env.STORMFORGE_KV.get(key.name);
    if (!raw) continue;
    const t = JSON.parse(raw) as ToolTask;
    stats.total++;
    if (t.status === 'running') stats.running++;
    else if (t.status === 'done') stats.done++;
    else if (t.status === 'error') stats.error++;
    else if (t.status === 'timeout') stats.timeout++;
    if (t.status === 'pending' && t.nextEligibleAt && Date.parse(t.nextEligibleAt) > now) {
      stats.scheduledRetries++;
    }
  }
  return stats;
}

/**
 * Delete terminal (done/error/timeout) task records older than the GC TTL.
 * Never removes tasks still referenced by the pending queue. Returns count removed.
 */
export async function gcTerminalTasks(env: Env, now = Date.now()): Promise<number> {
  const { gcTtlMs } = taskLimits(env);
  const pendingSet = new Set(await getPendingIds(env));
  const list = await env.STORMFORGE_KV.list({ prefix: 'task:' });
  let removed = 0;
  for (const key of list.keys) {
    const raw = await env.STORMFORGE_KV.get(key.name);
    if (!raw) continue;
    const t = JSON.parse(raw) as ToolTask;
    if (!TERMINAL.has(t.status)) continue;
    if (pendingSet.has(t.id)) continue; // still queued somehow — leave it
    const completedAt = t.result?.completedAt ?? t.createdAt;
    const age = now - Date.parse(completedAt);
    if (!Number.isFinite(age) || age < gcTtlMs) continue;
    await env.STORMFORGE_KV.delete(key.name);
    removed++;
  }
  return removed;
}

export interface MaintenanceOptions {
  now?: number;
}

/**
 * Run one maintenance cycle. Idempotent and safe to call from multiple triggers
 * (Cron watchdog + DO alarm); routing through the singleton coordinator DO keeps
 * these serialized in practice. Emits a structured log line for CF observability.
 */
export async function runMaintenanceTick(
  env: Env,
  opts: MaintenanceOptions = {},
): Promise<MaintenanceMetrics> {
  const now = opts.now ?? Date.now();
  const reclaimedIds = await reclaimExpired(env, now);
  const gc = await gcTerminalTasks(env, now);
  const stats = await collectQueueStats(env, now);

  const metrics: MaintenanceMetrics = {
    at: new Date(now).toISOString(),
    reclaimed: reclaimedIds.length,
    gc,
    ...stats,
  };

  console.log(JSON.stringify({ level: 'info', event: 'swarm.maintenance', ...metrics }));
  return metrics;
}
