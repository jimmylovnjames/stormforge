// Autonomy tunables (retry/backoff, GC, swarm heartbeat) read from env vars.
// All knobs have safe production defaults so the swarm runs hands-off even
// when wrangler [vars] are unset.

import type { Env } from '../types.js';

export interface TaskLimits {
  /** Max lease/execution attempts before a task is permanently failed. */
  maxAttempts: number;
  /** Base retry backoff in ms (attempt 1). */
  retryBaseMs: number;
  /** Maximum retry backoff in ms (cap for exponential growth). */
  retryCapMs: number;
  /** Age after which terminal (done/error/timeout) tasks are garbage-collected. */
  gcTtlMs: number;
}

function intFromSec(raw: string | undefined, fallbackSec: number, minSec: number, maxSec: number): number {
  const n = Number(raw);
  const sec = Number.isFinite(n) && n > 0 ? n : fallbackSec;
  return Math.max(minSec, Math.min(maxSec, Math.floor(sec))) * 1000;
}

function intPlain(raw: string | undefined, fallback: number, min: number, max: number): number {
  const n = Number(raw);
  const v = Number.isFinite(n) && n > 0 ? n : fallback;
  return Math.max(min, Math.min(max, Math.floor(v)));
}

export function taskLimits(env: Env): TaskLimits {
  return {
    maxAttempts: intPlain(env.TASK_MAX_ATTEMPTS, 4, 1, 10),
    retryBaseMs: intFromSec(env.TASK_RETRY_BASE_SEC, 30, 1, 3600),
    retryCapMs: intFromSec(env.TASK_RETRY_CAP_SEC, 900, 1, 86_400),
    gcTtlMs: intFromSec(env.TASK_GC_TTL_SEC, 21_600, 60, 604_800),
  };
}

/** Coordinator heartbeat interval in ms (how often the alarm re-runs maintenance). */
export function swarmTickMs(env: Env): number {
  return intFromSec(env.SWARM_TICK_SEC, 30, 5, 3600);
}

/** Whether the coordinator keeps rescheduling its own alarm (24/7 autopilot). */
export function autopilotOn(env: Env): boolean {
  const v = (env.SWARM_AUTOPILOT ?? 'true').toLowerCase();
  return v !== 'false' && v !== '0' && v !== 'off';
}

/**
 * Exponential backoff for retry attempt `n` (1-indexed): base * 2^(n-1), capped.
 * Deterministic (no jitter) so it is unit-testable and predictable in logs.
 */
export function backoffMs(attempt: number, baseMs: number, capMs: number): number {
  const n = Math.max(1, Math.floor(attempt));
  const raw = baseMs * 2 ** (n - 1);
  return Math.min(capMs, raw);
}
