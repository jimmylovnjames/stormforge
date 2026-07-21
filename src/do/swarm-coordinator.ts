// SwarmCoordinator — the heartbeat of 24/7 autonomy.
//
// A singleton Durable Object whose alarm() runs the maintenance tick (lease
// reclaim, retry backoff via completion, terminal-task GC, metrics) and then
// reschedules itself. This makes recovery independent of any executor polling
// or operator request. Hibernation-safe: no reliance on in-memory state — all
// durable state lives in ctx.storage and the alarm is always re-armed.

import type { Env } from '../types.js';
import { runMaintenanceTick, collectQueueStats, type MaintenanceMetrics } from '../tasks/maintenance.js';
import { autopilotOn, swarmTickMs } from '../tasks/config.js';

interface StoredMetrics extends MaintenanceMetrics {
  /** Monotonic count of maintenance ticks executed by this coordinator. */
  ticks: number;
}

export class SwarmCoordinator {
  constructor(
    private readonly ctx: DurableObjectState,
    private readonly env: Env,
  ) {}

  async fetch(request: Request): Promise<Response> {
    const { pathname } = new URL(request.url);

    if (pathname.endsWith('/tick')) {
      const metrics = await this.tick();
      return json({ ok: true, metrics });
    }

    if (pathname.endsWith('/ensure')) {
      const nextAlarmAt = await this.ensureAlarm();
      return json({ ok: true, nextAlarmAt, autopilot: autopilotOn(this.env) });
    }

    if (pathname.endsWith('/status')) {
      const metrics = (await this.ctx.storage.get<StoredMetrics>('metrics')) ?? null;
      const queue = await collectQueueStats(this.env);
      const nextAlarmAt = await this.ctx.storage.getAlarm();
      return json({
        ok: true,
        autopilot: autopilotOn(this.env),
        tickMs: swarmTickMs(this.env),
        nextAlarmAt,
        metrics,
        queue,
      });
    }

    return json({ error: 'not found' }, 404);
  }

  /** Cloudflare alarm callback — run maintenance then re-arm (if autopilot on). */
  async alarm(): Promise<void> {
    await this.tick();
  }

  private async tick(): Promise<StoredMetrics> {
    const base = await runMaintenanceTick(this.env);
    const prev = (await this.ctx.storage.get<StoredMetrics>('metrics')) ?? undefined;
    const metrics: StoredMetrics = { ...base, ticks: (prev?.ticks ?? 0) + 1 };
    await this.ctx.storage.put('metrics', metrics);
    // Always re-arm at the end so the loop is self-sustaining and hibernation-safe.
    await this.ensureAlarm();
    return metrics;
  }

  /** Ensure an alarm is scheduled when autopilot is on. Returns the alarm time. */
  private async ensureAlarm(): Promise<number | null> {
    if (!autopilotOn(this.env)) return null;
    const existing = await this.ctx.storage.getAlarm();
    if (existing != null) return existing;
    const at = Date.now() + swarmTickMs(this.env);
    await this.ctx.storage.setAlarm(at);
    return at;
  }
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}
