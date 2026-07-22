// Append-only audit trail of scope decisions and C2/executor actions.

import type { Env } from '../types.js';

export type AuditAction =
  | 'scan.refused'
  | 'scan.started'
  | 'scope.refused'
  | 'scope.allowed'
  | 'task.dispatch'
  | 'task.poll'
  | 'task.complete'
  | 'task.refused'
  | 'plan.attack'
  | 'auth.failed'
  | 'executor.refused';

export interface AuditEvent {
  at: string;
  action: AuditAction;
  program?: string;
  detail: string;
  target?: string;
  meta?: Record<string, string | number | boolean | undefined>;
}

const AUDIT_LIST_KEY = 'audit:index';
const MAX_EVENTS = 500;

/** Persist an audit event to KV (best-effort, never throws to caller). */
export async function auditLog(env: Env, event: Omit<AuditEvent, 'at'> & { at?: string }): Promise<void> {
  if (!env.STORMFORGE_KV) return;
  try {
    const full: AuditEvent = {
      ...event,
      at: event.at ?? new Date().toISOString(),
    };
    const id = `${full.at}:${full.action}:${Math.random().toString(36).slice(2, 8)}`;
    await env.STORMFORGE_KV.put(`audit:${id}`, JSON.stringify(full), {
      expirationTtl: 60 * 60 * 24 * 90,
    });

    const raw = await env.STORMFORGE_KV.get(AUDIT_LIST_KEY);
    const index: string[] = raw ? (JSON.parse(raw) as string[]) : [];
    index.push(id);
    while (index.length > MAX_EVENTS) {
      const drop = index.shift();
      if (drop) await env.STORMFORGE_KV.delete(`audit:${drop}`).catch(() => undefined);
    }
    await env.STORMFORGE_KV.put(AUDIT_LIST_KEY, JSON.stringify(index));
  } catch (e) {
    console.error('auditLog failed:', e);
  }
}

export async function listAuditEvents(env: Env, limit = 50): Promise<AuditEvent[]> {
  if (!env.STORMFORGE_KV) return [];
  const raw = await env.STORMFORGE_KV.get(AUDIT_LIST_KEY);
  const index: string[] = raw ? (JSON.parse(raw) as string[]) : [];
  const slice = index.slice(-limit).reverse();
  const out: AuditEvent[] = [];
  for (const id of slice) {
    const body = await env.STORMFORGE_KV.get(`audit:${id}`);
    if (body) out.push(JSON.parse(body) as AuditEvent);
  }
  return out;
}
