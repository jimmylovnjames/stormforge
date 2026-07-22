// KV-backed OAST payload + interaction store (mirrors FindingsStore patterns).
// Correlation key is the payload token; per-program index enables report/query.

import type { OastHit, OastPayload, OastResults } from './types.js';
import { parseCollaborator } from './collaborator.js';
import type { Env } from '../types.js';

const PAYLOAD_PREFIX = 'oast:payload:';
const HIT_PREFIX = 'oast:hits:';
const GLOBAL_INDEX = 'oast:index';
const PROGRAM_INDEX = 'oast:index:';
const LAST_POLL = 'oast:lastpoll';
const MAX_TOKENS = 3000;

export class OastStore {
  constructor(private readonly kv: KVNamespace) {}

  async registerPayload(p: OastPayload): Promise<void> {
    await this.kv.put(`${PAYLOAD_PREFIX}${p.token}`, JSON.stringify(p));

    const index = await this.list(GLOBAL_INDEX);
    index.push(p.token);
    // Bound the global index; GC oldest tokens + their records.
    while (index.length > MAX_TOKENS) {
      const drop = index.shift();
      if (drop) {
        await this.kv.delete(`${PAYLOAD_PREFIX}${drop}`).catch(() => undefined);
        await this.kv.delete(`${HIT_PREFIX}${drop}`).catch(() => undefined);
      }
    }
    await this.kv.put(GLOBAL_INDEX, JSON.stringify(index));

    const pidxKey = `${PROGRAM_INDEX}${p.program}`;
    const pidx = await this.list(pidxKey);
    if (!pidx.includes(p.token)) {
      pidx.push(p.token);
      await this.kv.put(pidxKey, JSON.stringify(pidx));
    }
  }

  async getPayload(token: string): Promise<OastPayload | null> {
    const raw = await this.kv.get(`${PAYLOAD_PREFIX}${token}`);
    return raw ? (JSON.parse(raw) as OastPayload) : null;
  }

  /** All known tokens (global, newest last). */
  async allTokens(): Promise<string[]> {
    return this.list(GLOBAL_INDEX);
  }

  /**
   * Record an interaction against a token. Returns the payload (with updated
   * hit state) if the token is known, else null. Idempotent-ish: appends hits,
   * flags first-hit time. `isFirstHit` tells the caller to raise a finding once.
   */
  async recordHit(hit: OastHit): Promise<{ payload: OastPayload; isFirstHit: boolean } | null> {
    const payload = await this.getPayload(hit.token);
    if (!payload) return null;

    const hits = await this.getHits(hit.token);
    hits.push(hit);
    await this.kv.put(`${HIT_PREFIX}${hit.token}`, JSON.stringify(hits.slice(-50)));

    const isFirstHit = !payload.hit;
    payload.hit = true;
    payload.hitCount = (payload.hitCount ?? 0) + 1;
    payload.firstHitAt = payload.firstHitAt ?? hit.at;
    await this.kv.put(`${PAYLOAD_PREFIX}${payload.token}`, JSON.stringify(payload));
    return { payload, isFirstHit };
  }

  async getHits(token: string): Promise<OastHit[]> {
    const raw = await this.kv.get(`${HIT_PREFIX}${token}`);
    return raw ? (JSON.parse(raw) as OastHit[]) : [];
  }

  async getLastPoll(): Promise<number | null> {
    const raw = await this.kv.get(LAST_POLL);
    const n = raw ? Number(raw) : NaN;
    return Number.isFinite(n) ? n : null;
  }

  async setLastPoll(ms: number): Promise<void> {
    await this.kv.put(LAST_POLL, String(Math.floor(ms)));
  }

  /** Full results for a program (payloads + hits), or all when program omitted. */
  async results(env: Env, program?: string): Promise<OastResults> {
    const cfg = parseCollaborator(env);
    const tokens = program ? await this.list(`${PROGRAM_INDEX}${program}`) : await this.list(GLOBAL_INDEX);
    const payloads: OastPayload[] = [];
    const hits: OastHit[] = [];
    for (const token of tokens) {
      const p = await this.getPayload(token);
      if (!p) continue;
      payloads.push(p);
      if (p.hit) hits.push(...(await this.getHits(token)));
    }
    const lastPoll = await this.getLastPoll();
    return {
      configured: !!cfg,
      callbackDomain: cfg?.callbackDomain ?? null,
      total: payloads.length,
      hitCount: hits.length,
      confirmed: payloads.filter((p) => p.hit).length,
      lastPollAt: lastPoll ? new Date(lastPoll).toISOString() : null,
      payloads,
      hits,
    };
  }

  private async list(key: string): Promise<string[]> {
    const raw = await this.kv.get(key);
    return raw ? (JSON.parse(raw) as string[]) : [];
  }
}
