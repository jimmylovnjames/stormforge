// Rate-limited, scope-guarded, non-destructive HTTP client.
//
// - Only issues safe methods (GET/HEAD by default).
// - Enforces a global token-bucket rate limit and a body-size cap.
// - Every request is checked against scope before it leaves the Worker.

import type { ProbeResult, Scope } from '../types.js';
import { assertInScope, ScopeError } from '../scope/scope-guard.js';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
const BODY_CAP_BYTES = 512 * 1024; // 512 KB
const DEFAULT_TIMEOUT_MS = 10_000;

/** Simple token-bucket limiter, shared across a scan. */
export class RateLimiter {
  private tokens: number;
  private lastRefill: number;

  constructor(
    private readonly ratePerSec: number,
    private readonly burst = ratePerSec,
  ) {
    this.tokens = burst;
    this.lastRefill = Date.now();
  }

  async acquire(): Promise<void> {
    while (true) {
      this.refill();
      if (this.tokens >= 1) {
        this.tokens -= 1;
        return;
      }
      const waitMs = Math.ceil((1 / this.ratePerSec) * 1000);
      await sleep(waitMs);
    }
  }

  private refill(): void {
    const now = Date.now();
    const elapsedSec = (now - this.lastRefill) / 1000;
    if (elapsedSec <= 0) return;
    this.tokens = Math.min(this.burst, this.tokens + elapsedSec * this.ratePerSec);
    this.lastRefill = now;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

export interface ProbeOptions {
  method?: string;
  headers?: Record<string, string>;
  timeoutMs?: number;
  /** Follow redirects (default true). */
  redirect?: boolean;
}

export class HttpClient {
  constructor(
    private readonly scope: Scope,
    private readonly limiter: RateLimiter,
    private readonly userAgent = 'StormForge/1.0 (+authorized-bug-bounty-recon)',
  ) {}

  /** Perform one non-destructive probe. Never throws on HTTP errors — returns a ProbeResult with `error` populated. */
  async probe(url: string, opts: ProbeOptions = {}): Promise<ProbeResult> {
    const method = (opts.method ?? 'GET').toUpperCase();
    if (!SAFE_METHODS.has(method)) {
      // Hard guardrail: this framework does not mutate remote state.
      return errorResult(url, method, `Unsafe method blocked: ${method}`);
    }

    try {
      assertInScope(url, this.scope);
    } catch (e) {
      if (e instanceof ScopeError) return errorResult(url, method, e.message);
      throw e;
    }

    await this.limiter.acquire();

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), opts.timeoutMs ?? DEFAULT_TIMEOUT_MS);
    const started = Date.now();

    try {
      const res = await fetch(url, {
        method,
        headers: { 'user-agent': this.userAgent, ...(opts.headers ?? {}) },
        redirect: opts.redirect === false ? 'manual' : 'follow',
        signal: controller.signal,
      });

      const headers: Record<string, string> = {};
      res.headers.forEach((v, k) => {
        headers[k.toLowerCase()] = v;
      });

      const body = method === 'HEAD' ? '' : await readCapped(res);

      return {
        url,
        method,
        status: res.status,
        headers,
        body,
        finalUrl: res.url && res.url !== url ? res.url : undefined,
        elapsedMs: Date.now() - started,
      };
    } catch (e) {
      return errorResult(url, method, describeError(e), Date.now() - started);
    } finally {
      clearTimeout(timeout);
    }
  }
}

async function readCapped(res: Response): Promise<string> {
  const reader = res.body?.getReader();
  if (!reader) return '';
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (total < BODY_CAP_BYTES) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      chunks.push(value);
      total += value.length;
    }
  }
  try {
    await reader.cancel();
  } catch {
    /* best effort */
  }
  const merged = new Uint8Array(Math.min(total, BODY_CAP_BYTES));
  let offset = 0;
  for (const c of chunks) {
    const remaining = merged.length - offset;
    if (remaining <= 0) break;
    merged.set(c.subarray(0, remaining), offset);
    offset += c.length;
  }
  return new TextDecoder('utf-8', { fatal: false, ignoreBOM: false }).decode(merged);
}

function errorResult(url: string, method: string, error: string, elapsedMs = 0): ProbeResult {
  return { url, method, status: 0, headers: {}, body: '', elapsedMs, error };
}

function describeError(e: unknown): string {
  if (e instanceof Error) {
    if (e.name === 'AbortError') return 'Request timed out';
    return e.message;
  }
  return String(e);
}
