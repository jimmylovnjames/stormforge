// Close the executor → Worker loop: turn katana/ffuf crawl URLs into a passive re-scan.

import type { Env, ScanRequest, Scope, ToolName } from '../types.js';
import { partitionByScope } from '../scope/scope-guard.js';

const CRAWL_TOOLS = new Set<ToolName>(['katana', 'ffuf', 'gobuster']);

/** Pull absolute http(s) URLs from recon tool stdout. */
export function extractCrawlUrls(tool: ToolName, stdout: string, max = 25): string[] {
  if (!CRAWL_TOOLS.has(tool) || !stdout) return [];
  const out: string[] = [];
  const seen = new Set<string>();
  for (const line of stdout.split('\n')) {
    const matches = line.match(/https?:\/\/[^\s"'<>\\]+/g) ?? [];
    for (let raw of matches) {
      raw = raw.replace(/[),.;]+$/g, '');
      if (seen.has(raw)) continue;
      seen.add(raw);
      out.push(raw);
      if (out.length >= max) return out;
    }
  }
  return out;
}

/**
 * Scope-filter + prefer parameterized URLs, then unique paths. Caps at `max`.
 */
export function selectRescanTargets(
  urls: string[],
  scope: Scope,
  max = 25,
): { targets: string[]; refused: string[] } {
  const { allowed, refused: refusedDetailed } = partitionByScope(urls, scope);
  const param: string[] = [];
  const plain: string[] = [];
  const seen = new Set<string>();
  for (const u of allowed) {
    const key = normalizeKey(u);
    if (seen.has(key)) continue;
    seen.add(key);
    if (/[?&]\w+=/.test(u)) param.push(u);
    else plain.push(u);
  }
  const targets = [...param, ...plain].slice(0, max);
  return { targets, refused: refusedDetailed.map((r) => r.target) };
}

export interface RescanOpts {
  parentScanId?: string;
  canaryBaseUrl?: string;
  sourceTool?: ToolName;
  session?: ScanRequest['session'];
}

export function buildWorkerRescanRequest(
  scope: Scope,
  targets: string[],
  opts: RescanOpts = {},
): ScanRequest {
  return {
    scope: { ...scope, authorized: true },
    targets,
    parentScanId: opts.parentScanId,
    canaryBaseUrl: opts.canaryBaseUrl,
    sourceTool: opts.sourceTool,
    session: opts.session,
  };
}

/**
 * Enqueue a Durable Object Worker re-scan for crawl-discovered URLs.
 * Dedupes via KV so the same URL set is not re-scanned within the TTL window.
 */
export async function enqueueWorkerRescan(
  env: Env,
  scope: Scope,
  urls: string[],
  opts: RescanOpts & { maxTargets?: number } = {},
): Promise<{ scanId: string; targets: number } | null> {
  if (!env.SCAN_ORCHESTRATOR || !urls.length) return null;
  const { targets } = selectRescanTargets(urls, scope, opts.maxTargets ?? 25);
  if (!targets.length) return null;

  const dedupeKey = `rescan:${scope.program}:${hashTargets(targets)}`;
  const existing = await env.STORMFORGE_KV.get(dedupeKey);
  if (existing) return null;

  const scanId = crypto.randomUUID();
  const req = buildWorkerRescanRequest(scope, targets, {
    parentScanId: opts.parentScanId,
    canaryBaseUrl: opts.canaryBaseUrl,
    sourceTool: opts.sourceTool,
    session: opts.session,
  });

  const id = env.SCAN_ORCHESTRATOR.idFromName(scanId);
  const stub = env.SCAN_ORCHESTRATOR.get(id);
  const res = await stub.fetch('https://do/start', {
    method: 'POST',
    body: JSON.stringify(req),
    headers: { 'content-type': 'application/json' },
  });
  if (!res.ok) return null;

  await env.STORMFORGE_KV.put(dedupeKey, scanId, { expirationTtl: 3600 });
  await env.STORMFORGE_KV.put(
    `rescan:meta:${scanId}`,
    JSON.stringify({
      scanId,
      program: scope.program,
      parentScanId: opts.parentScanId,
      sourceTool: opts.sourceTool,
      targets,
      createdAt: new Date().toISOString(),
    }),
    { expirationTtl: 86_400 },
  );
  return { scanId, targets: targets.length };
}

function normalizeKey(url: string): string {
  try {
    const u = new URL(url);
    u.hash = '';
    return u.toString();
  } catch {
    return url;
  }
}

function hashTargets(targets: string[]): string {
  // Lightweight non-crypto fingerprint for KV dedupe keys.
  const s = [...targets].sort().join('|');
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return (h >>> 0).toString(16);
}
