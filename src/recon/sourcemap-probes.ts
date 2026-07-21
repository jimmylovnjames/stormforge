// Source map discovery helpers (GET-safe).

import type { ProbeResult } from '../types.js';

const MAX_MAPS = 8;

/** Extract http(s) sourceMappingURL targets from JS/CSS/HTML bodies. */
export function extractSourceMappingUrls(body: string, baseUrl: string): string[] {
  if (!body) return [];
  let base: URL;
  try {
    base = new URL(baseUrl);
  } catch {
    return [];
  }
  const out = new Set<string>();
  const re = /(?:\/\/[#@]|\/\*)\s*sourceMappingURL\s*=\s*(\S+)/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(body)) !== null) {
    let raw = m[1]!.trim().replace(/[*\/]+$/, '').trim();
    if (!raw || raw.startsWith('data:')) continue;
    try {
      const abs = new URL(raw, base);
      if (abs.protocol !== 'http:' && abs.protocol !== 'https:') continue;
      out.add(abs.toString());
    } catch {
      /* skip */
    }
    if (out.size >= MAX_MAPS) break;
  }
  return [...out];
}

export function isSourceMapJson(body: string): boolean {
  if (!body || body.length > 5_000_000) return false;
  const trimmed = body.trim();
  if (!trimmed.startsWith('{')) return false;
  try {
    const j = JSON.parse(trimmed) as { version?: unknown; sources?: unknown; mappings?: unknown };
    return (
      j &&
      typeof j === 'object' &&
      (j.version === 3 || j.version === '3') &&
      (Array.isArray(j.sources) || typeof j.mappings === 'string')
    );
  } catch {
    return /"version"\s*:\s*3/.test(trimmed) && /"sources"\s*:|"mappings"\s*:/.test(trimmed);
  }
}

export function hasSourcesContent(body: string): boolean {
  if (!isSourceMapJson(body)) return false;
  try {
    const j = JSON.parse(body) as { sourcesContent?: unknown };
    return Array.isArray(j.sourcesContent) && j.sourcesContent.some((s) => typeof s === 'string' && s.length > 0);
  } catch {
    return /"sourcesContent"\s*:\s*\[\s*"/.test(body);
  }
}

export function shouldProbeSourcemap(probe: {
  url: string;
  status: number;
  headers: Record<string, string>;
  body: string;
  error?: string;
}): boolean {
  if (probe.error || probe.status < 200 || probe.status >= 300) return false;
  const ct = (probe.headers['content-type'] ?? '').toLowerCase();
  const path = safePath(probe.url);
  if (ct.includes('javascript') || ct.includes('ecmascript') || path.endsWith('.js')) return true;
  if (ct.includes('css') || path.endsWith('.css')) return true;
  if (/sourceMappingURL\s*=/i.test(probe.body ?? '')) return true;
  return false;
}

export function buildSourcemapFollowUpUrls(probe: ProbeResult): string[] {
  if (!shouldProbeSourcemap(probe)) return [];
  const base = probe.finalUrl ?? probe.url;
  const urls = extractSourceMappingUrls(probe.body ?? '', base);
  // Same-origin only for follow-up GETs (caller still scope-filters).
  let host: string;
  try {
    host = new URL(base).hostname;
  } catch {
    return [];
  }
  return urls.filter((u) => {
    try {
      return new URL(u).hostname === host;
    } catch {
      return false;
    }
  });
}

function safePath(url: string): string {
  try {
    return new URL(url).pathname.toLowerCase();
  } catch {
    return url.toLowerCase();
  }
}
