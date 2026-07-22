// OAST collaborator contract (pure). StormForge speaks a small, generic HTTP
// polling protocol so any self-hosted/adapter collaborator can be plugged in via
// the OAST_COLLABORATOR_ENDPOINT secret. See README "OAST" for the exact format.

import type { Env } from '../types.js';
import type { OastChannel, OastHit } from './types.js';

export interface CollaboratorConfig {
  /** Base for the poll API; poll happens at `${pollBase}/poll`. */
  pollBase: string;
  /** Domain callbacks land on: `<token>.<callbackDomain>`. */
  callbackDomain: string;
}

export function oastConfigured(env: Env): boolean {
  return !!(env.OAST_COLLABORATOR_ENDPOINT && env.OAST_COLLABORATOR_ENDPOINT.trim());
}

/**
 * Parse OAST_COLLABORATOR_ENDPOINT. Two accepted forms:
 *   1) "https://collab.example.com"
 *        → poll `https://collab.example.com/poll`, callbacks `<token>.collab.example.com`
 *   2) "https://poll.example.com/base|callback.example.com"
 *        → poll `https://poll.example.com/base/poll`, callbacks `<token>.callback.example.com`
 */
export function parseCollaborator(env: Env): CollaboratorConfig | null {
  const raw = (env.OAST_COLLABORATOR_ENDPOINT ?? '').trim();
  if (!raw) return null;
  const [urlPart, cbPart] = raw.split('|').map((s) => s.trim());
  if (!urlPart) return null;
  let base: URL;
  try {
    base = new URL(urlPart.includes('://') ? urlPart : `https://${urlPart}`);
  } catch {
    return null;
  }
  const pollBase = `${base.origin}${base.pathname.replace(/\/+$/, '')}`;
  const callbackDomain = (cbPart || base.hostname).toLowerCase().replace(/^\.+|\.+$/g, '');
  if (!callbackDomain.includes('.')) return null;
  return { pollBase, callbackDomain };
}

/** Unique, DNS-label-safe per-execution token (<=20 chars, [a-z0-9]). */
export function newOastToken(): string {
  const hex = crypto.randomUUID().replace(/-/g, '');
  return `sf${hex.slice(0, 18)}`;
}

/** Build the full injected callback for a token (HTTP for broad SSRF reach). */
export function buildOastPayload(
  cfg: CollaboratorConfig,
  token: string,
): { token: string; host: string; url: string } {
  const host = `${token}.${cfg.callbackDomain}`;
  return { token, host, url: `http://${host}/${token}` };
}

/** Poll request URL for interactions since `sinceMs` (unix ms). */
export function pollRequestUrl(cfg: CollaboratorConfig, sinceMs: number): string {
  return `${cfg.pollBase}/poll?since=${encodeURIComponent(String(Math.floor(sinceMs)))}`;
}

/** Extract our token (the label immediately left of the callback domain). */
export function extractToken(host: string, callbackDomain: string): string | null {
  const h = host.toLowerCase().replace(/\.$/, '');
  const suffix = `.${callbackDomain.toLowerCase()}`;
  if (!h.endsWith(suffix)) return null;
  const left = h.slice(0, -suffix.length);
  if (!left) return null;
  const label = left.split('.').pop() ?? left;
  return /^sf[a-z0-9]{4,}$/.test(label) ? label : label || null;
}

function normalizeChannel(v: unknown): OastChannel {
  const s = String(v ?? '').toLowerCase();
  if (s.includes('dns')) return 'dns';
  if (s.includes('https')) return 'https';
  if (s.includes('http')) return 'http';
  return 'unknown';
}

interface RawHit {
  id?: string;
  host?: string;
  name?: string;
  type?: string;
  protocol?: string;
  remoteAddress?: string;
  'remote-address'?: string;
  source?: string;
  timestamp?: string;
  at?: string;
  path?: string;
  raw?: string;
}

/**
 * Normalize a collaborator poll response into OastHits. Correlation token is the
 * DNS label under the callback domain, or an explicit `id` field.
 * Expected shape: { "hits": [ { host|name, type|protocol, remoteAddress?, timestamp?, path?, raw? } ] }
 */
export function parsePollResponse(json: unknown, callbackDomain: string): OastHit[] {
  const hits = (json as { hits?: RawHit[] } | null)?.hits;
  if (!Array.isArray(hits)) return [];
  const out: OastHit[] = [];
  for (const h of hits) {
    const host = String(h.host ?? h.name ?? '').toLowerCase();
    const token = extractToken(host, callbackDomain) ?? (h.id ? String(h.id).toLowerCase() : '');
    if (!token) continue;
    out.push({
      token,
      channel: normalizeChannel(h.type ?? h.protocol),
      host,
      remoteAddress: h.remoteAddress ?? h['remote-address'] ?? h.source,
      at: h.timestamp ?? h.at ?? new Date().toISOString(),
      path: h.path,
      raw: typeof h.raw === 'string' ? h.raw.slice(0, 500) : undefined,
    });
  }
  return out;
}
