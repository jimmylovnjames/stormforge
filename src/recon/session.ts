// Session header helpers for authenticated recon.
// Never log cookie / Authorization values.

import type { ScanSession } from '../types.js';

/** True when the request carries any usable session material. */
export function hasSession(session?: ScanSession): boolean {
  if (!session) return false;
  if (session.cookie?.trim()) return true;
  if (session.authorization?.trim()) return true;
  if (session.headers && Object.keys(session.headers).length > 0) return true;
  return false;
}

/** Build request headers from a ScanSession (cookie / Authorization / extras). */
export function sessionHeaders(session?: ScanSession): Record<string, string> {
  if (!session || !hasSession(session)) return {};
  const out: Record<string, string> = {};
  if (session.headers) {
    for (const [k, v] of Object.entries(session.headers)) {
      if (typeof k === 'string' && typeof v === 'string' && k.trim()) {
        out[k.toLowerCase()] = v;
      }
    }
  }
  if (session.cookie?.trim()) out.cookie = session.cookie.trim();
  if (session.authorization?.trim()) out.authorization = session.authorization.trim();
  return out;
}

/** Validate session shape; returns an error message or null. Does not echo secrets. */
export function validateSession(session?: ScanSession): string | null {
  if (session === undefined || session === null) return null;
  if (typeof session !== 'object' || Array.isArray(session)) {
    return 'session must be an object';
  }
  if (session.cookie !== undefined) {
    if (typeof session.cookie !== 'string') return 'session.cookie must be a string';
    if (/[\r\n]/.test(session.cookie)) return 'session.cookie must not contain newlines';
    if (session.cookie.length > 8192) return 'session.cookie too long (max 8192)';
  }
  if (session.authorization !== undefined) {
    if (typeof session.authorization !== 'string') return 'session.authorization must be a string';
    if (/[\r\n]/.test(session.authorization)) return 'session.authorization must not contain newlines';
    if (session.authorization.length > 8192) return 'session.authorization too long (max 8192)';
  }
  if (session.headers !== undefined) {
    if (typeof session.headers !== 'object' || session.headers === null || Array.isArray(session.headers)) {
      return 'session.headers must be an object of string values';
    }
    const entries = Object.entries(session.headers);
    if (entries.length > 32) return 'session.headers has too many keys (max 32)';
    for (const [k, v] of entries) {
      if (typeof k !== 'string' || typeof v !== 'string') {
        return 'session.headers keys and values must be strings';
      }
      if (!k.trim()) return 'session.headers keys must be non-empty';
      if (/[\r\n]/.test(k) || /[\r\n]/.test(v)) {
        return 'session.headers must not contain newlines';
      }
      if (v.length > 8192) return 'session.headers value too long';
      // Block hop-by-hop / dangerous overrides.
      const lk = k.toLowerCase();
      if (lk === 'host' || lk === 'content-length' || lk === 'transfer-encoding') {
        return `session.headers must not set ${lk}`;
      }
    }
  }
  return null;
}
