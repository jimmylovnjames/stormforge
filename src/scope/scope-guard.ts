// Scope enforcement — the single most important safety component.
//
// Every outbound probe passes through `assertInScope`. If a target is not
// explicitly authorized, the probe is refused before any network I/O. This is
// what keeps StormForge on the right side of a bug-bounty program's rules.

import type { Scope } from '../types.js';

export class ScopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ScopeError';
  }
}

/** Parse a URL or bare host into a normalized lowercase hostname. */
export function hostOf(target: string): string {
  let raw = target.trim();
  if (!/^https?:\/\//i.test(raw)) raw = `https://${raw}`;
  try {
    return new URL(raw).hostname.toLowerCase();
  } catch {
    throw new ScopeError(`Cannot parse host from target: ${target}`);
  }
}

/** Does `host` match a single pattern? Supports one leading "*." wildcard. */
export function hostMatches(host: string, pattern: string): boolean {
  const p = pattern.trim().toLowerCase();
  if (p === host) return true;
  if (p.startsWith('*.')) {
    const suffix = p.slice(1); // ".acme.com"
    // "*.acme.com" matches "a.acme.com" but NOT the apex "acme.com".
    return host.endsWith(suffix) && host.length > suffix.length;
  }
  return false;
}

export interface ScopeDecision {
  allowed: boolean;
  host: string;
  reason: string;
}

/** Pure decision function — testable without throwing. */
export function evaluateScope(target: string, scope: Scope): ScopeDecision {
  if (!scope.authorized) {
    return { allowed: false, host: '', reason: 'Scope is not marked authorized' };
  }
  let host: string;
  try {
    host = hostOf(target);
  } catch (e) {
    return { allowed: false, host: '', reason: (e as Error).message };
  }
  // Out-of-scope always wins.
  for (const pattern of scope.outOfScope) {
    if (hostMatches(host, pattern)) {
      return { allowed: false, host, reason: `Host matches out-of-scope pattern: ${pattern}` };
    }
  }
  for (const pattern of scope.inScope) {
    if (hostMatches(host, pattern)) {
      return { allowed: true, host, reason: `Matches in-scope pattern: ${pattern}` };
    }
  }
  return { allowed: false, host, reason: 'Host not present in inScope list' };
}

/** Throws ScopeError if the target may not be probed. */
export function assertInScope(target: string, scope: Scope): void {
  const decision = evaluateScope(target, scope);
  if (!decision.allowed) {
    throw new ScopeError(`Refused (out of scope): ${target} — ${decision.reason}`);
  }
}

/** Filter a candidate target list down to the authorized subset. */
export function partitionByScope(
  targets: string[],
  scope: Scope,
): { allowed: string[]; refused: { target: string; reason: string }[] } {
  const allowed: string[] = [];
  const refused: { target: string; reason: string }[] = [];
  for (const t of targets) {
    const d = evaluateScope(t, scope);
    if (d.allowed) allowed.push(t);
    else refused.push({ target: t, reason: d.reason });
  }
  return { allowed, refused };
}
