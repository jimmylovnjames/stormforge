// Correlate related findings into kill-chain style attack narratives for bounty drafts.

import type { Finding, Scope, Severity } from '../types.js';
import { SEVERITY_ORDER } from '../types.js';

export type AttackChainKind =
  | 'auth-takeover'
  | 'ssrf-chain'
  | 'injection-to-rce'
  | 'cache-to-account'
  | 'secret-to-cloud';

export interface AttackChain {
  id: string;
  kind: AttackChainKind;
  title: string;
  severity: Severity;
  host: string;
  findingIds: string[];
  narrative: string;
  program: string;
}

const AUTH_CHECKS = new Set([
  'auth-access-control',
  'auth-differential',
  'weak-jwt',
  'oauth-misconfig',
]);
const SSRF_CHECKS = new Set(['ssrf-open-redirect', 'ssrf-blind-canary']);
const INJECTION_CHECKS = new Set([
  'sql-injection-error',
  'command-injection',
  'xss-injection',
  'path-traversal',
  'prototype-pollution',
  'http-parameter-pollution',
]);
const CACHE_CHECKS = new Set(['cache-deception', 'cache-poisoning']);
const SECRET_CHECKS = new Set(['secret-exposure', 'cloud-bucket-exposure']);

export function correlateAttackChains(findings: Finding[], scope: Scope): AttackChain[] {
  const byHost = new Map<string, Finding[]>();
  for (const f of findings) {
    if (f.severity === 'info' || f.severity === 'low') continue;
    const host = hostOf(f.target);
    if (!host) continue;
    const list = byHost.get(host) ?? [];
    list.push(f);
    byHost.set(host, list);
  }

  const chains: AttackChain[] = [];
  for (const [host, group] of byHost) {
    const auth = group.filter((f) => AUTH_CHECKS.has(f.checkId));
    if (auth.some((f) => /jwt|oauth/i.test(f.checkId)) && auth.some((f) => /auth-access|auth-differential/i.test(f.checkId))) {
      chains.push(
        makeChain('auth-takeover', host, auth, scope.program, 'Authentication bypass + object access'),
      );
    }

    const ssrf = group.filter((f) => SSRF_CHECKS.has(f.checkId));
    if (ssrf.length >= 2 || (ssrf.some((f) => f.checkId === 'ssrf-blind-canary') && ssrf.length >= 1 && group.some((f) => f.cwe === 'CWE-601'))) {
      const members = [
        ...ssrf,
        ...group.filter((f) => f.cwe === 'CWE-601' && !ssrf.includes(f)),
      ];
      if (members.length >= 2) {
        chains.push(makeChain('ssrf-chain', host, members, scope.program, 'Open redirect / SSRF escalation'));
      }
    }

    const inj = group.filter((f) => INJECTION_CHECKS.has(f.checkId));
    if (inj.some((f) => f.checkId === 'command-injection') && inj.length >= 2) {
      chains.push(makeChain('injection-to-rce', host, inj, scope.program, 'Injection cluster with RCE potential'));
    }

    const cache = group.filter((f) => CACHE_CHECKS.has(f.checkId));
    if (cache.length && group.some((f) => AUTH_CHECKS.has(f.checkId) || /account|me|profile/i.test(f.target))) {
      const members = [
        ...cache,
        ...group.filter((f) => AUTH_CHECKS.has(f.checkId) || /\/(me|account|profile)/i.test(f.target)),
      ];
      if (members.length >= 2) {
        chains.push(makeChain('cache-to-account', host, members, scope.program, 'Cache abuse → account data'));
      }
    }

    const secrets = group.filter((f) => SECRET_CHECKS.has(f.checkId));
    if (secrets.length >= 2 || (secrets.length && group.some((f) => f.checkId === 'cloud-bucket-exposure'))) {
      chains.push(makeChain('secret-to-cloud', host, secrets, scope.program, 'Secret / cloud exposure cluster'));
    }
  }

  return chains.sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]);
}

function makeChain(
  kind: AttackChainKind,
  host: string,
  members: Finding[],
  program: string,
  titlePrefix: string,
): AttackChain {
  const uniq = [...new Map(members.map((m) => [m.id, m])).values()];
  const severity = uniq.reduce<Severity>(
    (best, f) => (SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[best] ? f.severity : best),
    'medium',
  );
  const checks = [...new Set(uniq.map((f) => f.checkId))].join(' + ');
  return {
    id: `chain:${kind}:${host}`,
    kind,
    title: `${titlePrefix} on ${host}`,
    severity,
    host,
    findingIds: uniq.map((f) => f.id),
    narrative: `Correlated ${uniq.length} findings (${checks}) on ${host}. Combined, these strengthen a single bounty narrative rather than isolated tickets.`,
    program,
  };
}

function hostOf(url: string): string | null {
  try {
    return new URL(url.includes('://') ? url : `https://${url}`).hostname.toLowerCase();
  } catch {
    return null;
  }
}
