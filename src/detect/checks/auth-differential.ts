// Authenticated horizontal IDOR — compare account markers across numeric IDs
// under the same session. Pure over ProbeResults (no I/O).

import type { Check, Finding, ProbeResult } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';
import { classifyPath } from './auth-access.js';

const EMAIL_RE = /"(?:email|user_email|mail)"\s*:\s*"([^"]+@[^"]+)"/i;
const USERNAME_RE = /"(?:username|user_name|login)"\s*:\s*"([^"]{2,64})"/i;
const ID_RE = /"(?:id|user_id|account_id)"\s*:\s*"?(\d{1,12})"?/i;

/**
 * Standalone check: single probe that looks like authenticated object access
 * with PII (used when session headers were present). Complements anon auth-access.
 */
export const authDifferentialCheck: Check = {
  id: 'auth-differential',
  title: 'Authenticated access-control / horizontal IDOR',
  cwe: 'CWE-639',
  run(probe: ProbeResult): Finding[] {
    // Multi-probe correlation runs via findHorizontalIdor(); single-probe is a no-op.
    void probe;
    return [];
  },
};

export interface AccountMarkers {
  email?: string;
  username?: string;
  objectId?: string;
}

export function extractAccountMarkers(body: string): AccountMarkers {
  const out: AccountMarkers = {};
  const email = body.match(EMAIL_RE)?.[1];
  if (email) out.email = email.toLowerCase();
  const username = body.match(USERNAME_RE)?.[1];
  if (username) out.username = username.toLowerCase();
  const objectId = body.match(ID_RE)?.[1];
  if (objectId) out.objectId = objectId;
  return out;
}

/**
 * When the same session retrieves different account identities on sibling
 * object paths (/users/1 vs /users/2), flag horizontal IDOR.
 */
export function findHorizontalIdor(probes: ProbeResult[]): Finding[] {
  type Entry = { probe: ProbeResult; base: string; id: string; markers: AccountMarkers };
  const byBase = new Map<string, Entry[]>();

  for (const p of probes) {
    if (p.error || !p.body) continue;
    if (p.status < 200 || p.status >= 300) continue;
    const pathClass = classifyPath(p.finalUrl ?? p.url);
    if (!pathClass || pathClass.kind === 'auth-bypass') continue;

    const parsed = splitObjectPath(p.finalUrl ?? p.url);
    if (!parsed) continue;
    const markers = extractAccountMarkers(p.body);
    if (!markers.email && !markers.username) continue;

    const list = byBase.get(parsed.base) ?? [];
    list.push({ probe: p, base: parsed.base, id: parsed.id, markers });
    byBase.set(parsed.base, list);
  }

  const findings: Finding[] = [];
  for (const [, entries] of byBase) {
    if (entries.length < 2) continue;
    // Distinct identity markers across IDs under one session.
    const identities = new Set(
      entries.map((e) => e.markers.email ?? e.markers.username ?? '').filter(Boolean),
    );
    if (identities.size < 2) continue;

    const sample = entries.slice(0, 4);
    const target = sample[0]!.probe.url;
    const evidenceLines = sample.map(
      (e) =>
        `ID ${e.id}: status=${e.probe.status} email=${e.markers.email ?? '-'} username=${e.markers.username ?? '-'}`,
    );

    findings.push({
      id: makeFindingId('auth-differential', target, `horizontal:${[...identities].sort().join(',')}`),
      checkId: 'auth-differential',
      title: 'Possible horizontal IDOR — session can read multiple users’ objects',
      severity: 'high',
      target,
      description:
        'With the same authenticated session, GETs to sibling object IDs returned different account identities (emails/usernames). This is a strong broken object-level authorization (horizontal IDOR) candidate.',
      evidence: `Compared paths under ${sample[0]!.base}\n${evidenceLines.join('\n')}\nBody preview (${sample[0]!.id}): ${preview(sample[0]!.probe.body)}`,
      reproduction: [
        'Authenticate with a low-privilege account',
        `curl -s -H 'Cookie: <session>' '${sample[0]!.probe.url}'`,
        `curl -s -H 'Cookie: <session>' '${sample[1]!.probe.url}'`,
        'Confirm each response contains a different user’s email/username — do not modify data',
      ],
      remediation:
        'Enforce object-level authorization: the authenticated principal may only read objects they own (or are explicitly granted). Prefer opaque IDs; never authorize solely by knowing a numeric ID.',
      cwe: 'CWE-639',
      references: [
        'https://cwe.mitre.org/data/definitions/639.html',
        'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/',
      ],
      needsManualReview: true,
      discoveredAt: new Date().toISOString(),
    });
  }
  return findings;
}

/**
 * Anon 401/403 vs auth 2xx with PII is expected. Flag when anon already gets
 * 2xx with PII *and* auth returns different richer admin markers (privilege gap signal).
 * More useful: flag when anon and auth return *identical* privileged bodies on admin paths
 * (session not required) — covered by auth-access on anon probes.
 *
 * This helper flags: auth-only admin surface returning is_admin / role=admin markers
 * on `/admin` after session was required (anon was 401) — informational privilege map,
 * not a vuln by itself. Skip — keep focused on horizontal IDOR only.
 */
export function buildNeighborIdUrls(url: string, neighbors = [2, 3]): string[] {
  const parsed = splitObjectPath(url);
  if (!parsed) return [];
  const out: string[] = [];
  for (const n of neighbors) {
    if (String(n) === parsed.id) continue;
    out.push(`${parsed.origin}${parsed.base}/${n}${parsed.suffix}`);
  }
  return out;
}

function splitObjectPath(url: string): { origin: string; base: string; id: string; suffix: string } | null {
  try {
    const u = new URL(url);
    const m = u.pathname.match(
      /^(.*\/(?:users?|accounts?|profiles?|orders?|customers?|user|account|profile|order))\/(\d+)(\/.*)?$/i,
    );
    if (!m) return null;
    return {
      origin: u.origin,
      base: m[1]!,
      id: m[2]!,
      suffix: m[3] ?? '',
    };
  } catch {
    return null;
  }
}

function preview(body: string): string {
  return body.slice(0, 200).replace(/\s+/g, ' ');
}
