// OAST poller: harvest collaborator interactions, correlate to emitted payloads,
// persist hits, and raise a confirmed blind-SSRF finding on first correlation.
// Callable from the control plane (POST /api/oast/poll) and any autonomous loop.

import type { Env, Finding } from '../types.js';
import { OastStore } from './store.js';
import { parseCollaborator, pollRequestUrl, parsePollResponse } from './collaborator.js';
import type { OastPayload, OastPollSummary } from './types.js';
import { FindingsStore } from '../findings/store.js';
import { makeFindingId } from '../findings/id.js';
import { auditLog } from '../audit/log.js';

const DEFAULT_LOOKBACK_MS = 60 * 60 * 1000; // 1h on first poll
const POLL_TIMEOUT_MS = 12_000;

export async function pollAndCorrelate(env: Env, now = Date.now()): Promise<OastPollSummary> {
  const cfg = parseCollaborator(env);
  if (!cfg) {
    return { configured: false, polled: 0, newHits: 0, confirmed: 0, since: new Date(0).toISOString(), at: new Date(now).toISOString(), error: 'OAST_COLLABORATOR_ENDPOINT not set' };
  }

  const store = new OastStore(env.STORMFORGE_KV);
  const last = (await store.getLastPoll()) ?? now - DEFAULT_LOOKBACK_MS;

  let hits;
  try {
    const res = await fetch(pollRequestUrl(cfg, last), {
      headers: { accept: 'application/json' },
      signal: AbortSignal.timeout(POLL_TIMEOUT_MS),
    });
    if (!res.ok) throw new Error(`collaborator poll ${res.status}`);
    const json = await res.json();
    hits = parsePollResponse(json, cfg.callbackDomain);
  } catch (e) {
    return {
      configured: true,
      polled: 0,
      newHits: 0,
      confirmed: 0,
      since: new Date(last).toISOString(),
      at: new Date(now).toISOString(),
      error: (e as Error).message,
    };
  }

  const findingsStore = new FindingsStore(env.STORMFORGE_KV);
  let newHits = 0;
  let confirmed = 0;

  for (const hit of hits) {
    const rec = await store.recordHit(hit);
    if (!rec) continue; // interaction for a token we didn't emit (other tenant) — ignore
    newHits++;
    if (rec.isFirstHit) {
      confirmed++;
      const finding = buildConfirmedFinding(rec.payload, hit.channel, hit.remoteAddress);
      await findingsStore.upsertMany(rec.payload.program, [finding], { keepRecon: true });
      await auditLog(env, {
        action: 'task.complete',
        detail: `OAST confirmed ${rec.payload.vector} on ${rec.payload.target} (${hit.channel})`,
        target: rec.payload.target,
        program: rec.payload.program,
        meta: { token: rec.payload.token, channel: hit.channel, scanId: rec.payload.scanId },
      });
    }
  }

  await store.setLastPoll(now);
  return {
    configured: true,
    polled: hits.length,
    newHits,
    confirmed,
    since: new Date(last).toISOString(),
    at: new Date(now).toISOString(),
  };
}

export function buildConfirmedFinding(
  payload: OastPayload,
  channel: string,
  remoteAddress?: string,
): Finding {
  return {
    id: makeFindingId('ssrf-oast-confirmed', payload.target, `${payload.vector}:${payload.token}`),
    checkId: 'ssrf-oast-confirmed',
    title: `Blind SSRF / out-of-band interaction confirmed (${payload.vector})`,
    severity: 'critical',
    target: payload.target,
    description: `An out-of-band ${channel.toUpperCase()} interaction was received on a unique, unguessable canary that was injected via \`${payload.vector}\`. The target's backend initiated a request to attacker-controlled infrastructure — confirming server-side request forgery (or equivalent blind out-of-band vulnerability). Impact ranges from internal network access and cloud-metadata theft to full compromise.`,
    evidence: `Injected vector: ${payload.vector}\nTarget: ${payload.target}\nCanary host: ${payload.host}\nChannel: ${channel}\nInteraction source: ${remoteAddress ?? '<unknown>'}\nScan/execution: ${payload.scanId}\nToken: ${payload.token}`,
    reproduction: [
      `Re-issue the request to ${payload.target} with the canary URL in \`${payload.vector}\``,
      `Observe an out-of-band ${channel} interaction on the collaborator for token ${payload.token}`,
      'Escalate carefully within RoE (e.g. fetch internal metadata) only if the program permits',
    ],
    remediation:
      'Do not fetch attacker-controlled URLs server-side. Enforce an allowlist of destinations, block internal/link-local ranges and cloud metadata IPs, disable unused URL schemes, and require DNS-rebinding-safe validation.',
    cwe: 'CWE-918',
    references: [
      'https://cwe.mitre.org/data/definitions/918.html',
      'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery',
    ],
    needsManualReview: true,
    evidenceGrade: 'canary',
    confidence: 0.95,
    submitReady: true,
    source: 'worker',
    discoveredAt: new Date().toISOString(),
  };
}
