// Reflected XSS / HTML reflection — passive query reflection + RoE-gated canary.

import type { Check, Finding, ProbeResult } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';
import {
  ACTIVE_MARKER_HEADER,
  ACTIVE_PARAM_HEADER,
  ACTIVE_CANARY_HEADER,
} from '../../recon/active-probes.js';

export type ReflectionContext = 'html' | 'attribute' | 'script' | 'unknown';

/** Classify how a reflected needle sits in an HTML document (best-effort). */
export function classifyReflection(body: string, needle: string): ReflectionContext {
  const idx = body.indexOf(needle);
  if (idx < 0) return 'unknown';
  const before = body.slice(Math.max(0, idx - 80), idx);
  if (/<script\b[^>]*>[^<]*$/i.test(before) || /(?:^|[^\\])['"`][^'"`]*$/i.test(before) && /<script/i.test(before)) {
    return 'script';
  }
  // Inside a tag's attribute value (unescaped quote break is highest signal).
  if (/<[a-z][^>]*$/i.test(before)) return 'attribute';
  return 'html';
}

/** True when needle appears raw (not HTML-entity-encoded) in the body. */
export function reflectsUnescaped(body: string, needle: string): boolean {
  if (!body || !needle || needle.length < 4) return false;
  if (!body.includes(needle)) return false;
  // If the only occurrences are entity-encoded forms, treat as escaped.
  const enc = needle
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
  if (body.includes(enc) && !countRaw(body, needle)) return false;
  return true;
}

function countRaw(body: string, needle: string): number {
  let n = 0;
  let i = 0;
  while ((i = body.indexOf(needle, i)) !== -1) {
    n++;
    i += needle.length;
  }
  return n;
}

function isHtml(probe: ProbeResult): boolean {
  const ct = (probe.headers['content-type'] ?? '').toLowerCase();
  return ct.includes('text/html') || ct.includes('application/xhtml') || ct === '';
}

function queryParams(url: string): Array<{ name: string; value: string }> {
  try {
    const u = new URL(url.includes('://') ? url : `https://${url}`);
    const out: Array<{ name: string; value: string }> = [];
    u.searchParams.forEach((value, name) => {
      if (value && value.length >= 4 && name !== 'sf_cb') out.push({ name, value });
    });
    return out;
  } catch {
    return [];
  }
}

function findingFor(
  checkId: string,
  probe: ProbeResult,
  param: string,
  needle: string,
  ctx: ReflectionContext,
  active: boolean,
): Finding {
  const sev = ctx === 'script' || ctx === 'attribute' ? 'high' : 'medium';
  return {
    id: makeFindingId(checkId, probe.url, `${param}:${ctx}`),
    checkId,
    title: active
      ? `Reflected XSS candidate via \`${param}\` (${ctx} context)`
      : `Query value reflected unescaped via \`${param}\` (${ctx} context)`,
    severity: sev,
    target: probe.url,
    description: active
      ? `An injected canary in \`${param}\` was reflected unescaped into the HTML response (${ctx} context). This is a strong XSS lead — confirm executable context and CSP bypass before filing.`
      : `The \`${param}\` query value appears unescaped in the HTML response (${ctx} context). Unescaped reflection is a prerequisite for reflected XSS.`,
    evidence: `URL: ${probe.url}\nStatus: ${probe.status}\nParameter: ${param}\nContext: ${ctx}\nNeedle (truncated): ${needle.slice(0, 64)}\nActive canary: ${active ? 'yes' : 'no'}`,
    reproduction: [
      `curl -s '${probe.url}' | head`,
      `Confirm the ${active ? 'canary' : 'query value'} appears unescaped in the ${ctx} context`,
      'Craft a context-appropriate payload (do not attack real users; keep within RoE)',
    ],
    remediation:
      'Context-encode all reflected input (HTML / attribute / JS). Prefer a strict CSP without unsafe-inline; use trusted-types where available.',
    cwe: 'CWE-79',
    references: [
      'https://cwe.mitre.org/data/definitions/79.html',
      'https://owasp.org/www-community/attacks/xss/',
    ],
    needsManualReview: true,
    evidenceGrade: active ? 'canary' : 'fingerprint',
    confidence: active ? (ctx === 'html' ? 0.75 : 0.88) : ctx === 'html' ? 0.55 : 0.7,
    submitReady: active && (ctx === 'script' || ctx === 'attribute'),
    source: 'worker',
    discoveredAt: new Date().toISOString(),
  };
}

export const xssReflectionCheck: Check = {
  id: 'xss-reflection',
  title: 'Reflected XSS / HTML reflection',
  cwe: 'CWE-79',
  run(probe: ProbeResult): Finding[] {
    if (probe.error || !probe.body || !isHtml(probe)) return [];

    // Active canary path (scanner stamps markers on the probe).
    if ((probe.headers[ACTIVE_MARKER_HEADER] ?? '') === 'xss-reflection') {
      const param = probe.headers[ACTIVE_PARAM_HEADER] ?? 'q';
      const canary = probe.headers[ACTIVE_CANARY_HEADER] ?? '';
      if (!canary || !reflectsUnescaped(probe.body, canary)) return [];
      const ctx = classifyReflection(probe.body, canary);
      return [findingFor(this.id, probe, param, canary, ctx, true)];
    }

    // Passive: existing query values reflected unescaped.
    const findings: Finding[] = [];
    const seen = new Set<string>();
    for (const { name, value } of queryParams(probe.url).slice(0, 8)) {
      // Skip boring numeric / uuid-looking values to cut noise.
      if (/^\d+$/.test(value) || /^[0-9a-f-]{36}$/i.test(value)) continue;
      if (!reflectsUnescaped(probe.body, value)) continue;
      const ctx = classifyReflection(probe.body, value);
      const key = `${name}:${ctx}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push(findingFor(this.id, probe, name, value, ctx, false));
    }
    return findings;
  },
};
