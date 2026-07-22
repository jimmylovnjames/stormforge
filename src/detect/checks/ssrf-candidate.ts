// SSRF-candidate tagging (passive surface tag).
//
// Flags high-risk parameters/contexts (URL-valued params, redirect/callback/
// webhook fields, file-inclusion paths) so they are prioritized during active
// OAST testing and surfaced in reports/queries. Emits at most one finding per
// URL summarizing its risky parameters. Confirmation happens out-of-band (OAST).

import type { Check, Finding, ProbeResult } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';

/** Parameter names that frequently take a URL / host / path (SSRF-prone). */
export const SSRF_PARAM_NAMES = new Set([
  'url', 'uri', 'link', 'href', 'src', 'source', 'dest', 'destination',
  'redirect', 'redirect_uri', 'redirecturl', 'redirect_url', 'return', 'returnurl',
  'return_to', 'next', 'continue', 'target', 'to', 'out', 'view', 'window',
  'file', 'path', 'page', 'template', 'include', 'inc', 'document', 'doc', 'folder',
  'img', 'image', 'imageurl', 'image_url', 'load', 'fetch', 'get', 'proxy',
  'forward', 'feed', 'host', 'domain', 'site', 'callback', 'callbackurl',
  'callback_url', 'webhook', 'webhook_url', 'webhookurl', 'notify', 'notifyurl',
  'upload', 'uploadurl', 'data', 'resource', 'open', 'api', 'apiurl', 'endpoint',
  'remote', 'ref', 'u', 'q', 'sourceurl', 'origin', 'referer', 'referrer', 'sync',
]);

/** File-inclusion-prone parameter names (LFI/RFI → SSRF via wrappers). */
const FILE_PARAM_NAMES = new Set([
  'file', 'path', 'template', 'include', 'inc', 'doc', 'document', 'page', 'view', 'folder', 'load', 'require',
]);

export type SsrfKind = 'url-param' | 'redirect' | 'callback' | 'file-inclusion' | 'host-param';

export interface SsrfCandidate {
  param: string;
  kind: SsrfKind;
  confidence: 'high' | 'medium';
  reason: string;
}

const URL_VALUE = /^(?:https?:)?\/\/|^https?%3a%2f%2f|:\/\//i;
const PATH_TRAVERSAL = /\.\.(?:\/|%2f|\\)/i;
const ABSOLUTE_PATH = /^(?:\/|%2f|[a-z]:\\|file:)/i;

/** Detect SSRF-candidate parameters on a URL (recon/param-discovery tagging). */
export function detectSsrfCandidates(rawUrl: string): SsrfCandidate[] {
  let params: URLSearchParams;
  try {
    params = new URL(rawUrl.includes('://') ? rawUrl : `https://${rawUrl}`).searchParams;
  } catch {
    return [];
  }
  const out: SsrfCandidate[] = [];
  const seen = new Set<string>();

  for (const [rawName, value] of params.entries()) {
    const name = rawName.toLowerCase();
    if (seen.has(name)) continue;
    const nameMatch = SSRF_PARAM_NAMES.has(name);
    const valueIsUrl = URL_VALUE.test(value);
    const isFileParam = FILE_PARAM_NAMES.has(name);
    const traversal = PATH_TRAVERSAL.test(value) || ABSOLUTE_PATH.test(value);

    let candidate: SsrfCandidate | null = null;
    if (isFileParam && (traversal || valueIsUrl)) {
      candidate = { param: rawName, kind: 'file-inclusion', confidence: 'high', reason: `file/path param with ${valueIsUrl ? 'URL' : 'traversal/absolute'} value` };
    } else if (/redirect|return|next|continue|dest|to\b/.test(name) && (nameMatch || valueIsUrl)) {
      candidate = { param: rawName, kind: 'redirect', confidence: valueIsUrl ? 'high' : 'medium', reason: `redirect-style param${valueIsUrl ? ' with URL value' : ''}` };
    } else if (/callback|webhook|notify/.test(name)) {
      candidate = { param: rawName, kind: 'callback', confidence: valueIsUrl ? 'high' : 'medium', reason: `callback/webhook param${valueIsUrl ? ' with URL value' : ''}` };
    } else if (name === 'host' || name === 'domain' || name === 'site') {
      candidate = { param: rawName, kind: 'host-param', confidence: 'medium', reason: 'host/domain-valued param' };
    } else if (nameMatch || valueIsUrl) {
      candidate = { param: rawName, kind: 'url-param', confidence: nameMatch && valueIsUrl ? 'high' : 'medium', reason: nameMatch && valueIsUrl ? 'known URL param with URL value' : nameMatch ? 'known URL-valued param name' : 'param value looks like a URL' };
    }

    if (candidate) {
      seen.add(name);
      out.push(candidate);
    }
  }
  return out;
}

export const ssrfCandidateCheck: Check = {
  id: 'ssrf-candidate',
  title: 'SSRF candidate parameter (needs OAST confirmation)',
  cwe: 'CWE-918',
  run(probe: ProbeResult): Finding[] {
    if (probe.error) return [];
    const url = probe.finalUrl ?? probe.url;
    const candidates = detectSsrfCandidates(url);
    if (!candidates.length) return [];

    const highest = candidates.some((c) => c.confidence === 'high') ? 'high' : 'medium';
    const severity: Finding['severity'] = highest === 'high' ? 'low' : 'info';
    const summary = candidates.map((c) => `${c.param} (${c.kind}, ${c.confidence})`).join(', ');

    return [
      {
        id: makeFindingId(this.id, url, candidates.map((c) => c.param).sort().join('|')),
        checkId: this.id,
        title: `SSRF-candidate parameter(s): ${candidates.map((c) => c.param).slice(0, 4).join(', ')}`,
        severity,
        target: url,
        description: `The endpoint exposes ${candidates.length} parameter(s) that commonly drive server-side fetches (${summary}). These are prioritized for out-of-band (OAST) confirmation during active testing; a received DNS/HTTP callback proves blind SSRF.`,
        evidence: `URL: ${url}\nCandidates: ${summary}`,
        reproduction: [
          `Inspect the parameters on ${url}`,
          'During active testing with OAST enabled, a unique canary URL is injected into each candidate',
          'A correlated out-of-band interaction confirms SSRF (see /api/oast/results)',
        ],
        remediation:
          'Validate and allowlist server-side fetch destinations; reject internal/link-local ranges and cloud metadata; avoid passing user input to URL fetchers.',
        cwe: 'CWE-918',
        references: [
          'https://cwe.mitre.org/data/definitions/918.html',
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery',
        ],
        needsManualReview: true,
        evidenceGrade: 'heuristic',
        confidence: highest === 'high' ? 0.55 : 0.4,
        submitReady: false,
        source: 'worker',
        discoveredAt: new Date().toISOString(),
      },
    ];
  },
};
