// Passive JWT analyzer — decode header/payload only (never verify or use the token).
// Escalates beyond the generic secret-exposure JWT regex when alg/claims are spicy.

import type { Check, Finding, ProbeResult, Severity } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';
import { redact } from '../../recon/secrets.js';

/** Compact JWS/JWT (header.payload.signature) — signature may be empty (alg=none). */
const JWT_RE = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]*)?/g;

const PRIV_CLAIM_KEYS = /^(?:admin|is_admin|isAdmin|role|roles|permissions|scope|scp|groups|entitlements)$/i;
const PRIV_CLAIM_VALUES = /\b(?:admin|root|superuser|sudo|write|delete|\*)\b/i;
const DANGEROUS_ALG = /^(?:none|HS256|HS384|HS512)$/i;
const PATHISH_KID = /(?:\.\.|\/|\\|%2e%2e|file:|http:)/i;

interface JwtParts {
  raw: string;
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  alg: string;
  kid?: string;
}

export function b64urlJson(part: string): Record<string, unknown> | null {
  try {
    const pad = '='.repeat((4 - (part.length % 4)) % 4);
    const b64 = (part + pad).replace(/-/g, '+').replace(/_/g, '/');
    // atob is available on Workers and modern Node (vitest).
    const json = globalThis.atob(b64);
    const parsed = JSON.parse(json);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

export function parseJwt(token: string): JwtParts | null {
  const parts = token.split('.');
  if (parts.length < 2 || parts.length > 3) return null;
  const header = b64urlJson(parts[0]!);
  const payload = b64urlJson(parts[1]!);
  if (!header || !payload) return null;
  const alg = typeof header.alg === 'string' ? header.alg : '';
  const kid = typeof header.kid === 'string' ? header.kid : undefined;
  return { raw: token, header, payload, alg, kid };
}

function collectJwtCandidates(probe: ProbeResult): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const push = (s: string) => {
    if (!s || seen.has(s)) return;
    seen.add(s);
    out.push(s);
  };

  const auth = probe.headers['authorization'] ?? '';
  const bearer = /\bBearer\s+(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)/i.exec(auth);
  if (bearer?.[1]) push(bearer[1]);

  const setCookie = probe.headers['set-cookie'] ?? '';
  JWT_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = JWT_RE.exec(setCookie)) !== null) push(m[0]);

  if (probe.body) {
    JWT_RE.lastIndex = 0;
    while ((m = JWT_RE.exec(probe.body)) !== null) push(m[0]);
  }

  return out.slice(0, 8);
}

function analyze(jwt: JwtParts): {
  severity: Severity;
  reasons: string[];
  submitReady: boolean;
  confidence: number;
} {
  const reasons: string[] = [];
  let severity: Severity = 'low';
  let submitReady = false;
  let confidence = 0.55;

  if (/^none$/i.test(jwt.alg) || jwt.alg === '') {
    reasons.push(`alg=${jwt.alg || '(empty)'} — unsigned / alg=none`);
    severity = 'critical';
    submitReady = true;
    confidence = 0.92;
  } else if (DANGEROUS_ALG.test(jwt.alg)) {
    reasons.push(`alg=${jwt.alg} (symmetric — verify server rejects alg confusion)`);
    severity = 'medium';
    confidence = 0.65;
  } else if (jwt.alg) {
    reasons.push(`alg=${jwt.alg}`);
  }

  if (jwt.kid && PATHISH_KID.test(jwt.kid)) {
    reasons.push(`path-like kid=${JSON.stringify(jwt.kid)} (possible key confusion / path traversal)`);
    if (severity !== 'critical') severity = 'high';
    confidence = Math.max(confidence, 0.8);
    submitReady = submitReady || severity === 'critical' || severity === 'high';
  }

  for (const [k, v] of Object.entries(jwt.payload)) {
    if (!PRIV_CLAIM_KEYS.test(k)) continue;
    const rendered = Array.isArray(v) ? v.join(',') : String(v);
    if (PRIV_CLAIM_VALUES.test(rendered) || /admin/i.test(k)) {
      reasons.push(`privileged claim ${k}=${JSON.stringify(v)}`);
      if (severity !== 'critical') severity = 'high';
      confidence = Math.max(confidence, 0.78);
      submitReady = true;
    } else {
      reasons.push(`authz claim present: ${k}`);
      if (severity === 'low') severity = 'medium';
    }
  }

  const exp = jwt.payload.exp;
  if (typeof exp === 'number') {
    const days = (exp * 1000 - Date.now()) / (86400 * 1000);
    if (days > 365) {
      reasons.push(`exp ${Math.round(days)}d in the future (long-lived token)`);
      if (severity === 'low') severity = 'medium';
    }
  } else if (!('exp' in jwt.payload)) {
    reasons.push('missing exp claim');
    if (severity === 'low') severity = 'medium';
  }

  if (!reasons.length) reasons.push('JWT present in response (manual review)');

  return { severity, reasons, submitReady, confidence };
}

export const jwtExposureCheck: Check = {
  id: 'jwt-exposure',
  title: 'JWT exposure / weak claims',
  cwe: 'CWE-347',
  run(probe: ProbeResult): Finding[] {
    if (probe.error) return [];
    const findings: Finding[] = [];
    for (const raw of collectJwtCandidates(probe)) {
      const jwt = parseJwt(raw);
      if (!jwt) continue;
      const { severity, reasons, submitReady, confidence } = analyze(jwt);
      const headerSnippet = JSON.stringify(jwt.header);
      const payloadKeys = Object.keys(jwt.payload).slice(0, 12).join(', ');
      findings.push({
        id: makeFindingId(this.id, probe.url, `${jwt.alg}:${redact(raw)}`),
        checkId: this.id,
        title:
          severity === 'critical'
            ? 'Unsigned JWT (alg=none) exposed'
            : severity === 'high'
              ? 'JWT with privileged claims / suspicious kid exposed'
              : 'JWT exposed in response',
        severity,
        target: probe.url,
        description:
          'A JWT was found in a client-visible response. Header/payload were decoded locally (signature not verified, token not used). Weak algorithms, privileged claims, or path-like kid values can enable auth bypass or privilege escalation.',
        evidence: `URL: ${probe.url}\nRedacted token: ${redact(raw)}\nHeader: ${headerSnippet}\nPayload keys: ${payloadKeys || '(none)'}\nSignals:\n${reasons.map((r) => `  - ${r}`).join('\n')}`,
        reproduction: [
          `Fetch ${probe.url}`,
          'Locate the JWT (body / Authorization / Set-Cookie)',
          'Base64url-decode the header and payload (do not use the token against the target)',
          'Confirm alg/claims match the signals above',
        ],
        remediation:
          'Never embed long-lived or privileged JWTs in client-visible assets. Reject alg=none and unexpected algs server-side; use asymmetric algs; keep kid opaque; set short exp; avoid putting role/admin claims in tokens that browsers can read.',
        cwe: /^none$/i.test(jwt.alg) ? 'CWE-347' : 'CWE-522',
        references: [
          'https://cwe.mitre.org/data/definitions/347.html',
          'https://portswigger.net/web-security/jwt',
        ],
        needsManualReview: !submitReady,
        evidenceGrade: 'fingerprint',
        confidence,
        submitReady,
        source: 'worker',
        discoveredAt: new Date().toISOString(),
      });
    }
    return findings;
  },
};
