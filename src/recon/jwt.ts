// JWT parsing helpers for weak-token detection.
// Decode-only (base64url header/payload). Never verifies signatures or uses tokens.

export interface JwtParts {
  raw: string;
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  /** Third segment as sent (may be empty). */
  signature: string;
  segmentCount: number;
}

export type WeakJwtKind =
  | 'alg-none'
  | 'empty-signature'
  | 'two-segment-unsigned'
  | 'path-traversal-kid'
  | 'alg-empty'
  | 'jku-url'
  | 'x5u-url'
  | 'url-kid';

export interface WeakJwtIssue {
  kind: WeakJwtKind;
  severity: 'critical' | 'high';
  detail: string;
}

const JWT_RE = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]*)?/g;

/** Find JWT-shaped strings in text (body, cookie, header value). */
export function findJwtCandidates(text: string): string[] {
  if (!text) return [];
  JWT_RE.lastIndex = 0;
  const out: string[] = [];
  const seen = new Set<string>();
  let m: RegExpExecArray | null;
  while ((m = JWT_RE.exec(text)) !== null) {
    const tok = m[0];
    if (seen.has(tok)) continue;
    seen.add(tok);
    out.push(tok);
  }
  return out;
}

export function parseJwt(token: string): JwtParts | null {
  const parts = token.split('.');
  if (parts.length < 2 || parts.length > 3) return null;
  const header = decodeJson(parts[0]);
  const payload = decodeJson(parts[1]);
  if (!header || !payload) return null;
  return {
    raw: token,
    header,
    payload,
    signature: parts[2] ?? '',
    segmentCount: parts.length,
  };
}

export function analyzeWeakJwt(token: string): WeakJwtIssue[] {
  const parsed = parseJwt(token);
  if (!parsed) return [];
  const issues: WeakJwtIssue[] = [];
  const algRaw = parsed.header.alg;
  const alg = typeof algRaw === 'string' ? algRaw.toLowerCase() : '';

  if (alg === 'none' || alg === 'n/a') {
    issues.push({
      kind: 'alg-none',
      severity: 'critical',
      detail: `JWT header declares alg="${String(algRaw)}" (unsigned / none).`,
    });
  }
  if (alg === '') {
    issues.push({
      kind: 'alg-empty',
      severity: 'high',
      detail: 'JWT header has an empty alg value.',
    });
  }
  if (parsed.segmentCount === 2) {
    issues.push({
      kind: 'two-segment-unsigned',
      severity: 'critical',
      detail: 'JWT has only two segments (header.payload) with no signature.',
    });
  } else if (parsed.segmentCount === 3 && parsed.signature.length === 0) {
    issues.push({
      kind: 'empty-signature',
      severity: 'critical',
      detail: 'JWT signature segment is empty.',
    });
  }

  const kid = parsed.header.kid;
  if (typeof kid === 'string' && /(\.\.|\/|\\|%2e%2e)/i.test(kid)) {
    issues.push({
      kind: 'path-traversal-kid',
      severity: 'high',
      detail: `JWT kid contains path-traversal characters: "${kid.slice(0, 64)}"`,
    });
  }
  if (typeof kid === 'string' && /^https?:\/\//i.test(kid)) {
    issues.push({
      kind: 'url-kid',
      severity: 'high',
      detail: `JWT kid is a remote URL (SSRF / key injection risk): "${kid.slice(0, 96)}"`,
    });
  }

  const jku = parsed.header.jku;
  if (typeof jku === 'string' && /^https?:\/\//i.test(jku)) {
    issues.push({
      kind: 'jku-url',
      severity: 'critical',
      detail: `JWT header declares jku="${jku.slice(0, 96)}" — attacker-controlled JWKS URL can forge tokens if trusted.`,
    });
  }

  const x5u = parsed.header.x5u;
  if (typeof x5u === 'string' && /^https?:\/\//i.test(x5u)) {
    issues.push({
      kind: 'x5u-url',
      severity: 'critical',
      detail: `JWT header declares x5u="${x5u.slice(0, 96)}" — attacker-controlled certificate URL can forge tokens if trusted.`,
    });
  }

  return issues;
}

function decodeJson(b64url: string): Record<string, unknown> | null {
  try {
    const json = decodeBase64Url(b64url);
    const v = JSON.parse(json) as unknown;
    if (v && typeof v === 'object' && !Array.isArray(v)) return v as Record<string, unknown>;
    return null;
  } catch {
    return null;
  }
}

function decodeBase64Url(input: string): string {
  const b64 = input.replace(/-/g, '+').replace(/_/g, '/');
  const pad = '='.repeat((4 - (b64.length % 4)) % 4);
  // atob is available in Workers and Vitest (happy-dom/node with polyfill via undici/global).
  const binary = atob(b64 + pad);
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

/** Redact JWT for evidence: keep header alg readable, hide payload/signature. */
export function redactJwt(token: string): string {
  const parts = token.split('.');
  if (parts.length < 2) return `${token.slice(0, 8)}…`;
  return `${parts[0]}.[payload-redacted].${parts[2] ? '[sig-redacted]' : ''}`;
}
