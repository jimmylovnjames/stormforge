// Canonicalize targets / evidence so near-duplicate findings collapse.

const CANARY_PARAM_RE =
  /(?:url|uri|redirect|next|return|dest|target|link|src|file|image|feed|u|r|path)=https?%3A%2F%2F[^&]*canary[^&]*/gi;

const STORMFORGE_TOKENS = [
  /sfHpp9f3a7c/gi,
  /sfPp9f3a7c/gi,
  /sfcp-[a-z0-9]+/gi,
  /sfPp/gi,
  /stormforge-redirect\.example/gi,
  /\/api\/canary\/[a-f0-9]{16,}/gi,
];

/** Remove StormForge probe noise from free-text evidence keys. */
export function stripStormforgeNoise(text: string): string {
  let out = text;
  for (const re of STORMFORGE_TOKENS) out = out.replace(re, '');
  return out.replace(/\s+/g, ' ').trim();
}

export function stableEvidenceKey(evidenceKey: string): string {
  return stripStormforgeNoise(evidenceKey).replace(/\s+/g, ' ').trim().toLowerCase();
}

/**
 * Normalize a finding target URL for dedupe:
 * - lowercase host
 * - drop default ports / hash
 * - strip trailing slash (except root)
 * - drop StormForge canary query values
 * - sort remaining query params
 */
export function canonicalTarget(target: string): string {
  let raw = target.trim();
  if (!raw) return '';
  if (!/^https?:\/\//i.test(raw)) raw = `https://${raw}`;

  try {
    const u = new URL(raw);
    u.hash = '';
    u.hostname = u.hostname.toLowerCase();
    if ((u.protocol === 'https:' && u.port === '443') || (u.protocol === 'http:' && u.port === '80')) {
      u.port = '';
    }
    if (u.pathname.length > 1 && u.pathname.endsWith('/')) {
      u.pathname = u.pathname.replace(/\/+$/, '');
    }

    // Drop canary-bearing params and sort the rest.
    const kept: Array<[string, string]> = [];
    for (const [k, v] of u.searchParams) {
      const lk = k.toLowerCase();
      if (/sfhpp|sfpp|sfcp/i.test(v)) continue;
      if (/canary/i.test(v)) continue;
      if (lk === '__proto__' || lk.startsWith('constructor')) continue;
      kept.push([k, v]);
    }
    kept.sort((a, b) => (a[0] === b[0] ? a[1].localeCompare(b[1]) : a[0].localeCompare(b[0])));
    u.search = '';
    for (const [k, v] of kept) u.searchParams.append(k, v);

    // Also strip encoded canary blobs that survived as a single param value.
    let out = u.toString().replace(CANARY_PARAM_RE, '');
    out = out.replace(/[?&]$/, '');
    return out;
  } catch {
    return stripStormforgeNoise(raw).toLowerCase();
  }
}
