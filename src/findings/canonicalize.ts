// Canonical target + evidence keys for stable cross-source finding IDs.

/** Normalize a URL or host for dedupe (scheme-insensitive, no trailing slash, lower host). */
export function canonicalizeTarget(target: string): string {
  const raw = target.trim();
  if (!raw) return '';
  try {
    const withScheme = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
    const u = new URL(withScheme);
    const host = u.hostname.toLowerCase();
    const port =
      u.port && u.port !== '80' && u.port !== '443' && u.port !== ''
        ? `:${u.port}`
        : '';
    let path = u.pathname || '/';
    if (path.length > 1 && path.endsWith('/')) path = path.slice(0, -1);
    // Drop default empty search noise; keep stable sorted query if present.
    const params = [...u.searchParams.entries()].sort(([a], [b]) => a.localeCompare(b));
    const qs = params.length
      ? `?${params.map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&')}`
      : '';
    return `${host}${port}${path}${qs}`;
  } catch {
    return raw.toLowerCase().replace(/\/+$/, '');
  }
}

/** Stable evidence key: trim, collapse whitespace, lower for case-insensitive markers. */
export function canonicalizeEvidenceKey(key: string): string {
  return key.trim().replace(/\s+/g, ' ').slice(0, 200);
}

/** Hash a sorted list into a stable short key (for subdomain/url sets). */
export function hashTokenList(items: string[]): string {
  const sorted = [...new Set(items.map((s) => s.trim().toLowerCase()).filter(Boolean))].sort();
  return sorted.slice(0, 50).join('|').slice(0, 180);
}
