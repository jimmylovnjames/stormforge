// Path traversal / LFI canary helpers (safe GET only).

export const LFI_CANARY_MARKERS = [
  'root:x:0:0:',
  '[extensions]',
  '<?xml',
  'for 16-bit app support',
] as const;

/** Payloads that seek well-known OS files without writing anything. */
export const LFI_PAYLOADS = [
  '../../../../../../../../etc/passwd',
  '..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd',
  '....//....//....//....//etc/passwd',
  '..\\..\\..\\..\\..\\..\\windows\\win.ini',
  '/etc/passwd',
  'file:///etc/passwd',
] as const;

export const LFI_PARAM_NAMES = ['file', 'path', 'page', 'doc', 'document', 'template', 'include', 'dir', 'folder', 'root', 'pg', 'style', 'lang'] as const;

export const LFI_PATHS: string[] = [
  '/download',
  '/file',
  '/files',
  '/static',
  '/assets',
  '/include',
  '/page',
  '/view',
  '/load',
  '/read',
  '/get',
  '/api/file',
  '/api/files',
  '/api/download',
  '/api/v1/file',
  '/api/v1/files',
];

export function buildPathTraversalProbeUrls(baseUrl: string, maxParams = 2): string[] {
  const out: string[] = [];
  try {
    for (const param of LFI_PARAM_NAMES.slice(0, maxParams)) {
      for (const payload of LFI_PAYLOADS.slice(0, 3)) {
        const u = new URL(baseUrl);
        for (const p of LFI_PARAM_NAMES) u.searchParams.delete(p);
        u.searchParams.set(param, payload);
        out.push(u.toString());
      }
    }
  } catch {
    return [];
  }
  return out;
}

export function urlCarriesLfiPayload(url: string): boolean {
  try {
    for (const v of new URL(url).searchParams.values()) {
      if (/\.\.|%2e%2e|etc\/passwd|win\.ini|file:\//i.test(v)) return true;
    }
  } catch {
    return /\.\.|etc\/passwd/i.test(url);
  }
  return false;
}

export function hasPathTraversalSuccess(body: string, probeUrl: string): boolean {
  if (!urlCarriesLfiPayload(probeUrl) && !/\.\.|etc\/passwd/i.test(probeUrl)) {
    // Still allow body-only passwd if path looks like file download with traversal in path
    if (!/\.\.|%2e%2e/i.test(probeUrl)) return false;
  }
  if (/root:x:0:0:/.test(body)) return true;
  if (/\[fonts\]|\[extensions\]/i.test(body) && /win\.ini|windows/i.test(probeUrl)) return true;
  if (/^root:.*:0:0:/m.test(body)) return true;
  return false;
}

export function shouldProbePathTraversal(probe: {
  url: string;
  status: number;
  headers: Record<string, string>;
  body: string;
  error?: string;
}): boolean {
  if (probe.error || probe.status === 0) return false;
  const path = safePath(probe.url);
  if (LFI_PATHS.some((p) => path === p || path.endsWith(p))) return true;
  if (/[?&](?:file|path|page|doc|include|template)=/i.test(probe.url)) return true;
  const ct = (probe.headers['content-type'] ?? '').toLowerCase();
  if (ct.includes('text/html') && /name=["'](?:file|path|page|doc|include)["']/i.test(probe.body)) return true;
  return false;
}

function safePath(url: string): string {
  try {
    return new URL(url).pathname.toLowerCase();
  } catch {
    return url.toLowerCase();
  }
}
