// Cloud object-store listing / public bucket signal helpers (GET/HEAD only).

export const BUCKET_LISTING_MARKERS: RegExp[] = [
  /<ListBucketResult[\s>]/i,
  /<Contents>\s*<Key>/i,
  /<Name>[^<]+<\/Name>\s*<Prefix>/i,
  /"kind"\s*:\s*"storage#objects"/i,
  /"items"\s*:\s*\[[^\]]*"bucket"/i,
  /<EnumerationResults[\s>]/i,
  /<Blobs>[\s\S]*<Blob>[\s\S]*<Name>/i,
  /<BlobPrefix>/i,
];

/** Host suffixes that indicate object-store endpoints. */
export const BUCKET_HOST_SUFFIXES = [
  '.s3.amazonaws.com',
  '.s3-us-west-1.amazonaws.com',
  '.s3-us-west-2.amazonaws.com',
  '.s3-eu-west-1.amazonaws.com',
  '.s3.amazonaws.com.cn',
  '.storage.googleapis.com',
  '.blob.core.windows.net',
  '.r2.cloudflarestorage.com',
  '.digitaloceanspaces.com',
] as const;

/** App paths that sometimes expose bucket-style XML/JSON listings. */
export const BUCKET_APP_PATHS: string[] = [
  '/assets/',
  '/static/',
  '/uploads/',
  '/media/',
  '/files/',
  '/backup/',
  '/data/',
];

export function isBucketLikeHost(hostname: string): boolean {
  const h = hostname.toLowerCase();
  return BUCKET_HOST_SUFFIXES.some((s) => h.endsWith(s)) || /^s3[.-]/i.test(h);
}

export function hasBucketListingBody(body: string): boolean {
  if (!body || body.length < 20) return false;
  return BUCKET_LISTING_MARKERS.some((re) => re.test(body));
}

export function shouldProbeBucket(probe: {
  url: string;
  status: number;
  headers: Record<string, string>;
  body: string;
  error?: string;
}): boolean {
  if (probe.error || probe.status === 0) return false;
  try {
    const u = new URL(probe.url);
    if (isBucketLikeHost(u.hostname)) return true;
    const path = u.pathname.toLowerCase();
    if (BUCKET_APP_PATHS.some((p) => path === p || path.startsWith(p))) {
      const ct = (probe.headers['content-type'] ?? '').toLowerCase();
      if (ct.includes('xml') || ct.includes('json') || /list|bucket|blob/i.test(probe.body.slice(0, 500))) {
        return true;
      }
    }
  } catch {
    return false;
  }
  return false;
}

/** Build listing probe URLs for bucket-like hosts (root + common prefixes). */
export function buildBucketProbeUrls(baseUrl: string): string[] {
  try {
    const u = new URL(baseUrl);
    if (!isBucketLikeHost(u.hostname) && !BUCKET_APP_PATHS.some((p) => u.pathname.startsWith(p))) {
      return [];
    }
    const origin = u.origin;
    const paths = isBucketLikeHost(u.hostname)
      ? ['/', '/?list-type=2', '/?delimiter=/', ...BUCKET_APP_PATHS]
      : BUCKET_APP_PATHS;
    return [...new Set(paths.map((p) => origin + p))].slice(0, 12);
  } catch {
    return [];
  }
}
