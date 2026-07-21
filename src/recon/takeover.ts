// Subdomain takeover fingerprint helpers (pure analysis; DoH is done by the scanner).

/** CNAME suffixes that commonly indicate dangling / claimable services. */
export const TAKEOVER_FINGERPRINTS: Array<{
  service: string;
  cname: RegExp;
  /** Body fingerprints if we ever fetch the service (optional). */
  body?: RegExp;
  severity: 'high' | 'critical';
}> = [
  { service: 'GitHub Pages', cname: /\.github\.io$/i, body: /There isn't a GitHub Pages site here/i, severity: 'high' },
  { service: 'Heroku', cname: /\.herokuapp\.com$/i, body: /no such app|No such app/i, severity: 'high' },
  { service: 'AWS Elastic Beanstalk', cname: /\.elasticbeanstalk\.com$/i, severity: 'high' },
  { service: 'AWS S3 website', cname: /\.s3-website[.-]/i, body: /NoSuchBucket|The specified bucket does not exist/i, severity: 'critical' },
  { service: 'Shopify', cname: /\.myshopify\.com$/i, body: /Sorry, this shop is currently unavailable/i, severity: 'high' },
  { service: 'Tumblr', cname: /\.tumblr\.com$/i, body: /There's nothing here/i, severity: 'high' },
  { service: 'WordPress.com', cname: /\.wordpress\.com$/i, body: /Do you want to register/i, severity: 'high' },
  { service: 'Ghost', cname: /\.ghost\.io$/i, severity: 'high' },
  { service: 'Help Scout', cname: /\.helpscoutdocs\.com$/i, severity: 'high' },
  { service: 'Cargo Collective', cname: /\.cargocollective\.com$/i, severity: 'high' },
  { service: 'Feedpress', cname: /\.feedpress\.me$/i, severity: 'high' },
  { service: 'Surge.sh', cname: /\.surge\.sh$/i, body: /project not found/i, severity: 'high' },
  { service: 'Pantheon', cname: /\.pantheonsite\.io$/i, severity: 'high' },
  { service: 'Netlify', cname: /\.netlify\.app$/i, body: /Not Found - Request ID/i, severity: 'high' },
  { service: 'Azure', cname: /\.azurewebsites\.net$/i, severity: 'high' },
  { service: 'Azure CloudApp', cname: /\.cloudapp\.net$/i, severity: 'high' },
  { service: 'Azure Traffic Manager', cname: /\.trafficmanager\.net$/i, severity: 'high' },
  { service: 'Unbounce', cname: /\.unbouncepages\.com$/i, severity: 'high' },
  { service: 'Freshdesk', cname: /\.freshdesk\.com$/i, severity: 'high' },
  { service: 'Statuspage', cname: /\.statuspage\.io$/i, severity: 'high' },
  { service: 'Zendesk', cname: /\.zendesk\.com$/i, body: /Help Center Closed/i, severity: 'high' },
  { service: 'Webflow', cname: /\.webflow\.io$/i, severity: 'high' },
  { service: 'Fly.io', cname: /\.fly\.dev$/i, severity: 'high' },
  { service: 'Vercel', cname: /\.vercel\.app$/i, body: /DEPLOYMENT_NOT_FOUND|NOT_FOUND/i, severity: 'high' },
];

export interface DnsLookupResult {
  host: string;
  cname?: string;
  aRecords: string[];
  nxdomain: boolean;
  raw?: unknown;
}

export function matchTakeoverFingerprint(cname: string): (typeof TAKEOVER_FINGERPRINTS)[number] | null {
  const c = cname.replace(/\.$/, '').toLowerCase();
  for (const fp of TAKEOVER_FINGERPRINTS) {
    if (fp.cname.test(c)) return fp;
  }
  return null;
}

/**
 * Candidate takeover when CNAME points at a claimable service and the host
 * has no resolving A/AAAA (NXDOMAIN or empty answers).
 */
export function isTakeoverCandidate(lookup: DnsLookupResult): {
  service: string;
  severity: 'high' | 'critical';
  cname: string;
} | null {
  if (!lookup.cname) return null;
  const fp = matchTakeoverFingerprint(lookup.cname);
  if (!fp) return null;
  if (lookup.aRecords.length > 0) return null;
  // NXDOMAIN or empty A set with dangling CNAME is the classic signal.
  if (lookup.nxdomain || lookup.aRecords.length === 0) {
    return { service: fp.service, severity: fp.severity, cname: lookup.cname.replace(/\.$/, '') };
  }
  return null;
}

/** Parse Cloudflare DoH JSON (application/dns-json). */
export function parseDohResponse(host: string, json: {
  Status?: number;
  Answer?: Array<{ type: number; data: string }>;
}): DnsLookupResult {
  const answers = json.Answer ?? [];
  const cname = answers.find((a) => a.type === 5)?.data;
  const aRecords = answers.filter((a) => a.type === 1 || a.type === 28).map((a) => a.data);
  // Status 3 = NXDOMAIN (RFC 1035)
  const nxdomain = json.Status === 3;
  return { host, cname, aRecords, nxdomain, raw: json };
}

export const DOH_ENDPOINT = 'https://cloudflare-dns.com/resolve';
