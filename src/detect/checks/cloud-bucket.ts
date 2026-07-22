// Publicly listable cloud object storage (S3 / GCS / Azure Blob).
//
// Passive: only flags when the fetched response body IS an open bucket listing
// (XML/JSON directory of objects) or a permission error that confirms the
// bucket exists and is anonymously reachable. Never downloads listed objects.

import type { Check, Finding, ProbeResult } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';

type Provider = 'AWS S3' | 'Google Cloud Storage' | 'Azure Blob Storage';

interface BucketSignal {
  provider: Provider;
  /** true = anonymous listing succeeded (data exposure); false = confirmed-exists error. */
  listable: boolean;
  detail: string;
}

const S3_HOST = /(^|\.)s3[.-][a-z0-9-]*\.?amazonaws\.com$/i;
const GCS_HOST = /(^|\.)storage\.googleapis\.com$/i;
const AZURE_HOST = /(^|\.)blob\.core\.windows\.net$/i;

export const cloudBucketCheck: Check = {
  id: 'open-cloud-bucket',
  title: 'Publicly listable cloud storage bucket',
  cwe: 'CWE-264',
  run(probe: ProbeResult): Finding[] {
    if (probe.error || !probe.body) return [];
    if (probe.status < 200 || probe.status >= 500) return [];

    const host = hostOf(probe.finalUrl ?? probe.url);
    const signal = detectBucketSignal(host, probe.body, probe.status);
    if (!signal) return [];

    const severity: Finding['severity'] = signal.listable ? 'high' : 'low';
    return [
      {
        id: makeFindingId(this.id, probe.url, `${signal.provider}:${signal.listable ? 'listable' : 'exists'}`),
        checkId: this.id,
        title: signal.listable
          ? `Public ${signal.provider} bucket allows anonymous listing`
          : `${signal.provider} bucket reachable anonymously (${signal.detail})`,
        severity,
        target: probe.url,
        description: signal.listable
          ? `An anonymous request to this ${signal.provider} bucket returned an object listing. Public listing exposes every stored key and often leaks backups, uploads, and internal files.`
          : `An anonymous request to this ${signal.provider} bucket returned "${signal.detail}", confirming the bucket exists and is reachable without credentials. Object read/write ACLs should be reviewed.`,
        evidence: `URL: ${probe.url}\nStatus: ${probe.status}\nProvider: ${signal.provider}\nSignal: ${signal.detail}\nBody preview: ${probe.body.slice(0, 220).replace(/\s+/g, ' ')}`,
        reproduction: [
          `curl -s '${probe.url}'`,
          signal.listable
            ? 'Confirm the response lists object keys (ListBucketResult / items[]) without authentication'
            : `Confirm the response is an anonymous ${signal.provider} error that reveals the bucket exists`,
          'Do not download or modify any listed objects — report the misconfiguration only',
        ],
        remediation:
          'Disable anonymous/public access on the bucket; remove public-read/list ACLs and bucket policies; enable "block public access" (S3) / uniform access with least privilege (GCS/Azure).',
        cwe: 'CWE-264',
        references: [
          'https://cwe.mitre.org/data/definitions/264.html',
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/',
        ],
        needsManualReview: !signal.listable,
        evidenceGrade: 'fingerprint',
        confidence: signal.listable ? 0.85 : 0.6,
        submitReady: signal.listable,
        source: 'worker',
        discoveredAt: new Date().toISOString(),
      },
    ];
  },
};

export function detectBucketSignal(host: string, body: string, status: number): BucketSignal | null {
  const provider = providerForHost(host);
  // Host-agnostic S3 listing bodies can appear on custom domains fronting S3.
  const s3Listing = /<ListBucketResult[\s>][\s\S]*<\/ListBucketResult>/i.test(body);
  const gcsListing =
    /"kind"\s*:\s*"storage#objects"/.test(body) || /<ListBucketResult[\s>]/i.test(body);
  const azureListing = /<EnumerationResults[\s>][\s\S]*<Blobs>/i.test(body);

  if (status >= 200 && status < 300) {
    if (provider === 'AWS S3' && s3Listing) return { provider, listable: true, detail: 'ListBucketResult' };
    if (provider === 'Google Cloud Storage' && gcsListing)
      return { provider, listable: true, detail: 'storage#objects listing' };
    if (provider === 'Azure Blob Storage' && azureListing)
      return { provider, listable: true, detail: 'EnumerationResults' };
    // Custom domain in front of S3.
    if (!provider && s3Listing) return { provider: 'AWS S3', listable: true, detail: 'ListBucketResult' };
  }

  // Confirmed-exists error bodies (anonymous request reached the bucket).
  if (provider === 'AWS S3' && /<Code>AccessDenied<\/Code>/i.test(body) && !/<Code>NoSuchBucket/i.test(body)) {
    return { provider, listable: false, detail: 'AccessDenied' };
  }
  if (provider === 'Azure Blob Storage' && /<Code>(?:AuthenticationFailed|ResourceNotFound)<\/Code>/i.test(body)) {
    // ResourceNotFound at container root still confirms the account exists.
    if (/<Code>AuthenticationFailed<\/Code>/i.test(body))
      return { provider, listable: false, detail: 'AuthenticationFailed' };
  }

  return null;
}

function providerForHost(host: string): Provider | null {
  if (S3_HOST.test(host)) return 'AWS S3';
  if (GCS_HOST.test(host)) return 'Google Cloud Storage';
  if (AZURE_HOST.test(host)) return 'Azure Blob Storage';
  return null;
}

function hostOf(url: string): string {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return '';
  }
}
