// Cloud object-store public listing detection.

import type { Check, Finding, ProbeResult } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';
import { hasBucketListingBody, isBucketLikeHost } from '../../recon/bucket-probes.js';

export const cloudBucketCheck: Check = {
  id: 'cloud-bucket-exposure',
  title: 'Cloud object-store listing exposure',
  cwe: 'CWE-200',
  run(probe: ProbeResult): Finding[] {
    if (probe.error || !probe.body) return [];
    if (probe.status < 200 || probe.status >= 400) return [];
    if (!hasBucketListingBody(probe.body)) return [];

    let host = '';
    try {
      host = new URL(probe.url).hostname;
    } catch {
      host = probe.url;
    }
    const bucketHost = isBucketLikeHost(host);

    return [
      {
        id: makeFindingId(this.id, probe.url, 'listing'),
        checkId: this.id,
        title: bucketHost
          ? 'Public cloud bucket listing exposed'
          : 'Directory / object listing exposed (bucket-style XML/JSON)',
        severity: 'critical',
        target: probe.url,
        description:
          'The response contains an object-store listing (S3 ListBucketResult, GCS storage#objects, Azure Blob EnumerationResults, or equivalent). Public listings expose file keys, often including backups, credentials, and PII.',
        evidence: `URL: ${probe.url}\nHost: ${host}\nStatus: ${probe.status}\nContent-Type: ${probe.headers['content-type'] ?? '<absent>'}\nBody preview: ${probe.body.slice(0, 260).replace(/\s+/g, ' ')}`,
        reproduction: [
          `curl -sI '${probe.url}'`,
          `curl -s '${probe.url}' | head`,
          'Confirm ListBucketResult / storage#objects / EnumerationResults markers',
        ],
        remediation:
          'Disable public list permissions; require IAM/SAS auth; block anonymous ListBucket; expose only intentional public objects via CDN with tight ACLs.',
        cwe: 'CWE-200',
        references: [
          'https://cwe.mitre.org/data/definitions/200.html',
          'https://owasp.org/www-community/vulnerabilities/Insecure_Cloud_Storage',
        ],
        needsManualReview: !bucketHost,
        discoveredAt: new Date().toISOString(),
      },
    ];
  },
};
