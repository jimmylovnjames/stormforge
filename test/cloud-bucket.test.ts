import { describe, it, expect } from 'vitest';
import {
  BUCKET_APP_PATHS,
  buildBucketProbeUrls,
  hasBucketListingBody,
  isBucketLikeHost,
  shouldProbeBucket,
} from '../src/recon/bucket-probes.js';
import { cloudBucketCheck } from '../src/detect/checks/cloud-bucket.js';
import { collectBucketFollowUps } from '../src/engine/scanner.js';
import { listChecks } from '../src/detect/registry.js';
import { draftFinding } from '../src/report/drafter.js';
import { planPathsFromFindings } from '../src/planning/llm-planner.js';
import { planFollowUpTasks } from '../src/planning/vuln-planner.js';
import type { CheckContext, Finding, ProbeResult, Scope } from '../src/types.js';

const scope: Scope = {
  program: 'p',
  platform: 'hackerone',
  inScope: ['*.s3.amazonaws.com', '*.x.com'],
  outOfScope: [],
  authorized: true,
};
const ctx: CheckContext = { scope };

function probe(over: Partial<ProbeResult>): ProbeResult {
  return {
    url: 'https://mybucket.s3.amazonaws.com/',
    method: 'GET',
    status: 200,
    headers: { 'content-type': 'application/xml' },
    body: '',
    elapsedMs: 5,
    ...over,
  };
}

describe('bucket probes', () => {
  it('recognizes bucket hosts and listing bodies', () => {
    expect(isBucketLikeHost('mybucket.s3.amazonaws.com')).toBe(true);
    expect(isBucketLikeHost('cdn.x.com')).toBe(false);
    expect(
      hasBucketListingBody(
        '<?xml version="1.0"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>b</Name><Contents><Key>a.txt</Key></Contents></ListBucketResult>',
      ),
    ).toBe(true);
    expect(BUCKET_APP_PATHS).toContain('/uploads/');
  });

  it('builds listing URLs for bucket hosts', () => {
    const urls = buildBucketProbeUrls('https://mybucket.s3.amazonaws.com/foo');
    expect(urls.some((u) => u.endsWith('/'))).toBe(true);
    expect(urls.some((u) => u.includes('list-type=2'))).toBe(true);
  });

  it('shouldProbeBucket on bucket hosts', () => {
    expect(shouldProbeBucket(probe({ status: 200, body: 'x' }))).toBe(true);
  });
});

describe('cloudBucketCheck', () => {
  it('flags S3 ListBucketResult as critical', () => {
    const findings = cloudBucketCheck.run(
      probe({
        body: '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>mybucket</Name><Contents><Key>secret.env</Key></Contents></ListBucketResult>',
      }),
      ctx,
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('critical');
    expect(findings[0]!.cwe).toBe('CWE-200');
    expect(findings[0]!.checkId).toBe('cloud-bucket-exposure');
  });

  it('ignores non-listing XML', () => {
    expect(cloudBucketCheck.run(probe({ body: '<Error><Code>AccessDenied</Code></Error>' }), ctx)).toHaveLength(0);
  });

  it('is registered and drafts impact', () => {
    expect(listChecks().some((c) => c.id === 'cloud-bucket-exposure')).toBe(true);
    const f: Finding = {
      id: 'b1',
      checkId: 'cloud-bucket-exposure',
      title: 'bucket',
      severity: 'critical',
      target: 'https://mybucket.s3.amazonaws.com/',
      description: 'd',
      evidence: 'e',
      reproduction: ['r'],
      remediation: 'fix',
      cwe: 'CWE-200',
      references: [],
      needsManualReview: false,
      discoveredAt: new Date().toISOString(),
    };
    expect(draftFinding(f, scope)).toMatch(/object-store|listing/i);
  });
});

describe('collectBucketFollowUps + autonomy', () => {
  it('emits bucket listing follow-ups', () => {
    const urls = collectBucketFollowUps([probe({ body: 'ok' })]);
    expect(urls.length).toBeGreaterThan(0);
  });

  it('planPathsFromFindings expands upload prefixes', () => {
    const plan = planPathsFromFindings([
      {
        id: 'b1',
        checkId: 'cloud-bucket-exposure',
        title: 'bucket',
        severity: 'critical',
        target: 'https://cdn.x.com/uploads/',
        description: 'd',
        evidence: 'e',
        reproduction: ['r'],
        remediation: 'fix',
        references: [],
        needsManualReview: false,
        discoveredAt: new Date().toISOString(),
      },
    ]);
    expect(plan.suggestedPaths).toContain('/backup/');
  });

  it('planFollowUpTasks schedules gobuster for bucket findings', () => {
    const plan = planFollowUpTasks(
      [
        {
          checkId: 'cloud-bucket-exposure',
          severity: 'critical',
          target: 'https://assets.x.com/uploads/',
          title: 'listing',
        },
      ],
      {
        program: 'p',
        platform: 'hackerone',
        inScope: ['*.x.com'],
        outOfScope: [],
        authorized: true,
      },
    );
    expect(plan.tasks.some((t) => t.tool === 'gobuster')).toBe(true);
  });
});
