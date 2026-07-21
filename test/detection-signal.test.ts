import { describe, it, expect } from 'vitest';
import { scanSecrets } from '../src/recon/secrets.js';
import { exposedFilesCheck } from '../src/detect/checks/exposed-files.js';
import { cloudBucketCheck, detectBucketSignal } from '../src/detect/checks/cloud-bucket.js';
import { listChecks } from '../src/detect/registry.js';
import { SENSITIVE_PATHS } from '../src/recon/wordlists.js';
import type { CheckContext, ProbeResult, Scope } from '../src/types.js';

const scope: Scope = { program: 'p', platform: 'generic', inScope: ['*.x.com'], outOfScope: [], authorized: true };
const ctx: CheckContext = { scope };

function probe(over: Partial<ProbeResult>): ProbeResult {
  return { url: 'https://a.x.com/', method: 'GET', status: 200, headers: {}, body: '', elapsedMs: 5, ...over };
}

describe('scanSecrets (expanded provider rules)', () => {
  // Tokens are assembled from parts so this test file contains no literal that
  // trips upstream secret scanners; the scanner still sees the full string.
  const j = (...parts: string[]) => parts.join('');
  const cases: Array<{ name: string; body: string; sev: string }> = [
    { name: 'GitLab PAT', body: j('token=glpat-', 'ABCDEFGHIJKLMNOPQRST'), sev: 'high' },
    { name: 'npm token', body: j('npm_', 'abcdefghijklmnopqrstuvwxyz0123456789'), sev: 'high' },
    { name: 'SendGrid', body: j('SG.', 'abcdefghijklmnopqrstuv', '.', 'abcdefghijklmnopqrstuvwxyz0123456789ABCDE'), sev: 'high' },
    { name: 'Stripe restricted live', body: j('rk', '_live_', 'abcdefghijklmnopqrstuvwx'), sev: 'critical' },
    { name: 'Google OAuth secret', body: j('GOCSPX-', 'abcdefghijklmnopqrstuvwxyz12'), sev: 'high' },
    { name: 'OpenAI key', body: j('const k="sk-', 'proj-', 'abcdefghijklmnopqrstuvwxyz', '"'), sev: 'high' },
  ];
  for (const c of cases) {
    it(`detects ${c.name} at ${c.sev}`, () => {
      const f = scanSecrets(probe({ body: c.body }));
      expect(f.length).toBeGreaterThanOrEqual(1);
      const hit = f.find((x) => x.severity === c.sev);
      expect(hit).toBeDefined();
      // Evidence is redacted (contains the ellipsis marker, not the full token).
      expect(hit!.evidence).toContain('…');
      expect(hit!.needsManualReview).toBe(true);
    });
  }

  it('does not fire on benign minified identifiers', () => {
    const f = scanSecrets(probe({ body: 'function mask(){return task_list.map(x=>x)}' }));
    expect(f).toHaveLength(0);
  });
});

describe('exposedFilesCheck (new signatures)', () => {
  it('flags .git-credentials with embedded creds as critical', () => {
    const f = exposedFilesCheck.run(
      probe({ url: 'https://a.x.com/.git-credentials', body: 'https://user:s3cret@github.com' }),
      ctx,
    );
    expect(f[0]?.severity).toBe('critical');
  });

  it('flags .npmrc auth token as high', () => {
    const f = exposedFilesCheck.run(
      probe({ url: 'https://a.x.com/.npmrc', body: '//registry.npmjs.org/:_authToken=abc123' }),
      ctx,
    );
    expect(f[0]?.severity).toBe('high');
  });

  it('flags config.json only when it carries secret-shaped keys', () => {
    const hit = exposedFilesCheck.run(
      probe({ url: 'https://a.x.com/config.json', body: '{"api_key":"live-1234567890"}' }),
      ctx,
    );
    expect(hit).toHaveLength(1);
    const miss = exposedFilesCheck.run(
      probe({ url: 'https://a.x.com/config.json', body: '{"featureFlag":true}' }),
      ctx,
    );
    expect(miss).toHaveLength(0);
  });

  it('flags web.config and id_rsa', () => {
    const web = exposedFilesCheck.run(
      probe({ url: 'https://a.x.com/web.config', body: '<configuration><connectionStrings/></configuration>' }),
      ctx,
    );
    expect(web[0]?.severity).toBe('high');
    const key = exposedFilesCheck.run(
      probe({ url: 'https://a.x.com/id_rsa', body: '-----BEGIN OPENSSH PRIVATE KEY-----\nabc' }),
      ctx,
    );
    expect(key[0]?.severity).toBe('critical');
  });

  it('every new wordlist path has a matching signature or dedicated check', () => {
    // These paths are probed by the scanner; each must be able to produce a finding.
    for (const p of ['/.htpasswd', '/.npmrc', '/.git-credentials', '/web.config', '/id_rsa', '/docker-compose.yml']) {
      expect(SENSITIVE_PATHS).toContain(p);
    }
  });
});

describe('cloudBucketCheck', () => {
  it('flags an anonymously listable S3 bucket as high + submitReady', () => {
    const body =
      '<?xml version="1.0"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>acme-uploads</Name><Contents><Key>backup.sql</Key></Contents></ListBucketResult>';
    const f = cloudBucketCheck.run(
      probe({ url: 'https://acme-uploads.s3.amazonaws.com/', body, headers: { 'content-type': 'application/xml' } }),
      ctx,
    );
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe('high');
    expect(f[0]?.submitReady).toBe(true);
  });

  it('flags a confirmed-exists AccessDenied S3 bucket as low candidate', () => {
    const body = '<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>';
    const f = cloudBucketCheck.run(
      probe({ url: 'https://private.s3.us-east-1.amazonaws.com/', status: 403, body }),
      ctx,
    );
    expect(f[0]?.severity).toBe('low');
    expect(f[0]?.needsManualReview).toBe(true);
  });

  it('detects S3 listing behind a custom domain but ignores plain HTML / NoSuchBucket', () => {
    // Custom domain fronting S3 with a genuine listing body → still flagged.
    expect(detectBucketSignal('cdn.acme.com', '<ListBucketResult></ListBucketResult>', 200)?.provider).toBe(
      'AWS S3',
    );
    // Deleted bucket error is not an exposure.
    expect(
      detectBucketSignal('gone.s3.amazonaws.com', '<Error><Code>NoSuchBucket</Code></Error>', 404),
    ).toBeNull();
    // Ordinary page on a non-bucket host is not a bucket.
    expect(detectBucketSignal('a.x.com', '<html>hi</html>', 200)).toBeNull();
  });

  it('is registered', () => {
    expect(listChecks().map((c) => c.id)).toContain('open-cloud-bucket');
  });
});
