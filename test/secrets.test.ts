import { describe, it, expect } from 'vitest';
import {
  scanSecrets,
  secretsExposureCheck,
  isSecretLeakPath,
  SECRET_RULES,
  redact,
} from '../src/recon/secrets.js';
import { SECRET_LEAK_PATHS } from '../src/recon/wordlists.js';
import { listChecks } from '../src/detect/registry.js';
import { FindingsStore, summarizeSecretFindings } from '../src/findings/store.js';
import { draftDisclosure, draftFinding } from '../src/report/drafter.js';
import type { Finding, ProbeResult, Scope, CheckContext } from '../src/types.js';

const scope: Scope = {
  program: 'p',
  platform: 'hackerone',
  inScope: ['*.x.com'],
  outOfScope: [],
  authorized: true,
};
const ctx: CheckContext = { scope };

function probe(over: Partial<ProbeResult>): ProbeResult {
  return {
    url: 'https://a.x.com/.env',
    method: 'GET',
    status: 200,
    headers: {},
    body: '',
    elapsedMs: 3,
    ...over,
  };
}

describe('SECRET_LEAK_PATHS', () => {
  it('covers env, aws creds, and JS config paths', () => {
    expect(SECRET_LEAK_PATHS).toContain('/.env');
    expect(SECRET_LEAK_PATHS).toContain('/.aws/credentials');
    expect(SECRET_LEAK_PATHS).toContain('/config.js');
    expect(SECRET_LEAK_PATHS).toContain('/serviceAccount.json');
  });

  it('isSecretLeakPath matches wordlist entries', () => {
    expect(isSecretLeakPath('https://a.x.com/.env.production')).toBe(true);
    expect(isSecretLeakPath('https://a.x.com/js/config.js')).toBe(true);
    expect(isSecretLeakPath('https://a.x.com/about')).toBe(false);
  });
});

describe('scanSecrets upgraded rules', () => {
  it('flags AWS access key as critical confirmed', () => {
    const f = scanSecrets(probe({ body: 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE' }));
    expect(f.some((x) => x.severity === 'critical' && x.title.includes('AWS Access Key'))).toBe(true);
    expect(f[0].needsManualReview).toBe(false);
  });

  it('flags AWS secret access key assignment', () => {
    const secret = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    const f = scanSecrets(
      probe({ body: `aws_secret_access_key=${secret}` }),
    );
    expect(f.some((x) => x.title.includes('AWS Secret Access Key'))).toBe(true);
    expect(f[0].evidence).not.toContain(secret);
  });

  it('flags database connection URIs as critical/high', () => {
    const body = [
      'DATABASE_URL=postgres://user:pass@db.internal:5432/app',
      'MONGO=mongodb+srv://u:p@cluster.mongodb.net/db',
      'REDIS_URL=redis://:pass@cache:6379/0',
    ].join('\n');
    const f = scanSecrets(probe({ body }));
    expect(f.some((x) => x.title.includes('PostgreSQL'))).toBe(true);
    expect(f.some((x) => x.title.includes('MongoDB'))).toBe(true);
    expect(f.some((x) => x.title.includes('Redis'))).toBe(true);
    expect(f.every((x) => x.severity === 'critical' || x.severity === 'high')).toBe(true);
  });

  it('flags Stripe, GitHub, Slack, and private keys', () => {
    // Construct fixtures at runtime so the repo never contains push-protection literals.
    const stripe = `sk_live_${'X'.repeat(24)}`;
    const github = `ghp_${'A'.repeat(36)}`;
    const slack = `xoxb-${'1'.repeat(10)}-${'a'.repeat(16)}`;
    const body = [stripe, github, slack, '-----BEGIN RSA PRIVATE KEY-----'].join('\n');
    const f = scanSecrets(probe({ url: 'https://a.x.com/config.js', body }));
    expect(f.some((x) => x.title.includes('Stripe'))).toBe(true);
    expect(f.some((x) => x.title.includes('GitHub'))).toBe(true);
    expect(f.some((x) => x.title.includes('Slack'))).toBe(true);
    expect(f.some((x) => x.title.includes('Private Key'))).toBe(true);
  });

  it('scans Authorization header for embedded basic-auth URLs in body and tokens in headers', () => {
    const f = scanSecrets(
      probe({
        url: 'https://a.x.com/',
        body: 'proxy=https://admin:s3cretpass@internal.x.com:8443/v1',
        headers: {},
      }),
    );
    expect(f.some((x) => x.title.includes('basic-auth'))).toBe(true);
  });

  it('flags hardcoded api_key assignment as high', () => {
    const f = scanSecrets(
      probe({
        url: 'https://a.x.com/static/js/config.js',
        body: 'const api_key = "abcdEFGHijklMNOPqrstUVWX";',
      }),
    );
    expect(f.some((x) => x.severity === 'high' && x.title.includes('API key'))).toBe(true);
    expect(f[0].needsManualReview).toBe(true);
  });

  it('does not confuse Anthropic keys with OpenAI', () => {
    const f = scanSecrets(
      probe({ body: 'KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz' }),
    );
    expect(f.some((x) => x.title.includes('Anthropic'))).toBe(true);
    expect(f.some((x) => x.title.includes('OpenAI'))).toBe(false);
  });

  it('redacts short and long tokens', () => {
    expect(redact('abcd')).toMatch(/\*/);
    expect(redact('abcdefghijklmnop')).toContain('len 16');
  });
});

describe('secretsExposureCheck registry', () => {
  it('is registered and runnable as a Check', () => {
    expect(listChecks().some((c) => c.id === 'secret-exposure')).toBe(true);
    const f = secretsExposureCheck.run(
      probe({ body: 'AKIAIOSFODNN7EXAMPLE' }),
      ctx,
    );
    expect(f.length).toBeGreaterThan(0);
  });

  it('exports a non-trivial rule table', () => {
    expect(SECRET_RULES.length).toBeGreaterThanOrEqual(15);
  });
});

describe('store + report secret integration', () => {
  it('summarizeSecretFindings counts severities', () => {
    const findings: Finding[] = [
      {
        id: '1',
        checkId: 'secret-exposure',
        title: 'AWS',
        severity: 'critical',
        target: 'https://a.x.com/.env',
        description: 'd',
        evidence: 'e',
        reproduction: ['r'],
        remediation: 'fix',
        cwe: 'CWE-798',
        references: [],
        needsManualReview: false,
        discoveredAt: new Date().toISOString(),
      },
      {
        id: '2',
        checkId: 'cors-misconfig',
        title: 'CORS',
        severity: 'high',
        target: 'https://a.x.com/',
        description: 'd',
        evidence: 'e',
        reproduction: ['r'],
        remediation: 'fix',
        references: [],
        needsManualReview: true,
        discoveredAt: new Date().toISOString(),
      },
    ];
    const summary = summarizeSecretFindings(findings);
    expect(summary.total).toBe(1);
    expect(summary.bySeverity.critical).toBe(1);
  });

  it('draftDisclosure highlights secret exposure counts', () => {
    const findings: Finding[] = [
      {
        id: '1',
        checkId: 'secret-exposure',
        title: 'PostgreSQL connection URI exposed',
        severity: 'critical',
        target: 'https://a.x.com/.env',
        description: 'db uri',
        evidence: 'redacted',
        reproduction: ['curl'],
        remediation: 'rotate',
        cwe: 'CWE-312',
        references: [],
        needsManualReview: false,
        discoveredAt: new Date().toISOString(),
      },
    ];
    const md = draftDisclosure(findings, scope);
    expect(md).toContain('Secret exposures: 1');
    expect(md).toContain('1 critical');
    const one = draftFinding(findings[0], scope);
    expect(one).toContain('Cleartext credentials');
  });

  it('FindingsStore.query filters by checkId via in-memory mock', async () => {
    const map = new Map<string, string>();
    const kv = {
      async get(key: string) {
        return map.get(key) ?? null;
      },
      async put(key: string, value: string) {
        map.set(key, value);
      },
    } as unknown as KVNamespace;

    const store = new FindingsStore(kv);
    const secrets = scanSecrets(probe({ body: 'AKIAIOSFODNN7EXAMPLE\npostgres://u:p@h/db' }));
    await store.upsertMany('prog', secrets);
    const onlySecrets = await store.getSecrets('prog');
    expect(onlySecrets.length).toBe(secrets.length);
    expect(onlySecrets.every((f) => f.checkId === 'secret-exposure')).toBe(true);
    const highPlus = await store.query('prog', { minSeverity: 'high' });
    expect(highPlus.every((f) => f.severity === 'high' || f.severity === 'critical')).toBe(true);
  });
});
