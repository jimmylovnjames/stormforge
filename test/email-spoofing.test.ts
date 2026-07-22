import { describe, it, expect } from 'vitest';
import {
  classifySpf,
  classifyDmarc,
  analyzeEmailPosture,
  txtStringsFromDoh,
  EMAIL_DNS_MARKER,
} from '../src/recon/dns-email.js';
import { emailSpoofingCheck } from '../src/detect/checks/email-spoofing.js';
import { listChecks } from '../src/detect/registry.js';
import { cvssFor } from '../src/report/cvss.js';
import type { CheckContext, ProbeResult, Scope } from '../src/types.js';

const scope: Scope = { program: 'p', platform: 'generic', inScope: ['*.acme.com', 'acme.com'], outOfScope: [], authorized: true };
const ctx: CheckContext = { scope };

function emailProbe(domain: string, spfTxts: string[], dmarcTxts: string[]): ProbeResult {
  return {
    url: `https://${domain}/`,
    method: 'GET',
    status: 200,
    headers: { 'x-stormforge-dns': EMAIL_DNS_MARKER, 'content-type': 'application/json' },
    body: JSON.stringify({ domain, spfTxts, dmarcTxts }),
    elapsedMs: 0,
  };
}

describe('dns-email parsing', () => {
  it('txtStringsFromDoh extracts + unquotes TXT records', () => {
    const txts = txtStringsFromDoh({
      Answer: [
        { type: 16, data: '"v=spf1 include:_spf.google.com ~all"' },
        { type: 1, data: '1.2.3.4' },
        { type: 16, data: '"chunk-a" "chunk-b"' },
      ],
    });
    expect(txts).toContain('v=spf1 include:_spf.google.com ~all');
    expect(txts).toContain('chunk-achunk-b');
    expect(txts).toHaveLength(2);
  });

  it('classifySpf reads the all qualifier', () => {
    expect(classifySpf(['v=spf1 -all']).all).toBe('-all');
    expect(classifySpf(['v=spf1 include:x +all']).all).toBe('+all');
    expect(classifySpf(['v=spf1 include:x']).all).toBe('none');
    expect(classifySpf(['nothing']).record).toBeUndefined();
  });

  it('classifyDmarc reads the policy', () => {
    expect(classifyDmarc(['v=DMARC1; p=reject; rua=mailto:x@y']).policy).toBe('reject');
    expect(classifyDmarc(['v=DMARC1; p=none']).policy).toBe('none');
    expect(classifyDmarc([]).policy).toBe('missing');
  });
});

describe('analyzeEmailPosture', () => {
  it('flags +all SPF as high', () => {
    const issues = analyzeEmailPosture({ domain: 'acme.com', spfTxts: ['v=spf1 +all'], dmarcTxts: ['v=DMARC1; p=reject'] });
    expect(issues.some((i) => i.key === 'spf-permissive' && i.severity === 'high')).toBe(true);
  });

  it('collapses weak SPF + weak DMARC into one medium email-spoofable finding', () => {
    const issues = analyzeEmailPosture({ domain: 'acme.com', spfTxts: [], dmarcTxts: [] });
    expect(issues).toHaveLength(1);
    expect(issues[0]!.key).toBe('email-spoofable');
    expect(issues[0]!.severity).toBe('medium');
  });

  it('flags missing DMARC as medium when SPF enforces', () => {
    const issues = analyzeEmailPosture({ domain: 'acme.com', spfTxts: ['v=spf1 -all'], dmarcTxts: [] });
    expect(issues.some((i) => i.key === 'dmarc-missing' && i.severity === 'medium')).toBe(true);
  });

  it('clean posture yields no issues', () => {
    const issues = analyzeEmailPosture({
      domain: 'acme.com',
      spfTxts: ['v=spf1 include:_spf.google.com -all'],
      dmarcTxts: ['v=DMARC1; p=reject; rua=mailto:dmarc@acme.com'],
    });
    expect(issues).toHaveLength(0);
  });
});

describe('emailSpoofingCheck', () => {
  it('emits findings from the synthetic email-DNS probe', () => {
    const f = emailSpoofingCheck.run(emailProbe('acme.com', [], []), ctx);
    expect(f).toHaveLength(1);
    expect(f[0]!.checkId).toBe('email-spoofing');
    expect(f[0]!.target).toBe('https://acme.com/');
    expect(f[0]!.severity).toBe('medium');
  });

  it('ignores probes without the marker header', () => {
    const f = emailSpoofingCheck.run(
      { url: 'https://acme.com/', method: 'GET', status: 200, headers: {}, body: '{}', elapsedMs: 0 },
      ctx,
    );
    expect(f).toHaveLength(0);
  });

  it('is registered and has a CVSS profile', () => {
    expect(listChecks().map((c) => c.id)).toContain('email-spoofing');
    expect(cvssFor({ checkId: 'email-spoofing', severity: 'medium' }).vector).toMatch(/\/I:L\//);
  });
});
