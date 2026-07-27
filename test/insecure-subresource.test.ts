import { describe, it, expect } from 'vitest';
import { insecureSubresourceCheck } from '../src/detect/checks/insecure-subresource.js';
import { listChecks } from '../src/detect/registry.js';
import type { ProbeResult, Scope, CheckContext } from '../src/types.js';

const scope: Scope = { program: 'p', platform: 'generic', inScope: ['*.x.com'], outOfScope: [], authorized: true };
const ctx: CheckContext = { scope };

function probe(over: Partial<ProbeResult>): ProbeResult {
  return {
    url: 'https://a.x.com/',
    method: 'GET',
    status: 200,
    headers: { 'content-type': 'text/html' },
    body: '',
    elapsedMs: 5,
    ...over,
  };
}

describe('insecureSubresourceCheck', () => {
  it('flags mixed active content on an HTTPS page', () => {
    const body = `<html><head>
      <script src="http://cdn.evil.com/a.js"></script>
      <link rel="stylesheet" href="http://cdn.evil.com/a.css">
    </head></html>`;
    const f = insecureSubresourceCheck.run(probe({ body }), ctx);
    const mixed = f.find((x) => x.title.includes('Mixed content'));
    expect(mixed).toBeTruthy();
    // A script over http:// is medium, which should win over the stylesheet's low.
    expect(mixed!.severity).toBe('medium');
    expect(mixed!.cwe).toBe('CWE-319');
    expect(mixed!.evidence).toContain('http://cdn.evil.com/a.js');
  });

  it('does not flag https sub-resources as mixed content', () => {
    const body = `<script src="https://a.x.com/a.js"></script>`;
    const f = insecureSubresourceCheck.run(probe({ body }), ctx);
    expect(f.some((x) => x.title.includes('Mixed content'))).toBe(false);
  });

  it('rates a cleartext login form as high and submit-ready', () => {
    const body = `<form action="http://a.x.com/login" method="post">
      <input type="text" name="user">
      <input type="password" name="pass">
    </form>`;
    const f = insecureSubresourceCheck.run(probe({ body }), ctx);
    const form = f.find((x) => x.title.includes('Login form'));
    expect(form).toBeTruthy();
    expect(form!.severity).toBe('high');
    expect(form!.submitReady).toBe(true);
  });

  it('rates a non-credential cleartext form as medium and needing review', () => {
    const body = `<form action="http://a.x.com/search"><input type="text" name="q"></form>`;
    const f = insecureSubresourceCheck.run(probe({ body }), ctx);
    const form = f.find((x) => x.title.startsWith('Form submits data'));
    expect(form).toBeTruthy();
    expect(form!.severity).toBe('medium');
    expect(form!.needsManualReview).toBe(true);
  });

  it('flags cross-origin script without integrity (missing SRI)', () => {
    const body = `<script src="https://cdn.jsdelivr.net/npm/lib.js"></script>`;
    const f = insecureSubresourceCheck.run(probe({ body }), ctx);
    const sri = f.find((x) => x.title.includes('Subresource Integrity'));
    expect(sri).toBeTruthy();
    expect(sri!.cwe).toBe('CWE-353');
    expect(sri!.evidence).toContain('cdn.jsdelivr.net');
  });

  it('does not flag cross-origin script that has an integrity attribute', () => {
    const body = `<script src="https://cdn.jsdelivr.net/npm/lib.js" integrity="sha384-abc" crossorigin="anonymous"></script>`;
    const f = insecureSubresourceCheck.run(probe({ body }), ctx);
    expect(f.some((x) => x.title.includes('Subresource Integrity'))).toBe(false);
  });

  it('does not flag same-origin scripts for SRI', () => {
    const body = `<script src="/local/app.js"></script>`;
    const f = insecureSubresourceCheck.run(probe({ body }), ctx);
    expect(f).toHaveLength(0);
  });

  it('ignores non-HTML and error responses', () => {
    expect(insecureSubresourceCheck.run(probe({ headers: { 'content-type': 'application/json' }, body: '{}' }), ctx)).toHaveLength(0);
    expect(insecureSubresourceCheck.run(probe({ error: 'timeout', body: '<script src="http://x">' }), ctx)).toHaveLength(0);
    expect(insecureSubresourceCheck.run(probe({ status: 404, body: '<script src="http://x">' }), ctx)).toHaveLength(0);
  });

  it('produces stable ids across identical runs', () => {
    const body = `<script src="http://cdn.evil.com/a.js"></script>`;
    const a = insecureSubresourceCheck.run(probe({ body }), ctx);
    const b = insecureSubresourceCheck.run(probe({ body }), ctx);
    expect(a[0]?.id).toBe(b[0]?.id);
  });
});

describe('registry', () => {
  it('registers the insecure-subresource check', () => {
    expect(listChecks().map((c) => c.id)).toContain('insecure-subresource');
  });
});
