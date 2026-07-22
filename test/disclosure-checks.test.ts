import { describe, it, expect } from 'vitest';
import { debugDisclosureCheck } from '../src/detect/checks/debug-disclosure.js';
import { directoryListingCheck } from '../src/detect/checks/directory-listing.js';
import { listChecks } from '../src/detect/registry.js';
import { planFromFindings } from '../src/planning/vuln-planner.js';
import { cvssFor } from '../src/report/cvss.js';
import type { CheckContext, Finding, ProbeResult, Scope } from '../src/types.js';

const scope: Scope = { program: 'p', platform: 'generic', inScope: ['*.x.com', 'x.com'], outOfScope: [], authorized: true };
const ctx: CheckContext = { scope };

function probe(over: Partial<ProbeResult>): ProbeResult {
  return { url: 'https://a.x.com/', method: 'GET', status: 200, headers: {}, body: '', elapsedMs: 5, ...over };
}

function finding(over: Partial<Finding> & Pick<Finding, 'checkId' | 'target'>): Finding {
  return {
    id: 'f',
    title: over.checkId,
    severity: 'medium',
    description: '',
    evidence: '',
    reproduction: [],
    remediation: '',
    references: [],
    needsManualReview: false,
    discoveredAt: new Date().toISOString(),
    ...over,
  };
}

describe('debugDisclosureCheck', () => {
  it('flags a Django DEBUG=True page as high + submitReady', () => {
    const body =
      '<html><body><h1>ValueError at /accounts/</h1><p>Traceback (most recent call last)</p>' +
      '<table><tr><td>Django Version:</td><td>4.2.1</td></tr></table>' +
      "<p>You&#39;re seeing this error because you have <code>DEBUG = True</code></p></body></html>";
    const f = debugDisclosureCheck.run(probe({ url: 'https://a.x.com/accounts/', status: 500, body }), ctx);
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('high');
    expect(f[0]!.submitReady).toBe(true);
    expect(f[0]!.checkId).toBe('debug-disclosure');
  });

  it('flags the Werkzeug interactive debugger as high', () => {
    const body =
      '<title>Werkzeug Debugger</title><div class="traceback"><h2>Traceback (most recent call last)</h2>' +
      '<div class="console">__debugger__</div>';
    const f = debugDisclosureCheck.run(probe({ url: 'https://a.x.com/boom', status: 500, body }), ctx);
    expect(f[0]!.severity).toBe('high');
    expect(f[0]!.title).toMatch(/Werkzeug/);
  });

  it('flags a PHP fatal with source path as medium', () => {
    const body = 'Fatal error: Uncaught Error: Class not found in /var/www/html/app/Model.php on line 42';
    const f = debugDisclosureCheck.run(probe({ url: 'https://a.x.com/x.php', status: 200, body }), ctx);
    expect(f[0]!.severity).toBe('medium');
  });

  it('does not flag an ordinary HTML page', () => {
    const f = debugDisclosureCheck.run(
      probe({ headers: { 'content-type': 'text/html' }, body: '<html><body>Welcome to Acme</body></html>' }),
      ctx,
    );
    expect(f).toHaveLength(0);
  });
});

describe('directoryListingCheck', () => {
  it('flags an Apache autoindex page', () => {
    const body =
      '<html><head><title>Index of /uploads</title></head><body><h1>Index of /uploads</h1>' +
      '<a href="../">Parent Directory</a><a href="a.txt">a.txt</a>' +
      '<address>Apache/2.4.41 (Ubuntu) Server at a.x.com Port 443</address></body></html>';
    const f = directoryListingCheck.run(probe({ url: 'https://a.x.com/uploads/', headers: { 'content-type': 'text/html' }, body }), ctx);
    expect(f).toHaveLength(1);
    expect(f[0]!.checkId).toBe('directory-listing');
    expect(f[0]!.severity).toBe('low');
  });

  it('raises severity when sensitive files are listed', () => {
    const body =
      '<title>Index of /backup</title><h1>Index of /backup</h1>' +
      '<a href="../">Parent Directory</a><a href="db.sql">db.sql</a><a href="app.env">app.env</a>' +
      '<address>Apache/2.4.41 Server at a.x.com Port 443</address>';
    const f = directoryListingCheck.run(probe({ url: 'https://a.x.com/backup/', body }), ctx);
    expect(f[0]!.severity).toBe('medium');
    expect(f[0]!.title).toMatch(/sensitive/i);
  });

  it('does not flag an application page that merely says "index"', () => {
    const f = directoryListingCheck.run(
      probe({ headers: { 'content-type': 'text/html' }, body: '<html><title>Home</title><body>Index page</body></html>' }),
      ctx,
    );
    expect(f).toHaveLength(0);
  });
});

describe('registry + cvss + planner wiring', () => {
  it('registers the new checks', () => {
    const ids = listChecks().map((c) => c.id);
    expect(ids).toContain('debug-disclosure');
    expect(ids).toContain('directory-listing');
  });

  it('debug-disclosure has a confidentiality-high CVSS profile (>= high band)', () => {
    const r = cvssFor({ checkId: 'debug-disclosure', severity: 'high' });
    expect(r.score).toBeGreaterThanOrEqual(7.0);
    expect(r.vector).toMatch(/\/C:H\//);
  });

  it('debug-disclosure finding fans out to an exposures/tokens nuclei task', () => {
    const plan = planFromFindings(
      [finding({ checkId: 'debug-disclosure', severity: 'high', target: 'https://a.x.com/boom' })],
      scope,
    );
    const nuclei = plan.tasks.find((t) => t.tool === 'nuclei');
    expect(nuclei).toBeDefined();
    expect(nuclei!.args.templates).toMatch(/tokens/);
    expect(nuclei!.args.cvss).toMatch(/^CVSS:3\.1\//);
  });

  it('directory-listing finding fans out to a directory-scoped ffuf', () => {
    const plan = planFromFindings(
      [finding({ checkId: 'directory-listing', severity: 'medium', target: 'https://a.x.com/backup/' })],
      scope,
    );
    const ffuf = plan.tasks.find((t) => t.tool === 'ffuf');
    expect(ffuf).toBeDefined();
    expect(ffuf!.target).toBe('https://a.x.com/backup/FUZZ');
  });
});
