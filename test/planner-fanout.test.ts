import { describe, it, expect } from 'vitest';
import { planFromFindings, paramNamesOf, MAX_EVOLVED_TASKS } from '../src/planning/vuln-planner.js';
import type { Finding, Scope } from '../src/types.js';

const scope: Scope = {
  program: 'acme',
  platform: 'hackerone',
  inScope: ['*.acme.com', 'acme.com'],
  outOfScope: [],
  authorized: true,
};

function finding(over: Partial<Finding> & Pick<Finding, 'checkId' | 'target'>): Finding {
  return {
    id: over.id ?? Math.random().toString(36).slice(2),
    title: over.title ?? over.checkId,
    severity: over.severity ?? 'medium',
    description: over.description ?? '',
    evidence: over.evidence ?? '',
    reproduction: [],
    remediation: '',
    references: [],
    needsManualReview: false,
    discoveredAt: new Date().toISOString(),
    ...over,
  };
}

const hostOf = (url: string) => new URL(url).hostname;

describe('planFromFindings — subfinder/katana host fan-out', () => {
  it('subfinder aggregate emits one scoped httpx per in-scope host + takeover nuclei', () => {
    const plan = planFromFindings(
      [
        finding({
          checkId: 'subfinder-enumeration',
          title: '3 subdomains discovered',
          severity: 'info',
          target: 'acme.com',
          evidence: 'api.acme.com, app.acme.com, cdn.acme.com',
        }),
      ],
      scope,
    );
    const httpxHosts = new Set(plan.tasks.filter((t) => t.tool === 'httpx').map((t) => hostOf(t.target)));
    expect(httpxHosts.has('api.acme.com')).toBe(true);
    expect(httpxHosts.has('app.acme.com')).toBe(true);
    expect(httpxHosts.has('cdn.acme.com')).toBe(true);
    expect(plan.tasks.some((t) => t.tool === 'nuclei' && /takeovers/.test(t.args.templates || ''))).toBe(true);
  });

  it('katana aggregate emits httpx per discovered host and sqlmap per param URL with -p', () => {
    const plan = planFromFindings(
      [
        finding({
          checkId: 'katana-endpoint-discovery',
          title: 'interesting endpoints',
          severity: 'low',
          target: 'https://app.acme.com',
          evidence:
            'https://app.acme.com/search?q=1\nhttps://api.acme.com/v1/items?id=2&sort=name\nhttps://app.acme.com/static/app.js',
        }),
      ],
      scope,
    );
    const httpxHosts = new Set(plan.tasks.filter((t) => t.tool === 'httpx').map((t) => hostOf(t.target)));
    expect(httpxHosts.has('app.acme.com')).toBe(true);
    expect(httpxHosts.has('api.acme.com')).toBe(true);

    const sqlmap = plan.tasks.filter((t) => t.tool === 'sqlmap');
    expect(sqlmap.length).toBeGreaterThanOrEqual(2);
    expect(sqlmap.every((t) => /[?&]\w+=/.test(t.target))).toBe(true);
    const idTask = sqlmap.find((t) => /id=2/.test(t.target));
    expect(idTask?.args.flags).toMatch(/-p (id|id,sort|sort,id)/);
    expect(idTask?.args.param).toMatch(/id/);
  });
});

describe('planFromFindings — API schema / GraphQL', () => {
  it('api-schema-exposure emits katana crawl + nuclei exposures,graphql,swagger', () => {
    const plan = planFromFindings(
      [finding({ checkId: 'api-schema-exposure', severity: 'high', target: 'https://api.acme.com/openapi.json' })],
      scope,
    );
    expect(plan.tasks.some((t) => t.tool === 'katana')).toBe(true);
    const nuclei = plan.tasks.find((t) => t.tool === 'nuclei');
    expect(nuclei).toBeDefined();
    for (const tag of ['exposures', 'graphql', 'swagger']) {
      expect(nuclei!.args.templates).toContain(tag);
    }
  });

  it('graphql-introspection leads with graphql,exposures templates', () => {
    const plan = planFromFindings(
      [finding({ checkId: 'graphql-introspection', severity: 'high', target: 'https://api.acme.com/graphql' })],
      scope,
    );
    const nuclei = plan.tasks.find((t) => t.tool === 'nuclei');
    expect(nuclei!.args.templates).toMatch(/graphql/);
    expect(nuclei!.args.templates).toMatch(/exposures/);
  });
});

describe('planFromFindings — secret + exposed-file packs', () => {
  it('secret-exposure emits a secret-confirmation nuclei pack (tokens)', () => {
    const plan = planFromFindings(
      [finding({ checkId: 'secret-exposure', severity: 'high', target: 'https://app.acme.com/static/main.js' })],
      scope,
    );
    const nuclei = plan.tasks.find((t) => t.tool === 'nuclei');
    expect(nuclei!.args.templates).toMatch(/tokens/);
    expect(nuclei!.args.templates).toMatch(/exposures/);
    expect(/Secret-confirmation/i.test(nuclei!.rationale)).toBe(true);
  });

  it('exposed-files emits a directory-scoped ffuf near the disclosure + exposures nuclei', () => {
    const plan = planFromFindings(
      [finding({ checkId: 'exposed-files', severity: 'high', target: 'https://app.acme.com/.git/config' })],
      scope,
    );
    const ffuf = plan.tasks.find((t) => t.tool === 'ffuf');
    expect(ffuf).toBeDefined();
    // Fuzz base should be scoped to the disclosure directory, not just the root.
    expect(ffuf!.target).toBe('https://app.acme.com/.git/FUZZ');
    expect(plan.tasks.some((t) => t.tool === 'nuclei' && /exposures/.test(t.args.templates || ''))).toBe(true);
  });
});

describe('planFromFindings — context + caps', () => {
  it('high/critical findings carry a CVSS vector and source provenance in task args', () => {
    const plan = planFromFindings(
      [finding({ checkId: 'api-schema-exposure', severity: 'high', target: 'https://api.acme.com/openapi.json' })],
      scope,
    );
    const t = plan.tasks[0]!;
    expect(t.args.srcCheck).toBe('api-schema-exposure');
    expect(t.args.srcSeverity).toBe('high');
    expect(t.args.cvss).toMatch(/^CVSS:3\.1\//);
  });

  it('never exceeds the evolved task cap even with many findings', () => {
    const many: Finding[] = [];
    for (let i = 0; i < 40; i++) {
      many.push(
        finding({
          id: `k${i}`,
          checkId: 'katana-endpoint-discovery',
          severity: 'low',
          target: `https://h${i}.acme.com`,
          evidence: `https://h${i}.acme.com/a?x=1\nhttps://h${i}.acme.com/b?y=2`,
        }),
      );
    }
    const plan = planFromFindings(many, scope);
    expect(plan.tasks.length).toBeLessThanOrEqual(MAX_EVOLVED_TASKS);
    expect(plan.source).toBe('evolved');
  });

  it('drops out-of-scope hosts discovered in evidence', () => {
    const plan = planFromFindings(
      [
        finding({
          checkId: 'katana-endpoint-discovery',
          severity: 'low',
          target: 'https://app.acme.com',
          evidence: 'https://evil.com/leak?t=1\nhttps://api.acme.com/x?id=9',
        }),
      ],
      scope,
    );
    expect(plan.tasks.every((t) => !/evil\.com/.test(t.target))).toBe(true);
    expect(plan.tasks.some((t) => /api\.acme\.com/.test(t.target))).toBe(true);
  });
});

describe('paramNamesOf', () => {
  it('extracts distinct query param names', () => {
    expect(paramNamesOf('https://a.acme.com/x?id=1&sort=asc&id=2')).toBe('id,sort');
    expect(paramNamesOf('/rel?token=abc&next=/home')).toBe('token,next');
    expect(paramNamesOf('https://a.acme.com/nofilter')).toBe('');
  });
});
