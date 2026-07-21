import { describe, it, expect } from 'vitest';
import {
  SQL_CANARY,
  SQL_PATHS,
  buildSqlInjectionProbeUrls,
  hasSqlErrorFingerprint,
  shouldProbeSqlInjection,
  urlCarriesSqlPayload,
} from '../src/recon/sql-probes.js';
import { sqlInjectionCheck } from '../src/detect/checks/sql-injection.js';
import { collectSqlInjectionFollowUps } from '../src/engine/scanner.js';
import { listChecks } from '../src/detect/registry.js';
import { draftFinding } from '../src/report/drafter.js';
import type { CheckContext, Finding, ProbeResult, Scope } from '../src/types.js';

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
    url: 'https://a.x.com/api/users',
    method: 'GET',
    status: 500,
    headers: { 'content-type': 'text/html' },
    body: '',
    elapsedMs: 5,
    ...over,
  };
}

describe('sql probes', () => {
  it('builds error payloads with canary', () => {
    const urls = buildSqlInjectionProbeUrls('https://a.x.com/api/users', 2);
    expect(urls.length).toBeGreaterThan(0);
    expect(urls.some((u) => urlCarriesSqlPayload(u))).toBe(true);
    expect(urls.some((u) => u.includes(SQL_CANARY) || u.includes('%27'))).toBe(true);
    expect(SQL_PATHS).toContain('/api/users');
  });

  it('detects DB error fingerprints', () => {
    expect(hasSqlErrorFingerprint('You have an error in your SQL syntax; check the manual')).toBe(true);
    expect(hasSqlErrorFingerprint('PG::SyntaxError: ERROR: syntax error at or near')).toBe(true);
    expect(hasSqlErrorFingerprint('ORA-00933: SQL command not properly ended')).toBe(true);
    expect(hasSqlErrorFingerprint('hello world')).toBe(false);
  });

  it('shouldProbeSqlInjection matches API and id params', () => {
    expect(shouldProbeSqlInjection(probe({ url: 'https://a.x.com/search', status: 200 }))).toBe(true);
    expect(
      shouldProbeSqlInjection(
        probe({
          url: 'https://a.x.com/api/v1/items?id=1',
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
      ),
    ).toBe(true);
  });
});

describe('sqlInjectionCheck', () => {
  it('flags MySQL syntax errors on payload URLs as critical', () => {
    const url = `https://a.x.com/api/users?id=' OR '${SQL_CANARY}'='${SQL_CANARY}`;
    const findings = sqlInjectionCheck.run(
      probe({
        url,
        status: 500,
        body: `You have an error in your SQL syntax near '${SQL_CANARY}'`,
      }),
      ctx,
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('critical');
    expect(findings[0]!.cwe).toBe('CWE-89');
    expect(findings[0]!.checkId).toBe('sql-injection-error');
  });

  it('ignores errors without SQL payload in URL', () => {
    expect(
      sqlInjectionCheck.run(
        probe({ body: 'You have an error in your SQL syntax' }),
        ctx,
      ),
    ).toHaveLength(0);
  });

  it('is registered and drafts impact', () => {
    expect(listChecks().some((c) => c.id === 'sql-injection-error')).toBe(true);
    const f: Finding = {
      id: 's1',
      checkId: 'sql-injection-error',
      title: 'SQLi',
      severity: 'critical',
      target: "https://a.x.com/u?id='",
      description: 'd',
      evidence: 'e',
      reproduction: ['r'],
      remediation: 'fix',
      cwe: 'CWE-89',
      references: [],
      needsManualReview: false,
      discoveredAt: new Date().toISOString(),
    };
    expect(draftFinding(f, scope)).toMatch(/SQL injection/i);
  });
});

describe('collectSqlInjectionFollowUps', () => {
  it('emits SQL probe URLs for search paths', () => {
    const urls = collectSqlInjectionFollowUps([
      probe({ url: 'https://a.x.com/search', status: 200, body: 'ok' }),
    ]);
    expect(urls.length).toBeGreaterThan(0);
    expect(urls.every((u) => urlCarriesSqlPayload(u))).toBe(true);
  });
});
