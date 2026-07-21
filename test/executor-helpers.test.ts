// @ts-nocheck — exercises executor.mjs helpers; typings live in the .mjs runtime.
import { describe, it, expect } from 'vitest';
import {
  canonicalizeTarget,
  makeFindingId,
  isInScope,
  hashTokenList,
  parseHttpxOutput,
  parseSubfinderOutput,
  parseNucleiOutput,
  parseKatanaOutput,
  parseSqlmapOutput,
} from '../executor/executor.mjs';

describe('executor helpers', () => {
  it('canonicalize + makeFindingId align with Worker-style stability', () => {
    const a = makeFindingId('nuclei', 'https://API.acme.com/x/', 't1');
    const b = makeFindingId('nuclei', 'http://api.acme.com/x', 't1');
    expect(a).toBe(b);
    expect(canonicalizeTarget('https://A.com/v1/')).toBe('a.com/v1');
  });

  it('isInScope requires authorized and pattern match', () => {
    const scope = {
      authorized: true,
      inScope: ['*.acme.com', 'httpbin.org'],
      outOfScope: ['blog.acme.com'],
    };
    expect(isInScope('https://app.acme.com', scope)).toBe(true);
    expect(isInScope('https://httpbin.org/get', scope)).toBe(true);
    expect(isInScope('https://blog.acme.com', scope)).toBe(false);
    expect(isInScope('https://app.acme.com', { ...scope, authorized: false })).toBe(false);
  });

  it('subfinder id uses content hash not count', () => {
    const task = { target: 'acme.com', scope: { authorized: true, inScope: ['acme.com'], outOfScope: [] } };
    const f1 = parseSubfinderOutput('a.acme.com\nb.acme.com\n', task);
    const f2 = parseSubfinderOutput('b.acme.com\na.acme.com\n', task);
    expect(f1[0].id).toBe(f2[0].id);
    expect(hashTokenList(['a', 'b'])).toBe(hashTokenList(['b', 'a']));
  });

  it('httpx tech uses stable tech-set key', () => {
    const task = {
      target: 'https://httpbin.org',
      scope: { authorized: true, inScope: ['httpbin.org'], outOfScope: [] },
    };
    const line = JSON.stringify({
      url: 'https://httpbin.org',
      tech: ['nginx', 'Go'],
      'status-code': 200,
      title: 'httpbin.org',
    });
    const f = parseHttpxOutput(line, task);
    expect(f).toHaveLength(1);
    expect(f[0].checkId).toBe('httpx-tech-detect');
  });

  it('nuclei drops info severity noise', () => {
    const task = { target: 'https://httpbin.org' };
    const info = JSON.stringify({
      host: 'https://httpbin.org',
      'template-id': 'tech-detect',
      info: { name: 'tech', severity: 'info' },
    });
    const high = JSON.stringify({
      host: 'https://httpbin.org',
      'matched-at': 'https://httpbin.org/admin',
      'template-id': 'cve-2020-1',
      'matcher-name': 'status',
      'extracted-results': ['admin'],
      'curl-command': 'curl https://httpbin.org/admin',
      info: { name: 'cve', severity: 'high', description: 'x' },
    });
    expect(parseNucleiOutput(info, task)).toHaveLength(0);
    const hits = parseNucleiOutput(high, task);
    expect(hits).toHaveLength(1);
    expect(hits[0].evidence).toMatch(/matcher/);
    expect(hits[0].target).toContain('/admin');
  });

  it('katana emits per-param URL findings', () => {
    const task = { target: 'https://app.acme.com' };
    const out = parseKatanaOutput(
      'https://app.acme.com/\nhttps://app.acme.com/search?q=1\nhttps://app.acme.com/api/v1\n',
      task,
    );
    expect(out.some((f) => f.checkId === 'katana-endpoint-discovery')).toBe(true);
    expect(out.some((f) => f.checkId === 'katana-param-url' && f.target.includes('q=1'))).toBe(true);
  });

  it('sqlmap extracts parameter and DBMS', () => {
    const task = { target: 'https://app.acme.com/?id=1' };
    const stdout = `
Parameter: id (GET) is vulnerable. Do you want to keep testing others? [y/N]
Type: boolean-based blind
back-end DBMS: MySQL >= 5.0
`;
    const f = parseSqlmapOutput(stdout, task);
    expect(f).toHaveLength(1);
    expect(f[0].title).toMatch(/id/);
    expect(f[0].description).toMatch(/MySQL/);
  });
});
