import { describe, it, expect, vi, afterEach } from 'vitest';
import {
  parseCollaborator,
  newOastToken,
  buildOastPayload,
  pollRequestUrl,
  extractToken,
  parsePollResponse,
  oastConfigured,
} from '../src/oast/collaborator.js';
import { OastStore } from '../src/oast/store.js';
import { pollAndCorrelate, buildConfirmedFinding } from '../src/oast/poller.js';
import { detectSsrfCandidates, ssrfCandidateCheck } from '../src/detect/checks/ssrf-candidate.js';
import { listChecks } from '../src/detect/registry.js';
import { cvssFor } from '../src/report/cvss.js';
import { FindingsStore } from '../src/findings/store.js';
import { memoryKv } from './helpers/memory-kv.js';
import type { CheckContext, Env, ProbeResult, Scope } from '../src/types.js';
import type { OastPayload as OP } from '../src/oast/types.js';

const scope: Scope = { program: 'acme', platform: 'generic', inScope: ['*.acme.com', 'acme.com'], outOfScope: [], authorized: true };
const ctx: CheckContext = { scope };

function env(kv: KVNamespace, over: Partial<Env> = {}): Env {
  return {
    SCAN_ORCHESTRATOR: {} as Env['SCAN_ORCHESTRATOR'],
    STORMFORGE_KV: kv,
    MAX_RPS: '5',
    MAX_CONCURRENCY: '5',
    SCAN_MODE: 'hybrid',
    LLM_PLANNER_ENDPOINT: '',
    LLM_PLANNER_MODEL: 'grok-4',
    ...over,
  };
}

function probe(over: Partial<ProbeResult>): ProbeResult {
  return { url: 'https://a.acme.com/', method: 'GET', status: 200, headers: {}, body: '', elapsedMs: 1, ...over };
}

afterEach(() => vi.unstubAllGlobals());

describe('collaborator config parsing', () => {
  it('parses single-host form', () => {
    const cfg = parseCollaborator(env(memoryKv(), { OAST_COLLABORATOR_ENDPOINT: 'https://collab.example.com' }))!;
    expect(cfg.pollBase).toBe('https://collab.example.com');
    expect(cfg.callbackDomain).toBe('collab.example.com');
  });
  it('parses split poll/callback form', () => {
    const cfg = parseCollaborator(env(memoryKv(), { OAST_COLLABORATOR_ENDPOINT: 'https://poll.example.com/base|cb.example.com' }))!;
    expect(cfg.pollBase).toBe('https://poll.example.com/base');
    expect(cfg.callbackDomain).toBe('cb.example.com');
  });
  it('oastConfigured reflects the secret', () => {
    expect(oastConfigured(env(memoryKv()))).toBe(false);
    expect(oastConfigured(env(memoryKv(), { OAST_COLLABORATOR_ENDPOINT: 'https://c.example.com' }))).toBe(true);
  });
});

describe('token + payload + poll url', () => {
  const cfg = { pollBase: 'https://collab.example.com', callbackDomain: 'collab.example.com' };
  it('token is dns-label safe and unique', () => {
    const a = newOastToken();
    const b = newOastToken();
    expect(a).toMatch(/^sf[a-z0-9]{4,}$/);
    expect(a).not.toBe(b);
  });
  it('payload host + url embed the token', () => {
    const p = buildOastPayload(cfg, 'sfabc123');
    expect(p.host).toBe('sfabc123.collab.example.com');
    expect(p.url).toBe('http://sfabc123.collab.example.com/sfabc123');
  });
  it('pollRequestUrl includes since', () => {
    expect(pollRequestUrl(cfg, 1700)).toBe('https://collab.example.com/poll?since=1700');
  });
  it('extractToken pulls the label under the callback domain', () => {
    expect(extractToken('sfabc123.collab.example.com', 'collab.example.com')).toBe('sfabc123');
    expect(extractToken('x.sfabc123.collab.example.com', 'collab.example.com')).toBe('sfabc123');
    expect(extractToken('evil.com', 'collab.example.com')).toBeNull();
  });
  it('parsePollResponse normalizes hits + channel', () => {
    const hits = parsePollResponse(
      { hits: [{ host: 'sfabc123.collab.example.com', protocol: 'DNS', remoteAddress: '1.2.3.4', timestamp: 't' }] },
      'collab.example.com',
    );
    expect(hits).toHaveLength(1);
    expect(hits[0]!.token).toBe('sfabc123');
    expect(hits[0]!.channel).toBe('dns');
  });
});

describe('detectSsrfCandidates', () => {
  it('flags url/redirect/callback/file/host params', () => {
    const c1 = detectSsrfCandidates('https://a.acme.com/p?url=https://x.com');
    expect(c1.some((c) => c.kind === 'url-param' && c.confidence === 'high')).toBe(true);
    expect(detectSsrfCandidates('https://a.acme.com/p?next=https://x.com').some((c) => c.kind === 'redirect')).toBe(true);
    expect(detectSsrfCandidates('https://a.acme.com/p?webhook=https://x.com').some((c) => c.kind === 'callback')).toBe(true);
    expect(detectSsrfCandidates('https://a.acme.com/p?file=../../etc/passwd').some((c) => c.kind === 'file-inclusion')).toBe(true);
    expect(detectSsrfCandidates('https://a.acme.com/p?host=internal').some((c) => c.kind === 'host-param')).toBe(true);
  });
  it('ignores benign params', () => {
    expect(detectSsrfCandidates('https://a.acme.com/p?color=red&size=3')).toHaveLength(0);
  });
});

describe('ssrfCandidateCheck', () => {
  it('tags a probe URL with SSRF candidate params', () => {
    const f = ssrfCandidateCheck.run(probe({ url: 'https://a.acme.com/fetch?url=https://x.com&next=/y' }), ctx);
    expect(f).toHaveLength(1);
    expect(f[0]!.checkId).toBe('ssrf-candidate');
    expect(f[0]!.severity).toBe('low'); // url-value present → high-confidence → low
  });
  it('is registered and has a CVSS profile', () => {
    expect(listChecks().map((c) => c.id)).toContain('ssrf-candidate');
    expect(cvssFor({ checkId: 'ssrf-oast-confirmed', severity: 'critical' }).vector).toMatch(/\/S:C\//);
  });
});

describe('OastStore + pollAndCorrelate', () => {
  function payload(over: Partial<OP> = {}): OP {
    return {
      token: 'sfabc123',
      url: 'http://sfabc123.collab.example.com/sfabc123',
      host: 'sfabc123.collab.example.com',
      scanId: 'scan-1',
      program: 'acme',
      target: 'https://a.acme.com/fetch?url=CANARY',
      vector: 'param:url',
      createdAt: new Date().toISOString(),
      ...over,
    };
  }

  it('registers, records a hit, and reports results', async () => {
    const kv = memoryKv();
    const store = new OastStore(kv);
    await store.registerPayload(payload());
    const rec = await store.recordHit({ token: 'sfabc123', channel: 'http', host: 'sfabc123.collab.example.com', at: 't' });
    expect(rec?.isFirstHit).toBe(true);
    const res = await store.results(env(kv, { OAST_COLLABORATOR_ENDPOINT: 'https://collab.example.com' }), 'acme');
    expect(res.total).toBe(1);
    expect(res.confirmed).toBe(1);
    expect(res.hitCount).toBe(1);
  });

  it('ignores hits for unknown tokens', async () => {
    const store = new OastStore(memoryKv());
    expect(await store.recordHit({ token: 'unknown', channel: 'dns', host: 'x', at: 't' })).toBeNull();
  });

  it('pollAndCorrelate records hits and raises a confirmed SSRF finding', async () => {
    const kv = memoryKv();
    const e = env(kv, { OAST_COLLABORATOR_ENDPOINT: 'https://collab.example.com', EXECUTOR_SECRET: 's' });
    const store = new OastStore(kv);
    await store.registerPayload(payload());

    vi.stubGlobal('fetch', async () =>
      new Response(
        JSON.stringify({ hits: [{ host: 'sfabc123.collab.example.com', type: 'http', remoteAddress: '10.0.0.5', timestamp: 't' }] }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      ),
    );

    const summary = await pollAndCorrelate(e);
    expect(summary.configured).toBe(true);
    expect(summary.newHits).toBe(1);
    expect(summary.confirmed).toBe(1);

    const findings = await new FindingsStore(kv).getAll('acme');
    const confirmed = findings.find((f) => f.checkId === 'ssrf-oast-confirmed');
    expect(confirmed).toBeDefined();
    expect(confirmed!.severity).toBe('critical');
    expect(confirmed!.submitReady).toBe(true);
    expect(confirmed!.evidence).toContain('param:url');
  });

  it('reports not-configured cleanly', async () => {
    const summary = await pollAndCorrelate(env(memoryKv()));
    expect(summary.configured).toBe(false);
    expect(summary.error).toMatch(/not set/);
  });
});

describe('buildConfirmedFinding', () => {
  it('links execution, target, and vector', () => {
    const f = buildConfirmedFinding(
      {
        token: 'sfx', url: 'u', host: 'h', scanId: 'scan-9', program: 'acme',
        target: 'https://a.acme.com/f?url=x', vector: 'param:url', createdAt: 't',
      } as OP,
      'dns',
      '203.0.113.9',
    );
    expect(f.checkId).toBe('ssrf-oast-confirmed');
    expect(f.evidence).toContain('scan-9');
    expect(f.evidence).toContain('203.0.113.9');
    expect(f.cwe).toBe('CWE-918');
  });
});
