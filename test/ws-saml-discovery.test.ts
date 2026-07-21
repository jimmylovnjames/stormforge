import { describe, it, expect } from 'vitest';
import { wsSamlDiscoveryCheck } from '../src/detect/checks/ws-saml-discovery.js';
import { FEDERATION_PATHS } from '../src/recon/wordlists.js';
import { listChecks } from '../src/detect/registry.js';
import { planPathsFromFindings } from '../src/planning/llm-planner.js';
import { fingerprint } from '../src/recon/fingerprint.js';
import type { ProbeResult, Scope, CheckContext, Finding } from '../src/types.js';

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
    url: 'https://a.x.com/',
    method: 'GET',
    status: 200,
    headers: {},
    body: '',
    elapsedMs: 5,
    ...over,
  };
}

describe('FEDERATION_PATHS', () => {
  it('includes OIDC discovery, SAML metadata, and WebSocket surfaces', () => {
    expect(FEDERATION_PATHS).toContain('/.well-known/openid-configuration');
    expect(FEDERATION_PATHS.some((p) => /saml/i.test(p))).toBe(true);
    expect(FEDERATION_PATHS.some((p) => /ws|socket|cable|realtime/i.test(p))).toBe(true);
  });
});

describe('wsSamlDiscoveryCheck', () => {
  it('is registered', () => {
    expect(listChecks().some((c) => c.id === 'ws-saml-discovery')).toBe(true);
  });

  it('flags OIDC discovery documents with issuer + jwks_uri', () => {
    const body = JSON.stringify({
      issuer: 'https://a.x.com',
      authorization_endpoint: 'https://a.x.com/oauth/authorize',
      token_endpoint: 'https://a.x.com/oauth/token',
      jwks_uri: 'https://a.x.com/.well-known/jwks.json',
    });
    const f = wsSamlDiscoveryCheck.run(
      probe({
        url: 'https://a.x.com/.well-known/openid-configuration',
        headers: { 'content-type': 'application/json' },
        body,
      }),
      ctx,
    );
    expect(f.some((x) => /openid|oidc/i.test(x.title))).toBe(true);
    expect(f[0]!.severity).toMatch(/info|low|medium/);
  });

  it('flags SAML metadata EntityDescriptor responses', () => {
    const body = `<?xml version="1.0"?>
<EntityDescriptor entityID="https://a.x.com/saml" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/>
</EntityDescriptor>`;
    const f = wsSamlDiscoveryCheck.run(
      probe({
        url: 'https://a.x.com/saml/metadata',
        headers: { 'content-type': 'application/xml' },
        body,
      }),
      ctx,
    );
    expect(f.some((x) => /saml/i.test(x.title))).toBe(true);
  });

  it('flags WebSocket upgrade / socket.io surfaces', () => {
    const f = wsSamlDiscoveryCheck.run(
      probe({
        url: 'https://a.x.com/socket.io/?EIO=4&transport=polling',
        status: 200,
        headers: { 'content-type': 'text/plain' },
        body: '0{"sid":"abc","upgrades":["websocket"],"pingInterval":25000}',
      }),
      ctx,
    );
    expect(f.some((x) => /websocket|socket/i.test(x.title))).toBe(true);
  });

  it('flags sec-websocket-accept / upgrade headers', () => {
    const f = wsSamlDiscoveryCheck.run(
      probe({
        url: 'https://a.x.com/ws',
        status: 101,
        headers: {
          upgrade: 'websocket',
          connection: 'Upgrade',
          'sec-websocket-accept': 's3pPLMBiTxaQ9kYGzzhZRbK+xOo=',
        },
        body: '',
      }),
      ctx,
    );
    expect(f.some((x) => /websocket/i.test(x.title))).toBe(true);
  });

  it('ignores unrelated HTML', () => {
    const f = wsSamlDiscoveryCheck.run(
      probe({ url: 'https://a.x.com/', headers: { 'content-type': 'text/html' }, body: '<html>hello</html>' }),
      ctx,
    );
    expect(f).toHaveLength(0);
  });
});

describe('fingerprint + planner follow-ups for federation', () => {
  it('fingerprints OIDC discovery and SAML metadata', () => {
    const oidc = fingerprint(
      probe({
        url: 'https://a.x.com/.well-known/openid-configuration',
        body: JSON.stringify({
          issuer: 'https://a.x.com',
          jwks_uri: 'https://a.x.com/jwks',
          authorization_endpoint: 'https://a.x.com/auth',
        }),
      }),
    );
    expect(oidc.some((t) => /openid|oidc/i.test(t.product))).toBe(true);

    const saml = fingerprint(
      probe({
        body: '<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"><IDPSSODescriptor/></EntityDescriptor>',
      }),
    );
    expect(saml.some((t) => /saml/i.test(t.product))).toBe(true);
  });

  it('planPathsFromFindings expands federation follow-ups', () => {
    const finding: Finding = {
      id: '1',
      checkId: 'ws-saml-discovery',
      title: 'OIDC discovery document exposed',
      severity: 'low',
      target: 'https://a.x.com/.well-known/openid-configuration',
      description: 'd',
      evidence: '',
      reproduction: [],
      remediation: '',
      references: [],
      needsManualReview: true,
      discoveredAt: new Date().toISOString(),
    };
    const plan = planPathsFromFindings([finding]);
    expect(plan.suggestedPaths).toContain('/.well-known/openid-configuration');
    expect(plan.suggestedPaths.some((p) => /jwks|saml|oauth|authorize/i.test(p))).toBe(true);
  });
});
