// Confirmed GraphQL introspection / explorer exposure (passive body signatures).

import type { Check, Finding, ProbeResult } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';
import { parseBodySignals, graphqlIntrospectionQuery } from '../../recon/body-parse.js';
import {
  extractGraphqlIdorFields,
  materializeGraphqlUrls,
  formatGraphqlIdorCandidates,
} from '../../recon/graphql-extract.js';

export const graphqlIntrospectionCheck: Check = {
  id: 'graphql-introspection',
  title: 'GraphQL introspection / explorer exposure',
  cwe: 'CWE-200',
  run(probe: ProbeResult): Finding[] {
    if (probe.error || !probe.body) return [];
    const signals = probe.signals ?? parseBodySignals(probe.body, probe.headers, probe.status);
    const findings: Finding[] = [];

    if (signals.graphqlIntrospection && probe.status >= 200 && probe.status < 300) {
      const fields = extractGraphqlIdorFields(probe.body);
      let endpoint = probe.url;
      try {
        const u = new URL(probe.finalUrl ?? probe.url);
        u.search = '';
        endpoint = u.toString();
      } catch {
        /* keep */
      }
      const candidates = materializeGraphqlUrls(endpoint, fields, 10);
      const idorBlock = candidates.length
        ? `\nIDOR-shaped Query fields: ${fields.map((f) => `${f.field}(${f.arg})`).slice(0, 8).join(', ')}\nCandidate GETs:\n${formatGraphqlIdorCandidates(candidates)}`
        : '';

      findings.push({
        id: makeFindingId(this.id, probe.url, 'introspection'),
        checkId: this.id,
        title: fields.length
          ? `GraphQL introspection enabled (${fields.length} IDOR-shaped Query field(s))`
          : 'GraphQL introspection enabled (schema disclosed)',
        severity: 'high',
        target: probe.url,
        description:
          'A GraphQL introspection query succeeded and returned a `__schema` payload. Attackers can enumerate every type, query, and mutation — including privileged operations — without authenticated discovery.' +
          (fields.length
            ? ` ${fields.length} Query field(s) accept ID-like arguments and are strong BOLA/IDOR follow-up targets.`
            : ''),
        evidence: `URL: ${probe.url}\nStatus: ${probe.status}\nQuery: ${graphqlIntrospectionQuery()}\nSignature: graphql-introspection\nBody preview: ${signals.preview}${idorBlock}`,
        reproduction: [
          `curl -sG '${stripQuery(probe.url)}' --data-urlencode 'query=${graphqlIntrospectionQuery()}'`,
          'Confirm the JSON response contains data.__schema.queryType and types[]',
          ...(candidates[0]
            ? [`Probe an IDOR-shaped field (GET-only): curl -sG '${stripQuery(probe.url)}' --data-urlencode 'query={…}'`]
            : []),
        ],
        remediation:
          'Disable introspection in production (`introspection: false` / equivalent). Restrict GraphQL explorers to non-production environments. Enforce object-level authorization on every ID-argument field.',
        cwe: 'CWE-200',
        references: [
          'https://cwe.mitre.org/data/definitions/200.html',
          'https://graphql.org/learn/introspection/',
          'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/',
        ],
        needsManualReview: false,
        evidenceGrade: 'canary',
        confidence: fields.length ? 0.96 : 0.95,
        submitReady: true,
        source: 'worker',
        discoveredAt: new Date().toISOString(),
      });
    }

    if (signals.graphqlExplorer && probe.status >= 200 && probe.status < 300) {
      findings.push({
        id: makeFindingId(this.id, probe.url, 'explorer'),
        checkId: this.id,
        title: 'GraphQL Playground / GraphiQL exposed',
        severity: 'high',
        target: probe.url,
        description:
          'An interactive GraphQL explorer (Playground or GraphiQL) is publicly reachable. This typically enables schema browsing and ad-hoc query execution against the live API.',
        evidence: `URL: ${probe.url}\nStatus: ${probe.status}\nSignature: graphql-explorer\nBody preview: ${signals.preview}`,
        reproduction: [
          `Open ${probe.url} in a browser`,
          'Confirm GraphiQL / GraphQL Playground loads and can run queries',
        ],
        remediation:
          'Disable GraphQL Playground/GraphiQL in production builds and gate any remaining explorer behind strong authentication.',
        cwe: 'CWE-200',
        references: ['https://cwe.mitre.org/data/definitions/200.html'],
        needsManualReview: false,
        evidenceGrade: 'fingerprint',
        confidence: 0.88,
        submitReady: true,
        source: 'worker',
        discoveredAt: new Date().toISOString(),
      });
    }

    return findings;
  },
};

function stripQuery(url: string): string {
  try {
    const u = new URL(url);
    u.search = '';
    return u.toString();
  } catch {
    return url.split('?')[0] ?? url;
  }
}
