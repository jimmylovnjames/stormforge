// Exposed API schemas: OpenAPI/Swagger specs, Swagger UI / ReDoc, GraphQL
// Playground / GraphiQL, and GraphQL introspection payloads.
//
// The recon wordlist already GETs /swagger.json, /openapi.json, /graphql, etc.
// This check confirms those (and any other) responses are real schemas/UIs via
// body signatures — status-alone never flags — to keep false positives low.
// Non-destructive: inspects probe bodies only; never sends introspection queries.

import type { Check, Finding, ProbeResult } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';

interface Hit {
  kind: string;
  title: string;
  severity: Finding['severity'];
  detail: string;
  remediation: string;
  cwe: string;
  needsManualReview: boolean;
}

export const apiSchemaExposureCheck: Check = {
  id: 'api-schema-exposure',
  title: 'Exposed API schema / GraphQL explorer',
  cwe: 'CWE-200',
  run(probe: ProbeResult): Finding[] {
    if (probe.error || probe.status !== 200 || !probe.body) return [];

    const hit = classify(probe);
    if (!hit) return [];

    return [
      {
        id: makeFindingId(this.id, probe.url, hit.kind),
        checkId: this.id,
        title: hit.title,
        severity: hit.severity,
        target: probe.url,
        description: hit.detail,
        evidence: `URL: ${probe.url}\nStatus: ${probe.status}\nContent-Type: ${probe.headers['content-type'] ?? '<absent>'}\nSignature: ${hit.kind}\nBody preview: ${preview(probe.body)}`,
        reproduction: [
          `Fetch ${probe.url}`,
          `Confirm the response matches ${hit.kind} (see evidence signature)`,
          'Manually assess whether the schema/UI is intentionally public before reporting',
        ],
        remediation: hit.remediation,
        cwe: hit.cwe,
        references: [
          `https://cwe.mitre.org/data/definitions/${hit.cwe.replace('CWE-', '')}.html`,
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces',
        ],
        needsManualReview: hit.needsManualReview,
        discoveredAt: new Date().toISOString(),
      },
    ];
  },
};

function classify(probe: ProbeResult): Hit | null {
  const body = probe.body;
  const ct = (probe.headers['content-type'] ?? '').toLowerCase();
  const isHtml = ct.includes('text/html') || /^\s*</.test(body);

  // GraphQL introspection JSON (strongest signal — full type map).
  if (hasGraphqlIntrospection(body)) {
    return {
      kind: 'graphql-introspection',
      title: 'GraphQL introspection schema exposed',
      severity: 'high',
      detail:
        'The response contains a GraphQL introspection `__schema` payload. Attackers can enumerate every type, query, and mutation — including privileged operations — without authenticated discovery.',
      remediation:
        'Disable introspection in production (`introspection: false` / equivalent). Restrict GraphQL explorers to non-production environments.',
      cwe: 'CWE-200',
      needsManualReview: false,
    };
  }

  // OpenAPI / Swagger document (JSON or YAML-ish).
  const openapi = detectOpenApi(body);
  if (openapi) {
    return {
      kind: openapi.kind,
      title: openapi.title,
      severity: openapi.hasPaths ? 'high' : 'medium',
      detail: openapi.hasPaths
        ? `A complete ${openapi.label} document with path definitions is publicly reachable. This maps authenticated and unauthenticated endpoints, parameters, and often auth schemes for attackers.`
        : `An ${openapi.label} document is publicly reachable. Even without a full path map this discloses API surface metadata.`,
      remediation:
        'Serve OpenAPI/Swagger specs only to authenticated operators or internal networks; remove production copies from the web root.',
      cwe: 'CWE-200',
      needsManualReview: true,
    };
  }

  if (isHtml) {
    if (hasGraphqlExplorer(body)) {
      return {
        kind: 'graphql-explorer',
        title: 'GraphQL Playground / GraphiQL exposed',
        severity: 'high',
        detail:
          'An interactive GraphQL explorer (Playground or GraphiQL) is publicly reachable. This typically enables schema browsing and ad-hoc query execution against the live API.',
        remediation:
          'Disable GraphQL Playground/GraphiQL in production builds and gate any remaining explorer behind strong authentication.',
        cwe: 'CWE-200',
        needsManualReview: false,
      };
    }
    if (hasSwaggerUi(body)) {
      return {
        kind: 'swagger-ui',
        title: 'Swagger UI / ReDoc API docs exposed',
        severity: 'medium',
        detail:
          'Interactive API documentation (Swagger UI or ReDoc) is publicly reachable. Combined with a live Try-it-out backend this accelerates endpoint discovery and abuse.',
        remediation:
          'Restrict API documentation UIs to authenticated staff or non-production environments.',
        cwe: 'CWE-200',
        needsManualReview: true,
      };
    }
  }

  return null;
}

/** Confirmed introspection: __schema plus queryType and/or types array. */
function hasGraphqlIntrospection(body: string): boolean {
  if (!body.includes('__schema')) return false;
  // Require a second strong marker so random mentions do not flag.
  const hasQueryType = /"queryType"\s*:/.test(body) || /queryType\s*:/.test(body);
  const hasTypes = /"types"\s*:\s*\[/.test(body);
  const hasMutationType = /"mutationType"\s*:/.test(body);
  return (hasQueryType || hasMutationType) && (hasTypes || hasQueryType);
}

function detectOpenApi(body: string): { kind: string; title: string; label: string; hasPaths: boolean } | null {
  const trimmed = body.trim();
  // JSON OpenAPI 3.x
  const openapi3 = /"openapi"\s*:\s*"3\.\d+(\.\d+)?"/.exec(trimmed);
  // JSON Swagger 2.0
  const swagger2 = /"swagger"\s*:\s*"2\.0"/.exec(trimmed);
  // YAML OpenAPI (common accidental exposure)
  const yamlOpenapi = /^openapi:\s*['"]?3\.\d+/m.exec(trimmed);
  const yamlSwagger = /^swagger:\s*['"]?2\.0/m.exec(trimmed);

  if (!openapi3 && !swagger2 && !yamlOpenapi && !yamlSwagger) return null;

  // Second confirmation: paths or info block (avoids tiny stub / echo pages).
  const hasPaths =
    /"paths"\s*:\s*\{/.test(trimmed) || /^paths:\s*$/m.test(trimmed) || /^paths:\s*\{/m.test(trimmed);
  const hasInfo =
    /"info"\s*:\s*\{/.test(trimmed) || /^info:\s*$/m.test(trimmed) || /^info:\s*\{/m.test(trimmed);
  if (!hasPaths && !hasInfo) return null;

  if (openapi3 || yamlOpenapi) {
    return {
      kind: 'openapi-3',
      title: 'Exposed OpenAPI 3 specification',
      label: 'OpenAPI 3',
      hasPaths,
    };
  }
  return {
    kind: 'swagger-2',
    title: 'Exposed Swagger 2.0 specification',
    label: 'Swagger 2.0',
    hasPaths,
  };
}

function hasGraphqlExplorer(body: string): boolean {
  return (
    /GraphQL Playground/i.test(body) ||
    /graphql-playground/i.test(body) ||
    /\bGraphiQL\b/.test(body) ||
    /graphiql\.min\.js/i.test(body) ||
    /cdn\.jsdelivr\.net\/npm\/graphiql/i.test(body)
  );
}

function hasSwaggerUi(body: string): boolean {
  return (
    /SwaggerUIBundle/.test(body) ||
    /swagger-ui(-dist|-bundle)?(\.min)?\.js/i.test(body) ||
    /id=["']swagger-ui["']/i.test(body) ||
    /<redoc[\s>]/i.test(body) ||
    /redoc\.standalone\.js/i.test(body)
  );
}

function preview(body: string): string {
  return body.slice(0, 240).replace(/\s+/g, ' ');
}
